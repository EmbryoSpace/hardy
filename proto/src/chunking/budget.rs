//! The time a transfer may spend waiting for the client.

use core::{future::Future, time::Duration};

use tokio::time::{Instant, sleep_until};

use tonic::Status;

use crate::{
    limits::Limits,
    timeouts::{Stage, Timeouts},
};

/// The time a transfer may spend waiting for the client, and the rule for
/// when it has run out.
///
/// A transfer starts with [`Limits::grace`] and earns more by moving bytes, at
/// [`Limits::min_rate`]. Only the time it spends blocked on the client is
/// spent out of that: the server's own work between one chunk and the next is
/// not the client's to pay for. [`Limits::idle`] is the ceiling on any single
/// wait, so a client that goes quiet is caught even with budget to spare, and
/// the rate rule can only tighten a bound.
///
/// Time is earned only by moving bytes, so a client moving one byte at a time
/// cannot hold a transfer open by resetting `idle`.
pub struct Budget<'a> {
    timeouts: &'a Timeouts,
    /// The stage whose waits this budget bounds.
    stage: Stage,
    /// How long the waits so far have taken.
    spent: Duration,
}

impl<'a> Budget<'a> {
    /// Creates the budget of a transfer whose waits on the client are those of
    /// `stage`, bounded by the session's `timeouts`.
    pub fn new(timeouts: &'a Timeouts, stage: Stage) -> Self {
        Self {
            timeouts,
            stage,
            spent: Duration::ZERO,
        }
    }

    /// Waits for `waiting`, charging the time it takes against the budget,
    /// given the `moved` bytes the transfer has moved so far.
    ///
    /// Only what is awaited here is the client's to pay for, so a caller holds
    /// its own work outside.
    ///
    /// # Errors
    ///
    /// Returns `DEADLINE_EXCEEDED` if the budget runs out first, leaving
    /// `waiting` undone and the session's first timeout recorded at the
    /// budget's stage.
    pub async fn spend<T>(
        &mut self,
        moved: u64,
        waiting: impl Future<Output = T>,
    ) -> Result<T, Status> {
        let Limits {
            idle,
            grace,
            min_rate,
            ..
        } = self.timeouts.limits();
        let since = Instant::now();
        let deadline = match min_rate {
            Some(min_rate) => {
                let earned = Duration::from_secs(moved / min_rate.get());
                let left = (grace + earned).saturating_sub(self.spent);
                (since + left).min(since + idle)
            }
            None => since + idle,
        };
        let waited = tokio::select! {
            biased;
            value = waiting => Ok(value),
            () = sleep_until(deadline) => Err(self.timeouts.time_out(self.stage)),
        };
        self.spent += since.elapsed();
        waited
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use hardy_async::CancellationToken;
    use tokio::time::{advance, sleep};

    use super::*;

    /// The timeouts of a session holding its clients to a minimum rate.
    fn rated() -> Timeouts {
        Timeouts::new(
            Limits {
                idle: Duration::from_secs(30),
                grace: Duration::from_secs(30),
                min_rate: NonZeroU64::new(1024),
                ..Limits::default()
            },
            CancellationToken::new(),
        )
    }

    /// Spends `taken` of the budget on a client that has moved `moved` bytes,
    /// returning whether the budget survived.
    async fn wait(budget: &mut Budget<'_>, moved: u64, taken: Duration) -> bool {
        budget.spend(moved, sleep(taken)).await.is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_goes_quiet_is_caught_by_the_idle_ceiling() {
        let timeouts = rated();
        let mut budget = Budget::new(&timeouts, Stage::Feed);

        assert!(
            !wait(&mut budget, 1024 * 1024 * 1024, Duration::from_secs(31)).await,
            "a burst then silence must still be caught by the idle rule"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_disabled_rate_floor_leaves_only_the_idle_rule() {
        let timeouts = Timeouts::new(
            Limits {
                min_rate: None,
                ..rated().limits()
            },
            CancellationToken::new(),
        );
        let mut budget = Budget::new(&timeouts, Stage::Feed);

        for _ in 0..60 {
            assert!(
                wait(&mut budget, 1, Duration::from_secs(29)).await,
                "one byte per wait must satisfy a disabled floor"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_drip_feeder_is_stalled_once_its_grace_is_spent() {
        let timeouts = rated();
        let mut budget = Budget::new(&timeouts, Stage::Feed);

        for second in 0..60 {
            if !wait(&mut budget, second, Duration::from_secs(1)).await {
                assert_eq!(second, 30, "a drip feeder must survive its grace period");
                return;
            }
        }
        panic!("one byte per second must not outlive a 1024 byte/s minimum");
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_sustaining_the_minimum_rate_is_never_stalled() {
        let timeouts = rated();
        let mut budget = Budget::new(&timeouts, Stage::Feed);

        for second in 0..600 {
            assert!(
                wait(&mut budget, second * 1024, Duration::from_secs(1)).await,
                "a client at the minimum rate must not be stalled"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_servers_own_time_is_not_charged_to_the_client() {
        let timeouts = rated();
        let mut budget = Budget::new(&timeouts, Stage::Feed);

        for _ in 0..60 {
            assert!(
                wait(&mut budget, 0, Duration::ZERO).await,
                "a prompt client must not pay for the server's work"
            );
            // The server takes longer over one chunk than the whole budget.
            advance(Duration::from_secs(60)).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_waits_of_a_transfer_are_charged_together() {
        let timeouts = rated();
        let mut budget = Budget::new(&timeouts, Stage::Feed);

        for _ in 0..3 {
            assert!(
                wait(&mut budget, 0, Duration::from_secs(10)).await,
                "ten seconds at a time must fit in a thirty second grace"
            );
        }

        assert!(
            !wait(&mut budget, 0, Duration::from_secs(1)).await,
            "a fourth wait must find the grace already spent"
        );
    }
}
