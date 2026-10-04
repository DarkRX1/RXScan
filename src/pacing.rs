use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PacingSample {
    pub rtt_ms: u64,
    pub timeout_ratio: f64,
    pub failure_ratio: f64,
    pub backlog: usize,
    pub socket_pressure: f64,
}

impl PacingSample {
    pub fn nominal() -> Self {
        Self {
            rtt_ms: 50,
            timeout_ratio: 0.0,
            failure_ratio: 0.0,
            backlog: 0,
            socket_pressure: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacingBounds {
    pub min_concurrency: usize,
    pub max_concurrency: usize,
    pub min_timeout_ms: u64,
    pub max_timeout_ms: u64,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl PacingBounds {
    pub fn clamp_concurrency(&self, value: usize) -> usize {
        value.clamp(self.min_concurrency, self.max_concurrency)
    }

    pub fn clamp_timeout(&self, value: u64) -> u64 {
        value.clamp(self.min_timeout_ms, self.max_timeout_ms)
    }

    pub fn clamp_delay(&self, value: u64) -> u64 {
        value.clamp(self.min_delay_ms, self.max_delay_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacingDecision {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retry_delay_ms: u64,
    pub slowed: bool,
    pub reason: PacingAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacingAction {
    Steady,
    SlowDown,
    SpeedUp,
}

impl PacingAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Steady => "steady",
            Self::SlowDown => "slow_down",
            Self::SpeedUp => "speed_up",
        }
    }
}

pub fn suggest(
    current_concurrency: usize,
    current_timeout: Duration,
    current_delay: Duration,
    sample: PacingSample,
    bounds: PacingBounds,
) -> PacingDecision {
    let stressed = sample.timeout_ratio > 0.2
        || sample.failure_ratio > 0.3
        || sample.socket_pressure > 0.8
        || sample.backlog > 512;
    let idle = sample.timeout_ratio < 0.02
        && sample.failure_ratio < 0.05
        && sample.socket_pressure < 0.3
        && sample.backlog < 16
        && sample.rtt_ms < 200;

    if stressed {
        let concurrency = bounds.clamp_concurrency(
            current_concurrency.saturating_sub((current_concurrency / 4).max(1)),
        );
        let timeout_ms = bounds.clamp_timeout(
            current_timeout.as_millis() as u64 + (current_timeout.as_millis() as u64 / 4).max(50),
        );
        let delay_ms = bounds.clamp_delay(current_delay.as_millis() as u64 + 25);
        return PacingDecision {
            concurrency,
            timeout_ms,
            retry_delay_ms: delay_ms,
            slowed: true,
            reason: PacingAction::SlowDown,
        };
    }
    if idle {
        let concurrency =
            bounds.clamp_concurrency(current_concurrency + (current_concurrency / 8).max(1));
        let timeout_ms = bounds.clamp_timeout(
            (current_timeout.as_millis() as u64)
                .saturating_sub((current_timeout.as_millis() as u64 / 8).max(10)),
        );
        return PacingDecision {
            concurrency,
            timeout_ms,
            retry_delay_ms: bounds.clamp_delay(current_delay.as_millis() as u64),
            slowed: false,
            reason: PacingAction::SpeedUp,
        };
    }
    PacingDecision {
        concurrency: bounds.clamp_concurrency(current_concurrency),
        timeout_ms: bounds.clamp_timeout(current_timeout.as_millis() as u64),
        retry_delay_ms: bounds.clamp_delay(current_delay.as_millis() as u64),
        slowed: false,
        reason: PacingAction::Steady,
    }
}

pub fn describe(decision: &PacingDecision) -> String {
    let action = match decision.reason {
        PacingAction::Steady => "steady",
        PacingAction::SlowDown => "slow-down",
        PacingAction::SpeedUp => "speed-up",
    };
    format!(
        "pacing {action}: concurrency {}, timeout {}ms, retry_delay {}ms",
        decision.concurrency, decision.timeout_ms, decision.retry_delay_ms
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> PacingBounds {
        PacingBounds {
            min_concurrency: 1,
            max_concurrency: 64,
            min_timeout_ms: 200,
            max_timeout_ms: 3000,
            min_delay_ms: 0,
            max_delay_ms: 1000,
        }
    }

    #[test]
    fn calm_sample_increases_within_bounds() {
        let out = suggest(
            16,
            Duration::from_millis(800),
            Duration::from_millis(50),
            PacingSample::nominal(),
            bounds(),
        );
        assert_eq!(out.reason, PacingAction::SpeedUp);
        assert!(out.concurrency >= 16 && out.concurrency <= 64);
    }

    #[test]
    fn timeout_storm_reduces_concurrency_and_raises_timeout() {
        let out = suggest(
            32,
            Duration::from_millis(800),
            Duration::from_millis(50),
            PacingSample {
                timeout_ratio: 0.5,
                failure_ratio: 0.1,
                rtt_ms: 400,
                backlog: 10,
                socket_pressure: 0.2,
            },
            bounds(),
        );
        assert_eq!(out.reason, PacingAction::SlowDown);
        assert!(out.concurrency < 32);
        assert!(out.timeout_ms > 800);
        assert!(out.slowed);
    }

    #[test]
    fn never_exceeds_configured_budgets() {
        let tight = PacingBounds {
            max_concurrency: 8,
            max_timeout_ms: 500,
            max_delay_ms: 100,
            ..bounds()
        };
        let out = suggest(
            8,
            Duration::from_millis(500),
            Duration::from_millis(100),
            PacingSample::nominal(),
            tight,
        );
        assert!(out.concurrency <= 8);
        assert!(out.timeout_ms <= 500);
        assert!(out.retry_delay_ms <= 100);
    }

    #[test]
    fn deterministic_for_same_input() {
        let sample = PacingSample {
            rtt_ms: 120,
            timeout_ratio: 0.05,
            failure_ratio: 0.05,
            backlog: 40,
            socket_pressure: 0.5,
        };
        let first = suggest(
            16,
            Duration::from_millis(800),
            Duration::from_millis(50),
            sample,
            bounds(),
        );
        let second = suggest(
            16,
            Duration::from_millis(800),
            Duration::from_millis(50),
            sample,
            bounds(),
        );
        assert_eq!(first, second);
        assert_eq!(first.reason, PacingAction::Steady);
    }

    #[test]
    fn describe_is_stable() {
        let out = suggest(
            16,
            Duration::from_millis(800),
            Duration::from_millis(50),
            PacingSample::nominal(),
            bounds(),
        );
        assert!(describe(&out).contains("concurrency"));
    }
}
