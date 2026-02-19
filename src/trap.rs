// src/trap.rs — UPS trap classification and state machine v1.5.0

use tokio::time::Instant;

// ── Trap enum ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsTrap {
    // ── Instant shutdown (non-cancellable) ──────────────────────────────
    DiagnosticsFailed             = 3,
    UpsDischarged                 = 4,
    UpsTurnedOff                  = 12,
    UpsRebootStarted              = 15,
    UpsScheduleShutdown           = 52,
    UpsShortCircuitShutdown       = 54,
    UpsHighDCShutdown             = 57,
    UpsEmergencyStop              = 58,
    UpsOverTemperatureShutdown    = 61,
    UpsOverLoadShutdown           = 62,
    UpsLowBatteryShutdown         = 67,

    // ── State transitions ────────────────────────────────────────────────
    CommunicationLost             = 1,   // informational
    UpsOnBattery                  = 5,   // → OnBattery
    LowBattery                    = 7,   // → low-battery sub-timer

    // ── Cancel / recovery ────────────────────────────────────────────────
    CommunicationEstablished      = 8,
    PowerRestored                 = 9,   // cancels OnBattery
    ReturnFromLowBattery          = 11,  // clears low-battery sub-timer
    UpsWokeUp                     = 14,
    UpsBypassAcNormal             = 49,  // cancels OnBattery
    UpsBypassReturn               = 53,

    Unknown                       = 0,
}

impl UpsTrap {
    pub fn from_oid(oid: &[u64]) -> Self {
        const PPC: [u64; 7] = [1, 3, 6, 1, 4, 1, 935];
        if oid.len() < PPC.len() + 2 { return Self::Unknown; }
        if oid[..PPC.len()] != PPC    { return Self::Unknown; }
        let rest     = &oid[PPC.len()..];
        let zero_pos = match rest.iter().rposition(|&v| v == 0) {
            Some(p) => p,
            None    => return Self::Unknown,
        };
        match rest.get(zero_pos + 1) {
            Some(&n) => Self::from_specific(n),
            None     => Self::Unknown,
        }
    }

    pub fn from_specific(n: u64) -> Self {
        match n {
            1  => Self::CommunicationLost,
            3  => Self::DiagnosticsFailed,
            4  => Self::UpsDischarged,
            5  => Self::UpsOnBattery,
            7  => Self::LowBattery,
            8  => Self::CommunicationEstablished,
            9  => Self::PowerRestored,
            11 => Self::ReturnFromLowBattery,
            12 => Self::UpsTurnedOff,
            14 => Self::UpsWokeUp,
            15 => Self::UpsRebootStarted,
            49 => Self::UpsBypassAcNormal,
            52 => Self::UpsScheduleShutdown,
            53 => Self::UpsBypassReturn,
            54 => Self::UpsShortCircuitShutdown,
            57 => Self::UpsHighDCShutdown,
            58 => Self::UpsEmergencyStop,
            61 => Self::UpsOverTemperatureShutdown,
            62 => Self::UpsOverLoadShutdown,
            67 => Self::UpsLowBatteryShutdown,
            _  => Self::Unknown,
        }
    }

    pub fn is_instant_shutdown(self) -> bool {
        matches!(self,
            Self::DiagnosticsFailed
            | Self::UpsDischarged
            | Self::UpsTurnedOff
            | Self::UpsRebootStarted
            | Self::UpsScheduleShutdown
            | Self::UpsShortCircuitShutdown
            | Self::UpsHighDCShutdown
            | Self::UpsEmergencyStop
            | Self::UpsOverTemperatureShutdown
            | Self::UpsOverLoadShutdown
            | Self::UpsLowBatteryShutdown
        )
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::CommunicationLost          => "Communication Lost",
            Self::DiagnosticsFailed          => "UPS Self-Test Failed",
            Self::UpsDischarged              => "UPS Runtime Calibration Discharge",
            Self::UpsOnBattery               => "On Battery",
            Self::LowBattery                 => "Low Battery",
            Self::CommunicationEstablished   => "Communication Established",
            Self::PowerRestored              => "Power Restored",
            Self::ReturnFromLowBattery       => "Return from Low Battery",
            Self::UpsTurnedOff               => "Turned Off by Management",
            Self::UpsWokeUp                  => "UPS Woke Up",
            Self::UpsRebootStarted           => "Reboot Sequence Started",
            Self::UpsBypassAcNormal          => "Bypass AC Normal",
            Self::UpsScheduleShutdown        => "Scheduled Shutdown",
            Self::UpsBypassReturn            => "Return from Bypass",
            Self::UpsShortCircuitShutdown    => "Short Circuit Shutdown",
            Self::UpsHighDCShutdown          => "High DC Shutdown",
            Self::UpsEmergencyStop           => "Emergency Stop",
            Self::UpsOverTemperatureShutdown => "Over Temperature Shutdown",
            Self::UpsOverLoadShutdown        => "Overload Shutdown",
            Self::UpsLowBatteryShutdown      => "Low Battery Shutdown",
            Self::Unknown                    => "Unknown Trap",
        }
    }
}

// ── State transition result ─────────────────────────────────────────────────

#[derive(Debug)]
pub enum StateTransition {
    None,
    EnterOnBattery,
    StartLowBattery,
    LowBatteryAlreadyRunning,
    IgnoredWrongState { note: &'static str },
    ClearLowBattery,
    ExitOnBattery { reason: &'static str },
}

// ── Operating state ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum UpsState {
    Normal,
    OnBattery {
        battery_since:     Instant,
        low_battery_since: Option<Instant>,
    },
}

impl UpsState {
    pub fn apply(&self, trap: UpsTrap) -> StateTransition {
        match (self, trap) {
            (Self::Normal, UpsTrap::UpsOnBattery) => StateTransition::EnterOnBattery,

            (Self::OnBattery { .. }, UpsTrap::UpsOnBattery) => StateTransition::None,

            (Self::OnBattery { low_battery_since: None, .. }, UpsTrap::LowBattery) =>
                StateTransition::StartLowBattery,

            (Self::OnBattery { low_battery_since: Some(_), .. }, UpsTrap::LowBattery) =>
                StateTransition::LowBatteryAlreadyRunning,

            (Self::Normal, UpsTrap::LowBattery) => StateTransition::IgnoredWrongState {
                note: "LowBattery (#7) received while not on battery — logged only",
            },

            (Self::OnBattery { .. }, UpsTrap::PowerRestored) =>
                StateTransition::ExitOnBattery { reason: "PowerRestored" },

            (Self::OnBattery { .. }, UpsTrap::UpsBypassAcNormal) =>
                StateTransition::ExitOnBattery { reason: "UpsBypassAcNormal" },

            (Self::OnBattery { .. }, UpsTrap::ReturnFromLowBattery) =>
                StateTransition::ClearLowBattery,

            (_, UpsTrap::ReturnFromLowBattery) => StateTransition::IgnoredWrongState {
                note: "ReturnFromLowBattery received — not in OnBattery state, ignored",
            },

            (_, UpsTrap::PowerRestored) => StateTransition::IgnoredWrongState {
                note: "PowerRestored received — not in OnBattery state, ignored",
            },

            (_, UpsTrap::UpsBypassAcNormal) => StateTransition::IgnoredWrongState {
                note: "UpsBypassAcNormal received — not in OnBattery state, ignored",
            },

            _ => StateTransition::None,
        }
    }
}

// ── Optional tests (25+ tests available if you want full coverage) ─────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_to_on_battery() {
        assert!(matches!(
            UpsState::Normal.apply(UpsTrap::UpsOnBattery),
            StateTransition::EnterOnBattery
        ));
    }
}