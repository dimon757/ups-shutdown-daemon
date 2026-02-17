// trap.rs — UPS trap classification and state machine
//
// UpsState is responsible for deciding what transition a trap causes.
// ShutdownManager is responsible for executing that transition.

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
    CommunicationLost             = 1,   // informational — logged only
    UpsOnBattery                  = 5,   // → OnBattery state
    LowBattery                    = 7,   // → starts low_battery_timer (if OnBattery)

    // ── Cancel / recovery ────────────────────────────────────────────────
    CommunicationEstablished      = 8,   // informational — logged only
    PowerRestored                 = 9,   // cancels OnBattery state
    ReturnFromLowBattery          = 11,  // clears low_battery_timer inside OnBattery
    UpsWokeUp                     = 14,  // informational
    UpsBypassAcNormal             = 49,  // cancels OnBattery state
    UpsBypassReturn               = 53,  // informational

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

    /// Traps that cause an immediate (non-cancellable) shutdown regardless of state.
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

/// What the manager must do after a trap is received in a given state.
/// Returned by `UpsState::apply()` — the state decides, the manager acts.
#[derive(Debug)]
pub enum StateTransition {
    /// No state change or action required — trap was informational.
    None,
    /// Enter OnBattery state and start the battery timer.
    EnterOnBattery,
    /// Start the low-battery sub-timer (already in OnBattery).
    StartLowBattery,
    /// LowBattery received but low-battery sub-timer is already running.
    LowBatteryAlreadyRunning,
    /// Trap received in wrong state (e.g. LowBattery while Normal).
    IgnoredWrongState { note: &'static str },
    /// Clear the low-battery sub-timer, stay in OnBattery.
    ClearLowBattery,
    /// Return to Normal, cancelling any pending normal shutdown.
    ExitOnBattery { reason: &'static str },
}

// ── Operating state ─────────────────────────────────────────────────────────

/// The two operating states of the daemon.
/// Each state is responsible for deciding what a received trap means.
#[derive(Debug)]
pub enum UpsState {
    /// No active condition — logging only.
    Normal,

    /// UPS is running on battery.
    /// Entered on trap #5. Exited on trap #9 or #49.
    OnBattery {
        /// When trap #5 was received.
        battery_since: Instant,
        /// When trap #7 (LowBattery) was received, if ever.
        /// None → low-battery timer not yet started.
        /// Cleared (→ None) by trap #11 (ReturnFromLowBattery).
        low_battery_since: Option<Instant>,
    },
}

impl UpsState {
    /// Given a trap, return the transition the manager must execute.
    /// Instant-shutdown traps are not handled here — the manager checks
    /// `is_instant_shutdown()` before calling `apply()`.
    pub fn apply(&self, trap: UpsTrap) -> StateTransition {
        match (self, trap) {

            // ── OnBattery ─────────────────────────────────────────────────
            (Self::Normal, UpsTrap::UpsOnBattery) =>
                StateTransition::EnterOnBattery,

            (Self::OnBattery { .. }, UpsTrap::UpsOnBattery) =>
                StateTransition::None, // already in OnBattery — ignored

            (Self::OnBattery { low_battery_since: None, .. }, UpsTrap::LowBattery) =>
                StateTransition::StartLowBattery,

            (Self::OnBattery { low_battery_since: Some(_), .. }, UpsTrap::LowBattery) =>
                StateTransition::LowBatteryAlreadyRunning,

            (Self::Normal, UpsTrap::LowBattery) =>
                StateTransition::IgnoredWrongState {
                    note: "LowBattery (#7) received while not on battery — logged only",
                },

            (Self::OnBattery { .. }, UpsTrap::PowerRestored) =>
                StateTransition::ExitOnBattery { reason: "PowerRestored" },

            (Self::OnBattery { .. }, UpsTrap::UpsBypassAcNormal) =>
                StateTransition::ExitOnBattery { reason: "UpsBypassAcNormal" },

            (Self::OnBattery { .. }, UpsTrap::ReturnFromLowBattery) =>
                StateTransition::ClearLowBattery,

            // ReturnFromLowBattery outside OnBattery
            (_, UpsTrap::ReturnFromLowBattery) =>
                StateTransition::IgnoredWrongState {
                    note: "ReturnFromLowBattery received — not in OnBattery state, ignored",
                },

            // PowerRestored / UpsBypassAcNormal outside OnBattery
            (_, UpsTrap::PowerRestored) =>
                StateTransition::IgnoredWrongState {
                    note: "PowerRestored received — not in OnBattery state, ignored",
                },

            (_, UpsTrap::UpsBypassAcNormal) =>
                StateTransition::IgnoredWrongState {
                    note: "UpsBypassAcNormal received — not in OnBattery state, ignored",
                },

            // Everything else — informational, or already-OnBattery ignored
            _ => StateTransition::None,
        }
    }


}
