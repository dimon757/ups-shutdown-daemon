use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use anyhow::{Context, Result};

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub snmp:     SnmpConfig,
    pub logging:  LoggingConfig,
    pub shutdown: ShutdownConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SnmpConfig {
    pub trap_port: u16,
    /// SNMP community string — every incoming trap is rejected unless it matches.
    pub community_string: String,
    /// If non-empty, only packets from these IP addresses are accepted.
    #[serde(default)]
    pub allowed_sources: Vec<IpAddr>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// File where all trap events are appended with timestamps.
    pub trap_log_file: String,
    /// Mirror log lines to stdout (same effect as --verbose CLI flag).
    #[serde(default)]
    pub verbose: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ShutdownConfig {
    // ── Timer-based (normal) shutdown ─────────────────────────────────────

    /// Maximum seconds UPS may run on battery (from trap #5) before a normal
    /// shutdown is initiated.
    pub time_on_battery: u64,

    /// Maximum seconds after LowBattery trap (#7) is received while in
    /// on-battery state, before a normal shutdown is initiated.
    /// Must be <= time_on_battery (validated at startup).
    /// Whichever timer fires first (on-battery or low-battery) wins.
    pub time_on_low_battery: u64,

    /// Graceful countdown (seconds) after a timer-based shutdown is triggered.
    /// Gives logged-in users time to save work before poweroff.
    pub delay_seconds: u64,


    // ── Instant-shutdown traps ─────────────────────────────────────────────

    /// Short countdown (seconds) for hardware-fault and UPS-initiated traps
    /// that indicate imminent or immediate power loss.
    /// Also used when the communication-lost timer fires.
    #[serde(default = "default_immediate_delay")]
    pub immediate_delay_seconds: u64,

    // ── Pre-shutdown script ────────────────────────────────────────────────

    /// Absolute path to an executable script run just before poweroff.
    /// Validated at startup: must exist and be executable.
    pub pre_shutdown_script: Option<String>,

    /// Hard deadline (seconds) for pre_shutdown_script.
    /// If exceeded the script is abandoned and shutdown proceeds.
    #[serde(default = "default_script_timeout")]
    pub script_timeout_seconds: u64,
}

fn default_immediate_delay() -> u64 { 5 }
fn default_script_timeout()  -> u64 { 25 }

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config: {}", path.as_ref().display()))?;
        toml::from_str(&content).context("Failed to parse config TOML")
    }

    pub fn validate(&self) -> Result<()> {
        if self.snmp.community_string.is_empty() {
            anyhow::bail!("snmp.community_string must not be empty");
        }
        if self.shutdown.time_on_battery < 10 {
            anyhow::bail!("shutdown.time_on_battery must be >= 10 (got {})",
                self.shutdown.time_on_battery);
        }
        if self.shutdown.time_on_low_battery < 5 {
            anyhow::bail!("shutdown.time_on_low_battery must be >= 5 (got {})",
                self.shutdown.time_on_low_battery);
        }
        if self.shutdown.time_on_low_battery > self.shutdown.time_on_battery {
            anyhow::bail!(
                "shutdown.time_on_low_battery ({}) must be <= time_on_battery ({})",
                self.shutdown.time_on_low_battery, self.shutdown.time_on_battery
            );
        }
        if self.shutdown.delay_seconds == 0 {
            anyhow::bail!("shutdown.delay_seconds must be > 0");
        }
        if self.shutdown.script_timeout_seconds == 0 {
            anyhow::bail!("shutdown.script_timeout_seconds must be > 0");
        }
        if let Some(ref script) = self.shutdown.pre_shutdown_script {
            let p = std::path::Path::new(script);
            if !p.exists() {
                anyhow::bail!("pre_shutdown_script '{}' does not exist", script);
            }
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(p)
                .with_context(|| format!("Cannot stat pre_shutdown_script '{}'", script))?
                .permissions().mode();
            if mode & 0o111 == 0 {
                anyhow::bail!("pre_shutdown_script '{}' is not executable", script);
            }
        }
        Ok(())
    }
}
