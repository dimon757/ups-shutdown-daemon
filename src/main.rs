// ups-shutdown-daemon — main.rs  v1.3.0
//
// State-machine based trap handler for PPC/Upsmate UPS devices.
//
// States
// ──────
//  Normal    — no active condition
//  OnBattery — #5 received; on_battery_timer running
//              optionally: #7 received → low_battery_timer also running
//
// Timer-based (normal) shutdown
// ──────────────────────────────
//  on_battery_timer  >= time_on_battery     → delay_seconds → poweroff
//  low_battery_timer >= time_on_low_battery → delay_seconds → poweroff
//  (whichever fires first wins)
//
// Instant-shutdown traps (immediate_delay_seconds, non-cancellable)
// ──────────────────────────────────────────────────────────────────
//  #3  DiagnosticsFailed          #12 UpsTurnedOff
//  #4  UpsDischarged              #15 UpsRebootStarted
//  #52 UpsScheduleShutdown        #54 UpsShortCircuitShutdown
//  #57 UpsHighDCShutdown          #58 UpsEmergencyStop
//  #61 UpsOverTemperatureShutdown #62 UpsOverLoadShutdown
//  #67 UpsLowBatteryShutdown
//
// Cancel conditions
// ──────────────────
//  OnBattery state: trap #9 (PowerRestored) or #49 (UpsBypassAcNormal)
//
// Informational only (logged, no state change, no action)
// ──────────────────────────────────────────────────────
//  #1  CommunicationLost        — logged only
//  #8  CommunicationEstablished — logged only

use anyhow::{Context, Result};
use clap::Parser;
use futures::future::OptionFuture;
use futures::stream::StreamExt;
use nix::sys::reboot::{reboot, RebootMode};
use nix::unistd::sync;
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use syslog::{Facility, Formatter3164};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Instant, interval_at};
use chrono;

mod config;
use config::Config;

// ====================== CLI ======================

#[derive(Parser, Debug)]
#[command(about = "UPS SNMP trap listener — PPC/Upsmate enterprise 1.3.6.1.4.1.935")]
struct Args {
    #[arg(short, long, default_value = "/etc/ups-shutdown/config.toml")]
    config: PathBuf,
    /// Simulate shutdown decisions without actually powering off.
    #[arg(short, long)]
    test_mode: bool,
    /// Print every received trap and decision to stdout.
    #[arg(short, long)]
    verbose: bool,
}

// ====================== Trap Enum ======================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpsTrap {
    // ── Instant shutdown (non-cancellable) ───────────────────────────────
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
    UpsLowBatteryShutdown         = 67,  // UPS itself shutting down — always immediate

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
    fn from_oid(oid: &[u64]) -> Self {
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

    fn from_specific(n: u64) -> Self {
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
    fn is_instant_shutdown(self) -> bool {
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

    fn description(self) -> &'static str {
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

// ====================== Daemon State Machine ======================

/// The three exclusive operating states of the daemon.
/// Transitions are driven exclusively by received SNMP traps.
#[derive(Debug)]
enum UpsState {
    /// No active condition — logging only.
    Normal,

    /// UPS is running on battery.
    /// Entered on trap #5 (UpsOnBattery).
    /// Exited on trap #9 (PowerRestored) or #49 (UpsBypassAcNormal).
    OnBattery {
        /// When trap #5 was received.
        battery_since: Instant,
        /// When trap #7 (LowBattery) was received, if ever.
        /// None → low-battery timer not yet started.
        /// Cleared (→ None) by trap #11 (ReturnFromLowBattery).
        low_battery_since: Option<Instant>,
    },
}

// ====================== Parsed SNMP Packet ======================

struct ParsedTrap {
    oid:       Vec<u64>,
    community: String,
}

// ====================== Shutdown Manager ======================

struct ShutdownManager {
    config:             Config,
    test_mode:          bool,
    verbose:            bool,
    state:              UpsState,
    /// 10-second tick interval — active only when state is OnBattery,
    /// None when state is Normal.
    tick_interval:      Option<tokio::time::Interval>,
    /// Shared with spawned normal-shutdown task.  Set to false to cancel.
    shutdown_scheduled: Arc<AtomicBool>,
    logger:             syslog::Logger<syslog::LoggerBackend, Formatter3164>,
}

impl ShutdownManager {
    fn new(config: Config, test_mode: bool, verbose: bool) -> Result<Self> {
        let formatter = Formatter3164 {
            facility: Facility::LOG_DAEMON,
            hostname: None,
            process:  "ups-shutdown".into(),
            pid:      std::process::id(),
        };
        let logger = syslog::unix(formatter)
            .map_err(|e| anyhow::anyhow!("Syslog init failed: {}", e))?;
        Ok(Self {
            config,
            test_mode,
            verbose,
            state:              UpsState::Normal,
            tick_interval:      None,
            shutdown_scheduled: Arc::new(AtomicBool::new(false)),
            logger,
        })
    }

    // ── Logging ────────────────────────────────────────────────────────────

    /// Write to trap log file (always) and stdout (when verbose).
    fn log(&self, msg: &str) {
        if self.verbose { println!("{}", msg); }
        if let Ok(mut f) = OpenOptions::new()
            .create(true).append(true)
            .open(&self.config.logging.trap_log_file)
        {
            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = writeln!(f, "[{}] {}", ts, msg);
        }
    }

    /// Log + syslog INFO.
    fn info(&mut self, msg: &str) {
        self.log(msg);
        let _ = self.logger.info(msg);
    }

    /// Log + syslog WARNING.
    fn warn(&mut self, msg: &str) {
        self.log(msg);
        let _ = self.logger.warning(msg);
    }

    /// Log + syslog ERR.
    fn err(&mut self, msg: &str) {
        self.log(msg);
        let _ = self.logger.err(msg);
    }

    // ── Source / community authentication ──────────────────────────────────

    fn is_allowed_source(&self, src: &SocketAddr) -> bool {
        let list = &self.config.snmp.allowed_sources;
        list.is_empty() || list.contains(&src.ip())
    }

    fn community_ok(&self, community: &str) -> bool {
        community == self.config.snmp.community_string
    }

    // ── Tick interval management ────────────────────────────────────────────

    /// Activate the 10-second tick.  First tick fires after 10 s (not immediately).
    fn start_tick(&mut self) {
        self.tick_interval = Some(interval_at(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(10),
        ));
    }

    /// Deactivate the 10-second tick.
    fn stop_tick(&mut self) {
        self.tick_interval = None;
    }

    // ── State transitions ───────────────────────────────────────────────────

    /// Enter OnBattery state and start the battery timer.
    fn enter_on_battery(&mut self) {
        self.info("STATE → OnBattery: on-battery timer started");
        self.state = UpsState::OnBattery {
            battery_since:    Instant::now(),
            low_battery_since: None,
        };
        self.start_tick();
    }

    /// While in OnBattery, begin the low-battery sub-timer.
    fn enter_low_battery(&mut self) {
        if let UpsState::OnBattery { ref mut low_battery_since, .. } = self.state {
            if low_battery_since.is_none() {
                *low_battery_since = Some(Instant::now());
                self.info("OnBattery+LowBattery: low-battery timer started");
            }
        }
    }

    /// Clear the low-battery sub-timer without leaving OnBattery.
    fn clear_low_battery(&mut self) {
        if let UpsState::OnBattery { ref mut low_battery_since, .. } = self.state {
            *low_battery_since = None;
            self.info("OnBattery: low-battery timer cleared (ReturnFromLowBattery)");
        }
    }

    /// Leave OnBattery and return to Normal.  Cancels any pending normal shutdown.
    fn exit_on_battery(&mut self, reason: &str) {
        self.warn(&format!("STATE → Normal: {} — cancelling any pending shutdown", reason));
        self.shutdown_scheduled.store(false, Ordering::SeqCst);
        self.state = UpsState::Normal;
        self.stop_tick();
    }





    // ── Periodic check (called every 10 s by tick) ──────────────────────────

    pub async fn check_timers(&mut self) -> Result<()> {
        match self.state {
            UpsState::OnBattery { battery_since, low_battery_since } => {
                let on_bat_secs = battery_since.elapsed().as_secs();

                // Low-battery timer fires first if it exists and has expired.
                if let Some(lb) = low_battery_since {
                    let lb_secs = lb.elapsed().as_secs();
                    if lb_secs >= self.config.shutdown.time_on_low_battery {
                        self.warn(&format!(
                            "Low-battery timeout: {}s >= time_on_low_battery={}s — normal shutdown",
                            lb_secs, self.config.shutdown.time_on_low_battery
                        ));
                        self.initiate_normal_shutdown("LowBattery timeout").await?;
                        return Ok(());
                    }
                }

                // On-battery timer.
                if on_bat_secs >= self.config.shutdown.time_on_battery {
                    self.warn(&format!(
                        "On-battery timeout: {}s >= time_on_battery={}s — normal shutdown",
                        on_bat_secs, self.config.shutdown.time_on_battery
                    ));
                    self.initiate_normal_shutdown("OnBattery timeout").await?;
                }
            }

            UpsState::Normal => {}
        }
        Ok(())
    }

    // ── Trap dispatcher ─────────────────────────────────────────────────────

    pub async fn handle_trap(&mut self, trap: UpsTrap, src: SocketAddr) -> Result<()> {
        // Every trap is logged — this is the primary audit trail.
        let msg = format!("Trap #{} ({}) from {}", trap as u64, trap.description(), src);
        self.info(&msg);

        // ── Instant shutdown — non-cancellable, state-independent ──────────
        if trap.is_instant_shutdown() {
            let reason = format!("Instant-shutdown trap: #{} {}", trap as u64, trap.description());
            self.err(&reason);
            self.initiate_immediate_shutdown(&reason).await?;
            return Ok(());
        }

        // ── State-driven trap handling ──────────────────────────────────────
        match trap {

            // ── Enter OnBattery ──────────────────────────────────────────────
            UpsTrap::UpsOnBattery => {
                match self.state {
                    UpsState::Normal => {
                        // Normal path: start battery timer.
                        self.enter_on_battery();
                    }
                    UpsState::OnBattery { .. } => {
                        self.info("UpsOnBattery received — already in OnBattery state, ignored");
                    }
                }
            }

            // ── Low battery (only meaningful while on battery) ───────────────
            UpsTrap::LowBattery => {
                match self.state {
                    UpsState::OnBattery { .. } => {
                        self.enter_low_battery();
                    }
                    _ => {
                        self.info("LowBattery received outside OnBattery state — logged only");
                    }
                }
            }

            // ── Cancel OnBattery ─────────────────────────────────────────────
            UpsTrap::PowerRestored => {
                match self.state {
                    UpsState::OnBattery { .. } => {
                        let msg = format!("Trap #{} {}", trap as u64, trap.description());
                        let _ = Command::new("wall").arg(&msg).output();
                        self.exit_on_battery("PowerRestored");
                    }
                    _ => { self.info("PowerRestored received — not in OnBattery state, ignored"); }
                }
            }

            UpsTrap::UpsBypassAcNormal => {
                match self.state {
                    UpsState::OnBattery { .. } => {
                        let msg = format!("Trap #{} {}", trap as u64, trap.description());
                        let _ = Command::new("wall").arg(&msg).output();
                        self.exit_on_battery("UpsBypassAcNormal");
                    }
                    _ => { self.info("UpsBypassAcNormal received — not in OnBattery state, ignored"); }
                }
            }

            // ── Return from low battery (clear sub-timer, stay OnBattery) ────
            UpsTrap::ReturnFromLowBattery => {
                self.clear_low_battery();
            }

            // ── Communication traps — informational only ─────────────────────
            // Trap #1 is never received in practice; trap #8 is informational.
            UpsTrap::CommunicationLost => {
                self.info("CommunicationLost (#1) received — logged only, no action");
            }

            UpsTrap::CommunicationEstablished => {
                self.info("CommunicationEstablished (#8) received — informational");
            }


            // ── Purely informational ─────────────────────────────────────────
            UpsTrap::UpsWokeUp | UpsTrap::UpsBypassReturn | UpsTrap::Unknown => {
                // Already logged above, no state change.
            }

            // ── Handled above by is_instant_shutdown() ───────────────────────
            _ => {}
        }

        Ok(())
    }

    // ── Shutdown execution ──────────────────────────────────────────────────

    /// Normal (timer-based) shutdown: cancellable within delay_seconds window.
    async fn initiate_normal_shutdown(&mut self, reason: &str) -> Result<()> {
        if self.shutdown_scheduled.load(Ordering::SeqCst) {
            // Already scheduled — stop the tick so this branch is never reached again.
            self.stop_tick();
            return Ok(());
        }
        let delay = self.config.shutdown.delay_seconds;
        self.shutdown_scheduled.store(true, Ordering::SeqCst);

        // Stop the 10s tick: shutdown is now committed, no further timer checks needed.
        self.stop_tick();

        let msg = format!(
            "SHUTDOWN in {}s — {} [{}]",
            delay, reason,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        // wall broadcasts to every terminal — do NOT also print via self.err() to stdout
        // or the line appears twice (once from wall, once from the verbose logger).
        let _ = Command::new("wall").arg(&msg).output();
        let _ = self.logger.err(&msg);
        // Write to trap log file only (no stdout).
        if let Ok(mut f) = OpenOptions::new().create(true).append(true)
            .open(&self.config.logging.trap_log_file)
        {
            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = writeln!(f, "[{}] {}", ts, msg);
        }

        if self.test_mode {
            println!("TEST MODE: would poweroff after {}s", delay);
            return Ok(());
        }

        let flag           = self.shutdown_scheduled.clone();
        let script         = self.config.shutdown.pre_shutdown_script.clone();
        let script_timeout = self.config.shutdown.script_timeout_seconds;

        tokio::spawn(async move {
            sleep(Duration::from_secs(delay)).await;
            if !flag.load(Ordering::SeqCst) {
                eprintln!("Normal shutdown cancelled during countdown.");
                return;
            }
            run_script_and_poweroff(script, script_timeout).await;
        });

        Ok(())
    }

    /// Immediate (non-cancellable) shutdown: short fixed delay then poweroff.
    async fn initiate_immediate_shutdown(&mut self, reason: &str) -> Result<()> {
        // Guard: if already scheduled (e.g. from a previous instant-shutdown trap
        // or a comm-lost timeout that fired repeatedly), do nothing and stop the tick.
        if self.shutdown_scheduled.load(Ordering::SeqCst) {
            self.stop_tick();
            return Ok(());
        }
        self.shutdown_scheduled.store(true, Ordering::SeqCst);

        // Stop the tick immediately — no further timer checks needed.
        self.stop_tick();

        let delay = self.config.shutdown.immediate_delay_seconds;

        let msg = format!(
            "IMMEDIATE SHUTDOWN in {}s — {} [{}]",
            delay, reason,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        let _ = Command::new("wall").arg(&msg).output();
        let _ = self.logger.err(&msg);
        if let Ok(mut f) = OpenOptions::new().create(true).append(true)
            .open(&self.config.logging.trap_log_file)
        {
            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = writeln!(f, "[{}] {}", ts, msg);
        }

        if self.test_mode {
            println!("TEST MODE: would poweroff immediately after {}s", delay);
            return Ok(());
        }

        let script         = self.config.shutdown.pre_shutdown_script.clone();
        let script_timeout = self.config.shutdown.script_timeout_seconds;

        tokio::spawn(async move {
            sleep(Duration::from_secs(delay)).await;
            run_script_and_poweroff(script, script_timeout).await;
        });

        Ok(())
    }
}

// ── Shared poweroff helper ──────────────────────────────────────────────────

async fn run_script_and_poweroff(script: Option<String>, script_timeout: u64) {
    if let Some(ref s) = script {
        let result = tokio::time::timeout(
            Duration::from_secs(script_timeout),
            tokio::process::Command::new(s).status(),
        ).await;
        match result {
            Ok(Ok(status)) => eprintln!("pre_shutdown_script exited: {}", status),
            Ok(Err(e))     => eprintln!("pre_shutdown_script failed to start: {}", e),
            Err(_)         => eprintln!("pre_shutdown_script timed out after {}s — proceeding", script_timeout),
        }
    }
    // Prefer systemctl so all systemd stop-hooks, journald flush, and
    // ExecStop= units run cleanly.  Fall back to raw kernel reboot only
    // if systemctl itself fails.
    let ok = Command::new("systemctl")
        .args(["poweroff", "--no-wall"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !ok {
        eprintln!("systemctl poweroff failed — raw kernel reboot");
        sync();
        let _ = reboot(RebootMode::RB_POWER_OFF);
    }
}

// ====================== SNMP Parsing ======================

fn read_asn1_header(data: &[u8], offset: usize) -> Option<(u8, usize, usize)> {
    if offset + 1 >= data.len() { return None; }
    let tag      = data[offset];
    let len_byte = data[offset + 1];
    if len_byte < 0x80 {
        Some((tag, len_byte as usize, 2))
    } else {
        let n = (len_byte & 0x7F) as usize;
        if offset + 1 + n >= data.len() { return None; }
        let mut len = 0usize;
        for i in 0..n { len = (len << 8) | data[offset + 2 + i] as usize; }
        Some((tag, len, 2 + n))
    }
}

fn read_header(data: &[u8], offset: usize, ctx: &str) -> Result<(u8, usize, usize)> {
    read_asn1_header(data, offset)
        .ok_or_else(|| anyhow::anyhow!("Truncated ASN.1 at '{}' offset {}", ctx, offset))
}

fn parse_oid_bytes(bytes: &[u8]) -> Result<Vec<u64>> {
    if bytes.is_empty() { return Ok(vec![]); }
    let mut oid = vec![(bytes[0] / 40) as u64, (bytes[0] % 40) as u64];
    let mut i   = 1;
    while i < bytes.len() {
        let mut val = 0u64;
        loop {
            if i >= bytes.len() { break; }
            let b = bytes[i]; i += 1;
            val = (val << 7) | (b & 0x7F) as u64;
            if b & 0x80 == 0 { break; }
        }
        oid.push(val);
    }
    Ok(oid)
}

fn parse_snmp_trap(data: &[u8]) -> Result<ParsedTrap> {
    let mut i = 0;
    let (_, _,    h)  = read_header(data, i, "outer SEQUENCE")?; i += h;
    let (_, vlen, vh) = read_header(data, i, "version")?;        i += vh + vlen;
    let (_, clen, ch) = read_header(data, i, "community")?;
    let community = String::from_utf8_lossy(&data[i + ch .. i + ch + clen]).into_owned();
    i += ch + clen;

    if i >= data.len() { anyhow::bail!("Truncated after community"); }
    let pdu_tag = data[i];

    // ── SNMPv2c Trap-PDU (0xa7) ──────────────────────────────────────────
    if pdu_tag == 0xa7 {
        let (_, _, hl) = read_header(data, i, "v2 PDU")?;
        let mut cur    = i + hl;
        for f in ["request-id", "error-status", "error-index"] {
            let (_, l, h) = read_header(data, cur, f)?; cur += h + l;
        }
        let (tag, vbl, h) = read_header(data, cur, "VarBindList")?;
        if tag != 0x30 { anyhow::bail!("Expected SEQUENCE for VarBindList"); }
        cur += h;
        let vbl_end = cur + vbl;
        while cur < vbl_end && cur < data.len() {
            let (tag, vb_len, h) = read_header(data, cur, "VarBind")?;
            if tag != 0x30 { break; }
            cur += h;
            let vb_end = cur + vb_len;
            let (tag, oid_len, h) = read_header(data, cur, "VB OID")?;
            if tag != 0x06 { cur = vb_end; continue; }
            let oid = parse_oid_bytes(&data[cur + h .. cur + h + oid_len])?;
            cur += h + oid_len;
            if oid == [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] {
                let (tag, tl, th) = read_header(data, cur, "trapOID value")?;
                if tag == 0x06 {
                    let trap_oid = parse_oid_bytes(&data[cur + th .. cur + th + tl])?;
                    return Ok(ParsedTrap { oid: trap_oid, community });
                }
            }
            cur = vb_end;
        }
        anyhow::bail!("snmpTrapOID.0 not found");
    }

    // ── SNMPv1 Trap-PDU (0xa4) ───────────────────────────────────────────
    if pdu_tag == 0xa4 {
        let (_, _, hl) = read_header(data, i, "v1 PDU")?;
        let mut cur    = i + hl;

        let (tag, el, eh) = read_header(data, cur, "enterprise")?;
        if tag != 0x06 { anyhow::bail!("Expected OID for enterprise"); }
        let enterprise = parse_oid_bytes(&data[cur + eh .. cur + eh + el])?;
        cur += eh + el;

        // agent-addr: skip header AND 4-byte value (fix: was skipping header only)
        let (_, al, ah) = read_header(data, cur, "agent-addr")?; cur += ah + al;

        let (_, gl, gh) = read_header(data, cur, "generic-trap")?;
        let gen = if gl > 0 { data[cur + gh] as u64 } else { 0 };
        cur += gh + gl;

        let (_, sl, sh) = read_header(data, cur, "specific-trap")?;
        let spec = if sl > 0 { data[cur + sh] as u64 } else { 0 };

        if gen == 6 {
            let mut full = enterprise;
            full.push(0);
            full.push(spec);
            return Ok(ParsedTrap { oid: full, community });
        }
        return Ok(ParsedTrap { oid: enterprise, community });
    }

    anyhow::bail!("Unsupported PDU tag 0x{:02x}", pdu_tag)
}

// ====================== Entry Point ======================

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !nix::unistd::Uid::effective().is_root() && !args.test_mode {
        anyhow::bail!("Must be run as root (or pass --test-mode for dry-run)");
    }

    let config  = Config::load(&args.config)?;
    config.validate()?;
    let verbose = args.verbose || config.logging.verbose;

    // Verify trap log is writable before the first real event.
    let _ = OpenOptions::new()
        .create(true).append(true)
        .open(&config.logging.trap_log_file)
        .with_context(|| format!(
            "Trap log '{}' not writable — check path and permissions",
            config.logging.trap_log_file
        ))?;

    let mut mgr = ShutdownManager::new(config.clone(), args.test_mode, verbose)?;

    println!("ups-shutdown-daemon v{} starting", env!("CARGO_PKG_VERSION"));
    println!("  Config              : {}", args.config.display());
    println!("  Port                : {}", config.snmp.trap_port);
    println!("  time_on_battery     : {}s", config.shutdown.time_on_battery);
    println!("  time_on_low_battery : {}s", config.shutdown.time_on_low_battery);
    println!("  delay_seconds       : {}s (normal shutdown countdown)", config.shutdown.delay_seconds);
    println!("  immediate_delay     : {}s (instant-shutdown traps)", config.shutdown.immediate_delay_seconds);
    println!("  Test mode           : {}", args.test_mode);
    println!("  Verbose             : {}", verbose);

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", config.snmp.trap_port))
        .await
        .with_context(|| format!("Cannot bind UDP port {}", config.snmp.trap_port))?;

    let mut signals = Signals::new(&[SIGTERM, SIGINT])?.fuse();
    let mut buf     = [0u8; 4096];

    println!("Ready — listening for SNMP traps.");

    loop {
        tokio::select! {
            // ── Incoming UDP packet ──────────────────────────────────────
            res = socket.recv_from(&mut buf) => {
                let (len, src) = match res {
                    Ok(x)  => x,
                    Err(e) => { mgr.warn(&format!("recv_from error: {}", e)); continue; }
                };

                if verbose { println!("\nReceived {} bytes from {}", len, src); }

                if !mgr.is_allowed_source(&src) {
                    let w = format!("Rejected: source {} not in allowed_sources", src);
                    mgr.warn(&w);
                    continue;
                }

                match parse_snmp_trap(&buf[..len]) {
                    Ok(parsed) => {
                        if !mgr.community_ok(&parsed.community) {
                            let w = format!(
                                "Rejected: bad community '{}' from {}", parsed.community, src
                            );
                            mgr.warn(&w);
                            continue;
                        }
                        if verbose {
                            println!("OID: {}", parsed.oid.iter()
                                .map(|n| n.to_string()).collect::<Vec<_>>().join("."));
                        }
                        let trap = UpsTrap::from_oid(&parsed.oid);
                        let _ = mgr.handle_trap(trap, src).await;
                    }
                    Err(e) => {
                        // Log malformed/unrecognised packets to the trap log always.
                        mgr.warn(&format!("Parse error from {}: {}", src, e));
                    }
                }
            }

            // ── SIGTERM / SIGINT ─────────────────────────────────────────
            _ = signals.next() => {
                println!("\nSignal received — daemon stopping.");
                break;
            }

            // ── 10-second tick — active only when in OnBattery
            _ = OptionFuture::from(
                    mgr.tick_interval.as_mut().map(|i| i.tick())
                ), if mgr.tick_interval.is_some() => {
                let _ = mgr.check_timers().await;
            }
        }
    }

    println!("ups-shutdown-daemon stopped.");
    Ok(())
}
