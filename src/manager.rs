// manager.rs — ShutdownManager: logging, state machine, shutdown execution

use crate::config::Config;
use crate::trap::{StateTransition, UpsTrap, UpsState};
use anyhow::Result;
use nix::sys::reboot::{reboot, RebootMode};
use nix::unistd::sync;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use syslog::{Facility, Formatter3164};
use tokio::time::{sleep, Instant, interval_at};

// ── Manager struct ──────────────────────────────────────────────────────────

pub struct ShutdownManager {
    config:             Config,
    test_mode:          bool,
    verbose:            bool,
    state:              UpsState,
    /// Log file opened once at startup and held open for the daemon lifetime.
    /// Eliminates an open()/close() syscall pair on every log line.
    log_file:           File,
    /// 10-second tick — active only when state is OnBattery, None otherwise.
    tick_interval:      Option<tokio::time::Interval>,
    /// Shared with the spawned normal-shutdown task. Set false to cancel.
    shutdown_scheduled: Arc<AtomicBool>,
    logger:             syslog::Logger<syslog::LoggerBackend, Formatter3164>,
}

impl ShutdownManager {
    pub fn new(config: Config, log_file: File, test_mode: bool, verbose: bool) -> Result<Self> {
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
            log_file,
            state:              UpsState::Normal,
            tick_interval:      None,
            shutdown_scheduled: Arc::new(AtomicBool::new(false)),
            logger,
        })
    }

    // ── Logging ─────────────────────────────────────────────────────────────

    /// Write to the open log file and optionally stdout (verbose).
    /// The file handle is held open for the daemon lifetime — no syscall overhead.
    fn log(&mut self, msg: &str) {
        if self.verbose { println!("{}", msg); }
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(self.log_file, "[{}] {}", ts, msg);
    }

    /// Write to log file only — used for shutdown announcements that are
    /// already broadcast via `wall` to avoid printing the line twice.
    fn log_file_only(&mut self, msg: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(self.log_file, "[{}] {}", ts, msg);
    }

    pub fn info(&mut self, msg: &str) {
        self.log(msg);
        let _ = self.logger.info(msg);
    }

    pub fn warn(&mut self, msg: &str) {
        self.log(msg);
        let _ = self.logger.warning(msg);
    }

    fn err(&mut self, msg: &str) {
        self.log(msg);
        let _ = self.logger.err(msg);
    }

    // ── Authentication ───────────────────────────────────────────────────────

    pub fn is_allowed_source(&self, src: &SocketAddr) -> bool {
        let list = &self.config.snmp.allowed_sources;
        list.is_empty() || list.contains(&src.ip())
    }

    pub fn community_ok(&self, community: &str) -> bool {
        community == self.config.snmp.community_string
    }

    // ── Tick management ──────────────────────────────────────────────────────

    pub fn start_tick(&mut self) {
        self.tick_interval = Some(interval_at(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(10),
        ));
    }

    pub fn stop_tick(&mut self) {
        self.tick_interval = None;
    }

    pub fn tick_interval_mut(&mut self) -> Option<&mut tokio::time::Interval> {
        self.tick_interval.as_mut()
    }

    pub fn has_tick(&self) -> bool {
        self.tick_interval.is_some()
    }

    // ── State transitions ────────────────────────────────────────────────────

    fn enter_on_battery(&mut self) {
        self.info("STATE → OnBattery: on-battery timer started");
        self.state = UpsState::OnBattery {
            battery_since:     Instant::now(),
            low_battery_since: None,
        };
        self.start_tick();
    }

    fn start_low_battery(&mut self) {
        let started = if let UpsState::OnBattery { ref mut low_battery_since, .. } = self.state {
            *low_battery_since = Some(Instant::now());
            true
        } else { false };
        if started { self.info("OnBattery+LowBattery: low-battery timer started"); }
    }

    fn clear_low_battery(&mut self) {
        let cleared = if let UpsState::OnBattery { ref mut low_battery_since, .. } = self.state {
            *low_battery_since = None;
            true
        } else { false };
        if cleared { self.info("OnBattery: low-battery timer cleared (ReturnFromLowBattery)"); }
    }

    fn exit_on_battery(&mut self, reason: &str) {
        self.warn(&format!("STATE → Normal: {} — cancelling any pending shutdown", reason));
        self.shutdown_scheduled.store(false, Ordering::SeqCst);
        self.state = UpsState::Normal;
        self.stop_tick();
    }

    // ── Periodic timer check (called every 10 s) ─────────────────────────────

    pub async fn check_timers(&mut self) -> Result<()> {
        match self.state {
            UpsState::OnBattery { battery_since, low_battery_since } => {
                let on_bat_secs = battery_since.elapsed().as_secs();

                // Low-battery timer fires first if set and expired.
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

    // ── Trap dispatcher ──────────────────────────────────────────────────────

    pub async fn handle_trap(&mut self, trap: UpsTrap, src: SocketAddr) -> Result<()> {
        // Every trap is logged — primary audit trail.
        let msg = format!("Trap #{} ({}) from {}", trap as u64, trap.description(), src);
        self.info(&msg);

        // Instant shutdown — non-cancellable, state-independent.
        if trap.is_instant_shutdown() {
            let reason = format!("Instant-shutdown trap: #{} {}", trap as u64, trap.description());
            self.err(&reason);
            self.initiate_immediate_shutdown(&reason).await?;
            return Ok(());
        }

        // Ask the current state what this trap means, then act on the answer.
        let transition = self.state.apply(trap);
        self.execute_transition(transition, trap).await
    }

    /// Execute a state transition returned by `UpsState::apply()`.
    async fn execute_transition(
        &mut self,
        transition: StateTransition,
        trap: UpsTrap,
    ) -> Result<()> {
        match transition {
            StateTransition::EnterOnBattery => {
                self.enter_on_battery();
            }

            StateTransition::StartLowBattery => {
                self.start_low_battery();
            }

            StateTransition::LowBatteryAlreadyRunning => {
                self.info("LowBattery (#7) received — sub-timer already running, ignored");
            }

            StateTransition::IgnoredWrongState { note } => {
                self.info(note);
            }

            StateTransition::ClearLowBattery => {
                self.clear_low_battery();
            }

            StateTransition::ExitOnBattery { reason } => {
                let msg = format!("Trap #{} {}", trap as u64, trap.description());
                let _ = Command::new("wall").arg(&msg).output();
                self.exit_on_battery(reason);
            }

            StateTransition::None => {
                // Purely informational traps — already logged in handle_trap, no note needed.
                // Covers: CommunicationLost, CommunicationEstablished, UpsWokeUp,
                //         UpsBypassReturn, Unknown, UpsOnBattery-while-already-OnBattery.
                let note = match trap {
                    UpsTrap::CommunicationLost =>
                        "CommunicationLost (#1) received — logged only, no action",
                    UpsTrap::CommunicationEstablished =>
                        "CommunicationEstablished (#8) received — informational",
                    UpsTrap::UpsOnBattery =>
                        "UpsOnBattery (#5) received — already in OnBattery state, ignored",
                    _ => return Ok(()),
                };
                self.info(note);
            }
        }
        Ok(())
    }

    // ── Shutdown execution ───────────────────────────────────────────────────

    /// Normal (timer-based) shutdown: cancellable within delay_seconds window.
    pub async fn initiate_normal_shutdown(&mut self, reason: &str) -> Result<()> {
        if self.shutdown_scheduled.load(Ordering::SeqCst) {
            self.stop_tick();
            return Ok(());
        }
        self.shutdown_scheduled.store(true, Ordering::SeqCst);
        self.stop_tick();

        let delay = self.config.shutdown.delay_seconds;
        let msg   = format!(
            "SHUTDOWN in {}s — {} [{}]",
            delay, reason,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        let _ = Command::new("wall").arg(&msg).output();
        let _ = self.logger.err(&msg);
        self.log_file_only(&msg);

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
    pub async fn initiate_immediate_shutdown(&mut self, reason: &str) -> Result<()> {
        if self.shutdown_scheduled.load(Ordering::SeqCst) {
            self.stop_tick();
            return Ok(());
        }
        self.shutdown_scheduled.store(true, Ordering::SeqCst);
        self.stop_tick();

        let delay = self.config.shutdown.immediate_delay_seconds;
        let msg   = format!(
            "IMMEDIATE SHUTDOWN in {}s — {} [{}]",
            delay, reason,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        let _ = Command::new("wall").arg(&msg).output();
        let _ = self.logger.err(&msg);
        self.log_file_only(&msg);

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

// ── Poweroff helper ─────────────────────────────────────────────────────────

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
