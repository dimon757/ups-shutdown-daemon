// ups-shutdown-daemon — main.rs  v1.4.0
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
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::fs::OpenOptions;
use std::path::PathBuf;
use tokio::net::UdpSocket;

mod config;
mod manager;
mod snmp;
mod trap;

use config::Config;
use manager::ShutdownManager;
use snmp::parse_snmp_trap;
use trap::UpsTrap;

// ── CLI ─────────────────────────────────────────────────────────────────────

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

// ── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Thin wrapper: init validates the environment, run drives the event loop.
    // Errors from either surface here with their full context chain.
    let (mut mgr, socket, verbose) = init().await?;
    run(&mut mgr, socket, verbose).await
}

// ── Startup ─────────────────────────────────────────────────────────────────

/// Validate environment, load config, open resources, print banner.
/// Returns a fully initialised manager, bound UDP socket, and verbose flag.
async fn init() -> Result<(ShutdownManager, UdpSocket, bool)> {
    let args = Args::parse();

    if !nix::unistd::Uid::effective().is_root() && !args.test_mode {
        anyhow::bail!("Must be run as root (or pass --test-mode for dry-run)");
    }

    let config  = Config::load(&args.config)?;
    config.validate()?;
    let verbose = args.verbose || config.logging.verbose;

    // Open the log file once here; the handle is moved into ShutdownManager
    // and held open for the daemon lifetime — no open/close overhead per line.
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.logging.trap_log_file)
        .with_context(|| format!(
            "Trap log '{}' not writable — check path and permissions",
            config.logging.trap_log_file
        ))?;

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

    let mgr = ShutdownManager::new(config, log_file, args.test_mode, verbose)?;

    println!("Ready — listening for SNMP traps.");
    Ok((mgr, socket, verbose))
}

// ── Event loop ───────────────────────────────────────────────────────────────

/// Drive the three-way select: UDP packets, signals, 10s battery tick.
async fn run(mgr: &mut ShutdownManager, socket: UdpSocket, verbose: bool) -> Result<()> {
    let mut signals = Signals::new(&[SIGTERM, SIGINT])?.fuse();
    let mut buf     = [0u8; 4096];

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
                    mgr.warn(&format!("Rejected: source {} not in allowed_sources", src));
                    continue;
                }

                match parse_snmp_trap(&buf[..len]) {
                    Ok(parsed) => {
                        if !mgr.community_ok(&parsed.community) {
                            mgr.warn(&format!(
                                "Rejected: bad community '{}' from {}", parsed.community, src
                            ));
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
                        mgr.warn(&format!("Parse error from {}: {}", src, e));
                    }
                }
            }

            // ── SIGTERM / SIGINT ─────────────────────────────────────────
            _ = signals.next() => {
                println!("\nSignal received — daemon stopping.");
                break;
            }

            // ── 10-second tick — active only when in OnBattery ──────────
            _ = OptionFuture::from(
                    mgr.tick_interval_mut().map(|i| i.tick())
                ), if mgr.has_tick() => {
                let _ = mgr.check_timers().await;
            }
        }
    }

    println!("ups-shutdown-daemon stopped.");
    Ok(())
}
