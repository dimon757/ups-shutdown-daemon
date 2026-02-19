// src/main.rs — ups-shutdown-daemon v1.5.0

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
    let (mut mgr, socket, verbose) = init().await?;
    run(&mut mgr, socket, verbose).await
}

// ── Startup ─────────────────────────────────────────────────────────────────

async fn init() -> Result<(ShutdownManager, UdpSocket, bool)> {
    let args = Args::parse();

    if !nix::unistd::Uid::effective().is_root() && !args.test_mode {
        anyhow::bail!("Must be run as root (or pass --test-mode for dry-run)");
    }

    let config  = Config::load(&args.config)?;
    config.validate()?;
    let verbose = args.verbose || config.logging.verbose;

    let log_path = config.logging.trap_log_file.clone();

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!(
            "Trap log '{}' not writable — check path and permissions",
            log_path
        ))?;

    println!("ups-shutdown-daemon v1.5.0 starting");
    println!("  Config              : {}", args.config.display());
    println!("  Port                : {}", config.snmp.trap_port);
    println!("  time_on_battery     : {}s", config.shutdown.time_on_battery);
    println!("  time_on_low_battery : {}s", config.shutdown.time_on_low_battery);
    println!("  delay_seconds       : {}s", config.shutdown.delay_seconds);
    println!("  immediate_delay     : {}s", config.shutdown.immediate_delay_seconds);
    println!("  Test mode           : {}", args.test_mode);
    println!("  Verbose             : {}", verbose);

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", config.snmp.trap_port))
        .await
        .with_context(|| format!("Cannot bind UDP port {}", config.snmp.trap_port))?;

    let mgr = ShutdownManager::new(config, log_path, log_file, args.test_mode, verbose)?;

    println!("Ready — listening for SNMP traps.");
    Ok((mgr, socket, verbose))
}

// ── Event loop ───────────────────────────────────────────────────────────────

async fn run(mgr: &mut ShutdownManager, socket: UdpSocket, _verbose: bool) -> Result<()> {
    let mut signals = Signals::new(&[SIGTERM, SIGINT, SIGHUP])?.fuse();
    let mut buf     = [0u8; 4096];

    loop {
        tokio::select! {
            // ── Incoming UDP packet ──────────────────────────────────────
            res = socket.recv_from(&mut buf) => {
                let (len, src) = match res {
                    Ok(x)  => x,
                    Err(e) => { mgr.warn(&format!("recv_from error: {}", e)); continue; }
                };

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

                        let trap = UpsTrap::from_oid(&parsed.oid);
                        let _ = mgr.handle_trap(trap, src).await;
                    }
                    Err(e) => {
                        mgr.warn(&format!("Parse error from {}: {}", src, e));
                    }
                }
            }

            // ── SIGTERM / SIGINT / SIGHUP ────────────────────────────────
            Some(sig) = signals.next() => {
                match sig {
                    SIGTERM | SIGINT => {
                        println!("\nSignal received — daemon stopping.");
                        break;
                    }
                    SIGHUP => {
                        if let Err(e) = mgr.reopen_log_file() {
                            eprintln!("Failed to reopen log file on SIGHUP: {}", e);
                        }
                    }
                    _ => {}
                }
            }

            // ── 10-second tick (only when in OnBattery) ─────────────────
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