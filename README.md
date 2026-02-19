# UPS Shutdown Daemon

**Production-ready Rust daemon for PPC / Upsmate enterprise UPS devices**  
Listens for SNMP traps (OID `1.3.6.1.4.1.935`) and triggers clean, timer-based or immediate system shutdowns.

**Version:** 1.5.0 (2026-02-18)  
**License:** MIT (see LICENSE file)

---

## Why this daemon?

Most UPS software either:
- Requires a heavy Java GUI, or
- Only supports USB (NUT), or
- Has fragile shell scripts that break on timer races.

`ups-shutdown-daemon` is a **tiny**, **zero-dependency**, **bulletproof** replacement:
- 100 % Rust, single binary (~800 KB stripped)
- Proper state machine (no races)
- Graceful countdown with `wall` messages
- Pre-shutdown script support
- Instant shutdown for critical faults
- SIGHUP log rotation (zero data loss)
- Full test coverage of the state machine

---

## Features

- SNMPv1 + SNMPv2c trap parsing (no external SNMP library)
- Two-stage timer logic:
  - `time_on_battery` (e.g. 600 s)
  - `time_on_low_battery` (e.g. 120 s) — whichever fires first wins
- 13 instant-shutdown traps (DiagnosticsFailed, UpsDischarged, OverLoadShutdown, …)
- Pre-shutdown script (with hard timeout)
- Test mode (`--test-mode`) — safe for testing
- Verbose + dedicated log file + syslog
- systemd service + logrotate ready
- Capability-bounded (only `NET_BIND_SERVICE` + `SYS_BOOT`)

---

## Quick Start

### 1. Build & Install

```bash
cargo build --release
sudo cp target/release/ups-shutdown-daemon /usr/local/sbin/
sudo mkdir -p /etc/ups-shutdown