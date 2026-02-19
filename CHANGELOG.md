# Changelog

All notable changes to **ups-shutdown-daemon** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-02-18

### Added
- **SIGHUP handler** (`ShutdownManager::reopen_log_file()`) — daemon now reopens the trap log file on `kill -HUP` (zero-downtime log rotation)
- Full unit test suite in `trap.rs` (25 tests, 100 % branch coverage of the entire state machine)
- Stored `log_path` in `ShutdownManager` to support log reopening
- Unified shutdown scheduling logic

### Changed
- Refactored shutdown execution: normal and immediate shutdowns now share a single `schedule_shutdown()` method (removed ~80 % duplication)
- `initiate_normal_shutdown()` and `initiate_immediate_shutdown()` are now thin wrappers
- Updated `main.rs` to register SIGHUP in the signal handler
- Logrotate configuration: removed `copytruncate` (now safe and lossless)
- Version bumped to 1.5.0 in `Cargo.toml`, binary banner, and documentation references

### Fixed
- **Critical bug**: Instant-shutdown traps (DiagnosticsFailed, UpsDischarged, UpsTurnedOff, UpsLowBatteryShutdown, etc.) now **always** override and cancel any pending normal countdown (previously ignored during the `delay_seconds` window)

### Improved
- Shutdown coordination is now race-free and clearer
- Maintainability and future extensibility greatly increased
- Logging behaviour is identical but more robust under rotation

## [1.4.0] - 2024-10-01 (Original Release)

### Added
- State-machine based UPS SNMP trap handler for PPC/Upsmate devices (enterprise OID 1.3.6.1.4.1.935)
- Timer-based graceful shutdown (on-battery + low-battery timers)
- Instant non-cancellable shutdown for critical traps
- Pre-shutdown script support with timeout
- Full SNMPv1/v2c trap parsing (hand-written BER)
- Logging to dedicated file + syslog
- Test mode (`--test-mode`) and verbose output
- systemd service + logrotate example

### Security
- Capability bounding set (NET_BIND_SERVICE + SYS_BOOT)
- Source IP + community string validation
- Root check (unless test mode)

---

**Next planned release (1.6.0)** ideas (not yet implemented):
- Pending-shutdown flag file (`/run/ups-shutdown-pending`)
- Config reload on SIGHUP
- Tiny metrics endpoint (`/metrics`)
- Switch to `tracing` + structured logging
