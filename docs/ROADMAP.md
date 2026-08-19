# Roadmap

## Completed

1. v0.1 - Rust + native Win32 GUI and basic read-only checks
2. v0.2 - expanded system scan, external lightweight heuristic rules, Windows CI workflow
3. v0.3 - ServiceDll, IFEO, BITS, Winsock, WMI persistence and browser policy checks
4. v0.4 - environment/logon-script, shell-open association, uninstall, browser shortcut and IE ElevationPolicy checks
5. v0.5 - per-user GitHub rule/database updater with SHA-256 verification and portable CI package
6. v0.6 - low-memory native background watcher for important persistence/configuration changes

## Next

7. v0.7 - baseline snapshots, event-log viewer and richer PUP naming/publisher/hash intelligence
8. v0.8 - reputation-feed plumbing using free/public sources where licensing and rate limits allow
9. v0.9 - safe quarantine/restore with explicit user approval
10. v1.0 - deeper COM/CLSID/TypeLib coverage, signed update channel and release hardening

The project remains read-only until restore and false-positive handling are mature enough to make remediation safe.
