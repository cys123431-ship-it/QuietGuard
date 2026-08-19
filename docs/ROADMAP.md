# Roadmap

## Completed

1. v0.1 - Rust + native Win32 GUI and basic read-only checks
2. v0.2 - expanded system scan, external lightweight heuristic rules, Windows CI workflow
3. v0.3 - ServiceDll, IFEO, BITS, Winsock, WMI persistence and browser policy checks
4. v0.4 - environment/logon-script, shell-open association, uninstall, browser shortcut and IE ElevationPolicy checks
5. v0.5 - per-user GitHub rule/database updater with SHA-256 verification and portable CI package

## Next

6. v0.6 - low-memory native background change watcher and baseline comparison
7. v0.7 - reputation-feed plumbing plus richer PUP naming/publisher/hash intelligence
8. v0.8 - safe quarantine/restore with explicit user approval
9. v0.9 - deeper COM/CLSID/TypeLib, browser notification and selected hidden-file heuristics
10. v1.0 - signed update channel, stable logs/settings and release hardening

The project remains read-only until restore and false-positive handling are mature enough to make remediation safe.
