# Roadmap

## Completed

1. v0.1 - Rust + native Win32 GUI and basic read-only checks
2. v0.2 - expanded system scan, external lightweight heuristic rules, Windows CI workflow
3. v0.3 - ServiceDll, IFEO, BITS, Winsock, WMI persistence and browser policy checks
4. v0.4 - environment/logon-script, shell-open association, uninstall, browser shortcut and IE ElevationPolicy checks
5. v0.5 - per-user GitHub rule/database updater with SHA-256 verification and portable CI package
6. v0.6 - low-memory native background watcher for important persistence/configuration changes
7. v0.7 - accepted-state baseline comparison and GUI watcher-log viewer
8. v0.8 - Active Setup, per-user COM, hidden-file and browser notification coverage
9. v0.9 - fake-system-process, numeric System32 file, Group Policy Registry.pol and Chromium extension metadata checks
10. v0.10 - service/driver combination analysis, Firefox metadata/policies and notification-origin details
11. v0.11 - targeted machine CLSID/App Paths checks and Authenticode signer context for suspicious files
12. v1.0 - network/policy inspection expansion, automatic rule checks, stronger rule integrity validation and wider low-memory change monitoring

## Post-1.0 hardening

- Optional public/licensed PUP/hash/domain reputation context with local caching
- Winsock/LSP provider baseline and allowlisting
- More precise service/driver reputation and signer scoring
- Safe quarantine/restore only after rollback and false-positive handling are mature
- Independent cryptographic publisher signing for rule/update metadata
- Settings/log retention and installer/release packaging

QuietGuard 1.0 intentionally remains read-only. It detects and records suspicious or unwanted system state without automatically removing or blocking entries.
