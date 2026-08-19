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

## Next

10. v0.10 - focused service/driver anomaly analysis, Firefox extension metadata and richer browser notification details
11. v0.11 - code-signature/publisher metadata for suspicious findings and targeted reputation plumbing
12. v0.12 - safe quarantine/restore with explicit user approval and rollback metadata
13. v1.0 - signed rule/update channel, settings/log hardening and stable release packaging

The project remains read-only until restore and false-positive handling are mature enough to make remediation safe.
