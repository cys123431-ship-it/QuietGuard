# Roadmap

## Completed

1. v0.1-v0.11 - native Win32 GUI, broad read-only Windows persistence/configuration inspection, rule updater, baseline and low-memory watcher foundations
2. v1.0 - wider network/policy inspection and rule integrity validation
3. v1.1 - no-key public PUP/adware/risk domain feeds with low-memory disk indexes
4. v1.2 - optional ThreatFox/URLhaus local IOC caches
5. v1.3 - optional ClamAV PUA bridge
6. v1.4 - YousList regional context and opt-in Google Safe Browsing
7. v1.4.1 - ThreatFox Community API compatibility fix
8. v1.5.0 - opt-in Windows startup, monitor autostart and scheduled DB updates; GUI-thread DB refresh fix and update mutex
9. v1.5.1 - repository hardening: watcher registration retries, registration-path validation, background scan/baseline work, baseline schema/backup, rule path normalization, exact extension update-host validation, numeric extension version selection, per-source update timestamps, rollback-safe DB replacement, bounded network/ClamAV helper execution and expanded CI tests

## Next hardening

- Recursive native directory notifications for scheduled-task and Startup subtrees
- More precise service/driver publisher and path scoring
- File/hash/PUP publisher intelligence where licensing permits
- Log retention/settings controls and installer/recovery packaging
- Independent signing for QuietGuard binaries and update metadata
- Safe quarantine/restore only after explicit user approval, reversible metadata and false-positive controls are mature

QuietGuard remains read-only until remediation safety is strong enough to avoid damaging normal software or system files.
