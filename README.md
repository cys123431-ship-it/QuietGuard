# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence, adware/browser hijacking and suspicious system configuration changes rather than traditional antivirus replacement.

## QuietGuard 1.4

### Always available without user setup

- Broad Windows persistence/configuration/browser inspection
- Low-memory native change watcher
- QuietGuard heuristic rule DB
- UncheckyAds, FadeMind add.Risk, KADhosts, StevenBlack and YousList public/regional domain intelligence
- Automatic background DB refresh with local disk indexes

### Optional abuse.ch intelligence

If an abuse.ch Auth-Key is later supplied through `QUIETGUARD_ABUSECH_AUTH_KEY` or `%LOCALAPPDATA%\QuietGuard\secrets.conf`, ThreatFox and URLhaus caches automatically activate. Without a key they are simply skipped.

### Optional ClamAV PUA bridge

QuietGuard automatically detects an existing `clamscan.exe` installation from PATH, common Program Files locations, or `QUIETGUARD_CLAMSCAN`.

When present:

- **시스템 점검** sends a limited set of autorun/service/startup file candidates to `clamscan --detect-pua`.
- Results are advisory and labelled separately as ClamAV findings.
- **DB 업데이트** uses `freshclam.exe` when available, at most once per 24 hours during automatic checks; pressing DB update forces a check.
- ClamAV is never started as an always-on daemon by QuietGuard.

When ClamAV is absent, no error or dependency is introduced and the normal QuietGuard/Defender workflow is unchanged.

### Korean advertising context

YousList is maintained as a separate low-confidence Korean advertising context source. Matches are not treated as a malware verdict.

### Optional Google Safe Browsing

Google Safe Browsing URL checks are implemented but disabled by default because raw URLs are sent to Google's API. They activate only when a local API key is configured and `google_safe_browsing_enabled=true` is explicitly set. Manual scans limit these checks to a bounded number of candidate URLs.

## Low-memory intelligence design

Public domain lists are downloaded from their upstream projects and converted to sorted fixed-width FNV64 indexes under `%LOCALAPPDATA%\QuietGuard\intel`. They are binary-searched on demand rather than loaded into resident memory. The always-on watcher performs no feed downloads and does not run ClamAV.

## Main detection surfaces

QuietGuard inspects Hosts, DNS/proxy/PAC, Run/RunOnce/Startup, Winlogon, AppInit/AppCert DLLs, Active Setup, services/drivers, scheduled tasks, IFEO, BITS, Winsock, WMI event consumers, shell associations, App Paths, browser shortcuts, Chrome/Edge/Firefox extensions/policies/notifications, COM registrations, selected hidden executables, suspicious Windows-process-name locations, Group Policy strings, firewall rules, execution restrictions, Software Restriction Policy, SafeBoot, MozillaPlugins, IE SearchScopes/DOMStorage and local IPsec policy.

Findings are advisory. Unusual or PUA-labelled software is not automatically deleted.

## Baseline and updates

**기준 저장/기준 비교** provides accepted-state change comparison. The GUI launches a short-lived hidden updater for QuietGuard rules and external DB caches. Results are written under `%LOCALAPPDATA%\QuietGuard`.

QuietGuard's own rule file is downloaded over HTTPS and verified against the SHA-256 in `rules/version.json`. An independent publisher-signature layer remains a hardening target.

See `docs/INTELLIGENCE.md` for source and privacy details.

## Build and validation

```text
cargo build --release
```

GitHub Actions validates feature branches on `windows-latest` with `cargo check --release`, `cargo build --release`, packaging and artifact upload before merge. The repository also contains a release workflow that publishes the validated Windows x64 package for v1.4.0.

## Status

QuietGuard 1.4 is a defensive, read-only prototype. It complements Microsoft Defender and does not replace antivirus protection. It currently does not automatically delete, quarantine or block findings.
