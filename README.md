# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence, adware/browser hijacking and suspicious system configuration changes rather than traditional antivirus replacement.

## QuietGuard 1.4

### Works automatically with no account or key

- Broad Windows persistence/configuration/browser inspection
- Low-memory native change watcher
- QuietGuard heuristic rule DB
- UncheckyAds, FadeMind add.Risk, KADhosts and StevenBlack public intelligence
- YousList Korean advertising-domain context, labelled as low-confidence ad context rather than malware
- Automatic background refresh into low-memory disk indexes

### Optional abuse.ch intelligence

One later-supplied abuse.ch Auth-Key automatically activates both ThreatFox and URLhaus caches. Without a key they are skipped and normal operation is unchanged.

### Optional ClamAV PUA bridge

If `clamscan.exe` already exists, QuietGuard scans a bounded set of autorun/service/startup candidates with `--detect-pua`. If `freshclam.exe` is available, **DB 업데이트** also checks ClamAV signatures. QuietGuard never starts ClamAV as an always-on daemon.

### Optional Google Safe Browsing

A working Safe Browsing v5 URL-search adapter is included but **disabled by default**. This is deliberate because URL search sends the checked raw URLs to Google.

It activates only when the local secrets configuration contains:

```text
google_safe_browsing_enabled=true
google_safe_browsing_key=YOUR_KEY
```

or the equivalent environment variables. A manual scan sends at most 50 candidate URLs and labels `UNWANTED_SOFTWARE` matches separately. Without explicit opt-in, QuietGuard sends no URLs to Google.

## Low-memory intelligence design

Bulk domain feeds are normalized, hashed and stored as sorted fixed-width FNV64 disk indexes under `%LOCALAPPDATA%\QuietGuard\intel`. They are binary-searched on demand instead of loaded wholesale into resident RAM. Raw downloaded list files are removed after indexing. The always-on watcher performs no intelligence downloads and does not run ClamAV or Safe Browsing queries.

## Main detection surfaces

QuietGuard inspects Hosts, DNS/proxy/PAC, Run/RunOnce/Startup, Winlogon, AppInit/AppCert DLLs, Active Setup, services/drivers, scheduled tasks, IFEO, BITS, Winsock, WMI event consumers, shell associations, App Paths, browser shortcuts, Chrome/Edge/Firefox extensions/policies/notifications, COM registrations, selected hidden executables, suspicious Windows-process-name locations, Group Policy strings, firewall rules, execution restrictions, Software Restriction Policy, SafeBoot, MozillaPlugins, IE SearchScopes/DOMStorage and local IPsec policy.

Findings are advisory. Unusual, advertising-related or PUA-labelled software is not automatically deleted.

## Baseline and updates

**기준 저장/기준 비교** provides accepted-state change comparison. The GUI launches a short-lived hidden updater for QuietGuard rules and external caches. Results live under `%LOCALAPPDATA%\QuietGuard`.

QuietGuard's own lightweight rule file is downloaded over HTTPS and verified against the SHA-256 in `rules/version.json`. An independent publisher-signature layer remains a hardening target.

See `docs/INTELLIGENCE.md` for source, licensing and privacy details.

## Build and validation

```text
cargo build --release
```

GitHub Actions validates feature branches on `windows-latest` with `cargo check --release`, `cargo build --release`, packaging and artifact upload before merge.

## Status

QuietGuard 1.4 is a defensive, read-only prototype. It complements Microsoft Defender and does not replace antivirus protection. It currently does not automatically delete, quarantine or block findings.
