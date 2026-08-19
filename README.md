# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence, adware/browser hijacking and suspicious system configuration changes rather than traditional antivirus replacement.

## Design goals

- Rust + native Win32 GUI; no Electron, Python runtime or .NET desktop runtime
- Keep the always-on watcher small and event-driven
- Read-only detection first; no automatic deletion until restore/quarantine and false-positive handling are mature
- Clean-room implementation: Malware Zero is used only as a reference for categories of Windows state worth inspecting; its code and proprietary databases are not copied

## QuietGuard 1.2

QuietGuard combines broad Windows persistence/configuration inspection with low-memory external intelligence.

### Always available, no API key

- QuietGuard system/persistence/browser heuristics
- UncheckyAds
- FadeMind add.Risk
- KADhosts
- StevenBlack Unified Hosts

These public domain lists are downloaded directly from upstream and converted to sorted fixed-width FNV64 disk indexes under `%LOCALAPPDATA%\QuietGuard\intel`. They are binary-searched on demand rather than loaded into resident memory. Normal automatic refresh is once per 24 hours; **DB 업데이트** forces an immediate refresh.

### Optional, automatically activated when one abuse.ch key exists

QuietGuard 1.2 includes working ThreatFox and URLhaus adapters. They are not required for normal operation.

- `QUIETGUARD_ABUSECH_AUTH_KEY` environment variable, or
- `%LOCALAPPDATA%\QuietGuard\secrets.conf` containing `abusech_auth_key=...`

activates both services. ThreatFox recent IOCs and URLhaus recent malicious URL hostnames are cached as the same low-memory disk indexes and refreshed at most every six hours. A failed refresh preserves the previous cache. The key is passed to the short-lived updater through its environment rather than embedded in source code or the repository.

A blank template is provided at `config/secrets.conf.example`. No user setup is necessary unless these two optional services are desired.

### Detection coverage

QuietGuard inspects Hosts, DNS/proxy/PAC, Run/RunOnce/Startup, Winlogon, AppInit/AppCert DLLs, Active Setup, services/drivers, scheduled tasks, IFEO, BITS, Winsock, WMI event consumers, shell associations, App Paths, browser shortcuts, browser extensions/policies/notifications, COM registrations, selected hidden executables, suspicious Windows-process-name locations, Group Policy strings, firewall rules, execution restrictions, Software Restriction Policy, SafeBoot, MozillaPlugins, IE SearchScopes/DOMStorage and local IPsec policy.

External DB matches are currently checked against proxy/PAC and selected registry URL settings, Chrome/Edge profile settings, extension manifests and scheduled-task text. Findings show the matching source/category.

Findings are advisory. Unusual does not automatically mean malicious.

## Baseline and low-memory watcher

**기준 저장/기준 비교** provides accepted-state change comparison. The `--watch` process uses native `RegNotifyChangeKeyValue` plus one `WaitForMultipleObjects` loop for important registry regions, with low-frequency metadata checks for Hosts, Startup and scheduled tasks. The watcher itself performs no feed downloads.

## Updates

The GUI launches a short-lived hidden updater. It updates QuietGuard's own lightweight rule file, no-key public feeds and, if configured, the abuse.ch caches. Results are written to `%LOCALAPPDATA%\QuietGuard\update.log`.

QuietGuard's own rule file is downloaded over HTTPS and verified against the SHA-256 recorded in `rules/version.json`. An independent publisher-signature layer is still a hardening target.

See `docs/INTELLIGENCE.md` for external-source details.

## Build and validation

```text
cargo build --release
```

GitHub Actions validates feature branches on `windows-latest` with `cargo check --release`, `cargo build --release`, packaging and artifact upload before merge.

## Status

QuietGuard 1.2 is a defensive, read-only prototype. It complements Microsoft Defender and does not replace antivirus protection. It currently does not automatically delete, quarantine or block findings.
