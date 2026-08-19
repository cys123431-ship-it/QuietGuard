# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence, adware/browser hijacking and suspicious system configuration changes rather than traditional antivirus replacement.

## Design goals

- Rust + native Win32 GUI; no Electron, Python runtime or .NET desktop runtime
- Keep the always-on watcher small and event-driven
- Read-only detection first; no automatic deletion until restore/quarantine and false-positive handling are mature
- Clean-room implementation: Malware Zero is used only as a reference for categories of Windows state worth inspecting; its code and proprietary databases are not copied

## QuietGuard 1.1 coverage

QuietGuard inspects a broad set of nuisance/PUP persistence and hijack surfaces, including Hosts, DNS/proxy/PAC, Run/RunOnce/Startup, Winlogon, AppInit/AppCert DLLs, Active Setup, services/drivers, scheduled tasks, IFEO, BITS, Winsock, WMI event consumers, shell associations, App Paths, browser shortcuts, browser extensions/policies/notifications, COM registrations, selected hidden executables, suspicious Windows-process-name locations, Group Policy strings, firewall rules, execution restrictions, Software Restriction Policy, SafeBoot, MozillaPlugins, IE SearchScopes/DOMStorage and local IPsec policy.

Findings are advisory. Unusual does not automatically mean malicious.

## Public PUP/adware intelligence (1.1)

QuietGuard now supplements its local heuristics with public domain intelligence that requires no API key:

- **UncheckyAds** — Windows installer advertising/PUP-related domains
- **FadeMind add.Risk** — risk-domain list
- **KADhosts** — fraud/adware/scam domains
- **StevenBlack Unified Hosts** — broader adware/malware aggregate

The app downloads these lists directly from their upstream projects at runtime. QuietGuard does not bundle or republish their source databases.

To minimize memory usage, downloaded domains are normalized, deduplicated per source, hashed with FNV-1a 64-bit and written as sorted fixed-width disk indexes under `%LOCALAPPDATA%\QuietGuard\intel`. The indexes are binary-searched on demand instead of being kept resident in RAM.

The automatic background updater refreshes public intelligence at most once per 24 hours. The GUI **DB 업데이트** action forces an immediate refresh. Failed sources keep their last known-good local index.

Manual scans currently cross-check public intelligence against proxy/PAC settings, browser policy/settings text, Chrome/Edge extension manifests and scheduled-task output. Matches identify the upstream source and category.

See `docs/INTELLIGENCE.md` for source/licensing and optional API plans.

## Baseline comparison

- **기준 저장** saves a normalized scan snapshot to `%LOCALAPPDATA%\QuietGuard\baseline.txt`.
- **기준 비교** rescans all current checks and shows newly added or removed/changed findings.

Save a baseline only after the current PC state has been reviewed as acceptable.

## Low-memory real-time watcher

The background `--watch` mode uses native `RegNotifyChangeKeyValue` notifications and one `WaitForMultipleObjects` loop instead of repeatedly rescanning the whole PC or creating a worker thread per target.

It watches important persistence/network/policy registry locations. Low-frequency metadata checks cover Hosts, Startup folders and the Windows scheduled-task store. Changes are written to `%LOCALAPPDATA%\QuietGuard\events.log` and can be viewed from the GUI.

The watcher itself performs no network updates. A separate short-lived updater process is spawned from the GUI so public DB updates do not increase always-on memory usage.

## QuietGuard rule updates

`rules/heuristics.conf` is an extendable lightweight rule database.

- Rules are retrieved from this repository over HTTPS.
- A downloaded rule file is accepted only when its SHA-256 matches `rules/version.json`.
- The installed rule hash is rechecked even when the version string is unchanged.
- The manifest can require a minimum compatible QuietGuard version.
- Updated rules live under `%LOCALAPPDATA%\QuietGuard\rules` and do not require administrator rights.
- Background update results are written to `%LOCALAPPDATA%\QuietGuard\update.log`.

The current rule channel verifies transport/integrity but does not yet provide an independent publisher signature.

## Optional sources that still need user credentials

ThreatFox and URLhaus Community APIs now require a free abuse.ch Auth-Key. Google Safe Browsing supports the `UNWANTED_SOFTWARE` threat type and is non-commercial-use only, but requires Google API access. QuietGuard keeps these as optional future integrations so the normal 1.1 update path works without asking the user for accounts or keys.

ClamAV supports PUA signatures and signed CVD databases; a future optional bridge can use it when installed without turning the low-memory watcher into a second always-on antivirus engine.

## Build and validation

```text
cargo build --release
```

GitHub Actions validates feature branches on `windows-latest` with `cargo check --release`, `cargo build --release`, packaging and artifact upload before merge.

## Status

QuietGuard 1.1 is a defensive, read-only prototype. It complements Microsoft Defender and does not replace antivirus protection. It currently does not automatically delete, quarantine or block findings.
