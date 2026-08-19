# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence and system/browser configuration changes rather than traditional antivirus replacement.

## Design goals

- Rust + native Win32 GUI; no Electron, Python runtime or .NET desktop runtime
- Keep the always-on component small; the GUI only exists while the user opens it
- Read-only detection first. No automatic deletion until restore/quarantine and false-positive handling are mature
- Clean-room implementation: Malware Zero is used only as a reference for categories of Windows state worth inspecting; its code and databases are not copied

## Current v0.11 coverage

QuietGuard now inspects a broad set of nuisance/PUP persistence and hijack surfaces:

- Hosts, proxy and explicit DNS configuration
- Run/RunOnce, Startup, Command Processor AutoRun, Winlogon, AppInit DLL and Active Setup
- Services, ServiceDll, Start/Type/ImagePath combinations, drivers, scheduled tasks, IFEO, BITS, Winsock and WMI event consumers
- Environment/logon scripts, shell-open associations, App Paths, uninstall commands and browser shortcuts
- Chrome/Edge/Firefox extensions, enterprise policies, home/search/startup policy overrides and site-notification permissions
- Per-user COM CLSID/TypeLib/Interface registrations and targeted machine-wide CLSID searches for user-writable path patterns
- Selected hidden/system executable or script files
- Core Windows process names executing outside System32/SysWOW64
- 4/12-digit executable-like files in System32/SysWOW64
- Group Policy `Registry.pol` suspicious command/path strings
- Chromium extension IDs, background declarations and external update URLs
- Firefox extension metadata, signature-state hints, source URIs and policy values
- Authenticode status and signer/publisher context for selected suspicious autorun/service files

Findings are advisory. Unusual does not automatically mean malicious.

## Baseline comparison

- **기준 저장** saves a normalized scan snapshot to `%LOCALAPPDATA%\QuietGuard\baseline.txt`.
- **기준 비교** rescans and shows newly added or removed/changed findings.

Save a baseline only after the current PC state has been reviewed as acceptable.

## Low-memory real-time watcher

The background `--watch` mode uses native `RegNotifyChangeKeyValue` notifications and one `WaitForMultipleObjects` loop instead of repeatedly rescanning the whole PC or creating a worker thread per target.

It watches important Run/RunOnce locations, proxy settings, Command Processor, Winlogon, the Services/driver tree, available Chrome/Edge policy keys, Hosts, Startup folders and the Windows scheduled-task store. Changes are written to `%LOCALAPPDATA%\QuietGuard\events.log` and can be viewed from the GUI.

## Rule database updates

`rules/heuristics.conf` is an extendable lightweight rule database.

- Rules are retrieved from this GitHub repository over HTTPS.
- A downloaded rule file is accepted only when its SHA-256 matches `rules/version.json`.
- Updated rules are stored under `%LOCALAPPDATA%\QuietGuard\rules` without requiring administrator rights.
- Per-user rules take priority over bundled rules; built-in fallback rules remain available.

The current channel verifies integrity but does not yet provide an independent publisher signature.

## Memory strategy

The project avoids heavy GUI/runtime frameworks. Manual checks may briefly launch built-in Windows tools such as `reg`, `schtasks`, `netsh`, `bitsadmin`, `curl`, `certutil`, or PowerShell. These are transient scan/update-time processes. The always-on watcher itself uses native Windows handles/events and no continuously polling subprocesses.

## Build and validation

```text
cargo build --release
```

GitHub Actions builds a portable Windows package containing `QuietGuard.exe` and starter rules. v0.7 through v0.11 feature branches were validated by Windows Actions with `cargo check --release`, `cargo build --release`, packaging and artifact upload succeeding before merge.

## Status

Early defensive prototype. QuietGuard complements Microsoft Defender and does not replace antivirus protection. It currently does not delete, quarantine or block findings.
