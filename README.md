# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence and system/browser configuration changes rather than traditional antivirus replacement.

## Design goals

- Rust + native Win32 GUI; no Electron, Python runtime or .NET desktop runtime
- Keep the always-on component small; the GUI only exists while the user opens it
- Read-only detection first. No automatic deletion until restore/quarantine and false-positive handling are mature
- Clean-room implementation: Malware Zero is used only as a reference for categories of Windows state worth inspecting; its code and databases are not copied

## Current 0.7 manual checks

QuietGuard inspects Hosts, proxy, explicit DNS configuration, Run/RunOnce and other registry persistence locations, Startup folders, service ImagePath and ServiceDll values, scheduled tasks, IFEO Debugger entries, BITS jobs, Winsock catalog output, WMI permanent event consumers, Chrome/Edge/Firefox extension inventory, browser force-install extension policies, browser home/search/startup policy overrides, environment/logon-script persistence, file/URL shell-open associations, uninstall commands, browser shortcut arguments and IE ElevationPolicy entries.

## Baseline comparison

Version 0.7 adds two manual actions:

- **기준 저장**: saves a normalized snapshot of the current QuietGuard scan results under `%LOCALAPPDATA%\QuietGuard\baseline.txt`.
- **기준 비교**: rescans and shows newly added or removed/changed findings compared with that snapshot.

Only save a baseline after the current PC state has been reviewed as acceptable. The baseline is a change-detection aid, not a declaration that every saved item is trustworthy.

## Low-memory real-time watcher

The background `--watch` mode uses Windows registry change notifications and a single `WaitForMultipleObjects` loop instead of repeatedly rescanning the whole PC or creating one worker thread per target. It watches important Run/RunOnce entries, proxy configuration, Command Processor AutoRun locations, Winlogon, the Services/driver registry tree, available Chrome/Edge policy keys, Hosts, Startup folders and the Windows scheduled-task store.

Changes are logged under `%LOCALAPPDATA%\QuietGuard\events.log`. The GUI **감시 로그** action shows the recent entries.

## Rule database updates

`rules/heuristics.conf` contains lightweight extendable heuristics. The GUI includes a **규칙 업데이트** action.

- The update manifest and rule file are downloaded from this GitHub repository over HTTPS.
- The downloaded rule file is accepted only when its SHA-256 matches `rules/version.json`.
- Updated rules are stored under `%LOCALAPPDATA%\QuietGuard\rules`, so administrator rights are not required.
- Per-user updated rules take priority over portable/bundled rules.
- Safe built-in defaults remain available if no external rule file exists.

The current channel provides integrity checking, not a separate cryptographic publisher signature. A signed update channel remains a later hardening target.

## Memory strategy

The project avoids heavy GUI/runtime frameworks. Manual checks may briefly launch Windows built-in utilities such as `reg`, `schtasks`, `netsh`, `bitsadmin`, `curl`, `certutil`, or PowerShell, but these are transient scan/update-time processes rather than always-on dependencies. The background watcher itself uses native Windows handles/events and no polling subprocesses.

## Build

```text
cargo build --release
```

GitHub Actions builds a portable Windows package. v0.7 was validated through a pull-request Windows Actions run where `cargo check --release`, `cargo build --release`, packaging and artifact upload all succeeded.

## Status

Early prototype. Findings are advisory and may include legitimate administrator/user configurations. QuietGuard does not currently delete, quarantine or block anything.
