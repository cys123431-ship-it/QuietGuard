# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence and system/browser configuration changes rather than traditional antivirus replacement.

## Design goals

- Rust + native Win32 GUI; no Electron, Python runtime or .NET desktop runtime
- Keep the always-on component small; the GUI only exists while the user opens it
- Read-only detection first. No automatic deletion until restore/quarantine and false-positive handling are mature
- Clean-room implementation: Malware Zero is used only as a reference for categories of Windows state worth inspecting; its code and databases are not copied

## Current 0.6 manual checks

QuietGuard inspects Hosts, proxy, explicit DNS configuration, Run/RunOnce and other registry persistence locations, Startup folders, service ImagePath and ServiceDll values, scheduled tasks, IFEO Debugger entries, BITS jobs, Winsock catalog output, WMI permanent event consumers, Chrome/Edge/Firefox extension inventory, browser force-install extension policies, browser home/search/startup policy overrides, environment/logon-script persistence, file/URL shell-open associations, uninstall commands, browser shortcut arguments and IE ElevationPolicy entries.

See `docs/COVERAGE.md` for the detailed coverage list.

## Low-memory real-time watcher

Version 0.6 adds a background `--watch` mode controlled from the native GUI.

The watcher uses Windows registry change notifications and a single `WaitForMultipleObjects` loop instead of repeatedly rescanning the whole PC or creating one worker thread per target. It currently watches important Run/RunOnce entries, proxy configuration, Command Processor AutoRun locations, Winlogon, the Services/driver registry tree, available Chrome/Edge policy keys, Hosts, Startup folders and the Windows scheduled-task store.

Changes are logged under:

```text
%LOCALAPPDATA%\QuietGuard\events.log
```

This version records changes but does not automatically block or delete them.

## Rule database updates

`rules/heuristics.conf` contains lightweight extendable heuristics. The GUI includes a **Rule Update** action.

- The update manifest and rule file are downloaded from this GitHub repository over HTTPS.
- The downloaded rule file is accepted only when its SHA-256 matches `rules/version.json`.
- Updated rules are stored under `%LOCALAPPDATA%\QuietGuard\rules`, so administrator rights are not required.
- The per-user updated rules take priority over the portable/bundled rules next to the executable.
- If no external rule file exists, QuietGuard keeps safe built-in defaults.

The current channel provides integrity checking, not a separate cryptographic publisher signature. A signed update channel remains a later hardening target.

## Memory strategy

The project avoids heavy GUI/runtime frameworks. Manual checks may briefly launch Windows built-in utilities such as `reg`, `schtasks`, `netsh`, `bitsadmin`, `curl`, `certutil`, or PowerShell, but these are transient scan/update-time processes rather than always-on dependencies. The background watcher itself uses native Windows handles/events and no polling subprocesses.

## Build

```text
cargo build --release
```

GitHub Actions builds a portable Windows package on every push to `main`. The artifact contains `QuietGuard.exe` plus the starter `rules` directory.

## Status

Early prototype. Findings are advisory and may include legitimate administrator/user configurations. QuietGuard does not currently delete, quarantine or block anything.
