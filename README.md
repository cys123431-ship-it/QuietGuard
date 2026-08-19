# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence and system/browser configuration changes rather than traditional antivirus replacement.

## Design goals

- Rust + native Win32 GUI; no Electron, Python runtime or .NET desktop runtime
- Keep the always-on component small; the GUI only exists while the user opens it
- Read-only detection first. No automatic deletion until restore/quarantine and false-positive handling are mature
- Clean-room implementation: Malware Zero is used only as a reference for categories of Windows state worth inspecting; its code and databases are not copied

## Current 1.0 manual checks

QuietGuard now covers a broad set of Windows nuisance/PUP persistence and hijack surfaces, including:

- Hosts, user proxy/PAC, WinHTTP proxy and explicit DNS configuration
- Run/RunOnce, Startup folders, Command Processor AutoRun, Winlogon and AppInit DLL locations
- Services, ServiceDll, scheduled tasks, IFEO Debugger, BITS, Winsock and WMI event-consumer persistence
- Environment/logon scripts, shell-open associations, uninstall commands and browser shortcuts
- Chrome/Edge/Firefox extension inventory and browser force-install/home/search/startup policies
- Active Setup StubPath persistence
- Per-user COM CLSID/TypeLib/Interface registrations with suspicious-path/command heuristics
- Selected hidden/system executable or script files
- Chrome/Edge site-notification permissions
- Core Windows process names executing outside Windows system directories
- 4/12-digit executable-like files in System32/SysWOW64
- Group Policy `Registry.pol` suspicious command/path strings
- Chromium extension IDs, background declarations and external `update_url` metadata
- Windows Firewall rules that launch from suspicious user/temp paths
- Explorer `DisallowRun` / `RestrictRun` execution policies
- Software Restriction Policy (`Safer`) suspicious path strings
- SafeBoot configuration suspicious path/command strings
- `App Paths` registrations pointing to suspicious locations
- Mozilla plugin registrations pointing to suspicious locations
- IE SearchScopes/DOMStorage review points
- Local IPsec/policy regions with suspicious path/command strings

Findings are intentionally labelled as information/review/warning rather than automatically declaring every unusual configuration malicious.

## Baseline comparison

- **기준 저장** saves a normalized scan snapshot to `%LOCALAPPDATA%\QuietGuard\baseline.txt`.
- **기준 비교** rescans all current 1.0 checks and shows newly added or removed/changed findings.

Only save a baseline after the current PC state has been reviewed as acceptable. The baseline is a change-detection aid, not a trust certificate.

## Low-memory real-time watcher

The background `--watch` mode uses native `RegNotifyChangeKeyValue` notifications and a single `WaitForMultipleObjects` loop rather than repeatedly rescanning the whole PC or creating a worker thread per target.

It watches Run/RunOnce, proxy/PAC, Command Processor, Winlogon, Services/drivers, SafeBoot, Windows Firewall rules, App Paths, Explorer execution-restriction policies, Software Restriction Policy, IE SearchScopes, MozillaPlugins and available Chrome/Edge policy keys. A low-frequency metadata check also watches Hosts, Startup folders and the Windows scheduled-task store. Changes are written to `%LOCALAPPDATA%\QuietGuard\events.log`; the GUI **감시 로그** action shows recent entries.

## Rule database updates

`rules/heuristics.conf` contains lightweight extendable heuristics. The GUI includes a **규칙 업데이트** action, and QuietGuard 1.0 also starts a hidden rule-update check when the GUI opens.

- Rules are retrieved from this GitHub repository over HTTPS.
- The downloaded rule file is accepted only when its SHA-256 matches `rules/version.json`.
- The updater verifies the installed rule hash even when the version string is unchanged.
- The manifest can declare a minimum compatible QuietGuard version.
- Updated rules are stored under `%LOCALAPPDATA%\QuietGuard\rules`, so administrator rights are not required.
- Per-user updated rules take priority over portable/bundled rules.
- Built-in fallback rules remain available if the external file is absent or the update fails.
- Background update results are written to `%LOCALAPPDATA%\QuietGuard\update.log`.

The current channel provides HTTPS transport and integrity checking but not an independent cryptographic publisher signature. A signed update channel remains a hardening target.

## Memory strategy

The project avoids heavy GUI/runtime frameworks. Manual checks may briefly launch built-in Windows utilities such as `reg`, `schtasks`, `netsh`, `bitsadmin`, `curl`, `certutil`, or PowerShell, but these are transient scan/update-time processes. The watcher itself uses native Windows handles/events and no continuously polling subprocesses.

## Build and validation

```text
cargo build --release
```

GitHub Actions builds a portable Windows package containing `QuietGuard.exe` and starter rules. Changes are validated on `windows-latest` with `cargo check --release` and `cargo build --release` before merge.

## Status

Defensive 1.0 prototype. QuietGuard complements Microsoft Defender and does not replace an antivirus product. Findings can include legitimate administrator/user configurations. QuietGuard does not currently delete, quarantine or block anything.
