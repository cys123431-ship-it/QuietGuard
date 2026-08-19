# QuietGuard coverage roadmap

QuietGuard is a clean-room Windows PUP/system-change monitor. It does not copy Malware Zero code or databases.

## Implemented in 0.6

### Manual system inspection

- Hosts custom-entry inspection
- Windows proxy state
- Explicit IPv4 DNS registry configuration detection
- Registry autorun points: HKCU/HKLM Run and RunOnce, WOW6432Node Run
- Command Processor AutoRun inspection
- Winlogon Shell/Userinit/Notify inspection
- AppInit_DLLs-related inspection
- User and all-users Startup folders
- Windows service ImagePath inspection
- ServiceDll inspection
- Scheduled task inspection
- IFEO Debugger persistence inspection
- BITS job output inspection
- Winsock catalog path inspection
- WMI permanent CommandLine/ActiveScript event-consumer inspection
- Chrome, Edge and Firefox extension inventory
- Chrome/Edge force-installed extension policy detection
- Browser home/search/startup policy inspection
- User/system environment-variable inspection
- UserInitMprLogonScript inspection
- User Shell Folders Startup override inspection
- EXE/script/HTTP(S) shell-open association inspection
- Uninstall/QuietUninstall command inspection
- Browser shortcut target/argument inspection
- IE ElevationPolicy AppName/AppPath inspection

### Rule/update infrastructure

- External heuristic rule file with built-in fallback rules
- Per-user rule database update under `%LOCALAPPDATA%\QuietGuard\rules`
- HTTPS GitHub rule retrieval with SHA-256 manifest verification
- Portable Windows CI artifact containing the executable and starter rules

### Low-memory real-time watcher

Registry notifications are armed for available important locations including:

- HKCU/HKLM Run and RunOnce
- Windows proxy settings
- HKCU/HKLM Command Processor
- Winlogon
- Services/drivers subtree
- Chrome/Edge user and system policy keys when present

A low-frequency metadata check also records changes to:

- Hosts
- User/all-users Startup folders
- Windows scheduled-task store

Events are written to `%LOCALAPPDATA%\QuietGuard\events.log`. The watcher is detection/logging only and does not modify the system.

## Next coverage targets

- Baseline snapshots and change comparison details
- Event-log viewer in the GUI
- Driver/service subkey heuristics beyond ImagePath/ServiceDll
- Winsock/LSP baselining and provider allowlisting
- Browser notification abuse
- Additional COM/CLSID/TypeLib/Interface persistence points
- Hidden/super-hidden executable heuristics in selected locations
- Browser extension metadata/reputation checks
- PUP publisher/name/hash intelligence feeds
- Safe quarantine/restore model
- Cryptographically signed rule/database update channel
