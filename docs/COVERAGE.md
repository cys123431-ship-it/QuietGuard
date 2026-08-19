# QuietGuard coverage roadmap

QuietGuard is a clean-room Windows PUP/system-change monitor. It does not copy Malware Zero code or databases.

## Implemented through 0.9

### Manual system inspection

- Hosts custom-entry inspection
- Windows proxy state and explicit IPv4 DNS configuration
- HKCU/HKLM Run and RunOnce, WOW6432Node Run
- Command Processor AutoRun
- Winlogon Shell/Userinit/Notify
- AppInit_DLLs-related values
- User and all-users Startup folders
- Service ImagePath and ServiceDll
- Scheduled tasks
- IFEO Debugger persistence
- BITS jobs
- Winsock catalog output
- WMI permanent CommandLine/ActiveScript event consumers
- Chrome, Edge and Firefox extension inventory
- Chrome/Edge force-installed extension policies
- Browser home/search/startup policy overrides
- User/system environment variables and UserInitMprLogonScript
- User Shell Folders Startup override
- EXE/script/HTTP(S) shell-open associations
- Uninstall/QuietUninstall commands
- Browser shortcut targets/arguments
- IE ElevationPolicy AppName/AppPath
- Active Setup StubPath
- Per-user COM CLSID/WOW64 CLSID/TypeLib/Interface registrations filtered by suspicious paths/commands
- Selected hidden executable/script files in user/profile/system-root locations
- Chrome/Edge site-notification permission counts
- Core Windows process names executing outside System32/SysWOW64
- 4/12-digit executable-like files in System32/SysWOW64
- Group Policy Registry.pol suspicious command/path strings
- Chromium extension ID validation, background declaration counts and external update_url inspection

### Baseline/change comparison

- Manual accepted-state snapshot under `%LOCALAPPDATA%\QuietGuard\baseline.txt`
- Added/removed scan-result comparison
- Recent real-time event viewer in the GUI

### Rule/update infrastructure

- External heuristic rule file with built-in fallback rules
- Per-user rule database under `%LOCALAPPDATA%\QuietGuard\rules`
- HTTPS GitHub retrieval with SHA-256 manifest verification
- Portable Windows CI artifact containing the executable and starter rules

### Low-memory real-time watcher

Native registry notifications are armed for available important locations including:

- HKCU/HKLM Run and RunOnce
- Windows proxy settings
- HKCU/HKLM Command Processor
- Winlogon
- Services/drivers subtree
- Chrome/Edge user and system policy keys when present

A low-frequency metadata check records changes to:

- Hosts
- User/all-users Startup folders
- Windows scheduled-task store

Events are written to `%LOCALAPPDATA%\QuietGuard\events.log`. The watcher is detection/logging only and does not modify the system.

## Remaining high-value coverage targets

- Focused service/driver anomaly checks: unusual Start/Type/ImagePath combinations and nonstandard driver locations
- Focused machine-wide COM hijack checks without dumping the entire HKLM COM registry
- Firefox extension metadata and policy details
- Browser notification origin details rather than counts only
- Winsock/LSP baseline/provider allowlisting
- Selected DNS/proxy reputation intelligence
- File publisher/signature metadata for suspicious findings
- PUP publisher/name/hash intelligence feeds where licensing permits
- Safe quarantine/restore with explicit user approval
- Cryptographically signed rule/database update channel

The target is functional overlap with the system areas Malware Zero inspects, not copying its proprietary signatures or database contents.
