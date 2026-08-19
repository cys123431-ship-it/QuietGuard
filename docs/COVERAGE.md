# QuietGuard coverage roadmap

QuietGuard is a clean-room Windows PUP/system-change monitor. It does not copy Malware Zero code or databases.

## Implemented through 1.0

### Manual system inspection

- Hosts, Windows user proxy/PAC, WinHTTP proxy and explicit IPv4 DNS configuration
- HKCU/HKLM Run and RunOnce, WOW6432Node Run, Explorer Policies Run and Startup folders
- Command Processor AutoRun, Winlogon, AppInit DLLs, AppCertDlls and Active Setup StubPath
- Service ImagePath, ServiceDll and Start/Type/ImagePath combination heuristics
- Scheduled tasks, IFEO Debugger, BITS, Winsock and WMI permanent event consumers
- User/system environment variables and UserInitMprLogonScript
- User Shell Folders Startup override
- EXE/script/HTTP(S) shell-open associations and App Paths
- Uninstall/QuietUninstall commands and browser shortcut targets/arguments
- IE ElevationPolicy AppName/AppPath
- Per-user COM CLSID/WOW64 CLSID/TypeLib/Interface registrations filtered by suspicious paths/commands
- Targeted HKLM CLSID searches for AppData/Temp/Downloads/Users-Public path patterns
- Selected hidden executable/script files in user/profile/system-root locations
- Core Windows process names executing outside System32/SysWOW64
- 4/12-digit executable-like files in System32/SysWOW64
- Group Policy Registry.pol suspicious command/path strings
- Chrome/Edge/Firefox extension inventory and enterprise policy checks
- Chromium extension ID validation, background declaration counts and external update_url inspection
- Firefox extensions.json metadata, active signature-state hints and external sourceURI checks
- Chrome/Edge allowed notification origin details
- Authenticode status and signer subject for selected suspicious autorun/service file candidates
- Windows Firewall rule executable-path heuristics
- Explorer DisallowRun/RestrictRun execution-policy inspection
- Software Restriction Policy (`Safer`) suspicious path/command inspection
- SafeBoot suspicious path/command inspection
- MozillaPlugins registration inspection
- IE SearchScopes and DOMStorage review points
- Local IPsec policy suspicious path/command inspection

### Baseline/change comparison

- Manual accepted-state snapshot under `%LOCALAPPDATA%\QuietGuard\baseline.txt`
- Added/removed scan-result comparison across all current manual checks
- Recent real-time event viewer in the GUI

### Rule/update infrastructure

- External heuristic rule file with built-in fallback rules
- Per-user rule database under `%LOCALAPPDATA%\QuietGuard\rules`
- HTTPS GitHub retrieval with SHA-256 manifest verification
- Installed-rule SHA-256 revalidation even when the version string is unchanged
- Minimum compatible application version enforcement from the manifest
- Hidden background rule check at GUI startup
- Background update result log under `%LOCALAPPDATA%\QuietGuard\update.log`
- Portable Windows CI artifact containing executable and starter rules

### Low-memory real-time watcher

Native registry notifications cover available important locations including:

- HKCU/HKLM Run and RunOnce
- Windows proxy/PAC settings
- HKCU/HKLM Command Processor
- Winlogon
- Services/drivers subtree
- SafeBoot
- Windows Firewall rules
- HKCU/HKLM App Paths
- HKCU/HKLM Explorer Policies
- Software Restriction Policy
- IE SearchScopes
- HKCU/HKLM MozillaPlugins
- Chrome/Edge user and system policy keys

Low-frequency metadata checks cover Hosts, Startup folders and the Windows scheduled-task store. Events are written to `%LOCALAPPDATA%\QuietGuard\events.log`. The watcher records changes only and does not modify the system.

## Remaining hardening targets

These are post-1.0 enhancements rather than blockers for the current read-only prototype:

- Winsock/LSP provider baseline and allowlisting
- More detailed DNS/proxy reputation intelligence using legally reusable public data
- More precise service/driver publisher/path scoring
- File/hash/PUP publisher intelligence where licensing permits
- Safe quarantine/restore with explicit user approval and rollback metadata
- Independent cryptographic signing for the rule/database update channel
- Stable settings/log retention and installer/release packaging

The goal is broad functional overlap with the Windows inspection surfaces Malware Zero covers, plus low-memory real-time monitoring, without copying Malware Zero's proprietary signatures or databases.
