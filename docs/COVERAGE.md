# QuietGuard coverage roadmap

QuietGuard is a clean-room Windows PUP/system-change monitor. It does not copy Malware Zero code or databases.

## Implemented through 1.1

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

### Public intelligence cross-checks

No-key runtime sources:

- UncheckyAds
- FadeMind add.Risk
- KADhosts
- StevenBlack Unified Hosts

Per-source domain lists are normalized and converted to fixed-width FNV64 indexes under `%LOCALAPPDATA%\QuietGuard\intel`. The database is not loaded wholesale into resident memory. Manual scans currently cross-check proxy/PAC and selected registry URL settings, Chrome/Edge profile settings, browser extension manifests and scheduled-task output.

### Baseline/change comparison

- Manual accepted-state snapshot under `%LOCALAPPDATA%\QuietGuard\baseline.txt`
- Added/removed scan-result comparison across all current manual checks, including external-intelligence matches
- Recent real-time event viewer in the GUI

### Rule/update infrastructure

- External heuristic rule file with built-in fallback rules
- Per-user rule database under `%LOCALAPPDATA%\QuietGuard\rules`
- HTTPS GitHub retrieval with SHA-256 manifest verification
- Installed-rule SHA-256 revalidation even when the version string is unchanged
- Minimum compatible application version enforcement from the manifest
- Hidden background data check at GUI startup
- 24-hour cached public-intelligence refresh, plus forced GUI refresh
- Failed external source preserves its previous local index
- Background update result log under `%LOCALAPPDATA%\QuietGuard\update.log`
- Portable Windows CI artifact containing executable and starter rules

### Low-memory real-time watcher

Native registry notifications cover available important locations including Run/RunOnce, proxy/PAC, Command Processor, Winlogon, Services/drivers, SafeBoot, Windows Firewall rules, App Paths, Explorer Policies, Software Restriction Policy, IE SearchScopes, MozillaPlugins and Chrome/Edge policy keys.

Low-frequency metadata checks cover Hosts, Startup folders and the Windows scheduled-task store. The watcher records changes only and performs no public-feed downloads.

## Remaining high-value targets

- Optional ThreatFox/URLhaus credential adapters and local IOC cache
- Optional Google Safe Browsing `UNWANTED_SOFTWARE` targeted URL lookups
- Optional on-demand ClamAV PUA bridge when ClamAV is present
- Winsock/LSP provider baseline and allowlisting
- More precise service/driver publisher/path scoring
- File/hash/PUP publisher intelligence where licensing permits
- Safe quarantine/restore with explicit user approval and rollback metadata
- Independent cryptographic signing for QuietGuard's own rule/update metadata
- Stable settings/log retention and installer/release packaging

The goal is broad functional overlap with the Windows inspection surfaces Malware Zero covers, plus low-memory real-time monitoring and legally reusable external intelligence, without copying Malware Zero's proprietary signatures or databases.
