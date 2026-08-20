# QuietGuard coverage

QuietGuard is a clean-room Windows PUP/system-change monitor. It does not copy Malware Zero code or databases.

## Implemented through 1.5.1

### Manual inspection

- Hosts, user proxy/PAC, WinHTTP proxy and explicit DNS configuration
- HKCU/HKLM Run and RunOnce, WOW6432Node Run, Explorer Policies Run and Startup folders
- Command Processor AutoRun, Winlogon, AppInit DLLs, AppCertDlls and Active Setup StubPath
- Service ImagePath, ServiceDll and Start/Type/ImagePath combination heuristics
- Scheduled tasks, IFEO Debugger, BITS, Winsock and WMI permanent event consumers
- User/system environment variables and UserInitMprLogonScript
- User Shell Folders Startup override
- EXE/script/HTTP(S) shell-open associations and App Paths
- Uninstall/QuietUninstall commands and browser shortcut targets/arguments
- IE ElevationPolicy AppName/AppPath
- Per-user COM registrations and targeted machine CLSID path checks
- Selected hidden executable/script files and suspicious Windows-process-name locations
- Group Policy Registry.pol suspicious strings
- Chrome/Edge/Firefox extension inventory, enterprise policy and notification settings
- Chromium extension ID/update URL/background metadata checks
- Firefox extension signature/source metadata hints
- Authenticode context for selected suspicious files
- Windows Firewall, DisallowRun/RestrictRun, Software Restriction Policy, SafeBoot, MozillaPlugins, IE SearchScopes/DOMStorage and local IPsec checks

### External intelligence

No-key runtime sources:

- UncheckyAds
- FadeMind add.Risk
- KADhosts
- StevenBlack Unified Hosts
- YousList (low-confidence Korean advertising context)

Optional sources:

- ThreatFox and URLhaus with one local abuse.ch Auth-Key
- Google Safe Browsing v5 when explicitly enabled
- ClamAV PUA scanning when an existing ClamAV installation is detected

Domain lists are converted to fixed-width FNV64 disk indexes under `%LOCALAPPDATA%\QuietGuard\intel` and binary-searched on demand. Public and abuse.ch sources keep per-source refresh timestamps so failures are retried independently.

### Baseline/change comparison

- Manual comparison snapshot under `%LOCALAPPDATA%\QuietGuard\baseline.txt`
- Schema/application-version metadata
- Previous snapshot backup at `baseline.prev.txt`
- Volatile DB status/count lines excluded from comparison
- Baseline is comparison-only and never becomes a detection allowlist
- Recent real-time event viewer in the GUI

### Update infrastructure

- External heuristic rule file with built-in fallback rules
- Per-user rule database under `%LOCALAPPDATA%\QuietGuard\rules`
- HTTPS GitHub retrieval with SHA-256 manifest verification
- Installed-rule SHA-256 revalidation even when the version is unchanged
- Minimum compatible application version enforcement
- Manual and optional scheduled DB refresh
- Named update mutex to prevent overlapping refreshes
- Rollback-safe replacement for rule/domain indexes
- Failed source preserves its previous local index
- Background update log under `%LOCALAPPDATA%\QuietGuard\update.log`

### Low-memory real-time watcher

Native registry notifications cover available important locations including Run/RunOnce, proxy/PAC, Command Processor, Winlogon, Services/drivers, SafeBoot, Firewall rules, App Paths, Explorer Policies, Software Restriction Policy, IE SearchScopes, MozillaPlugins and Chrome/Edge policy keys.

If a configured registry target does not exist when the watcher starts, QuietGuard periodically retries registration so a key created later can join the live watch set. Low-frequency metadata checks cover Hosts, Startup folders and the Windows scheduled-task store.

The watcher records changes only. It performs no feed downloads, quarantine, deletion or automatic remediation.

## Remaining hardening targets

- More precise recursive directory change notifications for task/startup subtrees
- Stronger service/driver signer/reputation scoring and false-positive controls
- Independent cryptographic publisher signing for QuietGuard update metadata and binaries
- Installer/recovery flow and stable settings/log retention controls
- Safe quarantine/restore only after explicit approval, robust rollback metadata and false-positive handling are mature
