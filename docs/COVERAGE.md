# QuietGuard coverage roadmap

QuietGuard is a clean-room Windows PUP/system-change monitor. It does not copy Malware Zero code or databases.

## Implemented in 0.2

- Hosts custom-entry inspection
- Windows proxy state
- Explicit IPv4 DNS registry configuration detection
- Registry autorun points: HKCU/HKLM Run and RunOnce, WOW6432Node Run
- Command Processor AutoRun inspection
- Winlogon Shell/Userinit/Notify inspection
- AppInit_DLLs-related inspection
- User and all-users Startup folders
- Windows service ImagePath inspection
- Scheduled task inspection
- Chrome, Edge and Firefox extension inventory
- Chrome/Edge force-installed extension policy detection
- External heuristic rule file

## Next coverage targets

- WMI permanent event subscriptions
- ServiceDll and driver/service subkeys
- BITS jobs
- Winsock/LSP and network stack anomalies
- IFEO debugger persistence
- Browser search/start-page policy changes
- File association and shell-open command hijacks
- Additional COM/CLSID persistence points
- Browser notification abuse
- PUP publisher/name/hash intelligence feeds
- Change baselines and low-memory real-time monitoring
