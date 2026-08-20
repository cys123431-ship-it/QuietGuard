# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence, adware/browser hijacking and suspicious system configuration changes rather than traditional antivirus replacement.

## QuietGuard 1.6.0

### Read-only safety model

QuietGuard findings are advisory. The program does not automatically delete, quarantine or block files. Baseline snapshots are comparison-only and never act as allowlists or detection exceptions.

### Opt-in automation

Automatic behavior remains off until the user enables each setting from the GUI.

- **윈도우 자동실행 설정**: current-user Windows login startup registration.
- **감시 자동시작 설정**: current-user login registration for the low-memory `--watch` process.
- **DB 자동업데이트 설정**: Task Scheduler job invoking `--update-data-silent` every 6 hours.
- **앱 자동업데이트 설정**: Task Scheduler job invoking `--self-update-silent` every 6 hours.

QuietGuard validates that startup registrations and scheduled tasks still point at the current executable. If the portable folder is moved, the GUI reports a path mismatch and pressing the corresponding settings button repairs the registration.

### Program self-update

When **앱 자동업데이트 설정** is enabled, QuietGuard checks the repository's latest official GitHub Release every six hours. Development commits on `main`, draft releases and prereleases are not installed through this channel.

For a newer release QuietGuard:

1. downloads the versioned Windows x64 release ZIP and its `.sha256` companion over HTTPS,
2. verifies the ZIP SHA-256 before extracting anything,
3. checks that the staged package contains `QuietGuard.exe` and the bundled starter rule files,
4. stops the low-memory watcher only when an actual program update is ready,
5. launches the newly downloaded QuietGuard executable from the staging directory as a replacement helper,
6. replaces the installed executable only after the updater process exits, while retaining `QuietGuard.exe.previous`,
7. restores/restarts the watcher after the replacement attempt.

If another QuietGuard GUI process keeps the executable locked, the helper leaves the installed version intact and the next scheduled update run retries. Update results are written to `%LOCALAPPDATA%\QuietGuard\app-update.log`.

The SHA-256 companion protects against corruption and mismatched release assets. It is not an independent publisher signature: compromise of the GitHub repository/release account could affect both the package and its hash. Independent signed update metadata remains a future hardening target.

### Low-memory real-time monitoring

The watcher uses native Windows registry notifications plus low-frequency metadata checks. It prevents duplicate watcher processes with a named mutex. Important registry locations that did not exist when the watcher started are retried periodically, so a policy/persistence key created later can be added to the live watch set without restarting QuietGuard.

The always-on watcher performs no feed downloads and does not run ClamAV. Changes are logged to `%LOCALAPPDATA%\QuietGuard\events.log`.

### Responsive scans and baseline work

Manual DB updates, system scans, baseline saves and baseline comparisons run outside the Win32 GUI message thread. Helper console windows are suppressed for the main scan modules.

Baseline files include a schema and application version, ignore volatile DB-status lines, and keep the previous baseline as `baseline.prev.txt` before replacement.

### Intelligence and update cadence

No-key public sources:

- UncheckyAds
- FadeMind add.Risk
- KADhosts
- StevenBlack Unified Hosts
- YousList (separate low-confidence Korean advertising context)

One optional abuse.ch Auth-Key enables ThreatFox and URLhaus. Their local indexes refresh independently, so one failed source does not postpone retrying the failed source or force the successful source to refresh again. Public no-key feeds also keep per-source refresh timestamps.

Default scheduled cadence when DB automation is enabled:

- ThreatFox / URLhaus: at most every 6 hours per source
- QuietGuard rule metadata: checked every scheduled 6-hour pass
- Public PUP/domain feeds: at most every 24 hours per source
- YousList: at most every 24 hours
- ClamAV signatures: at most every 24 hours when ClamAV is installed

Database and rule replacement keeps a backup and attempts automatic rollback if installing a new verified file fails.

### Optional services

**Google Safe Browsing** is implemented but disabled by default because checked raw URLs are sent to Google. Requests are bounded by a network timeout.

**ClamAV** is optional. If `clamscan.exe` is present, QuietGuard can run a bounded on-demand PUA scan of selected autorun/service/startup candidates. ClamAV and FreshClam helper executions have time limits; QuietGuard never starts a ClamAV daemon.

### Main detection surfaces

QuietGuard inspects Hosts, DNS/proxy/PAC, Run/RunOnce/Startup, Winlogon, AppInit/AppCert DLLs, Active Setup, services/drivers, scheduled tasks, IFEO, BITS, Winsock, WMI event consumers, shell associations, App Paths, browser shortcuts, Chrome/Edge/Firefox extensions/policies/notifications, COM registrations, selected hidden executables, suspicious Windows-process-name locations, Group Policy strings, firewall rules, execution restrictions, Software Restriction Policy, SafeBoot, MozillaPlugins, IE SearchScopes/DOMStorage and local IPsec policy.

Chromium extension `update_url` checks validate exact HTTPS hosts rather than substring matches, and extension version folders are compared numerically.

## Low-memory intelligence format

Public and optional domain lists are normalized and converted to sorted fixed-width FNV-1a 64-bit indexes under `%LOCALAPPDATA%\QuietGuard\intel`. Lookups binary-search the files on demand rather than loading large databases into resident memory. FNV is only a compact local lookup key, not an authenticity mechanism.

QuietGuard's own heuristic rule file is downloaded over HTTPS and verified against the SHA-256 in `rules/version.json`. An independent publisher-signature layer remains a future hardening target.

## Local secrets

Optional keys belong in `%LOCALAPPDATA%\QuietGuard\secrets.conf`. The repository ignores `secrets.conf`; never commit real API keys.

See `config/secrets.conf.example` and `docs/INTELLIGENCE.md`.

## Build and validation

```text
cargo check --release
cargo test --release
cargo build --release
```

GitHub Actions performs these checks on Windows and packages the native x64 executable with the starter rules.

## Status

QuietGuard 1.6.0 remains a defensive, read-only prototype. It complements Microsoft Defender and does not replace antivirus protection.
