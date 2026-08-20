# Intelligence sources

QuietGuard keeps external intelligence separate from its MIT-licensed source code. External lists are downloaded by the user's machine from original upstream locations and converted into local lookup indexes; upstream databases are not committed into this repository.

## Automatic no-key sources

| Source | QuietGuard use | License/status |
| --- | --- | --- |
| UncheckyAds | Windows installer advertising/PUP context | MIT |
| FadeMind add.Risk | Risk-domain context | MIT |
| KADhosts | Fraud/adware/scam context | CC BY-SA 4.0 |
| StevenBlack Unified Hosts | Broad adware/malware aggregate | Mixed upstream licenses; runtime cache only |
| YousList | Korean-site advertising context, low-confidence only | CC BY 4.0 |

The first four sources use `%LOCALAPPDATA%\QuietGuard\intel`; YousList uses the `regional` subdirectory. Public feeds refresh at most every 24 hours unless **DB 업데이트** is pressed. Since 1.5.1, each public source keeps its own refresh timestamp, so one failed source can retry later without forcing already-successful sources to download again. YousList matches are labelled as advertising references, not malware verdicts.

## Low-memory format

Normalized domains are hashed with FNV-1a 64-bit, sorted and stored as fixed-width 17-byte records. Lookups binary-search the files directly instead of loading the full databases into resident RAM. FNV is a compact local lookup key, not an authenticity mechanism.

When an updated index is installed, QuietGuard keeps a backup and attempts rollback if replacing the live file fails.

## Optional abuse.ch integration

One abuse.ch Auth-Key enables both ThreatFox and URLhaus adapters. QuietGuard checks `QUIETGUARD_ABUSECH_AUTH_KEY`, then `%LOCALAPPDATA%\QuietGuard\secrets.conf` for `abusech_auth_key=...`. Without a key, both adapters are skipped. With a key, recent data is cached into low-memory disk indexes and normally refreshed at most every six hours.

ThreatFox and URLhaus now keep separate refresh timestamps. A successful URLhaus refresh therefore does not delay retrying a failed ThreatFox refresh, and vice versa. Network requests use bounded timeouts and failed refreshes preserve the previous local index.

## Optional Google Safe Browsing v5

Google Safe Browsing URL search is privacy-sensitive because the checked raw URLs are sent to Google. QuietGuard therefore never enables it automatically.

To opt in, `%LOCALAPPDATA%\QuietGuard\secrets.conf` must contain both:

```text
google_safe_browsing_enabled=true
google_safe_browsing_key=YOUR_KEY
```

or equivalent `QUIETGUARD_GSB_ENABLED` / `QUIETGUARD_GSB_KEY` environment variables. QuietGuard sends at most 50 candidate URLs per manual scan, uses a bounded request timeout and reports `UNWANTED_SOFTWARE` separately from other threat types. Temporary local request/response files are deleted after the query.

## Optional ClamAV bridge

If `clamscan.exe` is already present, QuietGuard can run a bounded on-demand PUA scan of selected autorun/service/startup candidates using `--detect-pua`. Indirect command lines are inspected for additional executable/DLL/script candidates. If `freshclam.exe` is also present, DB update can check official ClamAV signatures. QuietGuard never launches ClamAV as an always-on daemon, and both ClamAV helper operations have execution time limits.

## Privacy

Default no-key sources are bulk downloads and do not receive local filenames, browser history, scan results or documents. ThreatFox/URLhaus are bulk/cache refreshes rather than per-file queries. Google Safe Browsing is the exception: it sends selected URLs and is therefore opt-in only.
