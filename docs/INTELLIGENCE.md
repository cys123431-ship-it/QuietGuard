# Intelligence sources

QuietGuard keeps external intelligence separate from its MIT-licensed source code. External lists are downloaded by the user's machine from their original upstream locations and converted into local lookup indexes. The upstream data is not committed into this repository.

## Enabled automatically with no account or API key

| Source | QuietGuard use | Upstream license/status |
| --- | --- | --- |
| UncheckyAds (FadeMind/hosts.extras) | Windows installer advertising/PUP network indicators | MIT repository |
| FadeMind add.Risk | Risk-domain indicators | MIT repository |
| KADhosts | Fraud/adware/scam indicators | CC BY-SA 4.0 |
| StevenBlack Unified Hosts | Broad adware/malware domain context | Aggregates multiple upstream lists with differing licenses; local runtime cache only |

Public intelligence refreshes at most every 24 hours unless **DB 업데이트** is pressed. Raw list files are removed after indexing, and failed sources retain their prior local index.

## Low-memory index format

Normalized domains are hashed with FNV-1a 64-bit, sorted and stored as fixed-width 17-byte records. QuietGuard uses binary search directly on disk instead of loading the full database into resident memory. FNV is only a compact lookup key, not an authenticity mechanism.

## Optional abuse.ch integration (implemented in 1.2)

One abuse.ch Auth-Key can enable both adapters. QuietGuard first checks the `QUIETGUARD_ABUSECH_AUTH_KEY` environment variable, then `%LOCALAPPDATA%\QuietGuard\secrets.conf` for `abusech_auth_key=...`. No secret is stored in the repository or placed literally in the PowerShell command line.

If no key exists, these adapters are skipped without affecting normal operation.

### ThreatFox

QuietGuard requests the recent 7-day IOC set, extracts domain-like IOCs and stores them in `%LOCALAPPDATA%\QuietGuard\intel\keyed\threatfox.f64`. The cache is refreshed at most every six hours unless a forced DB update is requested.

### URLhaus

QuietGuard downloads the authenticated recent CSV dataset, extracts URL hostnames and stores them in `%LOCALAPPDATA%\QuietGuard\intel\keyed\urlhaus.f64`. The same six-hour cache interval applies.

Both caches keep their last known-good index when an API request or parse fails. Scanner results identify ThreatFox/URLhaus matches separately from the broader PUP/adware lists.

A template is provided at `config/secrets.conf.example`; the user only needs to copy/fill it if they later want these optional services.

## Google Safe Browsing v5 (future opt-in)

Google Safe Browsing includes an `UNWANTED_SOFTWARE` threat type and is relevant to targeted PUP/PUA URL reputation checks. It requires Google API access and is intended for non-commercial use, so QuietGuard will keep it disabled unless explicitly configured.

## ClamAV (future optional bridge)

ClamAV supports PUA detection and distributes signed signature databases updated by FreshClam. QuietGuard can invoke it on-demand when present without making it another always-on engine; this preserves QuietGuard's low-memory Defender-companion design.

## Privacy

The default no-key feeds are bulk downloads and do not receive local filenames, scan results or user documents. ThreatFox/URLhaus bulk/cache refresh also avoids per-file lookups. Future query-style services such as Google Safe Browsing should remain opt-in because URL queries reveal information about what is being checked.
