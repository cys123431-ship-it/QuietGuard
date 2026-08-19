# Intelligence sources

QuietGuard keeps external intelligence separate from its MIT-licensed source code. External lists are downloaded by the user's machine from their original upstream locations and converted into local lookup indexes. The upstream data is not committed into this repository.

## Enabled automatically with no account or API key

| Source | QuietGuard use | Upstream license/status |
| --- | --- | --- |
| UncheckyAds (FadeMind/hosts.extras) | Windows installer advertising/PUP network indicators | MIT repository |
| FadeMind add.Risk | Risk-domain indicators | MIT repository |
| KADhosts | Fraud/adware/scam indicators | CC BY-SA 4.0 |
| StevenBlack Unified Hosts | Broad adware/malware domain context | Aggregates multiple upstream lists with differing licenses; local runtime cache only |

QuietGuard records source, category and license notes in `%LOCALAPPDATA%\QuietGuard\intel\*.meta`.

## Update behavior

- GUI startup launches a short-lived hidden updater process.
- Public intelligence is refreshed no more than once every 24 hours unless the user presses **DB 업데이트**.
- Each source is downloaded over HTTPS.
- A newly downloaded source is parsed into a temporary fixed-width index and only replaces the previous local index after parsing succeeds.
- If one source fails, the other sources continue to update and the previous index for the failed source remains usable.
- Raw downloaded list files are removed after indexing.
- The always-on watcher never downloads these lists.

## Low-memory index format

Each normalized domain is hashed with FNV-1a 64-bit. Per-source hashes are sorted and deduplicated, then stored as 16 lowercase hexadecimal characters plus a newline (`17 bytes` per record). Lookups use fixed-offset binary search against the file instead of loading the full database into memory.

FNV is used only as a compact local lookup key, not as a cryptographic authenticity check. Source transport/authenticity is a separate concern.

## Optional sources prepared for later credential activation

### ThreatFox

ThreatFox Community API is free under its fair-use terms but currently requires an abuse.ch Auth-Key. It provides recent IOCs and domain/payload-delivery/C2 information. IOCs older than six months are expired from current API/export results to reduce false positives.

### URLhaus

URLhaus Community API also requires an abuse.ch Auth-Key. Its recent/full datasets can supplement malicious URL/domain and payload-hash context. The service documents a `recent.csv` export and generates data frequently, but QuietGuard should cache it rather than request it excessively.

### Google Safe Browsing v5

Google Safe Browsing includes an `UNWANTED_SOFTWARE` threat type, which is directly relevant to PUP/PUA-style URL checks. The Safe Browsing API is for non-commercial use and requires Google API access. It is better suited to targeted URL reputation queries than to QuietGuard's no-key bulk local database.

### ClamAV

ClamAV supports PUA detection and distributes digitally signed CVD signature databases maintained by Cisco Talos. FreshClam is the supported updater. QuietGuard can add an optional on-demand ClamAV bridge when the engine is present, but it should not turn ClamAV into another always-on service because QuietGuard's design goal is to remain a low-memory Defender companion.

## Privacy

The enabled no-key feeds are bulk downloads. QuietGuard does not upload local filenames, browser history, scan results or user documents to those feed providers. Future query-style services such as Safe Browsing or hash reputation APIs must remain opt-in because queries can reveal information about the URL/hash being checked.
