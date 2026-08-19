# QuietGuard

QuietGuard is a low-memory Windows companion to Microsoft Defender focused on PUP/PUA, unwanted persistence and system/browser configuration changes rather than traditional antivirus replacement.

## Design goals

- Rust + native Win32 GUI; no Electron, Python runtime or .NET desktop runtime
- Keep the always-on component small; the GUI should only exist while the user opens it
- Read-only detection first. No automatic deletion until restore/quarantine and false-positive handling are mature
- Clean-room implementation: Malware Zero is used only as a reference for categories of Windows state worth inspecting; its code and databases are not copied

## Current 0.2 checks

Hosts, proxy, explicit DNS configuration, Run/RunOnce and other registry persistence locations, Startup folders, service ImagePath values, scheduled tasks, Chrome/Edge/Firefox extension inventory, and browser force-install extension policies.

See `docs/COVERAGE.md` for the detailed roadmap.

## Rules

`rules/heuristics.conf` contains simple extendable heuristics. The executable has safe built-in defaults, so it still runs if the external file is absent.

## Build

```text
cargo build --release
```

GitHub Actions also builds the Windows executable on every push to `main`.

## Status

Early prototype. Findings are advisory and may include legitimate administrator/user configurations. QuietGuard does not currently delete, quarantine or block anything.
