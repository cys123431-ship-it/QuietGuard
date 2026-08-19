# QuietGuard

QuietGuard is a low-memory Windows utility focused on PUP/PUA-style annoyances and suspicious system changes that can coexist with Microsoft Defender.

## Design goals

- Rust + native Win32 UI; no Electron, Python runtime, .NET/WPF, or embedded browser.
- Read-only detection first. No automatic deletion/blocking in v0.1.
- Complement Defender rather than replace antivirus protection.
- Keep background memory usage low.
- Separate executable updates from rules/database updates.

## v0.1 checks

- Hosts file custom entries
- Windows proxy enabled state
- Current-user startup entries
- Startup entries launching from temporary paths

## Planned architecture

- `quietguard-service.exe`: minimal background monitor, always-on.
- `quietguard.exe`: GUI launched only when the user opens it.
- `rules/`: independently updateable detection rules.

## Build on Windows

Install the stable Rust toolchain with MSVC support, then run:

```powershell
cargo build --release
```

Output:

```text
target\release\quietguard.exe
```

## Safety

This prototype reports findings only. It does not delete files, edit the registry, or disable services.
