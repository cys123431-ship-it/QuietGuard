# Release security

Release packages are built by GitHub Actions from the recorded release target commit. The workflow emits a SHA-256 sidecar for the Windows x64 ZIP. QuietGuard itself remains unsigned at v1.4.0; code-signing is a future hardening item.
