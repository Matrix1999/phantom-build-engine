# Universal Dumper — safe privilege audit

This directory contains the uploaded Universal Dumper bundle under
`original_bundle/`, plus a non-invasive `privilege_audit.py` utility.

The original DEX dumper already uses root-assisted userspace access to:

- `/proc/<PID>/maps`
- `/proc/<PID>/mem`

The added audit only opens sensitive interfaces and closes them immediately.
It does not read bytes from them and does not attempt to bypass Android or
Linux security controls.

## Run on a test device

```sh
su -c "python3 /sdcard/privilege_audit.py --pid <PID>"
```

For machine-readable output:

```sh
su -c "python3 /sdcard/privilege_audit.py --pid <PID> --json"
```

`openable` means only that the operating system allowed `open()`. It does not
prove that subsequent reads would succeed.

## Deliberate safety boundary

This package does **not** add or attempt:

- kernel-memory or physical-memory reads
- kernel-base-address resolution
- `/proc/kcore`, `/dev/kmem`, or `/dev/mem` dumping
- kernel-module loading or unloading
- exploit code or security-control bypasses

Those capabilities would turn a diagnostic DEX dumper into a kernel-level
memory acquisition/rootkit-style tool. The audit reports whether the
interfaces are available so testing can document the device's privilege
boundary without weakening the app or the device.