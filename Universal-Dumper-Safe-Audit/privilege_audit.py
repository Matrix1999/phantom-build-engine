#!/usr/bin/env python3
"""Read-only Android privilege and interface audit.

This script deliberately probes availability only. It opens each path and
immediately closes it; it never reads kernel or process-memory contents.
"""

import argparse
import json
import os
import platform
import sys


def probe(path, directory=False):
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
        os.close(fd)
        return {"path": path, "status": "openable"}
    except OSError as exc:
        return {
            "path": path,
            "status": "unavailable",
            "errno": exc.errno,
            "error": exc.strerror or exc.__class__.__name__,
        }


def audit(pid):
    result = {
        "tool": "privilege_audit",
        "mode": "read-only availability probes",
        "identity": {
            "euid": getattr(os, "geteuid", lambda: None)(),
            "egid": getattr(os, "getegid", lambda: None)(),
            "groups": list(getattr(os, "getgroups", lambda: [])()),
        },
        "kernel_release": platform.release(),
        "interfaces": [
            probe("/proc/kcore"),
            probe("/dev/kmem"),
            probe("/dev/mem"),
            probe("/proc/kallsyms"),
            probe("/proc/modules"),
            probe("/sys/module", directory=True),
        ],
        "target_process": [],
        "limits": [
            "No kernel or physical-memory bytes are read.",
            "No kernel base address is resolved.",
            "No module is loaded or unloaded.",
            "No exploit, ptrace attach, or process-memory read is attempted.",
            "openable means only that open() succeeded; it does not prove useful read access.",
        ],
    }

    if pid is not None:
        if pid <= 0:
            raise ValueError("PID must be a positive integer")
        result["target_process"] = [
            probe(f"/proc/{pid}/maps"),
            probe(f"/proc/{pid}/mem"),
        ]

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Safely audit Android privilege and proc interfaces."
    )
    parser.add_argument(
        "--pid",
        type=int,
        help="optional target PID; maps and mem are opened and closed without reading",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    args = parser.parse_args()

    try:
        result = audit(args.pid)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    print("Privilege audit: read-only availability probes")
    print(f"Effective UID/GID: {result['identity']['euid']}/{result['identity']['egid']}")
    print(f"Kernel release: {result['kernel_release']}")
    print("\nSensitive interfaces (opened, then immediately closed):")
    for item in result["interfaces"]:
        suffix = ""
        if item["status"] == "unavailable":
            suffix = f" — {item.get('error', 'unavailable')}"
        print(f"  {item['status']:11} {item['path']}{suffix}")

    if args.pid is not None:
        print(f"\nTarget process {args.pid} (no bytes read):")
        for item in result["target_process"]:
            suffix = ""
            if item["status"] == "unavailable":
                suffix = f" — {item.get('error', 'unavailable')}"
            print(f"  {item['status']:11} {item['path']}{suffix}")

    print("\nNo kernel bytes, physical memory, module operations, exploits, or kernel-base lookup were performed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())