#!/usr/bin/env python3
"""Static, non-invasive Phantom hardening verifier.

This checker reads source/blob files only. It never attaches to a process,
opens /proc/<pid>/mem, reads kernel interfaces, or executes target code.
"""

import argparse
import json
from pathlib import Path


REQUIRED_SOURCE_MARKERS = {
    "native DEX entry point": "nativeLoadShards",
    "pre-decrypt gate": "detect_general_dumper_before_decrypt",
    "Xposed class-loader gate": "detect_java_xposed_bridge",
    "read-only transition": "my_mprotect",
    "memory advice wrapper": "my_madvise",
    "secure wipe": "PH_ZERO",
    "direct DEX loader": "InMemoryDexClassLoader",
    "executable integrity support": "phantom_integrity.inc",
}

REQUIRED_DEFENSE_MARKERS = {
    "dumpability control": ("PR_SET_DUMPABLE", "prctl"),
    "dont-dump memory advice": ("MADV_DONTDUMP", "DONTDUMP"),
    "dont-fork memory advice": ("MADV_DONTFORK", "DONTFORK"),
    "read-only mapping": ("PROT_READ", "mprotect"),
}

FORBIDDEN_PLAINTEXT_MARKERS = (
    b"de.robv.android.xposed.XposedBridge",
    b"java/lang/ClassNotFoundException",
)


def check_source(source_path):
    data = source_path.read_text(encoding="utf-8", errors="replace")
    checks = {}
    for name, marker in REQUIRED_SOURCE_MARKERS.items():
        checks[name] = marker in data
    for name, markers in REQUIRED_DEFENSE_MARKERS.items():
        checks[name] = all(marker in data for marker in markers)
    return checks


def check_blob(blob_path):
    data = blob_path.read_bytes()
    return {
        "size_bytes": len(data),
        "plaintext_markers_absent": all(marker not in data for marker in FORBIDDEN_PLAINTEXT_MARKERS),
        "xposed_class_absent": b"XposedBridge" not in data and b"xposed" not in data.lower(),
        "class_not_found_exception_absent": b"ClassNotFoundException" not in data,
    }


def main():
    parser = argparse.ArgumentParser(description="Verify Phantom hardening artifacts.")
    parser.add_argument("--source", type=Path, required=True, help="phantom_key.c")
    parser.add_argument("--blob", type=Path, action="append", default=[], help="blob to scan; repeatable")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    result = {
        "tool": "phantom_hardening_check",
        "source": str(args.source),
        "source_checks": check_source(args.source),
        "blobs": {str(path): check_blob(path) for path in args.blob},
        "mode": "static read-only verification",
        "limitations": [
            "This is not a proof against a privileged kernel reader.",
            "This does not test a live process or read process/kernel memory.",
            "Passing means only that the checked source and artifacts contain the expected controls.",
        ],
    }
    result["passed"] = (
        all(result["source_checks"].values())
        and all(
            item["plaintext_markers_absent"]
            and item["xposed_class_absent"]
            and item["class_not_found_exception_absent"]
            for item in result["blobs"].values()
        )
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Source: {'PASS' if all(result['source_checks'].values()) else 'CHECK'}")
        for name, ok in result["source_checks"].items():
            print(f"  [{'OK' if ok else '!!'}] {name}")
        for path, item in result["blobs"].items():
            print(f"Blob: {path}")
            print(f"  [{'OK' if item['plaintext_markers_absent'] else '!!'}] encrypted probe markers absent")
            print(f"  [{'OK' if item['xposed_class_absent'] else '!!'}] Xposed markers absent")
            print(f"  [{'OK' if item['class_not_found_exception_absent'] else '!!'}] exception marker absent")
        print(f"Overall: {'PASS' if result['passed'] else 'CHECK FAILED'}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())