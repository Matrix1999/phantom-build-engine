#!/usr/bin/env python3
"""Stamp or verify Phantom's executable PT_LOAD integrity digest."""

import argparse
import hashlib
import struct
from pathlib import Path


PT_LOAD = 1
PF_X = 1


def executable_segment_digest(elf_path: Path) -> bytes:
    data = elf_path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError(f"{elf_path}: not an ELF file")
    if data[5] != 1:
        raise ValueError(f"{elf_path}: only little-endian ELF is supported")

    elf_class = data[4]
    if elf_class == 2:
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize = struct.unpack_from("<H", data, 54)[0]
        phnum = struct.unpack_from("<H", data, 56)[0]

        def fields(off: int) -> tuple[int, int, int, int]:
            return (
                struct.unpack_from("<I", data, off)[0],
                struct.unpack_from("<I", data, off + 4)[0],
                struct.unpack_from("<Q", data, off + 8)[0],
                struct.unpack_from("<Q", data, off + 32)[0],
            )
    elif elf_class == 1:
        phoff = struct.unpack_from("<I", data, 28)[0]
        phentsize = struct.unpack_from("<H", data, 42)[0]
        phnum = struct.unpack_from("<H", data, 44)[0]

        def fields(off: int) -> tuple[int, int, int, int]:
            return (
                struct.unpack_from("<I", data, off)[0],
                struct.unpack_from("<I", data, off + 24)[0],
                struct.unpack_from("<I", data, off + 4)[0],
                struct.unpack_from("<I", data, off + 16)[0],
            )
    else:
        raise ValueError(f"{elf_path}: unsupported ELF class {elf_class}")

    if phnum == 0 or phnum > 256:
        raise ValueError(f"{elf_path}: invalid program-header count {phnum}")
    if phoff + phentsize * phnum > len(data):
        raise ValueError(f"{elf_path}: truncated program-header table")

    leaves = []
    for index in range(phnum):
        off = phoff + index * phentsize
        p_type, p_flags, p_offset, p_filesz = fields(off)
        if p_type != PT_LOAD or not (p_flags & PF_X) or p_filesz == 0:
            continue
        end = p_offset + p_filesz
        if end <= p_offset or end > len(data):
            raise ValueError(f"{elf_path}: invalid executable segment {index}")
        leaves.append(hashlib.sha256(data[p_offset:end]).digest())

    if not leaves:
        raise ValueError(f"{elf_path}: no executable PT_LOAD segments")
    if len(leaves) > 32:
        raise ValueError(f"{elf_path}: too many executable PT_LOAD segments")
    return hashlib.sha256(b"".join(leaves)).digest()


def write_include(path: Path, digest: bytes) -> None:
    rows = []
    for offset in range(0, len(digest), 8):
        row = ", ".join(f"0x{byte:02x}" for byte in digest[offset:offset + 8])
        rows.append(f"    {row}")
    body = ",\n".join(rows)
    path.write_text(
        "/* Generated per ABI by stamp_phantom_integrity.py. */\n"
        "static volatile const uint8_t PHANTOM_EXPECTED_EXEC_SHA256[32] = {\n"
        f"{body}\n"
        "};\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--write-inc", type=Path)
    parser.add_argument("--expect", help="expected lowercase/uppercase SHA-256 hex")
    args = parser.parse_args()

    digest = executable_segment_digest(args.elf)
    actual = digest.hex()
    if args.expect is not None and actual.lower() != args.expect.lower():
        raise SystemExit(
            f"{args.elf}: executable-segment digest changed after stamping: "
            f"expected {args.expect}, got {actual}"
        )
    if args.write_inc is not None:
        write_include(args.write_inc, digest)
    print(actual)


if __name__ == "__main__":
    main()