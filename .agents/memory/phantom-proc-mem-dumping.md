---
name: Privileged proc-mem dumping
description: The boundary between process seals, mapping advice, and privileged /proc/PID/mem readers.
---

`PR_SET_DUMPABLE`, `MADV_DONTDUMP`, `MADV_DONTFORK`, and read-only permissions are not content confidentiality against a root/CAP_SYS_PTRACE reader opening `/proc/PID/mem` from another process. They only constrain particular dump, fork, or write paths.

**Why:** A root scanner can read readable process mappings directly and locate DEX by its `dex\n` magic plus the header endian tag. Target-process FD inspection cannot observe that external reader because its file descriptor lives in the dumper process.

**How to apply:** Keep process seals and anti-debug checks as layered defenses, but separately remove or scrub the scanner's discovery markers from every post-load ART/native plaintext copy. Validate the actual runtime mapping and scanner timing; source annotations and `MADV_DONTDUMP` are not proof of proc-mem resistance.