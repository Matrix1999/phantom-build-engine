---
name: Phantom combined TEE gate
description: Durable boundary for combining online Android attestation with an independent local Phantom fallback.
---

Phantom's normal hardware path is online: a server challenge, attested
public-key enrollment, and fresh server-nonce signature verification. It must
also have a complete local fallback using a Phantom-only Android Keystore P-256
alias, a local attestation challenge, complete chain validation, fresh local
signature proof, and separate continuity record.

**Why:** The reviewed Munowatch design provides a useful online
enrollment/nonce flow, but its authoritative validation lives on its Deno
server. Phantom needs both that online proof and a guard-like local proof so a
server outage does not block an otherwise valid installation.

**How to apply:** Keep JNI/Keystore collection outside the pure VMP boundary,
but put evidence validation, aggregation, and the final proceed/reject decision
under Phantom-owned VMP targets. Online success requires the local signer/TEE
checks plus server enrollment and nonce proof. Only an actual availability
failure may select the local fallback; an explicit server rejection remains a
failure. Never use the guard result as Phantom evidence.