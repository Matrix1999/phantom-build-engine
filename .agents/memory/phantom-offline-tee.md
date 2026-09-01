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

The uploaded APK signing-certificate SHA-256 is the authoritative application
identity for server enrollment. Package name is only a secondary attestation
binding and must never authorize an APK without the enrolled signer digest.

**Why:** Ultra Dex2c protects APKs from many unrelated users, so package names
are user-controlled and can collide or be copied. Re-signing must change the
authoritative identity and cause a hard failure before DEX decryption.

**How to apply:** Register the final output signer's SHA-256 during protection,
require the same digest in server and local Phantom evidence, and bind the
attested package name in addition to—not instead of—that signer identity.

The runtime attestation origin belongs in Phantom's encrypted native string
table and must be revealed and integrity-checked only inside a VMP target.
Upload-time enrollment may use the same public origin from the builder.

**Why:** A Java-only runtime endpoint is easy to redirect with a wrapper or
hook. The endpoint is not a secret, but the native gate must reject substituted
origins and independently verify the server's pinned signing key.

**How to apply:** Never accept a runtime origin supplied by Java. Keep redirect
following disabled, bind the exact HTTPS origin in VMP, and treat the pinned
server proof key—not URL secrecy—as the final authority.