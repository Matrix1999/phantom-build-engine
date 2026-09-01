# Munowatch Pincheck → Phantom TEE map

## Scope

Reviewed the supplied `Munowatch.Pincheck.zip`, including:

- `Munowatch/deno/main.ts`
- `Munowatch/apk_out/smali/com/munowatch/security/HardwareAttest.smali`

Deno 2 is installed in the workspace for future `main.ts` work. The supplied
`main.ts` is an upstream media/session proxy, not a drop-in Phantom component.
It should not be copied into Phantom.

The target is:

- Phantom has its own signer check and its own hardware-backed key check.
- The normal path uses an online hardware-TEE enrollment and nonce signature,
  modeled on Munowatch.
- If the server is unavailable, Phantom falls back to its own local TEE path,
  modeled on `guard.cpp`.
- Online and offline evidence belong to Phantom. Phantom does not call the
  guard exports or trust the guard's result.

## What Munowatch does well and we can borrow

### 1. Generate a P-256 key inside Android Keystore

`HardwareAttest.smali` uses:

- `KeyPairGenerator("EC", "AndroidKeyStore")`
- `secp256r1` / P-256
- signing and verification purposes
- a fresh attestation challenge through
  `KeyGenParameterSpec.Builder.setAttestationChallenge(...)`

This is the correct primitive for Phantom. The private key remains
non-exportable, and the attestation certificate chain is produced by the
Android Keystore/KeyMint path.

### 2. Read the complete attestation certificate chain

The code obtains the chain with
`KeyStore.getCertificateChain(alias)` and serializes the DER certificates.
The important part to borrow is obtaining and validating the complete chain,
not the PEM transport format.

### 3. Bind the attestation to a fresh challenge

The server implementation extracts the Android Key Attestation extension and
checks that the challenge in the leaf certificate equals the issued challenge.
Phantom must perform this check locally with a challenge generated for the
current gate attempt.

This prevents an old attestation chain from being replayed for a new key
creation attempt.

### 4. Require hardware security level

The reference distinguishes software, TEE, and StrongBox levels. Phantom
should accept:

- TEE-backed keys
- StrongBox-backed keys

The `KeyInfo` result is useful supporting evidence, but it must not be the only
proof because the application-side API can be hooked. The attestation
extension, chain validation, and signer/package binding are the authoritative
parts.

### 5. Prove possession with a fresh ECDSA signature

The reference signs a nonce using `SHA256withECDSA` and verifies it against the
public key in the enrolled leaf certificate. Phantom should keep this pattern:

1. Generate a fresh local challenge.
2. Ask the separate Phantom Keystore alias to sign it.
3. Verify the signature against the attested public key.
4. Require the result in the Phantom VMP reducer.

When a server is available, the same key can additionally sign a server nonce.
That is the normal online Phantom path. The local proof remains available as
the server-outage fallback.

### 6. Bind the key to the APK identity

The server-side code extracts the attestation application ID and its signature
digests. Phantom should validate that the attestation contains:

- the expected package name; and
- the digest of the currently installed APK signer.

The signer digest must come from Phantom's independent certificate reader, not
from a Java boolean, the guard result, or an unverified request field.

### 7. Use a separate alias and continuity record

Munowatch has a dedicated alias and a local device record. Phantom should use
its own alias and state, independent of guard state:

- Phantom-specific alias
- Phantom-specific public-key fingerprint
- Phantom-specific continuity record
- no reuse of guard exports or guard result variables

The continuity record should detect an unexpected key replacement while
allowing normal app upgrades signed by the same authorized signer.

## What must not be borrowed

### 8. Online enrollment and nonce verification

Munowatch's online path has two distinct proofs:

1. **Enrollment:** the app generates an attested key with a server-issued
   challenge, sends the certificate chain and APK signer digest, and the server
   validates the chain, challenge, security level, and application identity.
2. **Ongoing possession:** the server sends a fresh nonce, and the app signs it
   with the same non-exportable key. The server verifies the signature using
   the public key saved during enrollment.

Phantom should borrow this separation. The Phantom server may store the
attested public-key fingerprint and verify fresh server nonces, while Phantom
also performs its own local checks. A copied public key or device identifier is
not enough to produce the private-key signature.

## What must not be borrowed

### Server-only challenge as the primary gate

Munowatch begins with `GET /api/attest/challenge`. That cannot be Phantom's
only required path because a server outage would prevent first launch or
recovery. Phantom should use the server challenge for the normal online
enrollment, but must also generate and verify its own local challenge for the
offline fallback.

### Server-only certificate validation

Munowatch validates the attestation chain and extension on the server. Phantom
must carry a minimal local validator or equivalent platform-backed validation
for the offline path:

- validate each certificate signature up to pinned Android hardware-attestation
  roots;
- verify the attestation extension;
- verify the challenge;
- verify TEE/StrongBox security level;
- verify package and APK signer binding;
- verify the leaf public key used for the signature.

The online server may repeat these checks, but the local result must stand on
its own when the server is unavailable.

### `device_id` as an authority

Munowatch stores a server-issued `deviceId` and later requires
`device_id + device_sig`. Phantom has no need to trust an opaque local or
server ID. The local authority is:

```text
attested Phantom public key
+ signer/package binding
+ local continuity record
+ fresh signature verification
```

An online device identifier may be metadata only.

### Fail-open and asynchronous binding

The reference catches binding failures and allows the app to continue, and its
attestation flow runs asynchronously. That is unsuitable for the Phantom DEX
gate. Phantom must finish its independent signer + TEE decision before any
encrypted DEX shard is decrypted or mapped.

The existing compatibility behavior for unsupported devices remains an
explicit product policy in Phantom; it must not be an accidental network
failure fallback.

### Shared preferences as the security decision

Munowatch persists device ID and timestamps in `SharedPreferences`. Phantom
may use local storage for non-authoritative bookkeeping, but a stored string
must never be accepted as proof of hardware. The key operation and attested
public key must be checked again.

### Diagnostic logging and hardcoded server material

The reference contains diagnostic HTTP calls and embedded application/server
material in the supplied source. Phantom production logging remains disabled.
No server credentials, HMAC material, account credentials, or API tokens belong
in the APK, `libphantom`, or `phantom.vmp`.

The account credentials in the reference are correctly read from Deno
environment variables, but that proxy/session behavior is unrelated to
Phantom's offline security gate.

## Phantom design to implement

### Combined online/offline sequence

```text
nativeLoadShards(Context, encryptedShards, gateRecord)
    |
    +-- Phantom anti-debug/dumper precheck
    |
    +-- Phantom independent APK signer collection
    |     - read META-INF signer certificate
    |     - compute SHA-256 in native helper
    |     - compare independent duplicate computations
    |     - validate against the protected PHG1 record in VMP
    |
    +-- determine online availability with a short bounded timeout
    |
    +-- Online path, when the server is reachable
    |     - obtain a server challenge
    |     - create/use the Phantom-only P-256 Keystore key
    |     - obtain the attestation chain
    |     - locally validate the chain and signer binding
    |     - send enrollment evidence to the server
    |     - receive server acceptance for the public key
    |     - obtain a fresh server nonce
    |     - sign it with the Phantom Keystore key
    |     - server verifies the signature
    |
    +-- always run the local fallback-capable path
    |     - generate a local random challenge
    |     - validate the Phantom key's local attestation
    |     - sign and verify a fresh local challenge
    |     - check Phantom key continuity
    |
    +-- VMP evidence reducer
    |     - signer pass
    |     - local TEE pass
    |     - local fresh-signature pass
    |     - continuity pass
    |     - online enrollment and nonce pass when server is authoritative
    |     - fail closed according to explicit compatibility policy
    |
    +-- only then decrypt PHB3 shards and create InMemoryDexClassLoader
```

### Evidence that Phantom should own

The Phantom evidence structure should include independent facts equivalent to:

- signer bound to the installed APK;
- challenge fresh and matched in the attestation extension;
- hardware security level is TEE or StrongBox;
- attestation chain is valid;
- signature over the fresh local challenge is valid;
- public key matches the continuity record.

The collector can gather these facts outside the pure VMP boundary. The
evidence validation, aggregation, and final proceed/reject decision belong to
Phantom's VMP targets.

### Online path and server-off fallback

When online, the effective Phantom result is:

```text
local signer PASS
AND local Phantom TEE PASS
AND online enrollment PASS
AND online fresh-nonce signature PASS
```

The local checks are still required online. This prevents the server from
becoming the only place that understands the APK signer or attestation chain.

When the server is unavailable due to a network/availability failure, Phantom
uses:

```text
local signer PASS
AND local Phantom TEE PASS
AND local fresh-signature PASS
AND local continuity PASS
```

This is the `guard.cpp`-style fallback, duplicated inside Phantom. It is not a
call into the guard and does not consume `g_tee_*`, `g_sig_*`, or any other
guard-owned state.

Only a genuine availability failure may select fallback. A server response
that explicitly says the key is revoked, the attestation is invalid, the
signer is wrong, or the nonce signature is wrong must remain a failure; it must
not be disguised as "server offline."

The online path can additionally provide remote revocation, telemetry,
server-side revalidation, and cross-install enrollment. Those are benefits of
the online mode, not replacements for the local Phantom gate.

## Frida and patching boundary

Frida cannot execute inside the TEE or extract the non-exportable private key.
It can still hook the application-side Keystore calls, returned certificate
objects, signature APIs, JNI evidence, or the final decision.

Therefore Phantom should:

- collect and reduce evidence independently of guard;
- verify the attestation chain and challenge locally;
- require package and signer binding;
- use a fresh signature challenge;
- keep the final reducer inside VMP;
- include the Phantom gate and collector call sites in executable integrity
  coverage;
- avoid accepting a Java `isHardwareBacked` boolean as the authority.

This does not claim that a privileged process attacker is impossible to patch.
It ensures that a copied device ID, a fake Java hardware boolean, a replayed
signature, or a single hooked guard path is not sufficient to unlock Phantom.

## Decision

Borrow the **P-256 AndroidKeyStore key, server challenge/enrollment,
complete-chain validation, security-level distinction, signer/package binding,
and fresh server-nonce signature proof** for the online mode.

Mimic the guard's **local challenge, local chain/evidence validation, fresh
signature verification, continuity record, and VMP aggregate** for the
server-off fallback.

Do not borrow the **server-required first launch, server-only verification,
device ID as authority, fail-open async binding, diagnostic logging, or
embedded server material**.

The resulting Phantom gate combines online and offline TEE proofs. Online is
the normal path; offline is a complete local fallback. Both are duplicated
inside Phantom and independent of the guard implementation.