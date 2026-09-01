/**
 * Phantom hardware-attestation service.
 *
 * Protocol:
 *  1. GET  /api/phantom/attest/challenge
 *  2. POST /api/phantom/attest/bind
 *  3. POST /api/phantom/attest/nonce
 *  4. POST /api/phantom/attest/verify
 *
 * Challenge, enrollment, and nonce records are authenticated tokens. The
 * service therefore survives process restarts without accepting client-owned
 * device IDs as authority.
 */

import {
  createPrivateKey,
  createPublicKey,
  type KeyObject,
  sign as signEd25519,
} from "node:crypto";
import { Buffer } from "node:buffer";

const PORT = parseInt(Deno.env.get("PORT") ?? "5000", 10);
const TOKEN_VERSION = 1;
const CHALLENGE_TTL_MS = 2 * 60_000;
const NONCE_TTL_MS = 2 * 60_000;
const ENROLLMENT_TTL_MS = 90 * 24 * 60 * 60_000;
const MAX_BODY_BYTES = 96 * 1024;
const ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
const REVOCATION_URL = "https://android.googleapis.com/attestation/status";
const REVOCATION_CACHE_MS = 6 * 60 * 60_000;

// SHA-256 of the DER roots currently published by:
// https://android.googleapis.com/attestation/root
const GOOGLE_ATTESTATION_ROOTS = new Set([
  "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
  "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",
]);

type JsonRecord = Record<string, unknown>;

interface SignedRecord extends JsonRecord {
  v: number;
  typ: "challenge" | "enrollment" | "nonce";
  iat: number;
  exp: number;
}

interface DerNode {
  cls: number;
  tag: number;
  constructed: boolean;
  start: number;
  valueStart: number;
  end: number;
  value: Uint8Array;
  children: DerNode[];
}

interface AttestationDescription {
  attestationSecurityLevel: number;
  keymasterSecurityLevel: number;
  challenge: Uint8Array;
  packageNames: string[];
  signerDigests: string[];
}

interface VerifiedChain {
  leafDer: Uint8Array;
  leafSpki: Uint8Array;
  leafFingerprint: string;
  rootFingerprint: string;
  securityLevel: number;
}

let hmacKeyPromise: Promise<CryptoKey> | undefined;
let signingKeyPromise:
  | Promise<{ privateKey: KeyObject; publicSpki: Uint8Array; keyId: string }>
  | undefined;
const consumedNonces = new Map<string, number>();
const requestBuckets = new Map<string, { start: number; count: number }>();
let revocationCache:
  | { expires: number; entries: Record<string, { status?: string; reason?: string }> }
  | undefined;

function json(data: JsonRecord, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

function clientIp(request: Request): string {
  return request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    request.headers.get("x-real-ip") ||
    "unknown";
}

function rateLimited(request: Request): boolean {
  const ip = clientIp(request);
  const now = Date.now();
  const bucket = requestBuckets.get(ip);
  if (!bucket || now - bucket.start >= 60_000) {
    requestBuckets.set(ip, { start: now, count: 1 });
    return false;
  }
  bucket.count++;
  return bucket.count > 120;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64UrlDecode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(text)) throw new Error("invalid base64url");
  const padded = text.replaceAll("-", "+").replaceAll("_", "/") +
    "=".repeat((4 - text.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function cryptoBytes(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", cryptoBytes(bytes)));
}

async function hmacKey(): Promise<CryptoKey> {
  if (!hmacKeyPromise) {
    hmacKeyPromise = (async () => {
      const secret = Deno.env.get("SESSION_SECRET");
      if (!secret || secret.length < 32) {
        throw new Error("SESSION_SECRET must contain at least 32 characters");
      }
      return await crypto.subtle.importKey(
        "raw",
        cryptoBytes(utf8(secret)),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"],
      );
    })();
  }
  return await hmacKeyPromise;
}

async function signingKey(): Promise<{
  privateKey: KeyObject;
  publicSpki: Uint8Array;
  keyId: string;
}> {
  if (!signingKeyPromise) {
    signingKeyPromise = (async () => {
      const secret = Deno.env.get("SESSION_SECRET");
      if (!secret || secret.length < 32) {
        throw new Error("SESSION_SECRET must contain at least 32 characters");
      }
      const seed = await sha256(utf8(`phantom-ed25519-server-v1\0${secret}`));
      // RFC 8410 PKCS#8 wrapper for a raw 32-byte Ed25519 private seed.
      const prefix = Uint8Array.from([
        0x30,
        0x2e,
        0x02,
        0x01,
        0x00,
        0x30,
        0x05,
        0x06,
        0x03,
        0x2b,
        0x65,
        0x70,
        0x04,
        0x22,
        0x04,
        0x20,
      ]);
      const pkcs8 = new Uint8Array(prefix.length + seed.length);
      pkcs8.set(prefix);
      pkcs8.set(seed, prefix.length);
      seed.fill(0);
      const privateKey = createPrivateKey({
        key: Buffer.from(pkcs8),
        format: "der",
        type: "pkcs8",
      });
      pkcs8.fill(0);
      const publicKey = createPublicKey(privateKey);
      const publicSpki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
      const keyId = hex(await sha256(publicSpki)).slice(0, 16);
      return { privateKey, publicSpki, keyId };
    })();
  }
  return await signingKeyPromise;
}

async function signRecord(record: SignedRecord): Promise<string> {
  const payload = base64UrlEncode(utf8(JSON.stringify(record)));
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", await hmacKey(), cryptoBytes(utf8(payload))),
  );
  return `${payload}.${base64UrlEncode(signature)}`;
}

async function verifyRecord(token: string, type: SignedRecord["typ"]): Promise<SignedRecord> {
  const parts = token.split(".");
  if (parts.length !== 2) throw new Error("malformed token");
  const supplied = base64UrlDecode(parts[1]);
  const expected = new Uint8Array(
    await crypto.subtle.sign("HMAC", await hmacKey(), cryptoBytes(utf8(parts[0]))),
  );
  if (!timingSafeEqual(supplied, expected)) throw new Error("invalid token signature");
  const parsed = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0]))) as SignedRecord;
  const now = Date.now();
  if (parsed.v !== TOKEN_VERSION || parsed.typ !== type) throw new Error("wrong token type");
  if (!Number.isSafeInteger(parsed.iat) || !Number.isSafeInteger(parsed.exp)) {
    throw new Error("invalid token time");
  }
  if (parsed.iat > now + 30_000 || parsed.exp < now) throw new Error("expired token");
  return parsed;
}

function randomValue(bytes = 32): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

function parseDer(bytes: Uint8Array, offset = 0): [DerNode, number] {
  const start = offset;
  if (offset >= bytes.length) throw new Error("truncated DER tag");
  const first = bytes[offset++];
  const cls = first >>> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    let groups = 0;
    while (true) {
      if (offset >= bytes.length || ++groups > 5) throw new Error("invalid DER tag");
      const b = bytes[offset++];
      tag = tag * 128 + (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }
  if (offset >= bytes.length) throw new Error("truncated DER length");
  let length = bytes[offset++];
  if ((length & 0x80) !== 0) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || offset + count > bytes.length) {
      throw new Error("invalid DER length");
    }
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
  }
  const valueStart = offset;
  const end = valueStart + length;
  if (end > bytes.length) throw new Error("truncated DER value");
  const children: DerNode[] = [];
  if (constructed) {
    let childOffset = valueStart;
    while (childOffset < end) {
      const [child, next] = parseDer(bytes, childOffset);
      children.push(child);
      childOffset = next;
    }
    if (childOffset !== end) throw new Error("invalid DER children");
  }
  return [{
    cls,
    tag,
    constructed,
    start,
    valueStart,
    end,
    value: bytes.subarray(valueStart, end),
    children,
  }, end];
}

function derRoot(bytes: Uint8Array): DerNode {
  const [root, end] = parseDer(bytes);
  if (end !== bytes.length) throw new Error("trailing DER data");
  return root;
}

function derRaw(bytes: Uint8Array, node: DerNode): Uint8Array {
  return bytes.subarray(node.start, node.end);
}

function oid(node: DerNode): string {
  if (node.cls !== 0 || node.tag !== 6 || node.value.length === 0) throw new Error("not OID");
  const values = [Math.floor(node.value[0] / 40), node.value[0] % 40];
  let value = 0;
  for (const b of node.value.subarray(1)) {
    value = value * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      values.push(value);
      value = 0;
    }
  }
  return values.join(".");
}

function integer(node: DerNode): number {
  if (node.cls !== 0 || (node.tag !== 2 && node.tag !== 10)) throw new Error("not integer");
  let result = 0;
  for (const b of node.value) result = result * 256 + b;
  return result;
}

function pemToDer(pem: string): Uint8Array {
  const match = pem.match(
    /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/u,
  );
  if (!match) throw new Error("invalid certificate PEM");
  const binary = atob(match[1].replace(/\s+/gu, ""));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function certificateParts(der: Uint8Array): {
  tbs: DerNode;
  signatureOid: string;
  signature: Uint8Array;
  spki: DerNode;
} {
  const cert = derRoot(der);
  if (cert.cls !== 0 || cert.tag !== 16 || cert.children.length !== 3) {
    throw new Error("invalid certificate structure");
  }
  const tbs = cert.children[0];
  const signatureAlgorithm = cert.children[1];
  const signatureBits = cert.children[2];
  if (
    signatureAlgorithm.children.length < 1 || signatureBits.tag !== 3 ||
    signatureBits.value.length < 2 || signatureBits.value[0] !== 0
  ) {
    throw new Error("invalid certificate signature");
  }
  const spki = tbs.children.find((candidate) => {
    if (candidate.cls !== 0 || candidate.tag !== 16 || candidate.children.length !== 2) {
      return false;
    }
    const algorithm = candidate.children[0];
    return algorithm.tag === 16 && algorithm.children[0]?.tag === 6 &&
      candidate.children[1]?.tag === 3;
  });
  if (!spki) throw new Error("certificate SPKI missing");
  return {
    tbs,
    signatureOid: oid(signatureAlgorithm.children[0]),
    signature: signatureBits.value.subarray(1),
    spki,
  };
}

function certificateSerial(der: Uint8Array): { hex: string; decimal: string } {
  const { tbs } = certificateParts(der);
  const serialIndex = tbs.children[0]?.cls === 2 && tbs.children[0]?.tag === 0 ? 1 : 0;
  const serial = tbs.children[serialIndex];
  if (!serial || serial.cls !== 0 || serial.tag !== 2 || serial.value.length === 0) {
    throw new Error("certificate serial missing");
  }
  let bytes = serial.value;
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
  const serialHex = hex(bytes).replace(/^0+(?=[0-9a-f])/u, "");
  return { hex: serialHex, decimal: BigInt(`0x${serialHex}`).toString(10) };
}

function parseCertificateTime(node: DerNode): number {
  if (node.cls !== 0 || (node.tag !== 23 && node.tag !== 24)) {
    throw new Error("certificate validity time missing");
  }
  const text = new TextDecoder().decode(node.value);
  const match = node.tag === 23
    ? text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/u)
    : text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/u);
  if (!match) throw new Error("unsupported certificate time");
  const shortYear = node.tag === 23;
  const rawYear = Number(match[1]);
  const year = shortYear ? (rawYear >= 50 ? 1900 + rawYear : 2000 + rawYear) : rawYear;
  const offset = shortYear ? 0 : 0;
  const month = Number(match[2 + offset]);
  const day = Number(match[3 + offset]);
  const hour = Number(match[4 + offset]);
  const minute = Number(match[5 + offset]);
  const second = Number(match[6 + offset]);
  const timestamp = Date.UTC(year, month - 1, day, hour, minute, second);
  if (!Number.isFinite(timestamp)) throw new Error("invalid certificate time");
  return timestamp;
}

function verifyCertificateValidity(der: Uint8Array, now: number): void {
  const { tbs } = certificateParts(der);
  const validity = tbs.children.find(
    (candidate) =>
      candidate.cls === 0 && candidate.tag === 16 && candidate.children.length === 2 &&
      [23, 24].includes(candidate.children[0]?.tag) &&
      [23, 24].includes(candidate.children[1]?.tag),
  );
  if (!validity) throw new Error("certificate validity missing");
  const notBefore = parseCertificateTime(validity.children[0]);
  const notAfter = parseCertificateTime(validity.children[1]);
  if (now < notBefore || now > notAfter) throw new Error("certificate outside validity window");
}

async function revocationEntries(): Promise<
  Record<string, { status?: string; reason?: string }>
> {
  const now = Date.now();
  if (revocationCache && revocationCache.expires > now) return revocationCache.entries;
  const response = await fetch(REVOCATION_URL, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(8_000),
  });
  if (!response.ok) throw new Error("revocation service unavailable");
  const parsed = await response.json() as {
    entries?: Record<string, { status?: string; reason?: string }>;
  };
  if (!parsed.entries || typeof parsed.entries !== "object") {
    throw new Error("revocation response invalid");
  }
  revocationCache = { expires: now + REVOCATION_CACHE_MS, entries: parsed.entries };
  return parsed.entries;
}

async function verifyNotRevoked(chain: Uint8Array[]): Promise<void> {
  const entries = await revocationEntries();
  for (const certificate of chain.slice(0, -1)) {
    const serial = certificateSerial(certificate);
    const entry = entries[serial.decimal] ?? entries[serial.hex];
    if (entry && entry.status !== "GOOD") {
      throw new Error("attestation certificate revoked");
    }
  }
}

function spkiAlgorithm(der: Uint8Array, spki: DerNode): {
  kind: "RSA" | "EC";
  curve?: "P-256" | "P-384";
} {
  const algorithm = spki.children[0];
  const keyOid = oid(algorithm.children[0]);
  if (keyOid === "1.2.840.113549.1.1.1") return { kind: "RSA" };
  if (keyOid !== "1.2.840.10045.2.1") throw new Error("unsupported issuer key");
  const curveOid = oid(algorithm.children[1]);
  if (curveOid === "1.2.840.10045.3.1.7") return { kind: "EC", curve: "P-256" };
  if (curveOid === "1.3.132.0.34") return { kind: "EC", curve: "P-384" };
  throw new Error(`unsupported EC curve in ${hex(derRaw(der, spki))}`);
}

function signatureHash(signatureOid: string): "SHA-256" | "SHA-384" | "SHA-512" {
  const hashes: Record<string, "SHA-256" | "SHA-384" | "SHA-512"> = {
    "1.2.840.113549.1.1.11": "SHA-256",
    "1.2.840.113549.1.1.12": "SHA-384",
    "1.2.840.113549.1.1.13": "SHA-512",
    "1.2.840.10045.4.3.2": "SHA-256",
    "1.2.840.10045.4.3.3": "SHA-384",
    "1.2.840.10045.4.3.4": "SHA-512",
  };
  const hash = hashes[signatureOid];
  if (!hash) throw new Error("unsupported certificate signature algorithm");
  return hash;
}

function ecdsaDerToRaw(signature: Uint8Array, scalarBytes: number): Uint8Array {
  const sequence = derRoot(signature);
  if (sequence.tag !== 16 || sequence.children.length !== 2) {
    throw new Error("invalid ECDSA signature");
  }
  const out = new Uint8Array(scalarBytes * 2);
  for (let i = 0; i < 2; i++) {
    const part = sequence.children[i];
    if (part.tag !== 2 || part.value.length === 0) throw new Error("invalid ECDSA integer");
    let value = part.value;
    while (value.length > scalarBytes && value[0] === 0) value = value.subarray(1);
    if (value.length > scalarBytes) throw new Error("oversized ECDSA integer");
    out.set(value, i * scalarBytes + scalarBytes - value.length);
  }
  return out;
}

async function verifyCertificateLink(
  childDer: Uint8Array,
  issuerDer: Uint8Array,
): Promise<boolean> {
  const child = certificateParts(childDer);
  const issuer = certificateParts(issuerDer);
  const issuerSpki = derRaw(issuerDer, issuer.spki);
  const key = spkiAlgorithm(issuerDer, issuer.spki);
  const hash = signatureHash(child.signatureOid);
  if (key.kind === "RSA") {
    const publicKey = await crypto.subtle.importKey(
      "spki",
      cryptoBytes(issuerSpki),
      { name: "RSASSA-PKCS1-v1_5", hash },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      publicKey,
      cryptoBytes(child.signature),
      cryptoBytes(derRaw(childDer, child.tbs)),
    );
  }
  const publicKey = await crypto.subtle.importKey(
    "spki",
    cryptoBytes(issuerSpki),
    { name: "ECDSA", namedCurve: key.curve! },
    false,
    ["verify"],
  );
  const rawSignature = ecdsaDerToRaw(child.signature, key.curve === "P-384" ? 48 : 32);
  return await crypto.subtle.verify(
    { name: "ECDSA", hash },
    publicKey,
    cryptoBytes(rawSignature),
    cryptoBytes(derRaw(childDer, child.tbs)),
  );
}

function findExtension(der: Uint8Array, extensionOid: string): Uint8Array | null {
  const { tbs } = certificateParts(der);
  const extensionWrapper = tbs.children.find((node) => node.cls === 2 && node.tag === 3);
  const extensions = extensionWrapper?.children[0];
  if (!extensions) return null;
  for (const extension of extensions.children) {
    if (extension.tag !== 16 || extension.children.length < 2) continue;
    if (oid(extension.children[0]) !== extensionOid) continue;
    const value = extension.children[extension.children.length - 1];
    if (value.cls !== 0 || value.tag !== 4) throw new Error("invalid extension value");
    return value.value;
  }
  return null;
}

function parseAttestationDescription(leafDer: Uint8Array): AttestationDescription {
  const extension = findExtension(leafDer, ATTESTATION_OID);
  if (!extension) throw new Error("Android attestation extension missing");
  const description = derRoot(extension);
  if (description.tag !== 16 || description.children.length < 8) {
    throw new Error("invalid Android attestation description");
  }
  const attestationSecurityLevel = integer(description.children[1]);
  const keymasterSecurityLevel = integer(description.children[3]);
  const challengeNode = description.children[4];
  if (challengeNode.tag !== 4) throw new Error("attestation challenge missing");

  const packageNames: string[] = [];
  const signerDigests: string[] = [];
  for (const authorizationList of [description.children[6], description.children[7]]) {
    const appIdField = authorizationList.children.find(
      (node) => node.cls === 2 && node.tag === 709,
    );
    if (!appIdField) continue;
    const appIdOctets = appIdField.children[0];
    if (!appIdOctets || appIdOctets.tag !== 4) throw new Error("invalid attestation app ID");
    const appId = derRoot(appIdOctets.value);
    const packages = appId.children[0];
    const digests = appId.children[1];
    for (const pkg of packages?.children ?? []) {
      const name = pkg.children[0];
      if (name?.tag === 4) packageNames.push(new TextDecoder().decode(name.value));
    }
    for (const digest of digests?.children ?? []) {
      if (digest.tag === 4) signerDigests.push(hex(digest.value));
    }
  }
  return {
    attestationSecurityLevel,
    keymasterSecurityLevel,
    challenge: challengeNode.value,
    packageNames,
    signerDigests,
  };
}

function allowedSigners(): Set<string> {
  const configured = Deno.env.get("PHANTOM_ALLOWED_SIGNERS") ?? "";
  return new Set(
    configured.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean),
  );
}

async function verifyAttestationChain(
  chainPem: string[],
  challenge: Uint8Array,
  packageName: string,
  signerDigest: string,
): Promise<VerifiedChain> {
  if (!Array.isArray(chainPem) || chainPem.length < 2 || chainPem.length > 8) {
    throw new Error("attestation chain length rejected");
  }
  const chain = chainPem.map(pemToDer);
  const now = Date.now();
  for (const cert of chain) {
    if (cert.length < 128 || cert.length > 16 * 1024) throw new Error("certificate size rejected");
    verifyCertificateValidity(cert, now);
  }
  for (let i = 0; i < chain.length - 1; i++) {
    if (!(await verifyCertificateLink(chain[i], chain[i + 1]))) {
      throw new Error("certificate chain signature rejected");
    }
  }
  if (!(await verifyCertificateLink(chain[chain.length - 1], chain[chain.length - 1]))) {
    throw new Error("root certificate self-signature rejected");
  }
  await verifyNotRevoked(chain);
  const rootFingerprint = hex(await sha256(chain[chain.length - 1]));
  if (!GOOGLE_ATTESTATION_ROOTS.has(rootFingerprint)) {
    throw new Error("attestation root is not pinned");
  }

  const description = parseAttestationDescription(chain[0]);
  if (!timingSafeEqual(description.challenge, challenge)) {
    throw new Error("attestation challenge mismatch");
  }
  if (description.attestationSecurityLevel < 1 || description.keymasterSecurityLevel < 1) {
    throw new Error("software Keystore rejected");
  }
  if (!description.packageNames.includes(packageName)) {
    throw new Error("attested package name mismatch");
  }
  const normalizedSigner = signerDigest.toLowerCase();
  if (!description.signerDigests.includes(normalizedSigner)) {
    throw new Error("attested APK signer mismatch");
  }
  const allowlist = allowedSigners();
  if (allowlist.size > 0 && !allowlist.has(normalizedSigner)) {
    throw new Error("APK signer is not enrolled on server");
  }

  const leaf = certificateParts(chain[0]);
  return {
    leafDer: chain[0],
    leafSpki: derRaw(chain[0], leaf.spki),
    leafFingerprint: hex(await sha256(chain[0])),
    rootFingerprint,
    securityLevel: Math.min(
      description.attestationSecurityLevel,
      description.keymasterSecurityLevel,
    ),
  };
}

async function readJson(request: Request): Promise<JsonRecord> {
  const length = parseInt(request.headers.get("content-length") ?? "0", 10);
  if (length > MAX_BODY_BYTES) throw new Error("request too large");
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length > MAX_BODY_BYTES) throw new Error("request too large");
  return JSON.parse(new TextDecoder().decode(bytes)) as JsonRecord;
}

function requiredString(body: JsonRecord, name: string, max: number): string {
  const value = body[name];
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new Error(`invalid ${name}`);
  }
  return value;
}

async function challengeResponse(): Promise<Response> {
  const now = Date.now();
  const challenge = randomValue();
  const challengeToken = await signRecord({
    v: TOKEN_VERSION,
    typ: "challenge",
    iat: now,
    exp: now + CHALLENGE_TTL_MS,
    challenge,
  });
  return json({ ok: true, challenge, challengeToken });
}

async function bindResponse(request: Request): Promise<Response> {
  const body = await readJson(request);
  const challenge = requiredString(body, "challenge", 128);
  const challengeToken = requiredString(body, "challengeToken", 2048);
  const packageName = requiredString(body, "packageName", 255);
  const signerDigest = requiredString(body, "signerDigest", 64).toLowerCase();
  if (!/^[0-9a-f]{64}$/u.test(signerDigest)) throw new Error("invalid signer digest");
  const record = await verifyRecord(challengeToken, "challenge");
  if (record.challenge !== challenge) throw new Error("challenge token mismatch");
  const certChain = body.certChain;
  if (!Array.isArray(certChain) || !certChain.every((item) => typeof item === "string")) {
    throw new Error("invalid certChain");
  }
  const verified = await verifyAttestationChain(
    certChain as string[],
    base64UrlDecode(challenge),
    packageName,
    signerDigest,
  );
  const now = Date.now();
  const enrollmentToken = await signRecord({
    v: TOKEN_VERSION,
    typ: "enrollment",
    iat: now,
    exp: now + ENROLLMENT_TTL_MS,
    packageName,
    signerDigest,
    spki: base64UrlEncode(verified.leafSpki),
    leafFingerprint: verified.leafFingerprint,
    rootFingerprint: verified.rootFingerprint,
    securityLevel: verified.securityLevel,
  });
  return json({
    ok: true,
    enrollmentToken,
    securityLevel: verified.securityLevel,
    keyFingerprint: verified.leafFingerprint,
  });
}

async function nonceResponse(request: Request): Promise<Response> {
  const body = await readJson(request);
  const enrollmentToken = requiredString(body, "enrollmentToken", 32 * 1024);
  const enrollment = await verifyRecord(enrollmentToken, "enrollment");
  const now = Date.now();
  const nonce = randomValue();
  const enrollmentHash = hex(await sha256(utf8(enrollmentToken)));
  const nonceToken = await signRecord({
    v: TOKEN_VERSION,
    typ: "nonce",
    iat: now,
    exp: now + NONCE_TTL_MS,
    nonce,
    enrollmentHash,
  });
  return json({ ok: true, nonce, nonceToken });
}

async function verifyResponse(request: Request): Promise<Response> {
  const body = await readJson(request);
  const enrollmentToken = requiredString(body, "enrollmentToken", 32 * 1024);
  const nonceToken = requiredString(body, "nonceToken", 4096);
  const signature = requiredString(body, "signature", 4096);
  const enrollment = await verifyRecord(enrollmentToken, "enrollment");
  const nonce = await verifyRecord(nonceToken, "nonce");
  const enrollmentHash = hex(await sha256(utf8(enrollmentToken)));
  if (nonce.enrollmentHash !== enrollmentHash) throw new Error("nonce enrollment mismatch");
  const nonceId = hex(await sha256(utf8(nonceToken)));
  const now = Date.now();
  for (const [key, expiry] of consumedNonces) if (expiry < now) consumedNonces.delete(key);
  if (consumedNonces.has(nonceId)) throw new Error("nonce replay rejected");

  const spki = base64UrlDecode(String(enrollment.spki ?? ""));
  const publicKey = await crypto.subtle.importKey(
    "spki",
    cryptoBytes(spki),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const derSignature = base64UrlDecode(signature);
  const rawSignature = ecdsaDerToRaw(derSignature, 32);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    cryptoBytes(rawSignature),
    cryptoBytes(base64UrlDecode(String(nonce.nonce ?? ""))),
  );
  if (!valid) throw new Error("hardware signature rejected");
  consumedNonces.set(nonceId, Number(nonce.exp));
  const serverKey = await signingKey();
  const proof = base64UrlEncode(utf8(JSON.stringify({
    v: TOKEN_VERSION,
    typ: "approval",
    iat: now,
    exp: now + NONCE_TTL_MS,
    enrollmentHash,
    nonceId,
  })));
  const proofSignature = signEd25519(
    null,
    Buffer.from(utf8(proof)),
    serverKey.privateKey,
  );
  return json({
    ok: true,
    proof,
    proofSignature: base64UrlEncode(proofSignature),
    keyId: serverKey.keyId,
  });
}

export async function handler(request: Request): Promise<Response> {
  try {
    if (rateLimited(request)) return json({ ok: false, error: "rate_limited" }, 429);
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      await hmacKey();
      const serverKey = await signingKey();
      return json({
        ok: true,
        service: "phantom-attestation",
        version: TOKEN_VERSION,
        keyId: serverKey.keyId,
      });
    }
    if (request.method === "GET" && url.pathname === "/.well-known/phantom-attestation-key") {
      const serverKey = await signingKey();
      return json({
        ok: true,
        algorithm: "Ed25519",
        keyId: serverKey.keyId,
        spki: base64UrlEncode(serverKey.publicSpki),
      });
    }
    if (request.method === "GET" && url.pathname === "/api/phantom/attest/challenge") {
      return await challengeResponse();
    }
    if (request.method === "POST" && url.pathname === "/api/phantom/attest/bind") {
      return await bindResponse(request);
    }
    if (request.method === "POST" && url.pathname === "/api/phantom/attest/nonce") {
      return await nonceResponse(request);
    }
    if (request.method === "POST" && url.pathname === "/api/phantom/attest/verify") {
      return await verifyResponse(request);
    }
    return json({ ok: false, error: "not_found" }, 404);
  } catch (error) {
    const message = error instanceof Error ? error.message : "request rejected";
    console.warn("attestation request rejected:", message);
    return json({ ok: false, error: "attestation_rejected" }, 403);
  }
}

if (import.meta.main) {
  await hmacKey();
  console.log(`Phantom attestation service listening on 0.0.0.0:${PORT}`);
  Deno.serve({ hostname: "0.0.0.0", port: PORT }, handler);
}
