import { assert, assertEquals } from "jsr:@std/assert@1";
import { handler } from "./main.ts";

Deno.env.set("SESSION_SECRET", "test-only-session-secret-with-at-least-32-characters");

Deno.test("health endpoint is available", async () => {
  const response = await handler(new Request("http://localhost/healthz"));
  assertEquals(response.status, 200);
  const body = await response.json();
  assert(body.ok);
  assertEquals(body.service, "phantom-attestation");
});

Deno.test("challenge endpoint returns a signed opaque token", async () => {
  const response = await handler(
    new Request("http://localhost/api/phantom/attest/challenge"),
  );
  assertEquals(response.status, 200);
  const body = await response.json();
  assert(body.ok);
  assertEquals(typeof body.challenge, "string");
  assertEquals(typeof body.challengeToken, "string");
  assert(body.challenge.length >= 40);
  assert(body.challengeToken.includes("."));
});

Deno.test("unknown endpoint is rejected", async () => {
  const response = await handler(new Request("http://localhost/nope"));
  assertEquals(response.status, 404);
});

Deno.test("bind rejects untrusted client input", async () => {
  const response = await handler(
    new Request("http://localhost/api/phantom/attest/bind", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        challenge: "bad",
        challengeToken: "bad.bad",
        packageName: "example.invalid",
        signerDigest: "00".repeat(32),
        certChain: [],
      }),
    }),
  );
  assertEquals(response.status, 403);
  const body = await response.json();
  assertEquals(body.error, "attestation_rejected");
});
