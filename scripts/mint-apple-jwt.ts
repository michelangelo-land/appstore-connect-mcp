#!/usr/bin/env bun
/**
 * mint-apple-jwt.ts — signs the App Store Connect JWT LOCALLY with your .p8.
 * Your private key NEVER leaves your machine: it only runs here.
 *
 * Usage:
 *   export ASC_ISSUER_ID="..." ASC_KEY_ID="..."
 *   export ASC_PRIVATE_KEY="$(cat AuthKey_XXXX.p8)"   # or ASC_PRIVATE_KEY_FILE=./AuthKey_XXXX.p8
 *   bun run mint-jwt            # prints a JWT (15 min)
 *   bun run mint-jwt --export   # prints: export APPLE_JWT="..."
 *
 * Docs: https://developer.apple.com/documentation/appstoreconnectapi/generating-tokens-for-api-requests
 */
import { createSign, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

function base64url(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input) : input;
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function derToRawES256(der: Buffer): Buffer {
  let o = 0;
  if (der[o++] !== 0x30) throw new Error("DER: missing sequence");
  let seqLen = der[o++];
  if (seqLen & 0x80) {
    const n = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < n; i++) seqLen = (seqLen << 8) | der[o++];
  }
  if (der[o++] !== 0x02) throw new Error("DER: missing R");
  const rLen = der[o++];
  let r = der.subarray(o, o + rLen);
  o += rLen;
  if (der[o++] !== 0x02) throw new Error("DER: missing S");
  const sLen = der[o++];
  let s = der.subarray(o, o + sLen);
  const strip = (b: Buffer) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    return b.subarray(i);
  };
  r = strip(r);
  s = strip(s);
  if (r.length > 32 || s.length > 32) throw new Error("DER: R/S too long");
  const out = Buffer.alloc(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}

function getEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env ${name}.`);
  return v;
}

function normalizePrivateKey(raw: string): string {
  return (raw.includes("\\n") ? raw.replace(/\\n/g, "\n") : raw).trim();
}

function getPrivateKey(): string {
  if (process.env.ASC_PRIVATE_KEY) return normalizePrivateKey(process.env.ASC_PRIVATE_KEY);
  if (process.env.ASC_PRIVATE_KEY_FILE) return normalizePrivateKey(readFileSync(process.env.ASC_PRIVATE_KEY_FILE, "utf8"));
  throw new Error("Missing env ASC_PRIVATE_KEY or ASC_PRIVATE_KEY_FILE.");
}

const issuerId = getEnv("ASC_ISSUER_ID");
const keyId = getEnv("ASC_KEY_ID");
const privateKey = getPrivateKey();

const now = Math.floor(Date.now() / 1000);
const iat = now;
const exp = iat + 15 * 60; // Apple max is 20, keep a skew margin
const header = base64url(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JWT" }));
const payload = base64url(JSON.stringify({ iss: issuerId, iat, exp, aud: "appstoreconnect-v1", jti: randomUUID() }));
const data = `${header}.${payload}`;
const signer = createSign("SHA256");
signer.update(data);
signer.end();
const jwt = `${data}.${base64url(derToRawES256(signer.sign(privateKey)))}`;

if (process.argv.includes("--export")) {
  console.log(`export APPLE_JWT="${jwt}"`);
  console.error(`# valid until ${new Date(exp * 1000).toISOString()} (kid ${keyId})`);
} else {
  console.log(jwt);
  console.error(`# kid=${keyId} exp=${new Date(exp * 1000).toISOString()}`);
  console.error(`# MCP usage: pass this value as the appleJwt argument of every tool`);
}
