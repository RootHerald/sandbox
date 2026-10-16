// Integration checks for the sandbox backend. Each group spawns `node server.js`
// against an in-process stub of the RootHerald API on loopback, and plays the
// device with the global WebCrypto, never Node's crypto module: customers copy this repo.

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";

const here = path.dirname(fileURLToPath(import.meta.url));
const subtle = globalThis.crypto.subtle;

const CANARY = `rh_sk_canary${hex(16)}`;
const UEID = globalThis.crypto.randomUUID();
const KEY_ID = globalThis.crypto.randomUUID();
const ENROLLMENT_ID = `enr_${hex(12)}`;
const NONCE = `nonce_${hex(12)}`;
const KEY_NONCE = `knonce_${hex(12)}`;
const CHALLENGE = `rhc1.${hex(24)}`;
const KEY_CHALLENGE = `rhk1c.${hex(24)}`;
const DASH = "—";

const ENROLL_BEGIN = {
  platform: "linux",
  ekPublicKey: "AAEAC0AA",
  attestationKey: { publicArea: "AAEACw", parentPublicArea: "AAEACx", qualifiedName: "AAtQ" },
};
const EVIDENCE = { platform: "linux", quote: "AQID", signature: "BAUG", pcrs: "BwgJ" };
const CERTIFICATION = { publicArea: "AAEAAQ", attest: "/1RDR4AX", signature: "ABQACw" };

const ROUTES = [
  "/enroll/begin",
  "/enroll/complete",
  "/attest/challenge",
  "/attest/verify",
  "/sign/challenge",
  "/sign/certify",
  "/sign/verify",
  "/decrypt/challenge",
  "/decrypt/certify",
  "/decrypt/verify",
];
const CALLS_ROOTHERALD = ROUTES.filter((r) => !r.endsWith("/verify") || r === "/attest/verify");

// Everything any backend wrote or answered, for the secrecy checks.
const seen = { logs: [], bodies: [], sse: [] };

function hex(bytes) {
  return Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(bytes))).toString("hex");
}

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function pinnedNodeVersion() {
  const pkg = JSON.parse(readFileSync(path.join(here, "package.json"), "utf8"));
  return pkg.dependencies["@rootherald/node"];
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.unref();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

// ---------------------------------------------------------------- stub API

function verdictBody(device = {}, extra = {}) {
  const now = new Date();
  return {
    verdict: {
      acr: "urn:rootherald:acr:hardware",
      amr: ["hwk"],
      authTime: now.toISOString(),
      expiresAt: new Date(now.getTime() + 300_000).toISOString(),
      requestedAcrValues: [],
      device: {
        ueid: UEID,
        earStatus: "affirming",
        verdict: "pass",
        attestationType: "tpm",
        attestedAt: now.toISOString(),
        platform: "linux",
        tpmKind: "discrete-tpm",
        hardwareGenuine: true,
        ekChainTrusted: true,
        ...device,
      },
    },
    ...extra,
  };
}

function defaultHandlers(stub) {
  return {
    "/api/v1/attest/enroll": () => ({
      status: 201,
      body: { enrollmentId: ENROLLMENT_ID, credentialBlob: "Y3JlZA", encryptedSecret: "c2Vj" },
    }),
    "/api/v1/attest/activate": () => ({
      status: 200,
      body: { deviceId: UEID, status: "active", enrolledAt: new Date().toISOString() },
    }),
    "/api/v1/attest/challenge": () => ({
      status: 200,
      body: { nonce: NONCE, expiresAt: new Date(Date.now() + 300_000).toISOString(), challenge: CHALLENGE },
    }),
    "/api/v1/attest/verify": () => ({ status: 200, body: verdictBody(stub.device) }),
    "/api/v1/keys/challenge": () => ({
      status: 200,
      body: { nonce: KEY_NONCE, keyChallenge: KEY_CHALLENGE, expiresAt: new Date(Date.now() + 300_000).toISOString() },
    }),
    "/api/v1/keys/certify": () => {
      const k = stub.key;
      if (!k) return { status: 500, body: { error: "test_has_no_key" } };
      const body = {
        deviceId: UEID,
        keyId: KEY_ID,
        purpose: k.purpose,
        alg: k.alg,
        jwk: k.jwk,
        hardwareBound: k.hardwareBound ?? true,
        certifiedAt: new Date().toISOString(),
      };
      if (k.format) body.format = k.format;
      return { status: 200, body };
    },
  };
}

async function startStub() {
  const stub = {
    requests: [],
    overrides: new Map(),
    device: {},
    key: undefined,
    url: "",
    on(p, fn) {
      this.overrides.set(p, fn);
    },
    reset() {
      this.overrides.clear();
      this.device = {};
      this.key = undefined;
    },
    calls(p) {
      return this.requests.filter((r) => r.path === p);
    },
    last(p) {
      const all = this.calls(p);
      return all[all.length - 1];
    },
  };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      stub.requests.push({ path: req.url, headers: req.headers, body });
      const handler = stub.overrides.get(req.url) ?? defaultHandlers(stub)[req.url];
      const out = handler ? handler(body) : { status: 404, body: { error: "not_found" } };
      res.writeHead(out.status, { "content-type": "application/json", ...(out.headers ?? {}) });
      res.end(typeof out.body === "string" ? out.body : JSON.stringify(out.body));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  stub.url = `http://127.0.0.1:${server.address().port}`;
  stub.close = () => new Promise((r) => server.close(r));
  return stub;
}

// ---------------------------------------------------------------- backend

async function startBackend({ key = CANARY, url, port, env: extra = {} } = {}) {
  port ??= await freePort();
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/^(ROOTHERALD_|SANDBOX_)/i.test(k)) delete env[k];
  Object.assign(env, { ROOTHERALD_SECRET_KEY: key, ROOTHERALD_URL: url, SANDBOX_PORT: String(port) }, extra);

  const child = spawn(process.execPath, ["server.js"], { cwd: here, env, stdio: ["ignore", "pipe", "pipe"] });
  const out = { text: "" };
  let exited = null;
  child.stdout.on("data", (d) => (out.text += d.toString("utf8")));
  child.stderr.on("data", (d) => (out.text += d.toString("utf8")));
  child.on("exit", (code, signal) => (exited = { code, signal }));

  const host = `localhost:${port}`;
  const deadline = Date.now() + 15_000;
  for (;;) {
    if (exited) {
      throw new Error(`server.js exited (${JSON.stringify(exited)}) before answering:\n${out.text}`);
    }
    try {
      await request(port, "GET", "/", { headers: { Host: host } });
      break;
    } catch {
      if (Date.now() > deadline) throw new Error(`server.js never answered on 127.0.0.1:${port}:\n${out.text}`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  return {
    port,
    host,
    child,
    get logs() {
      return out.text;
    },
    get alive() {
      return exited === null;
    },
    post(route, body = {}, headers = {}) {
      return request(port, "POST", route, {
        headers: { Host: host, "Content-Type": "application/json", ...headers },
        body: typeof body === "string" ? body : JSON.stringify(body),
      });
    },
    get(route, headers = {}) {
      return request(port, "GET", route, { headers: { Host: host, ...headers } });
    },
    async stop() {
      seen.logs.push(out.text);
      if (exited) return;
      const done = new Promise((r) => child.once("exit", r));
      child.kill();
      await done;
    },
  };
}

function request(port, method, route, { headers = {}, body, address = "127.0.0.1" } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const req = http.request(
      { host: address, port, method, path: route, headers, setHost: false, agent: false, timeout: 10_000 },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          seen.bodies.push(text);
          let json;
          try {
            json = JSON.parse(text);
          } catch {
            json = undefined;
          }
          settled = true;
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
        res.on("error", (e) => !settled && reject(e));
      },
    );
    req.on("error", (e) => {
      if (!settled) reject(e);
    });
    req.on("timeout", () => req.destroy(new Error(`no answer from ${address}:${port}`)));
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function openEvents(backend) {
  const stream = { text: "", events: [], status: 0, headers: {} };
  const req = http.request(
    {
      host: "127.0.0.1",
      port: backend.port,
      method: "GET",
      path: "/events",
      headers: { Host: backend.host, Accept: "text/event-stream" },
      setHost: false,
      agent: false,
    },
    (res) => {
      stream.status = res.statusCode;
      stream.headers = res.headers;
      let buf = "";
      res.on("data", (d) => {
        const s = d.toString("utf8");
        stream.text += s;
        buf += s;
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const data = block
            .split("\n")
            .filter((l) => l.startsWith("data:"))
            .map((l) => l.slice(5).replace(/^ /, ""))
            .join("\n");
          if (data) stream.events.push(JSON.parse(data));
        }
      });
      res.on("error", () => {});
    },
  );
  req.on("error", () => {});
  req.end();
  stream.close = () => {
    seen.sse.push(stream.text);
    req.destroy();
  };
  stream.waitFor = async (pred, ms = 5000) => {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      if (pred(stream.events)) return stream.events;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.fail(`timed out waiting on /events; got ${stream.events.length} events`);
  };
  stream.settle = async (quietMs = 600, maxMs = 8000) => {
    const deadline = Date.now() + maxMs;
    let last = -1;
    let quietSince = Date.now();
    while (Date.now() < deadline) {
      if (stream.events.length !== last) {
        last = stream.events.length;
        quietSince = Date.now();
      } else if (Date.now() - quietSince >= quietMs) {
        return stream.events;
      }
      await new Promise((r) => setTimeout(r, 25));
    }
    return stream.events;
  };
  return stream;
}

// ---------------------------------------------------------------- the device

async function es256Key() {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const { kty, crv, x, y } = await subtle.exportKey("jwk", pair.publicKey);
  return {
    jwk: { kty, crv, x, y },
    alg: "ES256",
    sign: async (text) =>
      b64url(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, Buffer.from(text, "utf8"))),
  };
}

async function rs256Key() {
  const pair = await subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const { kty, n, e } = await subtle.exportKey("jwk", pair.publicKey);
  return {
    jwk: { kty, n, e },
    alg: "RS256",
    sign: async (text) =>
      b64url(await subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, pair.privateKey, Buffer.from(text, "utf8"))),
  };
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
}

// ECDH-ES + A256GCM JWE (RFC 7516 / 7518 §4.6), opened the way the device's Decrypt does.
async function ecdhKey() {
  const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const { kty, crv, x, y } = await subtle.exportKey("jwk", pair.publicKey);
  return {
    jwk: { kty, crv, x, y },
    alg: "ECDH-ES",
    format: "jwe",
    async open(jwe) {
      const [h, , iv, ct, tag] = jwe.split(".");
      const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
      assert.equal(header.alg, "ECDH-ES");
      assert.equal(header.enc, "A256GCM");
      const epk = await subtle.importKey(
        "jwk",
        { kty: "EC", crv: "P-256", x: header.epk.x, y: header.epk.y },
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
      );
      const z = Buffer.from(await subtle.deriveBits({ name: "ECDH", public: epk }, pair.privateKey, 256));
      const info = Buffer.concat([u32(7), Buffer.from("A256GCM", "ascii"), u32(0), u32(0), u32(256)]);
      const cek = Buffer.from(await subtle.digest("SHA-256", Buffer.concat([u32(1), z, info])));
      const aes = await subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["decrypt"]);
      const plain = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: Buffer.from(iv, "base64url"),
          additionalData: Buffer.from(h, "ascii"),
          tagLength: 128,
        },
        aes,
        Buffer.concat([Buffer.from(ct, "base64url"), Buffer.from(tag, "base64url")]),
      );
      return Buffer.from(plain);
    },
  };
}

// ---------------------------------------------------------------- helpers

function assertRefusal(res, { status, error, message }) {
  assert.equal(res.status, status, res.text);
  assert.equal(res.json?.error, error, res.text);
  assert.equal(res.json?.result, `RootHerald refused: ${error}`, res.text);
  if (message !== undefined) assert.equal(res.json?.message, message, res.text);
}

function assertFlatStrings(res) {
  assert.match(String(res.headers["content-type"]), /^application\/json/, `${res.status} ${res.text}`);
  assert.ok(res.json && typeof res.json === "object" && !Array.isArray(res.json), res.text);
  assert.equal(typeof res.json.result, "string", res.text);
  for (const [k, v] of Object.entries(res.json)) assert.equal(typeof v, "string", `field ${k} in ${res.text}`);
}

function assertNoDeviceIds(text) {
  for (const id of [UEID, KEY_ID]) {
    assert.ok(!text.toLowerCase().includes(id.toLowerCase()), `response carries ${id}: ${text}`);
  }
}

async function attest(backend, stub, device = {}) {
  stub.device = device;
  const c = await backend.post("/attest/challenge", {});
  assert.equal(c.status, 200, c.text);
  return backend.post("/attest/verify", EVIDENCE);
}

async function certify(backend, stub, route, key) {
  stub.key = key;
  const c = await backend.post(`/${route}/challenge`, {});
  assert.equal(c.status, 200, c.text);
  return backend.post(`/${route}/certify`, CERTIFICATION);
}

function lines(text) {
  return text.split(/\r?\n/);
}

// ================================================================ serve mode
//
// CI runs this file as the RootHerald API for the C client on swtpm:
//   SANDBOX_STUB_PORT=<port> SANDBOX_STUB_STATE=<file> node backend/server.test.js
// The backend's key picks what the stub does: rh_sk_stub_refuse refuses
// enrollment, _refuse_activation refuses it at activation, _allow admits the
// device as a software TPM, _block fails its verdict, _unenrolled answers every
// verify with enrollmentRequired.
// MakeCredential runs in tpm2_makecredential, so swtpm's ActivateCredential is
// the check on the enrollment crypto; the sign and decrypt checks are sdk-js's.

const STUB_POLICIES = ["refuse", "refuse_activation", "allow", "block", "unenrolled"];
const TPM_ST_ATTEST_CERTIFY = 0x8017;
const TPM_ST_ATTEST_QUOTE = 0x8018;
const TPM_ALG_RSA = 0x0001;
const TPM_ALG_ECC = 0x0023;
const TPM_ALG_NULL = 0x0010;
const TPM_ECC_NIST_P256 = 0x0003;

// TPM2B fields arrive with their size prefix; the stub compares the bytes inside.
function readTpm2b(buf, offset) {
  const size = buf.readUInt16BE(offset);
  return { bytes: buf.subarray(offset + 2, offset + 2 + size), next: offset + 2 + size };
}

// TPMS_ATTEST: magic, type, qualifiedSigner, extraData, clockInfo (17 bytes),
// firmwareVersion (8 bytes), then the attested union.
function parseAttest(b64) {
  const buf = Buffer.from(b64, "base64");
  if (buf.readUInt32BE(0) !== 0xff544347) throw new Error("TPMS_ATTEST magic");
  const type = buf.readUInt16BE(4);
  const signer = readTpm2b(buf, 6);
  const extra = readTpm2b(buf, signer.next);
  const attested = extra.next + 17 + 8;
  const certifiedName = type === TPM_ST_ATTEST_CERTIFY ? readTpm2b(buf, attested).bytes : undefined;
  return { type, signer: signer.bytes.toString("hex"), extraData: extra.bytes, certifiedName };
}

async function tpmName(publicArea) {
  const area = readTpm2b(publicArea, 0).bytes;
  const digest = Buffer.from(await subtle.digest("SHA-256", area));
  return Buffer.concat([area.subarray(2, 4), digest]);
}

// TPMT_PUBLIC to a JWK: type, nameAlg, objectAttributes, authPolicy, then the
// parameters (symmetric, scheme, then curve and kdf or keyBits and exponent)
// and the unique field.
function publicAreaJwk(publicArea) {
  const area = readTpm2b(publicArea, 0).bytes;
  const type = area.readUInt16BE(0);
  let offset = readTpm2b(area, 8).next;
  if (area.readUInt16BE(offset) !== TPM_ALG_NULL) offset += 4;
  offset += 2;
  if (area.readUInt16BE(offset) !== TPM_ALG_NULL) offset += 2;
  offset += 2;

  if (type === TPM_ALG_ECC) {
    if (area.readUInt16BE(offset) !== TPM_ECC_NIST_P256) throw new Error("curve is not P-256");
    offset += 2;
    if (area.readUInt16BE(offset) !== TPM_ALG_NULL) offset += 2;
    offset += 2;
    const x = readTpm2b(area, offset);
    const y = readTpm2b(area, x.next);
    const coordinate = (bytes) => b64url(Buffer.concat([Buffer.alloc(32 - bytes.length), bytes]));
    return { kty: "EC", crv: "P-256", x: coordinate(x.bytes), y: coordinate(y.bytes) };
  }
  if (type === TPM_ALG_RSA) {
    const exponent = area.readUInt32BE(offset + 2) || 65537;
    const n = readTpm2b(area, offset + 6).bytes;
    return { kty: "RSA", n: b64url(n), e: b64url(Buffer.from(exponent.toString(16).padStart(6, "0"), "hex")) };
  }
  throw new Error(`public area type ${type}`);
}

async function stableUuid(bytes) {
  const h = Buffer.from(await subtle.digest("SHA-256", bytes)).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

// tpm2_makecredential writes 0xBADCC0DE, a version, then the TPM2B_ID_OBJECT
// and TPM2B_ENCRYPTED_SECRET the client feeds to ActivateCredential as they are.
function makeCredential(ekPublicArea, akName, secret) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "rh-stub-"));
  try {
    writeFileSync(path.join(dir, "ek.pub"), ekPublicArea);
    writeFileSync(path.join(dir, "secret"), secret);
    execFileSync("tpm2_makecredential", [
      "-T", "none",
      "-u", path.join(dir, "ek.pub"),
      "-s", path.join(dir, "secret"),
      "-n", akName.toString("hex"),
      "-o", path.join(dir, "credential"),
    ], { stdio: ["ignore", "ignore", "inherit"] });
    const out = readFileSync(path.join(dir, "credential"));
    if (out.readUInt32BE(0) !== 0xbadcc0de) throw new Error("tpm2_makecredential output header");
    const blob = readTpm2b(out, 8);
    const encrypted = readTpm2b(out, blob.next);
    return {
      credentialBlob: out.subarray(8, blob.next).toString("base64"),
      encryptedSecret: out.subarray(blob.next, encrypted.next).toString("base64"),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function softwareTpm(ueid) {
  return { ueid, platform: "linux", tpmKind: "emulated", hardwareGenuine: false, ekChainTrusted: false };
}

async function serveStub(port, stateFile) {
  // Installations survive a restart through the state file; challenges and
  // enrollments in flight do not, as on a real server restart.
  let installations = {};
  if (stateFile && existsSync(stateFile)) installations = JSON.parse(readFileSync(stateFile, "utf8")).installations;
  const enrollments = new Map();
  const keyChallenges = new Map();
  let challengeNonce;

  function saveInstallations() {
    if (stateFile) writeFileSync(stateFile, JSON.stringify({ installations }));
  }

  async function answer(route, policy, body) {
    if (route === "/api/v1/attest/enroll") {
      if (policy === "refuse") {
        return { status: 400, body: { error: "ek_chain_rejected", message: "EK certificate chain did not reach a trusted root" } };
      }
      const ekPublicArea = Buffer.from(body.ekPublicKey, "base64");
      const akPublicArea = Buffer.from(body.attestationKey.publicArea, "base64");
      const qualifiedName = readTpm2b(Buffer.from(body.attestationKey.qualifiedName, "base64"), 0).bytes;
      const secret = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32)));
      const credential = makeCredential(ekPublicArea, await tpmName(akPublicArea), secret);
      const enrollmentId = `enr_${hex(12)}`;
      enrollments.set(enrollmentId, { secret, ekPublicArea, signer: qualifiedName.toString("hex") });
      return { status: 201, body: { enrollmentId, ...credential } };
    }

    if (route === "/api/v1/attest/activate") {
      const pending = enrollments.get(body.enrollmentId);
      enrollments.delete(body.enrollmentId);
      if (!pending || !Buffer.from(body.decryptedSecret ?? "", "base64").equals(pending.secret)) {
        return { status: 400, body: { error: "activation_failed", message: "the enrollment could not be activated" } };
      }
      if (policy === "refuse_activation") {
        return { status: 403, body: { error: "activation_refused", message: "the device is not admitted" } };
      }
      const deviceId = await stableUuid(pending.ekPublicArea);
      installations[pending.signer] = deviceId;
      saveInstallations();
      console.log(`stub deviceId ${deviceId}`);
      return { status: 200, body: { deviceId, status: "active", enrolledAt: new Date().toISOString() } };
    }

    if (route === "/api/v1/attest/challenge") {
      challengeNonce = randomNonce();
      const ask = b64url(Buffer.from(JSON.stringify({ ask: ["identity", "posture"] })));
      return {
        status: 200,
        body: { nonce: challengeNonce, challenge: `rhc1.${challengeNonce}.${ask}`, expiresAt: new Date(Date.now() + 300_000).toISOString() },
      };
    }

    if (route === "/api/v1/attest/verify") {
      const issued = challengeNonce;
      challengeNonce = undefined;
      const quote = parseAttest(body.evidence?.quote?.quoted ?? "");
      if (!issued || body.nonce !== issued || quote.type !== TPM_ST_ATTEST_QUOTE || !quote.extraData.equals(Buffer.from(issued, "base64url"))) {
        return { status: 400, body: { error: "challenge_mismatch", message: "the quote is not over the last challenge" } };
      }
      const ueid = installations[quote.signer];
      if (!ueid || policy === "unenrolled") {
        return { status: 200, body: verdictBody({ ...softwareTpm(undefined), verdict: "fail", earStatus: "contraindicated" }, { enrollmentRequired: true }) };
      }
      if (policy === "block") {
        return { status: 200, body: verdictBody({ ...softwareTpm(ueid), verdict: "fail", earStatus: "contraindicated" }) };
      }
      return { status: 200, body: verdictBody({ ...softwareTpm(ueid), verdict: "warn", earStatus: "warning" }) };
    }

    if (route === "/api/v1/keys/challenge") {
      const nonce = randomNonce();
      keyChallenges.set(nonce, body.purpose);
      const purpose = b64url(Buffer.from(JSON.stringify({ purpose: body.purpose })));
      return {
        status: 200,
        body: { nonce, keyChallenge: `rhk1c.${nonce}.${purpose}`, expiresAt: new Date(Date.now() + 300_000).toISOString() },
      };
    }

    if (route === "/api/v1/keys/certify") {
      const purpose = keyChallenges.get(body.nonce);
      keyChallenges.delete(body.nonce);
      const publicArea = Buffer.from(body.certification.publicArea, "base64");
      const attest = parseAttest(body.certification.attest);
      const deviceId = installations[attest.signer];
      if (
        !purpose ||
        !deviceId ||
        attest.type !== TPM_ST_ATTEST_CERTIFY ||
        !attest.extraData.equals(Buffer.from(body.nonce, "base64url")) ||
        !attest.certifiedName.equals(await tpmName(publicArea))
      ) {
        return { status: 400, body: { error: "certification_rejected", message: "the certification does not answer the key challenge" } };
      }
      const jwk = publicAreaJwk(publicArea);
      const alg = { "sign EC": "ES256", "sign RSA": "RS256", "decrypt EC": "ECDH-ES", "decrypt RSA": "RSA-OAEP-256" }[`${purpose} ${jwk.kty}`];
      return {
        status: 200,
        body: {
          deviceId,
          keyId: await stableUuid(Buffer.from(`${deviceId} ${purpose}`)),
          purpose,
          alg,
          ...(purpose === "decrypt" ? { format: "jwe" } : {}),
          jwk,
          hardwareBound: false,
          certifiedAt: new Date().toISOString(),
        },
      };
    }

    return { status: 404, body: { error: "not_found" } };
  }

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const key = String(req.headers.authorization ?? "").replace(/^Bearer rh_sk_stub_/, "");
      let out;
      if (!STUB_POLICIES.includes(key)) {
        out = { status: 401, body: { error: "invalid_secret_key", message: "not a stub key" } };
      } else {
        try {
          out = await answer(req.url, key, JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch (err) {
          console.log(`stub error ${err instanceof Error ? err.message : String(err)}`);
          out = { status: 400, body: { error: "malformed", message: "the stub could not read the request" } };
        }
      }
      console.log(`stub ${req.url} ${out.status}`);
      res.writeHead(out.status, { "content-type": "application/json" });
      res.end(JSON.stringify(out.body));
    });
  });

  await new Promise((r) => server.listen(port, "127.0.0.1", r));
  console.log(`stub ready on http://127.0.0.1:${port}`);
  await new Promise((r) => process.once("SIGTERM", r));
  server.close();
}

function randomNonce() {
  return b64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

// Holding the module here keeps node:test from registering the groups below.
if (process.env.SANDBOX_STUB_PORT) {
  await serveStub(Number(process.env.SANDBOX_STUB_PORT), process.env.SANDBOX_STUB_STATE);
  process.exit(0);
}

// ================================================================ startup

describe("startup", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  it("logs the pinned @rootherald/node version, the RootHerald URL and the local page", () => {
    const version = pinnedNodeVersion();
    assert.match(version, /^\d/, "the pin is exact");
    assert.ok(backend.logs.includes(`@rootherald/node ${version}`), backend.logs);
    assert.ok(backend.logs.includes(stub.url), backend.logs);
    assert.ok(backend.logs.includes(`http://localhost:${backend.port}/`), backend.logs);
  });

  it("never logs the key", () => {
    assert.ok(!backend.logs.includes(CANARY), backend.logs);
  });

  it("serves the page with the exact CSP and a live EventSource", async () => {
    const res = await backend.get("/");
    assert.equal(res.status, 200);
    assert.match(String(res.headers["content-type"]), /^text\/html/);
    assert.equal(
      res.headers["content-security-policy"],
      "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
    );
    assert.match(res.text, /EventSource\(\s*['"`]\/events['"`]\s*\)/);
    for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"]) {
      assert.ok(!res.text.includes(sink), `page uses ${sink}`);
    }
  });
});

// ================================================================ guard

describe("guard", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  const everyRoute = [...ROUTES.map((r) => ["POST", r]), ["GET", "/"], ["GET", "/events"]];
  const send = (method, route, headers) =>
    request(backend.port, method, route, {
      headers: { "Content-Type": "application/json", ...headers },
      body: method === "POST" ? "{}" : undefined,
    });

  it("refuses a Host that is not localhost or 127.0.0.1 with the port, on every route", async () => {
    for (const host of [`evil.test:${backend.port}`, "localhost", "127.0.0.1", `0.0.0.0:${backend.port}`, `localhost:${backend.port + 1}`]) {
      for (const [method, route] of everyRoute) {
        const res = await send(method, route, { Host: host });
        assert.equal(res.status, 403, `${method} ${route} Host ${host}: ${res.status} ${res.text}`);
        assert.match(res.text, /host/i, `${method} ${route}: refusal names Host`);
      }
    }
  });

  it("refuses a foreign Origin, on every route", async () => {
    for (const origin of ["http://evil.test", `http://evil.test:${backend.port}`, "null", `https://localhost:${backend.port}`]) {
      for (const [method, route] of everyRoute) {
        const res = await send(method, route, { Host: backend.host, Origin: origin });
        assert.equal(res.status, 403, `${method} ${route} Origin ${origin}: ${res.status} ${res.text}`);
        assert.match(res.text, /origin/i, `${method} ${route}: refusal names Origin`);
      }
    }
  });

  it("refuses Sec-Fetch-Site cross-site and same-site, on every route", async () => {
    for (const site of ["cross-site", "same-site"]) {
      for (const [method, route] of everyRoute) {
        const res = await send(method, route, { Host: backend.host, "Sec-Fetch-Site": site });
        assert.equal(res.status, 403, `${method} ${route} Sec-Fetch-Site ${site}: ${res.status} ${res.text}`);
        assert.match(res.text, /sec-fetch-site/i, `${method} ${route}: refusal names Sec-Fetch-Site`);
      }
    }
  });

  it("let no refused request reach RootHerald", () => {
    assert.equal(stub.requests.length, 0, JSON.stringify(stub.requests.map((r) => r.path)));
  });

  it("answers OPTIONS with 405 and never sends an Access-Control header", async () => {
    for (const route of ROUTES) {
      const res = await send("OPTIONS", route, {
        Host: backend.host,
        Origin: "http://evil.test",
        "Access-Control-Request-Method": "POST",
      });
      assert.ok(res.status === 405 || res.status === 403, `OPTIONS ${route}: ${res.status}`);
      const plain = await send("OPTIONS", route, { Host: backend.host });
      assert.equal(plain.status, 405, `OPTIONS ${route}: ${plain.status} ${plain.text}`);
      for (const r of [res, plain]) {
        assert.deepEqual(Object.keys(r.headers).filter((h) => h.startsWith("access-control-")), []);
      }
    }
  });

  it("accepts same-origin requests from its own page", async () => {
    for (const origin of [`http://localhost:${backend.port}`, `http://127.0.0.1:${backend.port}`]) {
      const res = await backend.post("/attest/challenge", {}, { Origin: origin, "Sec-Fetch-Site": "same-origin" });
      assert.equal(res.status, 200, res.text);
      assert.deepEqual(Object.keys(res.headers).filter((h) => h.startsWith("access-control-")), []);
    }
    const page = await request(backend.port, "GET", "/", {
      headers: { Host: `127.0.0.1:${backend.port}`, "Sec-Fetch-Site": "none" },
    });
    assert.equal(page.status, 200);
    assert.deepEqual(Object.keys(page.headers).filter((h) => h.startsWith("access-control-")), []);
  });

  it("answers 413 to a body over 2 MiB", async () => {
    const body = `{"x":"${"a".repeat(2 * 1024 * 1024)}"}`;
    const res = await backend.post("/attest/verify", body);
    assert.equal(res.status, 413, res.text.slice(0, 200));
  });

  it("answers 400 to a body that is not JSON", async () => {
    for (const route of ROUTES) {
      const res = await backend.post(route, "this is not json");
      assert.equal(res.status, 400, `${route}: ${res.text}`);
      assert.equal(res.json?.result, "request body is not JSON", `${route}: ${res.text}`);
    }
  });
});

// ================================================================ full run (enroll, attest, sign, decrypt)

describe("flow", () => {
  let stub;
  let backend;
  let events;
  const responses = [];
  const post = async (route, body) => {
    const res = await backend.post(route, body);
    responses.push({ route, res });
    return res;
  };
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
    events = openEvents(backend);
  });
  after(async () => {
    events?.close();
    await backend?.stop();
    await stub?.close();
  });

  let enrollChallenge;
  let message;
  let jwe;
  let signKey;
  let decryptKey;

  it("enroll: relays EnrollBegin verbatim and returns the challenge", async () => {
    const res = await post("/enroll/begin", ENROLL_BEGIN);
    assert.equal(res.status, 200, res.text);
    assertFlatStrings(res);
    assert.equal(res.json.result, "enrollment started");
    assert.deepEqual(stub.last("/api/v1/attest/enroll").body, ENROLL_BEGIN);
    enrollChallenge = JSON.parse(res.json.enrollChallenge);
    assert.equal(enrollChallenge.enrollmentId, ENROLLMENT_ID);
    assert.equal(enrollChallenge.credentialBlob, "Y3JlZA");
    assert.equal(enrollChallenge.encryptedSecret, "c2Vj");
  });

  it("enroll: the enrollmentId round-trips into activate unchanged", async () => {
    const activation = { enrollmentId: enrollChallenge.enrollmentId, decryptedSecret: "ZGVjcnlwdGVk" };
    const res = await post("/enroll/complete", activation);
    assert.equal(res.status, 200, res.text);
    assertFlatStrings(res);
    assert.equal(res.json.result, "enrolled");
    assert.deepEqual(stub.last("/api/v1/attest/activate").body, activation);
    assert.equal(stub.last("/api/v1/attest/activate").body.enrollmentId, ENROLLMENT_ID);
  });

  it("attest: issues a challenge and verifies under its nonce", async () => {
    const c = await post("/attest/challenge", {});
    assert.equal(c.status, 200, c.text);
    assertFlatStrings(c);
    assert.equal(c.json.result, "challenge issued");
    assert.equal(c.json.challenge, CHALLENGE);

    const v = await post("/attest/verify", EVIDENCE);
    assert.equal(v.status, 200, v.text);
    assertFlatStrings(v);
    assert.equal(v.json.result, `pass ${DASH} Discrete chip`);
    const sent = stub.last("/api/v1/attest/verify").body;
    assert.equal(sent.nonce, NONCE);
    assert.deepEqual(sent.evidence, EVIDENCE);
  });

  it("attest: the console names the verdict, ueid and chip", () => {
    const re = new RegExp(
      `^verdict pass ueid=${UEID} tpmKind=discrete-tpm hardwareGenuine=true ekChainTrusted=true$`,
    );
    assert.ok(lines(backend.logs).some((l) => re.test(l)), backend.logs);
  });

  it("sign: asks for a sign key bound to the attested device", async () => {
    signKey = await es256Key();
    stub.key = { purpose: "sign", ...signKey };
    const c = await post("/sign/challenge", {});
    assert.equal(c.status, 200, c.text);
    assertFlatStrings(c);
    assert.equal(c.json.result, "key challenge issued");
    assert.equal(c.json.keyChallenge, KEY_CHALLENGE);
    assert.deepEqual(stub.last("/api/v1/keys/challenge").body, { purpose: "sign", expectedDevices: [UEID] });
  });

  it("sign: certifies the key and hands out a message", async () => {
    const res = await post("/sign/certify", CERTIFICATION);
    assert.equal(res.status, 200, res.text);
    assertFlatStrings(res);
    assert.equal(res.json.result, "sign key certified");
    assert.deepEqual(stub.last("/api/v1/keys/certify").body, { nonce: KEY_NONCE, certification: CERTIFICATION });
    message = res.json.message;
    assert.match(message, /^[A-Za-z0-9_-]{43}$/, "base64url of 32 random bytes");
    assert.ok(lines(backend.logs).includes("certify sign hardwareBound=true"), backend.logs);
  });

  it("sign: verifies the device's signature over the message", async () => {
    const res = await post("/sign/verify", { signature: await signKey.sign(message) });
    assert.equal(res.status, 200, res.text);
    assertFlatStrings(res);
    assert.equal(res.json.result, "signature verified");
  });

  it("decrypt: asks for a decrypt key bound to the attested device", async () => {
    decryptKey = await ecdhKey();
    stub.key = { purpose: "decrypt", alg: decryptKey.alg, format: decryptKey.format, jwk: decryptKey.jwk };
    const c = await post("/decrypt/challenge", {});
    assert.equal(c.status, 200, c.text);
    assertFlatStrings(c);
    assert.equal(c.json.result, "key challenge issued");
    assert.deepEqual(stub.last("/api/v1/keys/challenge").body, { purpose: "decrypt", expectedDevices: [UEID] });
  });

  it("decrypt: certifies the key and encrypts a secret to it", async () => {
    const res = await post("/decrypt/certify", CERTIFICATION);
    assert.equal(res.status, 200, res.text);
    assertFlatStrings(res);
    assert.equal(res.json.result, "decrypt key certified");
    jwe = res.json.jwe;
    assert.equal(jwe.split(".").length, 5, "JWE compact serialization");
    assert.ok(lines(backend.logs).includes("certify decrypt hardwareBound=true"), backend.logs);
  });

  it("decrypt: the device recovers the secret", async () => {
    const secret = await decryptKey.open(jwe);
    assert.equal(secret.length, 32);
    const res = await post("/decrypt/verify", { plaintext: b64url(secret) });
    assert.equal(res.status, 200, res.text);
    assertFlatStrings(res);
    assert.equal(res.json.result, "secret recovered");
  });

  it("wire 7.0: no response to the client carries the ueid, deviceId or keyId", () => {
    assert.equal(responses.length, 10);
    for (const { route, res } of responses) {
      assertNoDeviceIds(`${route} ${res.text}`);
    }
  });

  it("the page's stream saw every call with the verdict's ueid and chip words", async () => {
    const evs = await events.waitFor(
      (e) => e.some((x) => x.verdict) && e.filter((x) => ROUTES.some((r) => String(x.route).includes(r))).length >= 10,
    );
    for (const ev of evs) {
      for (const field of ["run", "group", "route", "status"]) assert.ok(field in ev, `event lacks ${field}`);
    }
    const verdict = evs.find((e) => e.verdict);
    assert.ok(verdict, "a verdict event");
    assert.equal(verdict.verdict.ueid, UEID);
    assert.equal(verdict.verdict.tpmKind, "Discrete chip");
    assert.equal(verdict.verdict.hardwareGenuine, true);
    assert.equal(verdict.verdict.ekChainTrusted, true);
    assert.ok(/pass/.test(String(verdict.verdict.outcome)));
    assert.ok(!/bearer|authorization/i.test(events.text), "an event carries a header");
  });
});

// ================================================================ attest verdict lines

describe("attest", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  it("maps every chip kind to its words", async () => {
    const words = {
      "discrete-tpm": "Discrete chip",
      "firmware-tpm": "Firmware TPM",
      "cloud-vtpm": "Cloud virtual TPM",
      emulated: "Software TPM",
      "mobile-hardware": "Phone hardware",
      "mobile-software": "Phone software key",
      unknown: "Unknown chip",
      "quantum-tpm": "Unknown chip",
    };
    for (const [kind, word] of Object.entries(words)) {
      const res = await attest(backend, stub, { tpmKind: kind });
      assert.equal(res.status, 200, res.text);
      assert.equal(res.json.result, `pass ${DASH} ${word}`, kind);
    }
  });

  it("says so when the hardware is not genuine or no maker vouches for the chip", async () => {
    const cases = [
      [{ hardwareGenuine: false }, `pass ${DASH} Discrete chip, not genuine hardware`],
      [{ ekChainTrusted: false }, `pass ${DASH} Discrete chip, no maker vouches for this chip`],
      [
        { tpmKind: "emulated", hardwareGenuine: false, ekChainTrusted: false },
        `pass ${DASH} Software TPM, not genuine hardware, no maker vouches for this chip`,
      ],
      [{ hardwareGenuine: undefined }, `pass ${DASH} Discrete chip, not genuine hardware`],
      [{ ekChainTrusted: undefined }, `pass ${DASH} Discrete chip, no maker vouches for this chip`],
      [{ verdict: "warn", earStatus: "warning" }, `warn ${DASH} Discrete chip`],
      [
        { verdict: "warn", earStatus: "warning", hardwareGenuine: false },
        `warn ${DASH} Discrete chip, not genuine hardware`,
      ],
    ];
    for (const [device, line] of cases) {
      const res = await attest(backend, stub, device);
      assert.equal(res.status, 200, res.text);
      assert.equal(res.json.result, line, JSON.stringify(device));
      assertNoDeviceIds(res.text);
    }
  });

  it("answers a failing verdict with 403 blocked", async () => {
    const res = await attest(backend, stub, { verdict: "fail", earStatus: "contraindicated" });
    assert.equal(res.status, 403, res.text);
    assert.equal(res.json.result, `blocked ${DASH} Discrete chip`);
    const soft = await attest(backend, stub, {
      verdict: "fail",
      earStatus: "contraindicated",
      tpmKind: "emulated",
      hardwareGenuine: false,
      ekChainTrusted: false,
    });
    assert.equal(soft.status, 403, soft.text);
    assert.equal(soft.json.result, `blocked ${DASH} Software TPM, not genuine hardware, no maker vouches for this chip`);
    assertNoDeviceIds(res.text + soft.text);
  });

  it("answers enrollmentRequired with 409 not enrolled", async () => {
    stub.on("/api/v1/attest/verify", () => ({
      status: 200,
      body: verdictBody({ verdict: "fail", earStatus: "contraindicated", ueid: undefined }, { enrollmentRequired: true }),
    }));
    try {
      const c = await backend.post("/attest/challenge", {});
      assert.equal(c.status, 200);
      const res = await backend.post("/attest/verify", EVIDENCE);
      assert.equal(res.status, 409, res.text);
      assert.equal(res.json.result, "not enrolled");
    } finally {
      stub.reset();
    }
  });

  it("prints one console verdict line per verify, in the fixed token form", () => {
    const re = /^verdict (pass|warn|fail) ueid=\S+ tpmKind=\S+ hardwareGenuine=(true|false) ekChainTrusted=(true|false)$/;
    const verdictLines = lines(backend.logs).filter((l) => l.startsWith("verdict "));
    assert.ok(verdictLines.length >= 17, `${verdictLines.length} verdict lines:\n${backend.logs}`);
    for (const l of verdictLines.filter((l) => !/ueid=not/.test(l))) assert.match(l, re);
    assert.ok(verdictLines.includes(`verdict fail ueid=${UEID} tpmKind=emulated hardwareGenuine=false ekChainTrusted=false`));
    assert.ok(verdictLines.includes(`verdict warn ueid=${UEID} tpmKind=discrete-tpm hardwareGenuine=false ekChainTrusted=true`));
    assert.ok(verdictLines.includes(`verdict pass ueid=${UEID} tpmKind=mobile-software hardwareGenuine=true ekChainTrusted=true`));
  });
});

// ================================================================ sign

describe("sign", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
    const v = await attest(backend, stub);
    assert.equal(v.status, 200, v.text);
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  for (const make of [es256Key, rs256Key]) {
    it(`verifies a good ${make.name === "es256Key" ? "ES256" : "RS256"} signature once, and refuses its replay`, async () => {
      const key = await make();
      const cert = await certify(backend, stub, "sign", { purpose: "sign", ...key });
      assert.equal(cert.status, 200, cert.text);
      const signature = await key.sign(cert.json.message);
      const ok = await backend.post("/sign/verify", { signature });
      assert.equal(ok.status, 200, ok.text);
      assert.equal(ok.json.result, "signature verified");
      const replay = await backend.post("/sign/verify", { signature });
      assert.ok(replay.status >= 400, `replay answered ${replay.status} ${replay.text}`);
      assert.notEqual(replay.json?.result, "signature verified");
    });
  }

  it("refuses a signature over a different message with 422", async () => {
    const key = await es256Key();
    const cert = await certify(backend, stub, "sign", { purpose: "sign", ...key });
    assert.equal(cert.status, 200, cert.text);
    const res = await backend.post("/sign/verify", { signature: await key.sign(`${cert.json.message}x`) });
    assert.equal(res.status, 422, res.text);
    assert.equal(res.json.result, "signature does not verify");
  });

  it("refuses a signature by a different key with 422", async () => {
    const key = await es256Key();
    const other = await es256Key();
    const cert = await certify(backend, stub, "sign", { purpose: "sign", ...key });
    const res = await backend.post("/sign/verify", { signature: await other.sign(cert.json.message) });
    assert.equal(res.status, 422, res.text);
    assert.equal(res.json.result, "signature does not verify");
  });

  it("hands out a fresh message per certify", async () => {
    const key = await es256Key();
    const a = await certify(backend, stub, "sign", { purpose: "sign", ...key });
    const b = await certify(backend, stub, "sign", { purpose: "sign", ...key });
    assert.notEqual(a.json.message, b.json.message);
  });

  it("says when the key is not hardware-bound", async () => {
    const key = await es256Key();
    const res = await certify(backend, stub, "sign", { purpose: "sign", ...key, hardwareBound: false });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.result, "sign key certified, not hardware-bound");
    assert.ok(lines(backend.logs).includes("certify sign hardwareBound=false"), backend.logs);
    assertNoDeviceIds(res.text);
  });

  it("prints certify lines in the fixed token form", () => {
    const certifyLines = lines(backend.logs).filter((l) => l.startsWith("certify "));
    assert.ok(certifyLines.length >= 6, backend.logs);
    for (const l of certifyLines) assert.match(l, /^certify (sign|decrypt) hardwareBound=(true|false)$/);
  });
});

// ================================================================ decrypt

describe("decrypt", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
    const v = await attest(backend, stub);
    assert.equal(v.status, 200, v.text);
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  async function freshSecret() {
    const key = await ecdhKey();
    const cert = await certify(backend, stub, "decrypt", {
      purpose: "decrypt",
      alg: key.alg,
      format: key.format,
      jwk: key.jwk,
    });
    assert.equal(cert.status, 200, cert.text);
    assert.equal(cert.json.result, "decrypt key certified");
    return key.open(cert.json.jwe);
  }

  it("accepts the recovered secret once, and refuses its replay", async () => {
    const secret = await freshSecret();
    const ok = await backend.post("/decrypt/verify", { plaintext: b64url(secret) });
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.json.result, "secret recovered");
    const replay = await backend.post("/decrypt/verify", { plaintext: b64url(secret) });
    assert.ok(replay.status >= 400, `replay answered ${replay.status} ${replay.text}`);
    assert.notEqual(replay.json?.result, "secret recovered");
  });

  it("refuses a wrong plaintext with 422", async () => {
    const secret = await freshSecret();
    const wrong = Buffer.from(secret);
    wrong[31] ^= 0x01;
    const res = await backend.post("/decrypt/verify", { plaintext: b64url(wrong) });
    assert.equal(res.status, 422, res.text);
    assert.equal(res.json.result, "wrong secret");
  });

  it("refuses a plaintext of the wrong length with 422, prefix or not", async () => {
    for (const cut of [(s) => s.subarray(0, 31), (s) => Buffer.concat([s, Buffer.from([0])])]) {
      const secret = await freshSecret();
      const res = await backend.post("/decrypt/verify", { plaintext: b64url(cut(secret)) });
      assert.equal(res.status, 422, res.text);
      assert.equal(res.json.result, "wrong secret");
      assert.ok(backend.alive, "the backend crashed");
    }
  });

  it("refuses a 30-byte prefix whose base64url is a prefix of the secret's", async () => {
    const secret = await freshSecret();
    const prefix = b64url(secret.subarray(0, 30));
    assert.ok(b64url(secret).startsWith(prefix));
    const res = await backend.post("/decrypt/verify", { plaintext: prefix });
    assert.equal(res.status, 422, res.text);
    assert.equal(res.json.result, "wrong secret");
    assert.ok(!res.text.includes(b64url(secret)), `the secret leaked: ${res.text}`);
  });

  it("refuses an empty, missing or non-string plaintext with 422, without leaking the secret", async () => {
    for (const body of [{ plaintext: "" }, {}, { plaintext: null }, { plaintext: 0 }, { plaintext: [] }]) {
      const secret = await freshSecret();
      const res = await backend.post("/decrypt/verify", body);
      assert.equal(res.status, 422, `${JSON.stringify(body)}: ${res.text}`);
      assert.equal(res.json.result, "wrong secret", JSON.stringify(body));
      assert.ok(!res.text.includes(b64url(secret)), `the secret leaked: ${res.text}`);
      assert.ok(backend.alive, "the backend crashed");
    }
  });

  it("encrypts a fresh secret per certify", async () => {
    const a = await freshSecret();
    const b = await freshSecret();
    assert.ok(!a.equals(b));
  });

  it("refuses a key it cannot encrypt to with 422 and the SDK's code", async () => {
    const key = await ecdhKey();
    const res = await certify(backend, stub, "decrypt", {
      purpose: "decrypt",
      alg: "ECDH-ES",
      format: "apple-ecies",
      jwk: key.jwk,
    });
    assert.equal(res.status, 422, res.text);
    assert.equal(res.json.result, "cannot encrypt to this key: APPLE_ECIES_KEY");
    assertNoDeviceIds(res.text);
  });

  it("says when the key is not hardware-bound", async () => {
    const key = await ecdhKey();
    const res = await certify(backend, stub, "decrypt", {
      purpose: "decrypt",
      alg: key.alg,
      format: key.format,
      jwk: key.jwk,
      hardwareBound: false,
    });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.result, "decrypt key certified, not hardware-bound");
    assert.ok(lines(backend.logs).includes("certify decrypt hardwareBound=false"), backend.logs);
  });
});

// ================================================================ refusals

describe("refusals", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  it("keeps RootHerald's status and relays error and message unchanged", async () => {
    const cases = [
      [400, "invalid_ask", "ask is not a known claim"],
      [422, "expected_unknown", "expectedDevices names a device this tenant does not hold"],
      [429, "rate_limited", "slow down"],
      [503, "unavailable", "try later"],
    ];
    for (const [status, error, message] of cases) {
      stub.on("/api/v1/attest/challenge", () => ({ status, body: { error, message } }));
      const res = await backend.post("/attest/challenge", {});
      assertFlatStrings(res);
      assertRefusal(res, { status, error, message });
    }
    stub.reset();
  });

  it("keeps a 409 from verify as a refusal, not a verdict", async () => {
    stub.on("/api/v1/attest/verify", () => ({
      status: 409,
      body: { error: "challenge_consumed", message: "the challenge was already answered" },
    }));
    const c = await backend.post("/attest/challenge", {});
    assert.equal(c.status, 200);
    const res = await backend.post("/attest/verify", EVIDENCE);
    assertRefusal(res, { status: 409, error: "challenge_consumed", message: "the challenge was already answered" });
    stub.reset();
  });

  it("relays a revoked key's 401 unchanged", async () => {
    stub.on("/api/v1/attest/challenge", () => ({
      status: 401,
      body: { error: "invalid_secret_key", message: "API key revoked" },
    }));
    const res = await backend.post("/attest/challenge", {});
    assertRefusal(res, { status: 401, error: "invalid_secret_key", message: "API key revoked" });
    stub.reset();
  });

  it("relays an ek_chain_rejected enrollment as the plain refusal", async () => {
    const message = "EK certificate chain did not reach a trusted root";
    stub.on("/api/v1/attest/enroll", () => ({ status: 400, body: { error: "ek_chain_rejected", message } }));
    const res = await backend.post("/enroll/begin", ENROLL_BEGIN);
    assertFlatStrings(res);
    assertRefusal(res, { status: 400, error: "ek_chain_rejected", message });
    stub.reset();
  });

  it("answers 502, never 2xx, when RootHerald's 2xx body is malformed", async () => {
    stub.on("/api/v1/attest/challenge", () => ({ status: 200, body: {} }));
    const res = await backend.post("/attest/challenge", {});
    assertRefusal(res, { status: 502, error: "INVALID_RESPONSE" });
    stub.on("/api/v1/attest/enroll", () => ({ status: 201, body: { unexpected: true } }));
    const enroll = await backend.post("/enroll/begin", ENROLL_BEGIN);
    assertRefusal(enroll, { status: 502, error: "INVALID_RESPONSE" });
    stub.reset();
  });

  it("answers 400 to an SDK input check, without calling RootHerald", async () => {
    const before = stub.requests.length;
    const res = await backend.post("/enroll/begin", {});
    assertRefusal(res, { status: 400, error: "INVALID_ENROLL_BLOB" });
    const act = await backend.post("/enroll/complete", { enrollmentId: "" });
    assertRefusal(act, { status: 400, error: "INVALID_ACTIVATION_BLOB" });
    assert.equal(stub.requests.length, before);
  });

  it("redacts device ids in a refusal message, and keeps them on the console", async () => {
    const alias = globalThis.crypto.randomUUID();
    const message = `expectedDevices alias ${alias} is not one of this tenant's devices; nor is ${KEY_ID}`;
    stub.on("/api/v1/attest/challenge", () => ({ status: 422, body: { error: "expected_unknown", message } }));
    const res = await backend.post("/attest/challenge", {});
    assertRefusal(res, {
      status: 422,
      error: "expected_unknown",
      message: "expectedDevices alias [device id] is not one of this tenant's devices; nor is [device id]",
    });
    assert.ok(!res.text.includes(alias));
    assert.ok(backend.logs.includes(alias), "the console keeps the alias");
    stub.reset();
  });

  it("sends the key to RootHerald as a Bearer token and nowhere else", () => {
    const auth = stub.requests.map((r) => r.headers.authorization);
    assert.ok(auth.length > 0);
    for (const a of auth) assert.equal(a, `Bearer ${CANARY}`);
  });
});

describe("refusals before RootHerald", () => {
  const stacks = [];
  after(async () => {
    for (const s of stacks) await s.stop();
  });

  it("answers 502 NETWORK_ERROR when RootHerald is unreachable", async () => {
    const dead = await freePort();
    const backend = await startBackend({ url: `http://127.0.0.1:${dead}` });
    stacks.push(backend);
    const res = await backend.post("/attest/challenge", {});
    assertRefusal(res, { status: 502, error: "NETWORK_ERROR" });
  });

  it("answers 500 INVALID_BASE_URL to a cleartext non-loopback URL", async () => {
    const backend = await startBackend({ url: "http://rootherald.invalid" });
    stacks.push(backend);
    const res = await backend.post("/attest/challenge", {});
    assertRefusal(res, { status: 500, error: "INVALID_BASE_URL" });
  });

  it("answers 401 INVALID_SECRET_KEY_FORMAT to a badly formatted key", async () => {
    const stub = await startStub();
    stacks.push({ stop: () => stub.close() });
    const backend = await startBackend({ key: "sk_live_notarootheraldkey", url: stub.url });
    stacks.push(backend);
    for (const route of CALLS_ROOTHERALD) {
      const res = await backend.post(route, {});
      assertRefusal(res, { status: 401, error: "INVALID_SECRET_KEY_FORMAT" });
    }
    assert.equal(stub.requests.length, 0);
    assert.ok(!backend.logs.includes("sk_live_notarootheraldkey"), backend.logs);
  });
});

// ================================================================ events

describe("events", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  it("is an event stream that pushes each call live, without a reconnect", async () => {
    const live = openEvents(backend);
    try {
      const n = (await live.settle(300)).length;
      const res = await backend.post("/attest/challenge", {});
      assert.equal(res.status, 200);
      const evs = await live.waitFor((e) => e.length > n);
      assert.equal(live.status, 200);
      assert.match(String(live.headers["content-type"]), /^text\/event-stream/);
      const ev = evs[evs.length - 1];
      assert.ok(String(ev.route).includes("/attest/challenge"), JSON.stringify(ev));
      assert.equal(Number(ev.status), 200);
    } finally {
      live.close();
    }
  });

  it("numbers runs: a new run on /enroll/begin, and on /attest/challenge after an attest", async () => {
    const live = openEvents(backend);
    try {
      const start = (await live.settle(300)).length;
      const steps = [
        ["/enroll/begin", ENROLL_BEGIN],
        ["/enroll/complete", { enrollmentId: ENROLLMENT_ID, decryptedSecret: "ZGVj" }],
        ["/attest/challenge", {}],
        ["/attest/verify", EVIDENCE],
        ["/attest/challenge", {}],
        ["/attest/verify", EVIDENCE],
        ["/enroll/begin", ENROLL_BEGIN],
      ];
      for (const [route, body] of steps) {
        const res = await backend.post(route, body);
        assert.ok(res.status < 300, `${route}: ${res.text}`);
      }
      const evs = (await live.waitFor((e) => e.length >= start + steps.length)).slice(start);
      const runs = evs.map((e) => Number(e.run));
      const [r] = runs;
      assert.deepEqual(runs, [r, r, r, r, r + 1, r + 1, r + 2], JSON.stringify(evs.map((e) => [e.route, e.run])));
      const verdicts = evs.filter((e) => e.verdict);
      assert.equal(verdicts.length, 2);
      for (const v of verdicts) {
        assert.equal(v.verdict.ueid, UEID, "two runs, one device, one ueid");
        assert.equal(v.verdict.tpmKind, "Discrete chip");
      }
    } finally {
      live.close();
    }
  });

  it("replays everything on connect, capped at 500", async () => {
    const first = openEvents(backend);
    const had = (await first.settle(300)).length;
    first.close();
    assert.ok(had >= 8, `a new connection replayed ${had} events`);

    for (let i = 0; i < 520; i += 20) {
      await Promise.all(Array.from({ length: 20 }, () => backend.post("/attest/challenge", {})));
    }
    const again = openEvents(backend);
    try {
      const evs = await again.settle(800, 15_000);
      assert.equal(evs.length, 500);
    } finally {
      again.close();
    }
  });
});

// ================================================================ no key

describe("nokey", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ key: "", url: stub.url });
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  it("starts, says once that the key is not set, and keeps serving", async () => {
    assert.ok(backend.alive);
    const notSet = lines(backend.logs).filter((l) => /not set/i.test(l));
    assert.equal(notSet.length, 1, backend.logs);
    assert.match(notSet[0], /ROOTHERALD_SECRET_KEY|key/i);
    const page = await backend.get("/");
    assert.equal(page.status, 200);
  });

  it("the local verify routes answer that attestation comes first", async () => {
    let res = await backend.post("/sign/verify", { signature: "AAAA" });
    assert.equal(res.status, 409, res.text);
    assert.equal(res.json.result, "attest first");
    res = await backend.post("/decrypt/verify", { plaintext: "AAAA" });
    assert.equal(res.status, 409, res.text);
    assert.equal(res.json.result, "attest first");
  });

  it("every route that calls RootHerald answers 401 MISSING_SECRET_KEY, run or no run", async () => {
    const bodies = {
      "/enroll/begin": ENROLL_BEGIN,
      "/enroll/complete": { enrollmentId: ENROLLMENT_ID, decryptedSecret: "ZGVj" },
      "/attest/verify": EVIDENCE,
      "/sign/certify": CERTIFICATION,
      "/decrypt/certify": CERTIFICATION,
    };
    for (const route of CALLS_ROOTHERALD) {
      const res = await backend.post(route, bodies[route] ?? {});
      assertFlatStrings(res);
      assertRefusal(res, { status: 401, error: "MISSING_SECRET_KEY" });
    }
    assert.equal(stub.requests.length, 0);
    assert.ok(backend.alive);
  });
});

describe("no run", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  it("with a key, the key routes and the local verify routes answer 409 attest first", async () => {
    for (const route of ["/sign/challenge", "/decrypt/challenge", "/sign/verify", "/decrypt/verify"]) {
      const body = route === "/sign/verify" ? { signature: "AAAA" } : route === "/decrypt/verify" ? { plaintext: "AAAA" } : {};
      const res = await backend.post(route, body);
      assert.equal(res.status, 409, `${route}: ${res.text}`);
      assert.equal(res.json.result, "attest first", route);
    }
    assert.equal(stub.calls("/api/v1/keys/challenge").length, 0);
  });
});

// ================================================================ blocked

describe("blocked", () => {
  let stub;
  let backend;
  before(async () => {
    stub = await startStub();
    backend = await startBackend({ url: stub.url });
  });
  after(async () => {
    await backend?.stop();
    await stub?.close();
  });

  async function assertKeyRoutesRefused(why) {
    const before = stub.calls("/api/v1/keys/challenge").length;
    for (const route of ["/sign/challenge", "/decrypt/challenge"]) {
      const res = await backend.post(route, {});
      assert.equal(res.status, 409, `${why}, ${route}: ${res.text}`);
      assert.equal(res.json.result, "attest first", `${why}, ${route}`);
    }
    assert.equal(stub.calls("/api/v1/keys/challenge").length, before, `${why}: a key challenge reached RootHerald`);
  }

  it("a blocked verdict on the first run keeps no ueid for the key routes", async () => {
    const res = await attest(backend, stub, { verdict: "fail", earStatus: "contraindicated" });
    assert.equal(res.status, 403, res.text);
    await assertKeyRoutesRefused("blocked on the first run");
  });

  it("a blocked verdict after a passing run keeps no ueid for the key routes", async () => {
    const pass = await attest(backend, stub);
    assert.equal(pass.status, 200, pass.text);
    const ok = await backend.post("/sign/challenge", {});
    assert.equal(ok.status, 200, ok.text);
    const res = await attest(backend, stub, { verdict: "fail", earStatus: "contraindicated" });
    assert.equal(res.status, 403, res.text);
    await assertKeyRoutesRefused("blocked after a pass");
  });

  it("an enrollmentRequired answer that names a ueid keeps no ueid for the key routes", async () => {
    stub.on("/api/v1/attest/verify", () => ({
      status: 200,
      body: verdictBody({ verdict: "fail", earStatus: "contraindicated" }, { enrollmentRequired: true }),
    }));
    try {
      const res = await attest(backend, stub);
      assert.equal(res.status, 409, res.text);
      assert.equal(res.json.result, "not enrolled");
      await assertKeyRoutesRefused("not enrolled");
    } finally {
      stub.reset();
    }
  });
});

// ================================================================ listen

// The Host guard does not stop a LAN client that sends Host: localhost:<port>,
// so a native start must not be reachable off the machine at all.
function lanAddress() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list ?? []) {
      if (a.family === "IPv4" && !a.internal && !a.address.startsWith("169.254.")) return a.address;
    }
  }
  return undefined;
}

describe("listen", () => {
  const lan = lanAddress();
  let stub;
  before(async () => {
    stub = await startStub();
  });
  after(async () => {
    await stub?.close();
  });

  it("this machine has a non-loopback IPv4 address to probe from", () => {
    assert.ok(lan, `no non-loopback IPv4 address: ${JSON.stringify(os.networkInterfaces())}`);
  });

  it("with SANDBOX_LISTEN=0.0.0.0, as compose sets it, it answers on that address", { skip: !lan }, async () => {
    const backend = await startBackend({ url: stub.url, env: { SANDBOX_LISTEN: "0.0.0.0" } });
    try {
      const res = await request(backend.port, "GET", "/", { headers: { Host: backend.host }, address: lan });
      assert.equal(res.status, 200, res.text);
    } finally {
      await backend.stop();
    }
  });

  it("started natively, it answers on loopback and refuses a connection on that address", { skip: !lan }, async () => {
    const backend = await startBackend({ url: stub.url });
    try {
      const local = await backend.get("/");
      assert.equal(local.status, 200, local.text);
      const got = await request(backend.port, "GET", "/", { headers: { Host: backend.host }, address: lan }).then(
        (res) => `answered ${res.status}`,
        (err) => err.code ?? err.message,
      );
      assert.equal(got, "ECONNREFUSED", `a client on ${lan} reached the backend: ${got}`);
    } finally {
      await backend.stop();
    }
  });
});

// ================================================================ secrecy, across every backend above

describe("secrecy", () => {
  it("the key is in no log line, response body or event", () => {
    assert.ok(seen.logs.length >= 8, "every group ran a backend");
    for (const text of [...seen.logs, ...seen.bodies, ...seen.sse]) {
      assert.ok(!text.includes(CANARY), "the canary key leaked");
      assert.ok(!text.includes(CANARY.slice("rh_sk_".length)), "the canary key leaked");
    }
  });

  it("no event carries a header", () => {
    assert.ok(seen.sse.some((t) => t.includes("data:")), "the event streams were read");
    for (const text of seen.sse) assert.ok(!/bearer|authorization/i.test(text), text.slice(0, 400));
  });
});
