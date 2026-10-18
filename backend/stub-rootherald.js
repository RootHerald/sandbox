// A stub of the RootHerald API for the C client on swtpm, run by CI:
//   SANDBOX_STUB_PORT=<port> SANDBOX_STUB_STATE=<file> node backend/stub-rootherald.js
// The backend's key picks what the stub does: rh_sk_stub_refuse refuses
// enrollment, _refuse_activation refuses it at activation, _allow admits the
// device as a software TPM, _block fails its verdict, _unenrolled answers every
// verify with enrollmentRequired.
// MakeCredential runs in tpm2_makecredential, so swtpm's ActivateCredential is
// the check on the enrollment crypto; the sign and decrypt checks are sdk-js's.

import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const subtle = globalThis.crypto.subtle;

function hex(bytes) {
  return Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(bytes))).toString("hex");
}

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function verdictBody(device, extra = {}) {
  const now = new Date();
  return {
    verdict: {
      acr: "urn:rootherald:acr:hardware",
      amr: ["hwk"],
      authTime: now.toISOString(),
      expiresAt: new Date(now.getTime() + 300_000).toISOString(),
      requestedAcrValues: [],
      device: { attestationType: "tpm", attestedAt: now.toISOString(), ...device },
    },
    ...extra,
  };
}


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
        const blocked = verdictBody({ ...softwareTpm(ueid), verdict: "fail", earStatus: "contraindicated" });
        // As platform 9b4655c4 sends it: VerdictReasons.cs, VerdictReasonWireTests.AFail_CarriesTheReason_OnTheVerdict.
        blocked.verdict.reason = { code: "chip_kind_not_accepted", text: "Platform or chip not in this policy" };
        return { status: 200, body: blocked };
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


await serveStub(Number(process.env.SANDBOX_STUB_PORT), process.env.SANDBOX_STUB_STATE);
