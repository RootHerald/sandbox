// @ts-check
// The sandbox's stand-in for a customer backend: the only place the rh_sk_ key
// lives. The device calls these routes; this calls RootHerald.

import http from "node:http";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  RootHeraldClient,
  RootHeraldError,
  RootHeraldApiError,
  EncryptToDeviceError,
  verifyKeySignature,
  encryptToDevice,
} from "@rootherald/node";

/** @typedef {import("@rootherald/node").AttestResult} AttestResult */
/** @typedef {import("@rootherald/node").CertifiedKeyResult} CertifiedKeyResult */
/** @typedef {import("@rootherald/node").KeyPurpose} KeyPurpose */

const here = path.dirname(fileURLToPath(import.meta.url));

const secretKey = process.env.ROOTHERALD_SECRET_KEY ?? "";
const baseUrl = process.env.ROOTHERALD_URL || "https://rootherald.io";
const port = Number(process.env.SANDBOX_PORT || 47823);

// The package's exports map hides package.json from import resolution.
const sdkVersion = JSON.parse(
  readFileSync(path.join(here, "node_modules", "@rootherald", "node", "package.json"), "utf8"),
).version;
const page = readFileSync(path.join(here, "index.html"));

const MAX_BODY = 2 * 1024 * 1024;
const MAX_EVENTS = 500;
const DASH = "—";
const CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'";
const ALLOWED_HOSTS = [`localhost:${port}`, `127.0.0.1:${port}`];
const ALLOWED_ORIGINS = ALLOWED_HOSTS.map((h) => `http://${h}`);
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

/** @type {Record<string, string>} */
const CHIP_WORDS = {
  "discrete-tpm": "Discrete chip",
  "firmware-tpm": "Firmware TPM",
  "cloud-vtpm": "Cloud virtual TPM",
  emulated: "Software TPM",
  "mobile-hardware": "Phone hardware",
  "mobile-software": "Phone software key",
};

/** @param {unknown} kind */
function chipWords(kind) {
  return (typeof kind === "string" && Object.hasOwn(CHIP_WORDS, kind) && CHIP_WORDS[kind]) || "Unknown chip";
}

// ---------------------------------------------------------------- run state

/**
 * @typedef {{ nonce?: string, key?: CertifiedKeyResult, pending?: string }} KeyGroup
 * @typedef {{ number: number, nonce?: string, attested: boolean, ueid?: string, sign: KeyGroup, decrypt: KeyGroup }} Run
 */

/** @type {Run} */
let run = newRun(0);

/** @param {number} number @returns {Run} */
function newRun(number) {
  return { number, attested: false, sign: {}, decrypt: {} };
}

function randomB64url() {
  return Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
}

// ---------------------------------------------------------------- events

/** @type {object[]} */
const events = [];
/** @type {Set<http.ServerResponse>} */
const listeners = new Set();

/** @param {object} event */
function publish(event) {
  events.push(event);
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
  const frame = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of listeners) res.write(frame);
}

/** @param {http.ServerResponse} res */
function streamEvents(res) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  for (const event of events) res.write(`data: ${JSON.stringify(event)}\n\n`);
  listeners.add(res);
  res.on("close", () => listeners.delete(res));
}

// ---------------------------------------------------------------- responses

/**
 * @typedef {{ status: number, body: Record<string, string>, log?: string, sdkCall?: string, sent?: unknown, received?: unknown, verdict?: object }} Outcome
 */

/** @param {number} status @param {string} result @param {Record<string, string>} [extra] */
function reply(status, result, extra = {}) {
  return { status, body: { result, ...extra } };
}

/**
 * The one function for refusals. RootHerald's own status survives; the
 * SDK's local failures map to the status a client can act on.
 * @param {unknown} err
 * @returns {Outcome}
 */
function refusal(err) {
  if (!(err instanceof RootHeraldError)) {
    console.error(err instanceof Error ? err.stack : String(err));
    return reply(500, "backend error");
  }
  let status;
  if (err instanceof RootHeraldApiError) status = err.status >= 400 ? err.status : 502;
  else if (err.code === "MISSING_SECRET_KEY" || err.code === "INVALID_SECRET_KEY_FORMAT") status = 401;
  else if (err.code === "NETWORK_ERROR") status = 502;
  else if (err.code === "INVALID_BASE_URL") status = 500;
  else status = 400;

  const error = (err instanceof RootHeraldApiError && err.errorCode) || err.code;
  // expected_unknown messages echo the alias the request named.
  const message = err.message.replace(UUID, "[device id]");
  return {
    status,
    body: { result: `RootHerald refused: ${error}`, error, message },
    log: `refused ${status} ${error}: ${err.message}`,
    received: { status, error, message: err.message },
  };
}

// ---------------------------------------------------------------- routes

/**
 * @typedef {(body: Record<string, unknown>) => Promise<Outcome>} Handler
 * @type {Record<string, { group: string, handler: Handler }>}
 */
const routes = {
  "/enroll/begin": {
    group: "enroll",
    async handler(body) {
      const rh = client();
      run = newRun(run.number + 1);
      const { challenge } = await rh.relayEnroll(/** @type {any} */ (body));
      return {
        ...reply(200, "enrollment started", { enrollChallenge: JSON.stringify(challenge) }),
        sdkCall: "relayEnroll",
        sent: body,
        received: challenge,
      };
    },
  },

  "/enroll/complete": {
    group: "enroll",
    async handler(body) {
      const rh = client();
      const activated = await rh.relayActivate(/** @type {any} */ (body));
      return { ...reply(200, "enrolled"), sdkCall: "relayActivate", sent: body, received: activated };
    },
  },

  "/attest/challenge": {
    group: "attest",
    async handler() {
      const rh = client();
      if (run.attested) run = newRun(run.number + 1);
      const issued = await rh.issueChallenge();
      run.nonce = issued.nonce;
      return {
        ...reply(200, "challenge issued", { challenge: issued.challenge }),
        sdkCall: "issueChallenge",
        sent: {},
        received: issued,
      };
    },
  },

  "/attest/verify": {
    group: "attest",
    async handler(body) {
      const rh = client();
      const nonce = run.nonce;
      const result = await rh.verify(/** @type {any} */ (body), { nonce: /** @type {string} */ (nonce) });
      run.attested = true;
      return verdictOutcome(result, { sdkCall: "verify", sent: { evidence: body, nonce } });
    },
  },

  "/sign/challenge": { group: "sign", handler: () => keyChallenge("sign") },
  "/sign/certify": { group: "sign", handler: (body) => certify("sign", body) },

  "/sign/verify": {
    group: "sign",
    async handler(body) {
      const { key, pending: message } = run.sign;
      if (!key || message === undefined) return reply(409, "attest first");
      run.sign.pending = undefined;
      const signature = typeof body.signature === "string" ? body.signature : "";
      const ok = verifyKeySignature(key.jwk, message, signature);
      return {
        ...(ok ? reply(200, "signature verified") : reply(422, "signature does not verify")),
        sdkCall: "verifyKeySignature",
        sent: { jwk: key.jwk, message, signature },
        received: ok,
      };
    },
  },

  "/decrypt/challenge": { group: "decrypt", handler: () => keyChallenge("decrypt") },
  "/decrypt/certify": { group: "decrypt", handler: (body) => certify("decrypt", body) },

  "/decrypt/verify": {
    group: "decrypt",
    async handler(body) {
      const secret = run.decrypt.pending;
      if (!run.decrypt.key || secret === undefined) return reply(409, "attest first");
      run.decrypt.pending = undefined;
      const plaintext = typeof body.plaintext === "string" ? body.plaintext : "";
      const expected = Buffer.from(secret, "base64url");
      const got = Buffer.from(plaintext, "base64url");
      const ok = got.length === expected.length && got.equals(expected);
      return {
        ...(ok ? reply(200, "secret recovered") : reply(422, "wrong secret")),
        sdkCall: "compare",
        sent: { plaintext },
        received: ok,
      };
    },
  },
};

function client() {
  return new RootHeraldClient({ secretKey, baseUrl });
}

/**
 * @param {AttestResult} result
 * @param {{ sdkCall: string, sent: unknown }} call
 * @returns {Outcome}
 */
function verdictOutcome(result, call) {
  const device = result.device ?? {};
  const outcome = device.verdict;
  const genuine = device.hardwareGenuine === true;
  const vouched = device.ekChainTrusted === true;
  const ueid = typeof device.ueid === "string" ? device.ueid : undefined;

  let line = chipWords(device.tpmKind);
  if (!genuine) line += ", not genuine hardware";
  if (!vouched) line += ", no maker vouches for this chip";

  /** @type {Outcome} */
  let answer;
  if (result.enrollmentRequired === true) answer = reply(409, "not enrolled");
  else if (outcome === "fail") answer = reply(403, `blocked ${DASH} ${line}`);
  else {
    answer = reply(200, `${outcome} ${DASH} ${line}`);
    run.ueid = ueid;
  }

  return {
    ...answer,
    ...call,
    received: result,
    log:
      `verdict ${outcome} ueid=${ueid ?? "not disclosed"} tpmKind=${String(device.tpmKind ?? "unknown")} ` +
      `hardwareGenuine=${genuine} ekChainTrusted=${vouched}`,
    verdict: { outcome, ueid, tpmKind: chipWords(device.tpmKind), hardwareGenuine: genuine, ekChainTrusted: vouched },
  };
}

/** @param {KeyPurpose} purpose @returns {Promise<Outcome>} */
async function keyChallenge(purpose) {
  const rh = client();
  if (!run.ueid) return reply(409, "attest first");
  const ask = { purpose, expectedDevices: [run.ueid] };
  const issued = await rh.issueKeyChallenge(ask);
  run[purpose] = { nonce: issued.nonce };
  return {
    ...reply(200, "key challenge issued", { keyChallenge: issued.keyChallenge }),
    sdkCall: "issueKeyChallenge",
    sent: ask,
    received: issued,
  };
}

/** @param {KeyPurpose} purpose @param {Record<string, unknown>} body @returns {Promise<Outcome>} */
async function certify(purpose, body) {
  const rh = client();
  const group = run[purpose];
  const nonce = group.nonce;
  group.nonce = undefined;
  const key = await rh.certifyKey(/** @type {string} */ (nonce), /** @type {any} */ (body));
  const bound = key.hardwareBound === true;
  const result = `${purpose} key certified${bound ? "" : ", not hardware-bound"}`;
  const call = { sdkCall: "certifyKey", sent: { nonce, certification: body }, log: `certify ${purpose} hardwareBound=${bound}` };

  if (purpose === "sign") {
    const message = randomB64url();
    run.sign = { key, pending: message };
    return { ...reply(200, result, { message }), ...call, received: key };
  }

  const secret = randomB64url();
  let jwe;
  try {
    jwe = encryptToDevice(key, Buffer.from(secret, "base64url"));
  } catch (err) {
    if (!(err instanceof EncryptToDeviceError)) throw err;
    return { ...reply(422, `cannot encrypt to this key: ${err.code}`), ...call, received: key };
  }
  run.decrypt = { key, pending: secret };
  return { ...reply(200, result, { jwe }), ...call, sdkCall: "certifyKey, encryptToDevice", received: { key, jwe } };
}

// ---------------------------------------------------------------- server

/**
 * Host and Origin are checked so that a web page cannot drive this backend
 * through DNS rebinding or a cross-site form; there is no auth beyond that.
 * @param {http.IncomingMessage} req
 */
function refusedHeader(req) {
  if (!ALLOWED_HOSTS.includes(req.headers.host ?? "")) return "Host";
  const origin = req.headers.origin;
  if (origin !== undefined && !ALLOWED_ORIGINS.includes(origin)) return "Origin";
  const site = req.headers["sec-fetch-site"];
  if (site === "cross-site" || site === "same-site") return "Sec-Fetch-Site";
  return undefined;
}

/** @param {http.ServerResponse} res @param {number} status @param {Record<string, string>} body */
function sendJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

/** @param {http.IncomingMessage} req @returns {Promise<Buffer | null>} null when over the cap */
function readBody(req) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size <= MAX_BODY) chunks.push(chunk);
    });
    req.on("end", () => resolve(size > MAX_BODY ? null : Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** @param {http.IncomingMessage} req @param {http.ServerResponse} res */
async function handle(req, res) {
  const refused = refusedHeader(req);
  if (refused) return sendJson(res, 403, { result: `refused: ${refused} header` });

  const route = (req.url ?? "/").split("?")[0];
  if (req.method === "GET" && route === "/") {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": CSP,
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Cache-Control": "no-store",
    });
    return res.end(page);
  }
  if (req.method === "GET" && route === "/events") return streamEvents(res);

  const entry = Object.hasOwn(routes, route) ? routes[route] : undefined;
  if (!entry && route !== "/" && route !== "/events") return sendJson(res, 404, { result: "no such route" });
  if (req.method !== "POST" || !entry) return sendJson(res, 405, { result: "method not allowed" });

  const raw = await readBody(req);
  if (raw === null) return sendJson(res, 413, { result: "request body is over 2 MiB" });
  let body;
  try {
    body = JSON.parse(raw.toString("utf8"));
  } catch {
    return sendJson(res, 400, { result: "request body is not JSON" });
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return sendJson(res, 400, { result: "request body is not a JSON object" });
  }

  /** @type {Outcome} */
  let outcome;
  try {
    outcome = await entry.handler(body);
  } catch (err) {
    outcome = refusal(err);
  }

  console.log(outcome.log ?? `${route} ${outcome.status} ${outcome.body.result}`);
  publish({
    run: run.number,
    group: entry.group,
    route,
    at: new Date().toISOString(),
    sdkCall: outcome.sdkCall,
    sent: outcome.sent,
    received: outcome.received,
    status: outcome.status,
    result: outcome.body.result,
    ...(outcome.verdict ? { verdict: outcome.verdict } : {}),
  });
  sendJson(res, outcome.status, outcome.body);
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error(err instanceof Error ? err.stack : String(err));
    if (!res.headersSent) sendJson(res, 500, { result: "backend error" });
    else res.end();
  });
});

console.log(`@rootherald/node ${sdkVersion}`);
console.log(`RootHerald ${baseUrl}`);
if (!secretKey) console.log("ROOTHERALD_SECRET_KEY is not set");

// 0.0.0.0 inside the container; compose publishes the port on 127.0.0.1 only.
server.listen(port, "0.0.0.0", () => {
  console.log(`Sandbox backend on http://localhost:${port}/`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    for (const res of listeners) res.end();
    server.close(() => process.exit(0));
    server.closeAllConnections();
  });
}
