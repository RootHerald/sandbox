/*
 * Root Herald — wire contract shared by the native SDKs.
 *
 * Documents the strings the client consumes and the JSON it emits. The C-API
 * surface itself is in rootherald.h. Identical byte-for-byte across all SDK
 * repos; CI fails on drift.
 *
 * This header declares nothing. It is installed because the wire contract is
 * what an integrator or auditor needs to read alongside the C API.
 *
 * READ THIS FIRST: there are THREE ceremonies, and each is the installation's
 * attestation key answering one value the server minted. Enroll creates the
 * key and binds it to the endorsement key; mint has it certify a new app key;
 * attest has it quote what was asked. The envelope is common; the objects
 * inside it are per-platform, and the server discriminates on `platform`.
 *
 * NOTHING THE CLIENT SENDS LOCATES A ROW. The server resolves the tenant from
 * the backend's rh_sk_ key, the challenge from the nonce the proof was made
 * over, the enrollment from the `enrollmentId` it minted, and the installation
 * from the proof itself: a quote or certification names its signing key inside
 * the signed structure, a Mac presents the enclave key it enrolled, an iPhone
 * presents its App Attest key id. No device identifier travels in any body
 * below, and no identifier the server assigns is ever relayed to a device.
 */

#ifndef ROOTHERALD_PROTOCOL_H
#define ROOTHERALD_PROTOCOL_H

/* ====================================================================
 * THE ENVELOPE — common to every platform
 * ==================================================================== */
/*
 * Six endpoints. The CLIENT never calls them; it emits bodies the embedder's
 * BACKEND relays, authenticated with the backend's rh_sk_ secret.
 *
 *   POST /api/v1/attest/enroll        enroll, leg 1          <- RootHeraldEnrollBegin
 *   POST /api/v1/attest/activate      enroll, leg 2          <- RootHeraldEnrollComplete
 *   POST /api/v1/keys/challenge       backend mints a key challenge (THE KEY CHALLENGE)
 *   POST /api/v1/keys/certify         mint a key             <- RootHeraldMintKey
 *   POST /api/v1/attest/challenge     backend mints a challenge (THE CHALLENGE)
 *   POST /api/v1/attest/verify        attest                 <- RootHeraldAttest
 *
 * `platform` on the enroll body is the discriminator. It is recorded on the
 * installation, and ACTIVATION decides which proof to demand from the RECORDED
 * platform rather than from the request — so a caller cannot downgrade a TPM
 * device onto a weaker ceremony by reshaping its own JSON.
 *
 * Every installation is its own row. The alias the backend sees is derived
 * from the endorsement key, so a new attestation key, a re-enrollment or a
 * TPM clear never changes it.
 *
 * Policies bind to the backend's key, not to a call. No body names one.
 */

/* ====================================================================
 * THE CHALLENGE — what the backend relays to RootHeraldAttest
 * ==================================================================== */
/*
 * POST /api/v1/attest/challenge  { "ask"?: ["identity" | "posture"],
 *                                  "expectedKey"?: "<keyId>",
 *                                  "expectedDevices"?: ["<alias>", ...] }
 * -> { "nonce", "challenge", "expiresAt" }
 *
 * `nonce` is the backend's handle for this challenge: 32 random bytes,
 * base64url without padding, 43 characters. The backend passes it to verify
 * and the server finds the challenge by it. It is random bytes, not an id:
 * it exists because the proof is made over it.
 *
 * `challenge` is the string the client receives, verbatim:
 *
 *   rhc1.<base64url nonce>.<base64url ask-json>
 *
 * where the nonce segment is the same bytes as `nonce` and ask-json is
 * {"ask":["identity","posture"]}. The client parses it only to learn what to
 * collect. The TPM signs the 32-byte NONCE and nothing else; the ask is bound
 * on the server by the challenge row it was minted on, never by the signature.
 * A client lied to about the ask produces evidence the server refuses —
 * nothing weakens. A string that does not start with "rhc1." is
 * RH_ERR_INVALID_ARG. Relay `challenge` to the device; keep `nonce` for verify.
 *
 *   identity   quote over the nonce, PCR 7 only, EK certificate if present.
 *              No event log. Proves the enrolled installation is present and
 *              answering.
 *   posture    quote over PCRs 0-4 and 7 and the firmware TCG event log. The
 *              server derives Secure Boot posture from the log after binding it
 *              to the quote.
 *
 * An ask name the client does not know is IGNORED: it collects what it can and
 * the server appraises against the row, so a later ask on an older client
 * yields evidence without the new material and the policy decides.
 * RH_ERR_ASK_UNSUPPORTED is only for a known ask a platform cannot answer.
 *
 * `expectedKey` and `expectedDevices` are resolved when the challenge is
 * minted and enforced after the proof verifies; the client never sees them.
 *
 * POST /api/v1/attest/verify  { "nonce", "evidence", "requestedDisclosureClass"? }
 * -> { "verdict", "assuranceClaimsMet", "enrollmentRequired" }
 *
 * A proof that names no live installation of this tenant answers with a
 * failing verdict and `enrollmentRequired: true`; nothing is recorded for it.
 * Attestation releases no key.
 */

/* ====================================================================
 * THE KEY CHALLENGE — what the backend relays to RootHeraldMintKey
 * ==================================================================== */
/*
 * POST /api/v1/keys/challenge  { "purpose": "sign" | "decrypt",
 *                                "expectedDevices"?: ["<alias>", ...] }
 * -> { "nonce", "keyChallenge", "expiresAt" }
 *
 *   rhk1c.<base64url nonce>.<base64url purpose-json>
 *
 * where purpose-json is {"purpose":"sign"}. Same nonce rules as THE CHALLENGE.
 * A string that does not start with "rhk1c." is RH_ERR_INVALID_ARG; a purpose
 * the client does not implement is RH_ERR_ASK_UNSUPPORTED. The purpose the
 * server honours is the one on its row, never one in the certification.
 *
 * POST /api/v1/keys/certify  { "nonce", "certification" }
 * -> { "deviceId", "keyId", "purpose", "alg", "format"?, "jwk", "hardwareBound", "certifiedAt" }
 *
 *   alg      ES256 | RS256 | ECDH-ES | RSA-OAEP-256
 *   format   decrypt keys only: "jwe" for a TPM key, "apple-ecies" for a
 *            macOS key (ENVELOPES below); absent on a sign key
 *   deviceId the tenant's alias for the device, for the backend to bind the
 *            key to an account; never relayed to the device
 *   hardwareBound  true for a TPM key and for an App Attest key, whose
 *            residency Apple's attestation chain vouched for at enrollment;
 *            false on macOS, where the key proves possession only
 *
 * One live key per installation and purpose: minting again rotates it under
 * the same keyId. No quote and no PCRs are involved — a key is a property of
 * the chip, not of a boot. A backend that wants posture before minting runs an
 * attest challenge first and mints on a pass. Only a certify releases a key;
 * neither activation nor attestation does.
 */

/* ====================================================================
 * ENVELOPES — what encryptToDevice produces and RootHeraldDecrypt opens
 * ==================================================================== */
/*
 * Encrypting to a decrypt key uses only its public half, so it lives in the
 * server SDKs (encryptToDevice(key, bytes)); opening the result uses the
 * private half and lives in RootHeraldDecrypt. The `format` on the certify
 * response names the envelope. Nothing on the server ever parses one.
 *
 * format "jwe" (TPM keys, Windows and Linux): one JWE compact serialization,
 *
 *   BASE64URL(protected) . BASE64URL(encrypted key) . BASE64URL(iv)
 *     . BASE64URL(ciphertext) . BASE64URL(tag)
 *
 * with base64url unpadded and exact (no '=', no whitespace, zero fill bits).
 *   ECC P-256 key   alg "ECDH-ES", enc "A256GCM": direct key agreement, the
 *                   encrypted-key segment EMPTY. epk is {"kty":"EC",
 *                   "crv":"P-256","x","y"} with 32-byte coordinates, and the
 *                   client checks the point is on the curve in software before
 *                   TPM2_ECDH_ZGen. Z is the x coordinate of the shared point.
 *                   CEK = Concat KDF (RFC 7518 4.6.2, SHA-256, one round):
 *                   SHA-256(0x00000001 || Z || 0x00000007 || "A256GCM"
 *                   || 0x00000000 || 0x00000000 || 0x00000100), that is the
 *                   enc name as AlgorithmID, empty apu and apv, and a 256-bit
 *                   key length.
 *   RSA-2048 key    alg "RSA-OAEP-256", enc "A256GCM": the 32-byte CEK is
 *                   OAEP-encrypted with SHA-256 for both the hash and MGF1
 *                   and an empty label, 256 bytes in the encrypted-key
 *                   segment. The TPM opens it with TPM2_RSA_Decrypt under the
 *                   key's own OAEP/SHA-256 scheme.
 *   Content         AES-256-GCM, 12-byte IV, 16-byte tag. AAD is the ASCII of
 *                   the base64url protected-header segment exactly as sent.
 *   Protected header  a whitelist: exactly alg, enc and (ECC only) epk, and
 *                   inside epk exactly kty, crv, x, y. Any other member
 *                   (kid, apu, apv, zip, crit, cty, typ, ...), a duplicated
 *                   member or a string escape is RH_ERR_DECRYPT_FAILED. The
 *                   operation performed is chosen by the LOADED KEY's type;
 *                   the header's alg must agree with it and never selects
 *                   anything. A refusal and a failed tag answer the same
 *                   code; an OAEP failure substitutes a random CEK and still
 *                   runs the GCM check so its timing is the same.
 *
 * format "apple-ecies" (macOS): the bytes SecKeyCreateEncryptedData produces
 * under kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM
 * for the key's public half — the ephemeral public point in X9.63 form
 * followed by the AES-GCM ciphertext and its 16-byte tag — as one base64url
 * string without padding. The server SDKs do not produce this envelope in
 * 8.1: encrypting to a macOS key needs an Apple-side encryptor, and
 * encryptToDevice refuses a key whose format is apple-ecies. Not attested:
 * the key proves possession only, like every macOS key.
 *
 * iOS has no envelope: App Attest keys only sign and the Swift package has no
 * decrypt.
 */

/* ====================================================================
 * VARIANT A — TPM 2.0        platform: "windows" | "linux"
 * ==================================================================== */
/*
 * Two legs are irreducible here because the server's challenge is a FUNCTION of
 * what leg 1 emits: it seals a secret to this EK, bound to this AK's Name.
 *
 * POST /api/v1/attest/enroll
 * {
 *   "ekPublicKey":    "<base64 TPM2B_PUBLIC of the RSA EK>",
 *   "attestationKey": {
 *       "publicArea":       "<base64 TPM2B_PUBLIC of this installation's AK>",
 *       "parentPublicArea": "<base64 TPM2B_PUBLIC of its storage parent>",
 *       "qualifiedName":    "<base64 TPM2B_NAME, as TPM2_ReadPublic returned it>"
 *   },
 *   "platform":       "windows" | "linux",
 *   "ekCertPem":      "<PEM>",             optional; firmware TPMs may have no NV cert
 *   "ekCertificateChain": ["<PEM>", ...]   optional intermediates recovered locally
 *   "tpmSelfReport":  { "manufacturer", "vendorString" }   optional, unsigned
 * }
 * -> 201 { "enrollmentId", "credentialBlob", "encryptedSecret" }
 *    credentialBlob and encryptedSecret are TPM2_MakeCredential outputs, already
 *    TPM2B-framed: feed them straight into TPM2_ActivateCredential, do not re-wrap.
 *    Hand the whole response body to RootHeraldEnrollComplete.
 *
 * The AK is a restricted signing key created with TPM2_Create under a storage
 * parent that is itself a primary under the owner hierarchy: the Windows SRK at
 * 0x81000001, or the SDK's own storage primary on Linux. A quote's
 * qualifiedSigner is nameAlg || H(QN(parent) || Name(AK)) with
 * QN(parent) = nameAlg || H(TPM_RH_OWNER || Name(parent)), so the server
 * derives it from the two public areas above, recomputes `qualifiedName` and
 * refuses leg 1 on a mismatch (400 invalid_enroll_shape): a wrong parent fails
 * before any elevation prompt and before any row is written. The nested
 * `attestationKey` object is what tells this contract from the flat 7.0 body,
 * which is refused (wire_version_unsupported).
 *
 * tpmSelfReport is the TPM's own answer to TPM2_GetCapability and is not
 * signed. The server uses it only downward: it can recognise a software TPM
 * that presents no EK certificate, never promote a device.
 *
 * When ekCertPem is absent the SERVER fetches the vendor certificate (Intel
 * EKOP, AMD AIA) keyed by the EK public key. The client makes no network call.
 *
 * ekCertificateChain sources are TPM NV (Intel PTT On-Die CA at 0x01C00100..0x01C0010F)
 * and platform vendor-intermediate stores. Entries are deduplicated by SHA-256 of
 * DER and capped at 8. Order is not significant and the source is not labeled; the
 * server treats every entry uniformly and still requires the chain to terminate at
 * a seeded vendor root.
 *
 * POST /api/v1/attest/activate
 * { "enrollmentId", "decryptedSecret" }  -> 200 { "deviceId", "status", "enrolledAt" }
 *
 * Returning the decrypted secret proves two things at once: only the TPM
 * holding the private EK could recover it, and MakeCredential bound it to the
 * AK's Name, so that AK lives in the SAME silicon as the EK. Without the second
 * property a real EK certificate could be paired with a software AK. An
 * unknown, spent or foreign enrollmentId, a wrong secret and a cross-tenant AK
 * collision are refused alike, with one answer. Activation releases no key.
 *
 * certification for /api/v1/keys/certify (what RootHeraldMintKey writes):
 * {
 *   "publicArea": "<base64 TPM2B_PUBLIC of the new key>",
 *   "attest":     "<base64 TPMS_ATTEST, type TPM_ST_ATTEST_CERTIFY, extraData = nonce>",
 *   "signature":  "<base64 TPMT_SIGNATURE by the AK>"
 * }
 * The server resolves the installation from attest.qualifiedSigner, verifies
 * the signature under that installation's AK, requires Name(publicArea) to
 * equal the certified Name, and requires fixedTPM, fixedParent and
 * sensitiveDataOrigin SET, restricted CLEAR, and exactly one of sign or decrypt,
 * matching the purpose on the key-challenge row.
 *
 * evidence for /api/v1/attest/verify (what RootHeraldAttest writes):
 * {
 *   "pcrValues": { "sha256": { "0": "<hex>", ... } },     identity: "7" only
 *   "quote":     { "quoted": "<base64 TPMS_ATTEST>",
 *                  "signature": "<base64 TPMT_SIGNATURE>" },
 *   "logs":      { "srtm": "<base64 TCG log>" },   posture only; OMITTED when none
 *   "ekCertPem": "<PEM>",                optional
 *   "ekCertificateChain": ["<PEM>", ...] optional
 * }
 *
 * Everything the server needs about the quote is inside `quoted`: the signer's
 * qualified name, the nonce as extraData, the PCR selection and the PCR
 * digest. Nothing beside it repeats those values. `pcrValues` is not itself
 * signed — only the quote's digest over it is — so trusting it without the
 * quote lets an attacker on the device choose arbitrary PCRs. `logs` is keyed
 * by the measurement chain each log records; every log is bound to the same
 * quote over its own PCR range. A missing log is NOT an error: most VMs and
 * every software TPM have none, and the appraisal proceeds with fewer claims.
 *
 * KEY FAMILIES. ECC P-256 (ECDSA / SHA-256 for signing, ECDH for decrypt)
 * where the TPM reports ECC, ECDSA, ECDH and NIST P-256; RSA-2048 (RSASSA /
 * SHA-256, OAEP / SHA-256) otherwise. The SDK chooses, never the caller; the
 * template is bound into the key's Name, so the server reads the real family
 * from the public area. Quote, Certify, Sign and RSA_Decrypt are issued with
 * inScheme TPM_ALG_NULL, so the key's own scheme applies.
 *
 * BLOBS. Opaque to everyone but this SDK, wrapped by the storage parent's seed,
 * useless on any other TPM, and killed by a TPM clear (RH_ERR_KEY_UNLOADABLE).
 * Each is a header followed by TPM2B_PUBLIC | TPM2B_PRIVATE, both with their
 * size prefixes; the private area ends exactly at the end of the blob:
 *
 *   "rha1" | version 1 | parent id u8 | template id u8 | ...   attestation key
 *   "rhk1" | version 2 | parent id u8 | template id u8 | ...   app key
 *
 * parent id: 1 Windows SRK, 2 Linux ECC P-256 primary, 3 Linux RSA-2048
 * primary. template id: 1 ak-ecc-p256, 2 ak-rsa-2048, 3 app-sign-ecc-p256,
 * 4 app-sign-rsa-2048, 5 app-decrypt-ecc-p256, 6 app-decrypt-rsa-2048. The
 * key's family and purpose are read from its public area, never from the
 * header. An "rhk1" of version 1 (minted under 7.0) is RH_ERR_INVALID_ARG.
 */

/* ====================================================================
 * VARIANT B — Apple Secure Enclave      platform: "macos"
 * ==================================================================== */
/*
 * MakeCredential cannot be reused here and the reason is not incidental: it
 * OAEP-encrypts a seed to the endorsement key, which is inherently RSA, and the
 * Secure Enclave has no endorsement key at all. The analogue proves residency
 * by SIGNING instead — the server issues a nonce in the clear and the device
 * returns an ECDSA-P256-SHA256 signature over it. Publishing the nonce is safe
 * because the secret under test is the signing key, not the nonce.
 *
 * The device key is one per app: the keychain scopes it to the app's access
 * group, so it is already per installation. EnrollBegin writes no blob, and
 * ak_blob is NULL with length 0 on every verb.
 *
 * DOMAIN SEPARATION. The device key also serves RootHeraldSign, so every
 * signature a ceremony asks of it is over
 *
 *   "rootherald.v8." || nonce
 *
 * (the 14 ASCII bytes of the prefix, then the 32 raw nonce bytes), never the
 * raw nonce, and RootHeraldSign refuses data that begins with the prefix. An
 * app that signs attacker-chosen bytes can then never produce a ceremony
 * signature.
 *
 * POST /api/v1/attest/enroll
 * {
 *   "ekPublicKey":  "<base64>",   the enclave key, X9.63 uncompressed (65 bytes)
 *   "akPublicArea": "<base64>",   THE SAME KEY — there is no separate EK to bind
 *   "platform":     "macos"
 * }
 * -> 201 { "enrollmentId", "challengeNonce" }
 *
 * The body stays flat: there is no parent, so there is no nested object.
 *
 * POST /api/v1/attest/activate
 * { "enrollmentId", "signature" }  -> 200
 *   over prefix || challengeNonce; DER (SecKeyCreateSignature's default) or
 *   IEEE-P1363, both accepted.
 *
 * certification for /api/v1/keys/certify (what RootHeraldMintKey writes):
 * {
 *   "platform":  "macos",
 *   "publicKey": "<base64 X9.63 of the device key>",
 *   "signature": "<base64 ECDSA-P256-SHA256 by the device key over prefix || nonce>"
 * }
 * For purpose "sign" no new key is created: the device key is the key. A
 * re-mint presents the same key, so certify is idempotent (it refreshes the
 * row, never inserts a second).
 *
 * For purpose "decrypt" the SDK keeps a second enclave key for ECIES
 * (ENVELOPES, "apple-ecies"). The server has never seen that key, so the
 * certification carries the enrolled device key beside it, and the device
 * key binds the new one to the installation:
 * {
 *   "platform":        "macos",
 *   "publicKey":       "<base64 X9.63 of the decrypt key>",
 *   "signature":       "<base64 DER ECDSA-P256-SHA256 by the decrypt key over prefix || nonce>",
 *   "devicePublicKey": "<base64 X9.63 of the enrolled device key>",
 *   "deviceSignature": "<base64 DER ECDSA-P256-SHA256 by the device key over
 *                        prefix || nonce || the 65 raw bytes of publicKey>"
 * }
 * The server resolves the installation from devicePublicKey (SHA-256 of the
 * point, as for every macOS proof), verifies deviceSignature under the
 * enrolled key, then possession of the decrypt key. A re-mint presents the
 * same decrypt key, so certify is idempotent here too.
 *
 * evidence for /api/v1/attest/verify:
 * { "keyAttestation": { "signedNonce": "<base64, over prefix || nonce>", "publicKey": "<base64>" } }
 *
 * ASKS. Only `identity` is served; `posture` returns RH_ERR_ASK_UNSUPPORTED.
 *
 * APP-KEY BLOB. "rhm1" | version 1 | purpose u8. No key material: the key
 * stays in the Secure Enclave and the keychain, and LoadKey selects it by
 * purpose. RootHeraldCheckKey with a NULL blob answers whether the device key
 * is in the keychain, which is a Mac's "am I enrolled" signal.
 *
 * WHAT THIS PROVES. Possession of a key that cannot leave the enclave — enough
 * to defeat session export, cookie theft and credential replay, because the
 * attacker cannot move the key. It does NOT prove the key is in hardware: this
 * ceremony cannot distinguish a Secure Enclave key from a software P-256 key,
 * so the server classes these devices AppleSecureEnclaveUnattested, which is
 * deliberately not real hardware and does not satisfy `real-device`. A key
 * minted here carries the same claim: hardwareBound is false.
 */

/* ====================================================================
 * VARIANT C — Apple App Attest          platform: "ios"
 * ==================================================================== */
/*
 * Documented here because the SERVER accepts it and a cross-platform relay has
 * to handle it. Implemented by the Swift package (sdk-ios), which carries this
 * header for the contract and does not compile it.
 *
 * One leg. The attestation object carries Apple's signed certificate chain,
 * the attested public key and the challenge binding in one blob, so there is
 * no credential to activate. The Swift SDK still exposes enroll and attest
 * separately, because attestKey contacts Apple and generateAssertion does not.
 *
 * POST /api/v1/attest/enroll
 * { "platform": "ios", "iosKeyId": "<base64>", "iosAttestationObject": "<base64 CBOR>",
 *   "nonce": "<base64url>" }
 * -> 201 {}
 *
 * `nonce` is the second segment of the challenge string the attestation was
 * made over, so the SDK derives it; the backend relays the body as-is. The
 * server finds that challenge by (tenant, nonce) and spends it whether or not
 * the attestation validates. The 201 body is empty: the backend learns the
 * device's identifier from the first verdict.
 *
 * evidence for /api/v1/attest/verify:
 * { "iosAttestation": { "assertion": "<base64 CBOR>", "keyId": "<base64>" } }
 *
 * certification for /api/v1/keys/certify (the Swift mintKey):
 * { "platform": "ios", "keyId": "<base64>", "assertion": "<base64 CBOR>" }
 *
 * Assertions only, each over clientData = prefix || nonce with the VARIANT B
 * prefix. The server locates the installation by `keyId`, verifies the
 * assertion under the key it recorded with a counter that only moves forward,
 * and a mint advances the counter like a verify. An attestation object
 * presented after enrollment is refused.
 *
 * ASKS. `identity` is served; `posture` is unsupported. A `sign` key challenge
 * certifies the App Attest key itself, since it is the only key an app can
 * hold: certify returns its JWK with hardwareBound true (Apple's attestation
 * chain vouched for the key's residency at enrollment), and later signatures
 * are assertions, which a backend verifies as App Attest assertions, not as
 * JOSE signatures. `decrypt` is never served: App Attest keys only sign, so
 * the Swift package has no mint for it and no decrypt.
 */

#endif /* ROOTHERALD_PROTOCOL_H */
