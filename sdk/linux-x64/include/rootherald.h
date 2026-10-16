/*
 * Root Herald — public C ABI for the embeddable native SDK.
 *
 * C11, no C++ constructs, so this is consumable from C, C++, Rust, Go, Zig,
 * Swift, and P/Invoke without a shim. Identical byte-for-byte in sdk-windows,
 * sdk-linux, sdk-macos and sdk-ios; CI fails on drift. Version history is in
 * CHANGELOG.md.
 *
 * The client holds no Root Herald key and opens no socket to anything. It does
 * local TPM/enclave work and emits opaque JSON the embedder's backend relays,
 * authenticated with the backend's rh_sk_ secret. A verdict is only a security
 * control when enforced server-side, so it never travels through the client.
 *
 * SHAPE. Flat functions over opaque handles, Win32 style. RH_HANDLE is a
 * session: one TPM (or enclave) context, opened once. RH_KEY_HANDLE is an app
 * key loaded under that session. Both are distinct incomplete types, so a key
 * handle cannot be passed where a session is expected.
 *
 * THREE CEREMONIES, each this installation's attestation key answering one
 * value the server minted (protocol.h). Enroll creates the key and binds it to
 * the hardware; MintKey has it certify a new app key over a nonce; Attest has
 * it quote what the server asked over a nonce.
 *
 * BLOBS are the embedder's. On a TPM platform the SDK persists nothing: the
 * attestation-key blob EnrollBegin writes and every app-key blob MintKey writes
 * are wrapped by the TPM, useless on any other TPM, and stored by the app that
 * links this library, which passes the attestation-key blob back to every
 * Attest and MintKey. Any local process holding a blob can use the key, so
 * store it where only that app can read it (DPAPI, an app-only-readable file).
 * macOS keeps its keys in the keychain and writes no blob.
 *
 * BUFFERS are always the caller's. Every function that produces bytes takes
 * (buf, cap, out_len): it writes at most cap bytes and sets *out_len to the
 * number produced. If buf is NULL or cap is too small it returns
 * RH_ERR_BUFFER_TOO_SMALL with *out_len set to the size required, so the
 * caller can query once and allocate however it likes — a stack array, a
 * vector's data(), a pool. The library never allocates for the caller and
 * there is nothing to free. String outputs are NUL-terminated and the
 * terminator is included in both the required size and *out_len.
 *
 * THREADS. A handle is not thread-safe and the library takes no locks. Give
 * each thread its own session or serialise in the caller. Nothing here is
 * meant to be called out of order; a caller that does has a bug the library
 * cannot fix for it.
 *
 * DIAGNOSTICS. This library emits no log messages. Everything it can tell you
 * about a failure is the RH_STATUS it returns, and every code below names a
 * distinct thing for the caller to DO — that is the test a code has to pass to
 * exist. Log the code in your own logging stack, where it belongs; the per-code
 * cause-and-remedy reference lives at rootherald.io/developers/sdks/status-codes.
 */

#ifndef ROOTHERALD_H
#define ROOTHERALD_H

#include <stdint.h>
#include <stddef.h>

#define ROOTHERALD_ABI_VERSION_MAJOR 8
#define ROOTHERALD_ABI_VERSION_MINOR 1

/* Static archive: no import/export decoration. Retained as a no-op so older
 * translation units referencing it still compile. */
#define ROOTHERALD_API

/*
 * SAL annotations document each pointer's direction and nullability and are
 * checked by MSVC /analyze. They compile to nothing, and the shim keeps
 * non-MSVC consumers building.
 */
#if defined(_MSC_VER) && defined(__has_include)
#  if __has_include(<sal.h>)
#    include <sal.h>
#    define ROOTHERALD_HAS_SAL 1
#  endif
#endif
#ifndef ROOTHERALD_HAS_SAL
#  define _In_
#  define _In_z_
#  define _In_opt_
#  define _In_reads_bytes_(n)
#  define _In_reads_bytes_opt_(n)
#  define _Out_
#  define _Out_opt_
#  define _Outptr_
#  define _Out_writes_bytes_to_opt_(cap, n)
#  define _Success_(expr)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Handles                                                            */
/* ------------------------------------------------------------------ */

typedef struct RH_HANDLE__     *RH_HANDLE;      /* one session: one TPM context, in-flight enroll state */
typedef struct RH_KEY_HANDLE__ *RH_KEY_HANDLE;  /* one loaded app key, owned by a session */

/* ------------------------------------------------------------------ */
/* Status                                                             */
/* ------------------------------------------------------------------ */

/*
 * Every code names a different next action. Codes 3, 4 and 5 were retired in
 * 5.0 and are deliberately NOT reused: 3 and 5 described a network client that
 * 3.0 deleted, and 4 reported local TPM failures as "the server returned an
 * error". A consumer compiled against an older header must fail to build, not
 * silently re-map onto a new meaning. 18 arrived in 8.1 with RootHeraldDecrypt
 * and is the only addition 8.1 made to this list.
 */
typedef enum {
    RH_OK = 0,

    /* Caller bug — the arguments are wrong. Fix the call; retrying is pointless.
     * A NULL attestation-key blob on a TPM platform, a blob of the wrong kind
     * or format, a challenge string of the wrong form, Sign on a decrypt key,
     * Decrypt on a sign key. */
    RH_ERR_INVALID_ARG = 1,

    /* No TPM 2.0 / Secure Enclave reachable at all. A hardware ceiling: gate the
     * feature off for this device rather than retrying. */
    RH_ERR_TPM_UNAVAILABLE = 2,

    /* EnrollComplete only: this session holds no in-flight EnrollBegin state
     * the leg needs. Restart from EnrollBegin. */
    RH_ERR_NOT_ENROLLED = 6,

    /* Windows only. EnrollComplete needs an elevated process and this one is
     * not; nothing was consumed and the same call succeeds elevated. The SDK
     * never elevates on your behalf. No other verb returns it. */
    RH_ERR_ELEVATION_REQUIRED = 7,

    /* A TPM is present but its endorsement key could not be read. Distinct from
     * TPM_UNAVAILABLE because it is usually fixable: a missing resource manager
     * (tpm2-abrmd), a permissions problem on /dev/tpmrm0, or a driver fault.
     * Worth surfacing to the operator rather than degrading silently. */
    RH_ERR_EK_READ_FAILED = 8,

    /* Enrollment could not create the attestation key or read its storage
     * parent. The device's TPM state is the problem, not the caller's
     * arguments — retry enrollment. */
    RH_ERR_AK_FAILED = 9,

    /* The enrollment challenge could not be consumed: TPM2_ActivateCredential
     * failed, or the enclave could not sign it. Restart from EnrollBegin. */
    RH_ERR_ACTIVATION_FAILED = 10,

    /* Attest only. Reading PCRs or producing the quote failed after the
     * attestation key loaded. Retry the attestation; keep the blob. */
    RH_ERR_QUOTE_FAILED = 11,

    /* macOS/iOS only. The host executable is not signed with a provisioning
     * profile granting data-protection keychain access, so the Secure Enclave is
     * unreachable from this binary (OSStatus -34018). A build/signing
     * misconfiguration in the EMBEDDING app — add the entitlement and re-sign.
     * Not a device fault and not retriable. */
    RH_ERR_ENTITLEMENT_MISSING = 12,

    /* A known ask this platform cannot answer ('posture' on macOS), or a key
     * purpose this library does not implement or does not know (MintKey names
     * which purposes each platform serves). A platform ceiling, not a fault:
     * tell the backend, which will ask for less. An ask name the library does
     * not know is ignored, never refused: the server appraises what arrives
     * against its own row. */
    RH_ERR_ASK_UNSUPPORTED = 13,

    /* A blob no longer loads under its parent: the TPM was cleared or the
     * storage parent changed. The key is gone for good. For the attestation-key
     * blob (Attest, MintKey, CheckKey): discard it, enroll again, retry once.
     * For an app-key blob (LoadKey, CheckKey): discard it and mint a new key.
     * Returned only when the TPM says the blob is dead; a transient TPM
     * failure is a different code and a retry, never a re-enroll: Attest
     * answers QUOTE_FAILED, MintKey KEY_CREATE_FAILED, and LoadKey and CheckKey
     * answer a TPM warning such as TPM_RC_OBJECT_MEMORY (every object slot
     * held) with RH_ERR_INTERNAL, which the caller retries once after closing
     * a key. */
    RH_ERR_KEY_UNLOADABLE = 14,

    /* MintKey only. TPM2_Create or TPM2_Certify failed for the new key after
     * the attestation key loaded. Retry the key challenge once; then report. */
    RH_ERR_KEY_CREATE_FAILED = 15,

    /* Sign only. The key is loaded but TPM2_Sign failed. Retry; a second
     * failure means the TPM is wedged, not the key. */
    RH_ERR_SIGN_FAILED = 16,

    /* The caller's buffer is NULL or too small. *out_len holds the size
     * required. Not a fault: allocate and call again. */
    RH_ERR_BUFFER_TOO_SMALL = 17,

    /* Decrypt only. The ciphertext did not open under this key: wrong key,
     * tampered envelope, or a header the library refuses. Not retriable with
     * the same bytes; the backend encrypts again to the key it certified. */
    RH_ERR_DECRYPT_FAILED = 18,

    /* Nothing above fits. Genuinely unexpected — report it. From LoadKey or
     * CheckKey it is also the transient answer (see KEY_UNLOADABLE): close a
     * key, retry once, then report. */
    RH_ERR_INTERNAL = 99
} RH_STATUS;

/* ------------------------------------------------------------------ */
/* Posture                                                            */
/* ------------------------------------------------------------------ */

/* RH_POSTURE.capabilities bits. A new capability is a new bit, never a new
 * struct field. The key family is the SDK's choice from these, never the
 * caller's. */
typedef enum {
    RH_CAP_AK_ECC_P256 = 1,   /* ECC, ECDSA, ECDH and NIST P-256 present: the default family */
    RH_CAP_AK_RSA_2048 = 2    /* RSA-2048 with RSASSA present: the fallback family */
    /* later: RH_CAP_DRTM_LOG = 4 */
} RH_CAP;

/*
 * Device-readiness snapshot: everything the device can know about itself with
 * no server round-trip, and the free pre-flight check before spending a billable
 * attestation.
 *
 * These are READINESS SIGNALS, not a verdict. The verdict is server-side (tenant
 * policy plus trust-anchor chain validation) and is unknowable locally. Never
 * render them as "you will pass".
 *
 * Whether this installation is enrolled is not here: on a TPM platform the
 * answer is whether the app still holds an attestation-key blob that loads
 * (RootHeraldCheckKey), and only the app knows where it keeps one.
 *
 * Tri-state ints use -1 for undetermined; counts use -1 for unavailable. -1 is
 * distinct from 0 everywhere in this struct: 0 means "we looked and it is off /
 * there are none", -1 means "we could not tell". Reporting 0 for something never
 * examined would claim knowledge the device does not have.
 */
typedef struct {
    int  has_tpm;                 /* 1 = TPM 2.0 / Secure Enclave reachable */
    int  ek_cert_present;         /* 1 = vendor EK certificate found */
    int  secure_boot;             /* 1 on, 0 off, -1 undetermined */
    int  oem_keyed;               /* 1 known-OEM PK, 0 custom/unknown, -1 undetermined */
    char oem_name[64];            /* "" when unknown */
    int  boot_log_measurements;   /* measured-boot entries; -1 unavailable */
    /* Measured entries whose digest appears in the platform's dbx revocation
     * list. NOT COMPUTED by any platform today, so it always reports -1.
     * Deriving it means cross-referencing each parsed entry against the dbx
     * hash set, which no analyser does yet — the dbx list's SIZE is known, but
     * that is a property of the firmware, not a finding about this device, and
     * reporting it here would show a revocation count on every healthy machine.
     * The field stays because consumers already render it and degrade correctly
     * on -1; it will report a real number when the cross-reference is built. */
    int  boot_log_revoked;
    /* 1 = MintKey serves a key challenge here. A macOS key proves possession
     * only (protocol.h, VARIANT B). */
    int  app_keys_supported;
    uint32_t capabilities;        /* RH_CAP bits; 0 where there is no TPM */
    char platform_name[16];       /* "windows" | "linux" | "macos" | "ios" */
    char detail_json[2048];       /* machine-readable detail snapshot */
} RH_POSTURE;

/* ------------------------------------------------------------------ */
/* Session                                                            */
/* ------------------------------------------------------------------ */

/*
 * Opens the TPM (or enclave) context once for the life of the handle and, on
 * a TPM, reads which key families it supports. Returns a status rather than a
 * handle because failure has distinguishable causes: TPM_UNAVAILABLE is a
 * hardware ceiling, ENTITLEMENT_MISSING is a signing bug in the embedding app.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldOpen(_Outptr_ RH_HANDLE* out_handle);

/* Closes the session and every key handle still open under it. NULL is a no-op. */
ROOTHERALD_API void RootHeraldClose(_In_opt_ RH_HANDLE h);

/* Local readiness, no server round-trip. */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldPreCheck(_In_ RH_HANDLE h, _Out_ RH_POSTURE* out);

/* ------------------------------------------------------------------ */
/* 1. Enroll                                                          */
/* ------------------------------------------------------------------ */

/*
 * Two legs, irreducible: the server's credential is a function of what leg 1
 * emits. The attestation key is created under the storage parent and handed
 * back wrapped at leg 1, so nothing is held in process memory across the
 * relay and leg 2 can run in a different process. On Windows only leg 2 needs
 * elevation (TBS blocks TPM2_ActivateCredential otherwise); an integrator's
 * elevated helper runs EnrollComplete alone, with the blob and the server's
 * credential as its inputs. One elevation per enrollment.
 *
 * When to enroll:
 *   no attestation-key blob stored        enroll first; attempt no Attest or MintKey
 *   Attest or MintKey -> KEY_UNLOADABLE   discard the blob, enroll, retry once
 *   verdict says enrollmentRequired       enroll, retry once
 *   NULL ak_blob on a TPM platform        INVALID_ARG: a caller bug, never a prompt
 */

/*
 * Leg 1. Creates this installation's attestation key, writes the JSON body the
 * backend relays to POST /api/v1/attest/enroll into buf, and writes the key's
 * blob into ak_blob. Unprivileged. Keep the blob: EnrollComplete, Attest and
 * MintKey all take it, and it is useless on any other TPM. macOS writes no
 * blob: *ak_len is 0 and ak_blob may be NULL.
 *
 * Both lengths are always set. If either buffer is too small nothing is
 * written, the key just created is kept on the session, and the next call on
 * this session hands it over without creating another; a call after RH_OK
 * creates a new key.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldEnrollBegin(
    _In_ RH_HANDLE h,
    _Out_writes_bytes_to_opt_(cap, *out_len) char* buf, size_t cap, _Out_ size_t* out_len,
    _Out_writes_bytes_to_opt_(ak_cap, *ak_len) uint8_t* ak_blob, size_t ak_cap, _Out_ size_t* ak_len);

/*
 * Leg 2. Consumes the credential the backend relayed back (the /enroll
 * response body, verbatim) under the blob EnrollBegin wrote, and writes the
 * JSON body for POST /api/v1/attest/activate. Windows: elevated, or
 * RH_ERR_ELEVATION_REQUIRED with nothing consumed. On RH_ERR_BUFFER_TOO_SMALL
 * the recovered proof is kept on the session and the next call hands it over
 * without activating again.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldEnrollComplete(
    _In_ RH_HANDLE h,
    _In_reads_bytes_(challenge_len) const char* challenge_json, size_t challenge_len,
    _Out_writes_bytes_to_opt_(cap, *out_len) char* buf, size_t cap, _Out_ size_t* out_len,
    _In_reads_bytes_opt_(ak_len) const uint8_t* ak_blob, size_t ak_len);

/* ------------------------------------------------------------------ */
/* 2. Mint a key                                                      */
/* ------------------------------------------------------------------ */

/*
 * Creates a new app key and has this installation's attestation key certify it
 * over the server's nonce: Create, Load, Certify, Flush. No elevation. The
 * purpose rides inside the key challenge; the call is the same for a sign key
 * and a decrypt key. Both purposes are served locally on Windows, Linux and
 * macOS (a macOS decrypt key is a second enclave key, protocol.h VARIANT B);
 * a purpose name the library does not know is RH_ERR_ASK_UNSUPPORTED on
 * every SDK.
 *
 * key_challenge  The string the backend relayed, verbatim:
 *                "rhk1c.<nonce>.<purpose>" (protocol.h). Anything else is
 *                RH_ERR_INVALID_ARG.
 * ak_blob        The blob EnrollBegin wrote. Required on a TPM platform (NULL
 *                is RH_ERR_INVALID_ARG); NULL with ak_len 0 on macOS.
 * certification  JSON the backend relays to POST /api/v1/keys/certify.
 * key_blob       The new key's blob, which only the app on the device can
 *                store. NULL or too small is RH_ERR_BUFFER_TOO_SMALL with
 *                *key_len set, like every other output buffer.
 *
 * Both lengths are always set. If either buffer is too small nothing is
 * written, the key just created is kept on the session, and the next call with
 * the same key_challenge hands it over without creating another.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldMintKey(
    _In_ RH_HANDLE h,
    _In_z_ const char* key_challenge,
    _In_reads_bytes_opt_(ak_len) const uint8_t* ak_blob, size_t ak_len,
    _Out_writes_bytes_to_opt_(cap, *len) char* certification, size_t cap, _Out_ size_t* len,
    _Out_writes_bytes_to_opt_(key_cap, *key_len) uint8_t* key_blob, size_t key_cap, _Out_ size_t* key_len);

/* ------------------------------------------------------------------ */
/* 3. Attest                                                          */
/* ------------------------------------------------------------------ */

/*
 * Answers a challenge with evidence and nothing else: never enrolls, never
 * mints, never elevates, never opens a socket.
 *
 * challenge   The string the backend relayed, verbatim: "rhc1.<nonce>.<ask>"
 *             (protocol.h). Anything else is RH_ERR_INVALID_ARG: there is one
 *             challenge format, and relaying the bare nonce instead of the
 *             challenge string is a caller bug worth failing loudly on.
 * ak_blob     The blob EnrollBegin wrote. Required on a TPM platform (NULL is
 *             RH_ERR_INVALID_ARG); NULL with ak_len 0 on macOS.
 * evidence    JSON: the object POST /api/v1/attest/verify expects in `evidence`.
 *
 * Attest does its TPM work before it knows the size, so a size query is not
 * free: it quotes. Prefer a generous first capacity (64 KiB) and grow once on
 * RH_ERR_BUFFER_TOO_SMALL.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldAttest(
    _In_ RH_HANDLE h,
    _In_z_ const char* challenge,
    _In_reads_bytes_opt_(ak_len) const uint8_t* ak_blob, size_t ak_len,
    _Out_writes_bytes_to_opt_(evidence_cap, *evidence_len) char* evidence, size_t evidence_cap, _Out_ size_t* evidence_len);

/* ------------------------------------------------------------------ */
/* App keys — no server, no nonce                                     */
/* ------------------------------------------------------------------ */

typedef enum { RH_KEY_PURPOSE_SIGN = 1, RH_KEY_PURPOSE_DECRYPT = 2 } RH_KEY_PURPOSE;

typedef enum {
    RH_KEY_ALG_ES256        = 1,   /* ECDSA P-256 / SHA-256; Sign emits r||s, 64 bytes */
    RH_KEY_ALG_RS256        = 2,   /* RSASSA-PKCS1-v1_5 / SHA-256; Sign emits 256 bytes */
    RH_KEY_ALG_ECDH_ES      = 3,   /* decrypt key, ECC P-256; Decrypt opens ECDH-ES + A256GCM */
    RH_KEY_ALG_RSA_OAEP_256 = 4    /* decrypt key, RSA-2048; Decrypt opens RSA-OAEP-256 + A256GCM */
} RH_KEY_ALG;

typedef struct {
    RH_KEY_PURPOSE purpose;
    RH_KEY_ALG     alg;
    size_t         signature_len;  /* bytes Sign writes; 0 for a decrypt key */
} RH_KEY_INFO;

/*
 * Loads a blob MintKey wrote and keeps it loaded for the life of the key
 * handle, so Sign is one TPM command rather than load, sign, flush. A loaded
 * key holds a TPM object slot until CloseKey.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldLoadKey(
    _In_ RH_HANDLE h,
    _In_reads_bytes_(blob_len) const uint8_t* key_blob, size_t blob_len,
    _Outptr_ RH_KEY_HANDLE* out_key);

/* The loaded key's purpose, algorithm and signature size, read from its public area. */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldKeyInfo(_In_ RH_KEY_HANDLE key, _Out_ RH_KEY_INFO* out);

/*
 * Signs arbitrary bytes with a sign key. No network, no nonce, no Root Herald
 * involvement: the backend verifies with the JWK /keys/certify handed it. A
 * signature proves possession at that moment, not how the machine booted.
 * The library hashes `data` with SHA-256; pass the message, not a digest.
 * The signature is RH_KEY_INFO.signature_len bytes: r||s for ES256, PKCS#1
 * v1.5 for RS256. A decrypt key is RH_ERR_INVALID_ARG.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldSign(
    _In_ RH_KEY_HANDLE key,
    _In_reads_bytes_(data_len) const uint8_t* data, size_t data_len,
    _Out_writes_bytes_to_opt_(sig_cap, *sig_len) uint8_t* sig, size_t sig_cap, _Out_ size_t* sig_len);

/*
 * Opens an envelope the backend's encryptToDevice addressed to this decrypt
 * key's public half, with the private half inside the TPM or enclave. No
 * network, no nonce, no Root Herald involvement. jwe is the string
 * encryptToDevice produced for the key's format (protocol.h, ENVELOPES): the
 * JWE compact serialization for a TPM key, the apple-ecies envelope for a
 * macOS key. The plaintext is never longer than the envelope, so an envelope
 * sized buffer never measures twice. A sign key is RH_ERR_INVALID_ARG; an
 * envelope that does not open is RH_ERR_DECRYPT_FAILED, with nothing written.
 *
 * Absent on iOS, where App Attest keys only sign: the Swift package has no
 * decrypt and a decrypt key challenge is refused there (VARIANT C).
 *
 * Any local process holding the blob can open everything ever sent to this
 * key: the key has an empty auth value and the blob is the credential.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldDecrypt(
    _In_ RH_KEY_HANDLE key,
    _In_reads_bytes_(jwe_len) const char* jwe, size_t jwe_len,
    _Out_writes_bytes_to_opt_(cap, *out_len) uint8_t* plaintext, size_t cap, _Out_ size_t* out_len);

/* Unloads the key. NULL is a no-op. Closing the session does this for every key. */
ROOTHERALD_API void RootHeraldCloseKey(_In_opt_ RH_KEY_HANDLE key);

/*
 * Whether a blob still loads: an attestation-key blob or an app-key blob. A
 * TPM loads and flushes it; macOS looks the key up in the keychain. RH_OK, or
 * RH_ERR_KEY_UNLOADABLE when it is gone for good.
 */
_Success_(return == RH_OK)
ROOTHERALD_API RH_STATUS RootHeraldCheckKey(
    _In_ RH_HANDLE h,
    _In_reads_bytes_opt_(blob_len) const uint8_t* blob, size_t blob_len);

/* ------------------------------------------------------------------ */
/* Utility                                                            */
/* ------------------------------------------------------------------ */

/* Static storage, valid for the life of the process; never freed. */
ROOTHERALD_API const char* RootHeraldErrorString(RH_STATUS status);
ROOTHERALD_API const char* RootHeraldAbiVersion(void);      /* "8.1" */
ROOTHERALD_API const char* RootHeraldLibraryVersion(void);  /* e.g. "0.6.0" */

#ifdef __cplusplus
}
#endif

#endif /* ROOTHERALD_H */
