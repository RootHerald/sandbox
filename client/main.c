/*
 * The device half of the RootHerald sandbox: enrollment, attestation, signing
 * and decryption with the RootHerald SDK, each step sent to the local backend,
 * which holds the key and calls RootHerald. The program holds no RootHerald
 * key and talks to nothing but that backend.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rootherald.h"
#include "platform.h"

#if ROOTHERALD_ABI_VERSION_MAJOR != 8 || ROOTHERALD_ABI_VERSION_MINOR < 1
#error "This sample is written against RootHerald ABI 8.1."
#endif

/* Each use case's outcome, and the program's exit code. */
typedef enum {
    STEP_OK = 0,        /* carry on */
    STEP_FAILED = 1,    /* a local SDK or HTTP failure */
    STEP_STOPPED = 2    /* the backend answered with a non-2xx status */
} STEP_RESULT;

static const char* AK_BLOB_FILE = "ak.blob";
static const char* ENROLL_AK_BLOB_FILE = "enroll-ak.blob";
static const char* ENROLL_CHALLENGE_FILE = "enroll-challenge.json";
static const char* ENROLL_ACTIVATE_FILE = "enroll-activate.json";

static STEP_RESULT PostRoute(const char* backendUrl, const char* route, const char* body, size_t bodyLen,
                             long* httpStatus, char** response, size_t* responseLen);
static STEP_RESULT ReadResponseField(const char* response, size_t responseLen, const char* name, char** value);
static int ReadStringField(const char* json, size_t len, const char* name, char* out, size_t cap);
static void Base64UrlEncode(const uint8_t* data, size_t len, char* out);

static STEP_RESULT SdkFailed(const char* verb, RH_STATUS status)
{
    printf("%s failed: %s\n", verb, RootHeraldErrorString(status));
    return STEP_FAILED;
}

/*
 * Enrollment: create this installation's attestation key, have the backend
 * relay it to RootHerald, and answer the credential RootHerald sends back.
 * On success *akBlob holds the attestation key blob, also written to state/.
 */
static STEP_RESULT RunEnrollment(RH_HANDLE session, const char* backendUrl, uint8_t** akBlob, size_t* akLen)
{
    STEP_RESULT result = STEP_FAILED;
    RH_STATUS status;
    char* beginBody = NULL;
    size_t beginLen = 0;
    uint8_t* blob = NULL;
    size_t blobLen = 0;
    char* response = NULL;
    size_t responseLen = 0;
    long httpStatus = 0;
    char* challenge = NULL;
    char* activateBody = NULL;
    size_t activateLen = 0;

    /* The first call only measures; the key it creates is kept for the second. */
    status = RootHeraldEnrollBegin(session, NULL, 0, &beginLen, NULL, 0, &blobLen);
    if (status != RH_ERR_BUFFER_TOO_SMALL) {
        result = SdkFailed("RootHeraldEnrollBegin", status);
        goto cleanup;
    }
    beginBody = malloc(beginLen);
    blob = malloc(blobLen);
    if (beginBody == NULL || blob == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    /* A real app protects the blob at rest, for example with DPAPI. */
    status = RootHeraldEnrollBegin(session, beginBody, beginLen, &beginLen, blob, blobLen, &blobLen);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldEnrollBegin", status);
        goto cleanup;
    }
    printf("  RootHeraldEnrollBegin: %zu bytes\n", beginLen - 1);

    result = PostRoute(backendUrl, "/enroll/begin", beginBody, beginLen - 1, &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /enroll/begin\n");
    }
    if (result != STEP_OK) {
        goto cleanup;
    }
    result = ReadResponseField(response, responseLen, "enrollChallenge", &challenge);
    if (result != STEP_OK) {
        goto cleanup;
    }

    activateLen = 4096;
    activateBody = malloc(activateLen);
    if (activateBody == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    status = RootHeraldEnrollComplete(session, challenge, strlen(challenge),
                                      activateBody, activateLen, &activateLen, blob, blobLen);
    if (status == RH_ERR_BUFFER_TOO_SMALL) {
        free(activateBody);
        activateBody = malloc(activateLen);
        if (activateBody == NULL) {
            result = STEP_FAILED;
            goto cleanup;
        }
        status = RootHeraldEnrollComplete(session, challenge, strlen(challenge),
                                          activateBody, activateLen, &activateLen, blob, blobLen);
    }

    if (status == RH_ERR_ELEVATION_REQUIRED) {
        printf("Elevation required: relaunching for RootHeraldEnrollComplete\n");
        free(activateBody);
        activateBody = NULL;
        if (!WriteStateFile(ENROLL_AK_BLOB_FILE, blob, blobLen) ||
            !WriteStateFile(ENROLL_CHALLENGE_FILE, challenge, strlen(challenge))) {
            result = STEP_FAILED;
            goto cleanup;
        }
        status = RunElevatedEnrollmentStep();
        if (status == RH_ERR_ELEVATION_REQUIRED) {
            printf("Elevation declined: %s\n", RootHeraldErrorString(status));
            result = STEP_FAILED;
            goto cleanup;
        }
        if (status != RH_OK) {
            result = SdkFailed("RootHeraldEnrollComplete", status);
            goto cleanup;
        }
        if (!ReadStateFile(ENROLL_ACTIVATE_FILE, (uint8_t**)&activateBody, &activateLen)) {
            printf("The elevated step wrote no %s\n", ENROLL_ACTIVATE_FILE);
            result = STEP_FAILED;
            goto cleanup;
        }
    } else if (status != RH_OK) {
        result = SdkFailed("RootHeraldEnrollComplete", status);
        goto cleanup;
    } else {
        activateLen -= 1;
    }
    printf("  RootHeraldEnrollComplete: %zu bytes\n", activateLen);

    free(response);
    response = NULL;
    result = PostRoute(backendUrl, "/enroll/complete", activateBody, activateLen, &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /enroll/complete\n");
    }
    if (result != STEP_OK) {
        goto cleanup;
    }

    if (!WriteStateFile(AK_BLOB_FILE, blob, blobLen)) {
        result = STEP_FAILED;
        goto cleanup;
    }
    *akBlob = blob;
    *akLen = blobLen;
    blob = NULL;

cleanup:
    DeleteStateFile(ENROLL_AK_BLOB_FILE);
    DeleteStateFile(ENROLL_CHALLENGE_FILE);
    DeleteStateFile(ENROLL_ACTIVATE_FILE);
    free(activateBody);
    free(challenge);
    free(response);
    free(blob);
    free(beginBody);
    return result;
}

/*
 * The elevated relaunch on Windows: RootHeraldEnrollComplete alone, from the
 * files the unelevated process wrote. It makes no HTTP call and keeps no
 * attestation key; the process that started it does both.
 */
static RH_STATUS CompleteEnrollmentElevated(void)
{
    RH_STATUS status = RH_ERR_NOT_ENROLLED;
    RH_HANDLE session = NULL;
    uint8_t* blob = NULL;
    size_t blobLen = 0;
    uint8_t* challenge = NULL;
    size_t challengeLen = 0;
    char* activateBody = NULL;
    size_t activateLen = 4096;

    if (!ReadStateFile(ENROLL_AK_BLOB_FILE, &blob, &blobLen) ||
        !ReadStateFile(ENROLL_CHALLENGE_FILE, &challenge, &challengeLen)) {
        printf("Nothing to complete: no %s in %s\n", ENROLL_AK_BLOB_FILE, SANDBOX_STATE_DIR);
        goto cleanup;
    }

    status = RootHeraldOpen(&session);
    if (status != RH_OK) {
        goto cleanup;
    }
    activateBody = malloc(activateLen);
    if (activateBody == NULL) {
        status = RH_ERR_INTERNAL;
        goto cleanup;
    }
    /* A retry after BUFFER_TOO_SMALL must use this session, which holds the recovered proof. */
    status = RootHeraldEnrollComplete(session, (const char*)challenge, challengeLen,
                                      activateBody, activateLen, &activateLen, blob, blobLen);
    if (status == RH_ERR_BUFFER_TOO_SMALL) {
        free(activateBody);
        activateBody = malloc(activateLen);
        if (activateBody == NULL) {
            status = RH_ERR_INTERNAL;
            goto cleanup;
        }
        status = RootHeraldEnrollComplete(session, (const char*)challenge, challengeLen,
                                          activateBody, activateLen, &activateLen, blob, blobLen);
    }
    if (status != RH_OK) {
        goto cleanup;
    }
    if (!WriteStateFile(ENROLL_ACTIVATE_FILE, activateBody, activateLen - 1)) {
        status = RH_ERR_INTERNAL;
    }

cleanup:
    RootHeraldClose(session);
    free(activateBody);
    free(challenge);
    free(blob);
    return status;
}

/*
 * Attestation: answer a fresh challenge with evidence and have the backend
 * verify it. When the backend says the device is not enrolled, enroll and try
 * once more.
 */
static STEP_RESULT RunAttestation(RH_HANDLE session, const char* backendUrl, uint8_t** akBlob, size_t* akLen,
                                  bool mayEnroll)
{
    STEP_RESULT result = STEP_FAILED;
    RH_STATUS status;
    char* response = NULL;
    size_t responseLen = 0;
    long httpStatus = 0;
    char* challenge = NULL;
    char* evidence = NULL;
    size_t evidenceLen = 64 * 1024;

    result = PostRoute(backendUrl, "/attest/challenge", "{}", 2, &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /attest/challenge\n");
    }
    if (result != STEP_OK) {
        goto cleanup;
    }
    result = ReadResponseField(response, responseLen, "challenge", &challenge);
    if (result != STEP_OK) {
        goto cleanup;
    }

    /* Attest quotes before it knows the size, so start large and grow once. */
    evidence = malloc(evidenceLen);
    if (evidence == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    status = RootHeraldAttest(session, challenge, *akBlob, *akLen, evidence, evidenceLen, &evidenceLen);
    if (status == RH_ERR_BUFFER_TOO_SMALL) {
        free(evidence);
        evidence = malloc(evidenceLen);
        if (evidence == NULL) {
            result = STEP_FAILED;
            goto cleanup;
        }
        status = RootHeraldAttest(session, challenge, *akBlob, *akLen, evidence, evidenceLen, &evidenceLen);
    }
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldAttest", status);
        goto cleanup;
    }
    printf("  RootHeraldAttest: %zu bytes\n", evidenceLen - 1);

    free(response);
    response = NULL;
    result = PostRoute(backendUrl, "/attest/verify", evidence, evidenceLen - 1, &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED && httpStatus == 409 && mayEnroll) {
        DeleteStateFile(AK_BLOB_FILE);
        free(*akBlob);
        *akBlob = NULL;
        *akLen = 0;
        result = RunEnrollment(session, backendUrl, akBlob, akLen);
        if (result == STEP_OK) {
            result = RunAttestation(session, backendUrl, akBlob, akLen, false);
        }
        goto cleanup;
    }
    if (result == STEP_STOPPED) {
        printf("stopped at /attest/verify\n");
    }

cleanup:
    free(evidence);
    free(challenge);
    free(response);
    return result;
}

/*
 * Signing: mint a sign key the attestation key certifies, have the backend
 * certify it, sign the message the backend returns, and have it check the
 * signature.
 */
static STEP_RESULT RunSigning(RH_HANDLE session, const char* backendUrl, const uint8_t* akBlob, size_t akLen)
{
    STEP_RESULT result = STEP_FAILED;
    RH_STATUS status;
    char* response = NULL;
    size_t responseLen = 0;
    long httpStatus = 0;
    char* keyChallenge = NULL;
    char* certification = NULL;
    size_t certificationLen = 0;
    uint8_t* keyBlob = NULL;
    size_t keyBlobLen = 0;
    char* message = NULL;
    RH_KEY_HANDLE key = NULL;
    RH_KEY_INFO info;
    uint8_t* signature = NULL;
    size_t signatureLen = 0;
    char* encoded = NULL;
    char* verifyBody = NULL;

    result = PostRoute(backendUrl, "/sign/challenge", "{}", 2, &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /sign/challenge\n");
    }
    if (result != STEP_OK) {
        goto cleanup;
    }
    result = ReadResponseField(response, responseLen, "keyChallenge", &keyChallenge);
    if (result != STEP_OK) {
        goto cleanup;
    }

    /* The first call only measures; the key it creates is kept for the second. */
    status = RootHeraldMintKey(session, keyChallenge, akBlob, akLen, NULL, 0, &certificationLen, NULL, 0, &keyBlobLen);
    if (status != RH_ERR_BUFFER_TOO_SMALL) {
        result = SdkFailed("RootHeraldMintKey", status);
        goto cleanup;
    }
    certification = malloc(certificationLen);
    keyBlob = malloc(keyBlobLen);
    if (certification == NULL || keyBlob == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    status = RootHeraldMintKey(session, keyChallenge, akBlob, akLen,
                               certification, certificationLen, &certificationLen, keyBlob, keyBlobLen, &keyBlobLen);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldMintKey", status);
        goto cleanup;
    }
    printf("  RootHeraldMintKey: %zu bytes\n", certificationLen - 1);

    free(response);
    response = NULL;
    result = PostRoute(backendUrl, "/sign/certify", certification, certificationLen - 1, &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /sign/certify\n");
    }
    if (result != STEP_OK) {
        goto cleanup;
    }
    result = ReadResponseField(response, responseLen, "message", &message);
    if (result != STEP_OK) {
        goto cleanup;
    }

    status = RootHeraldLoadKey(session, keyBlob, keyBlobLen, &key);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldLoadKey", status);
        goto cleanup;
    }
    status = RootHeraldKeyInfo(key, &info);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldKeyInfo", status);
        goto cleanup;
    }
    signature = malloc(info.signature_len);
    if (signature == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    /* The backend checks a signature over the message's UTF-8 bytes. */
    status = RootHeraldSign(key, (const uint8_t*)message, strlen(message), signature, info.signature_len, &signatureLen);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldSign", status);
        goto cleanup;
    }
    printf("  RootHeraldSign: %zu bytes\n", signatureLen);

    encoded = malloc((signatureLen + 2) / 3 * 4 + 1);
    if (encoded == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    Base64UrlEncode(signature, signatureLen, encoded);
    size_t verifyCap = strlen(encoded) + 32;
    verifyBody = malloc(verifyCap);
    if (verifyBody == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    snprintf(verifyBody, verifyCap, "{\"signature\":\"%s\"}", encoded);

    free(response);
    response = NULL;
    result = PostRoute(backendUrl, "/sign/verify", verifyBody, strlen(verifyBody), &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /sign/verify\n");
    }

cleanup:
    RootHeraldCloseKey(key);
    free(verifyBody);
    free(encoded);
    free(signature);
    free(message);
    free(keyBlob);
    free(certification);
    free(keyChallenge);
    free(response);
    return result;
}

/*
 * Decryption: mint a decrypt key the attestation key certifies, have the
 * backend certify it and encrypt a secret to it, open the envelope, and send
 * the secret back for the backend to compare.
 */
static STEP_RESULT RunDecryption(RH_HANDLE session, const char* backendUrl, const uint8_t* akBlob, size_t akLen)
{
    STEP_RESULT result = STEP_FAILED;
    RH_STATUS status;
    char* response = NULL;
    size_t responseLen = 0;
    long httpStatus = 0;
    char* keyChallenge = NULL;
    char* certification = NULL;
    size_t certificationLen = 0;
    uint8_t* keyBlob = NULL;
    size_t keyBlobLen = 0;
    char* jwe = NULL;
    RH_KEY_HANDLE key = NULL;
    uint8_t* plaintext = NULL;
    size_t plaintextLen = 0;
    char* encoded = NULL;
    char* verifyBody = NULL;

    result = PostRoute(backendUrl, "/decrypt/challenge", "{}", 2, &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /decrypt/challenge\n");
    }
    if (result != STEP_OK) {
        goto cleanup;
    }
    result = ReadResponseField(response, responseLen, "keyChallenge", &keyChallenge);
    if (result != STEP_OK) {
        goto cleanup;
    }

    status = RootHeraldMintKey(session, keyChallenge, akBlob, akLen, NULL, 0, &certificationLen, NULL, 0, &keyBlobLen);
    if (status != RH_ERR_BUFFER_TOO_SMALL) {
        result = SdkFailed("RootHeraldMintKey", status);
        goto cleanup;
    }
    certification = malloc(certificationLen);
    keyBlob = malloc(keyBlobLen);
    if (certification == NULL || keyBlob == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    status = RootHeraldMintKey(session, keyChallenge, akBlob, akLen,
                               certification, certificationLen, &certificationLen, keyBlob, keyBlobLen, &keyBlobLen);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldMintKey", status);
        goto cleanup;
    }
    printf("  RootHeraldMintKey: %zu bytes\n", certificationLen - 1);

    free(response);
    response = NULL;
    result = PostRoute(backendUrl, "/decrypt/certify", certification, certificationLen - 1, &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /decrypt/certify\n");
    }
    if (result != STEP_OK) {
        goto cleanup;
    }
    result = ReadResponseField(response, responseLen, "jwe", &jwe);
    if (result != STEP_OK) {
        goto cleanup;
    }

    status = RootHeraldLoadKey(session, keyBlob, keyBlobLen, &key);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldLoadKey", status);
        goto cleanup;
    }
    /* The plaintext is never longer than the envelope. */
    plaintext = malloc(strlen(jwe));
    if (plaintext == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    status = RootHeraldDecrypt(key, jwe, strlen(jwe), plaintext, strlen(jwe), &plaintextLen);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldDecrypt", status);
        goto cleanup;
    }
    printf("  RootHeraldDecrypt: %zu bytes\n", plaintextLen);

    encoded = malloc((plaintextLen + 2) / 3 * 4 + 1);
    if (encoded == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    Base64UrlEncode(plaintext, plaintextLen, encoded);
    size_t verifyCap = strlen(encoded) + 32;
    verifyBody = malloc(verifyCap);
    if (verifyBody == NULL) {
        result = STEP_FAILED;
        goto cleanup;
    }
    snprintf(verifyBody, verifyCap, "{\"plaintext\":\"%s\"}", encoded);

    free(response);
    response = NULL;
    result = PostRoute(backendUrl, "/decrypt/verify", verifyBody, strlen(verifyBody), &httpStatus, &response, &responseLen);
    if (result == STEP_STOPPED) {
        printf("stopped at /decrypt/verify\n");
    }

cleanup:
    RootHeraldCloseKey(key);
    free(verifyBody);
    free(encoded);
    free(plaintext);
    free(jwe);
    free(keyBlob);
    free(certification);
    free(keyChallenge);
    free(response);
    return result;
}

int main(int argc, char** argv)
{
    STEP_RESULT result = STEP_FAILED;
    RH_STATUS status;
    RH_HANDLE session = NULL;
    RH_POSTURE posture;
    uint8_t* akBlob = NULL;
    size_t akLen = 0;

    if (argc > 1 && strcmp(argv[1], "--complete-enrollment") == 0) {
        return (int)CompleteEnrollmentElevated();
    }

    PlatformInit();
    const char* backendUrl = ReadBackendUrl();
    const char* libraryVersion = RootHeraldLibraryVersion();
    printf("RootHerald SDK: ABI %s, library %s\n", RootHeraldAbiVersion(), libraryVersion);
    printf("Backend: %s\n", backendUrl);
    printf("State: %s\n", SANDBOX_STATE_DIR);
    if (strncmp(libraryVersion, "stub-", 5) == 0) {
        printf("This is the SDK's stub library, which has no TPM code; link the release library.\n");
        return STEP_FAILED;
    }

    status = RootHeraldOpen(&session);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldOpen", status);
        goto cleanup;
    }
    status = RootHeraldPreCheck(session, &posture);
    if (status != RH_OK) {
        result = SdkFailed("RootHeraldPreCheck", status);
        goto cleanup;
    }
    printf("Platform: %s\n", posture.platform_name);

    if (ReadStateFile(AK_BLOB_FILE, &akBlob, &akLen)) {
        status = RootHeraldCheckKey(session, akBlob, akLen);
        if (status == RH_OK) {
            printf("Enrollment skipped: state/%s loads\n", AK_BLOB_FILE);
        } else if (status == RH_ERR_KEY_UNLOADABLE) {
            printf("state/%s no longer loads: %s\n", AK_BLOB_FILE, RootHeraldErrorString(status));
            DeleteStateFile(AK_BLOB_FILE);
            free(akBlob);
            akBlob = NULL;
            akLen = 0;
        } else {
            result = SdkFailed("RootHeraldCheckKey", status);
            goto cleanup;
        }
    }

    result = STEP_OK;
    if (akBlob == NULL) {
        result = RunEnrollment(session, backendUrl, &akBlob, &akLen);
    }
    if (result == STEP_OK) {
        result = RunAttestation(session, backendUrl, &akBlob, &akLen, true);
    }
    if (result == STEP_OK) {
        result = RunSigning(session, backendUrl, akBlob, akLen);
    }
    if (result == STEP_OK) {
        result = RunDecryption(session, backendUrl, akBlob, akLen);
    }

cleanup:
    free(akBlob);
    RootHeraldClose(session);
    return (int)result;
}

/*
 * POSTs one route, prints "  POST <route>  <result>", and returns STEP_OK for
 * a 2xx, STEP_STOPPED otherwise. The caller prints where the run stopped.
 */
static STEP_RESULT PostRoute(const char* backendUrl, const char* route, const char* body, size_t bodyLen,
                             long* httpStatus, char** response, size_t* responseLen)
{
    char* line = NULL;

    if (!PostJson(backendUrl, route, body, bodyLen, httpStatus, response, responseLen)) {
        return STEP_FAILED;
    }
    if (ReadResponseField(*response, *responseLen, "result", &line) != STEP_OK) {
        printf("  POST %s  HTTP %ld\n", route, *httpStatus);
        return STEP_FAILED;
    }
    printf("  POST %s  %s\n", route, line);
    free(line);
    return (*httpStatus >= 200 && *httpStatus < 300) ? STEP_OK : STEP_STOPPED;
}

/* Copies one string field of the backend's response into a buffer the caller frees. */
static STEP_RESULT ReadResponseField(const char* response, size_t responseLen, const char* name, char** value)
{
    char* field = malloc(responseLen + 1);
    if (field == NULL) {
        return STEP_FAILED;
    }
    if (ReadStringField(response, responseLen, name, field, responseLen + 1) < 0) {
        printf("The backend's response has no \"%s\" field\n", name);
        free(field);
        return STEP_FAILED;
    }
    *value = field;
    return STEP_OK;
}

static unsigned int HexDigit(char c)
{
    if (c >= '0' && c <= '9') return (unsigned int)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (unsigned int)(c - 'A' + 10);
    return 16;
}

/*
 * Finds "name":"..." in the backend's response, a flat JSON object whose
 * values are all strings, and unescapes the value into out as UTF-8. Returns
 * the value's length, or -1 when the field is absent or the JSON is not that
 * shape. An unescaped value is never longer than its escaped form.
 */
static int ReadStringField(const char* json, size_t len, const char* name, char* out, size_t cap)
{
    size_t i = 0;
    bool readingKey = true;
    bool keyMatches = false;

    while (i < len && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t')) i++;
    if (i >= len || json[i] != '{') return -1;
    i++;

    for (;;) {
        while (i < len && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t' || json[i] == ',')) i++;
        if (i >= len || json[i] != '"') return -1;
        i++;

        size_t n = 0;
        while (i < len && json[i] != '"') {
            unsigned long c = (unsigned char)json[i++];
            if (c == '\\') {
                if (i >= len) return -1;
                char escape = json[i++];
                switch (escape) {
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u':
                    c = 0;
                    for (int k = 0; k < 4; k++) {
                        if (i >= len || HexDigit(json[i]) > 15) return -1;
                        c = (c << 4) | HexDigit(json[i++]);
                    }
                    /* A character beyond the BMP arrives as a surrogate pair. */
                    if (c >= 0xD800 && c <= 0xDBFF && i + 6 <= len && json[i] == '\\' && json[i + 1] == 'u') {
                        unsigned long low = 0;
                        for (int k = 2; k < 6; k++) {
                            if (HexDigit(json[i + k]) > 15) return -1;
                            low = (low << 4) | HexDigit(json[i + k]);
                        }
                        if (low >= 0xDC00 && low <= 0xDFFF) {
                            c = 0x10000 + ((c - 0xD800) << 10) + (low - 0xDC00);
                            i += 6;
                        }
                    }
                    break;
                default:
                    return -1;
                }
                if (n + 4 >= cap) return -1;
                if (c < 0x80) {
                    out[n++] = (char)c;
                } else if (c < 0x800) {
                    out[n++] = (char)(0xC0 | (c >> 6));
                    out[n++] = (char)(0x80 | (c & 0x3F));
                } else if (c < 0x10000) {
                    out[n++] = (char)(0xE0 | (c >> 12));
                    out[n++] = (char)(0x80 | ((c >> 6) & 0x3F));
                    out[n++] = (char)(0x80 | (c & 0x3F));
                } else {
                    out[n++] = (char)(0xF0 | (c >> 18));
                    out[n++] = (char)(0x80 | ((c >> 12) & 0x3F));
                    out[n++] = (char)(0x80 | ((c >> 6) & 0x3F));
                    out[n++] = (char)(0x80 | (c & 0x3F));
                }
            } else {
                if (n + 1 >= cap) return -1;
                out[n++] = (char)c;
            }
        }
        if (i >= len) return -1;
        i++;
        out[n] = '\0';

        if (readingKey) {
            keyMatches = strcmp(out, name) == 0;
            while (i < len && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t')) i++;
            if (i >= len || json[i] != ':') return -1;
            i++;
            while (i < len && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t')) i++;
            readingKey = false;
        } else {
            if (keyMatches) return (int)n;
            readingKey = true;
        }
    }
}

/* Unpadded base64url into out, which holds at least 4 * ceil(len / 3) + 1 bytes. */
static void Base64UrlEncode(const uint8_t* data, size_t len, char* out)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t n = 0;

    for (size_t i = 0; i < len; i += 3) {
        unsigned long triple = (unsigned long)data[i] << 16;
        if (i + 1 < len) triple |= (unsigned long)data[i + 1] << 8;
        if (i + 2 < len) triple |= data[i + 2];
        out[n++] = alphabet[(triple >> 18) & 0x3F];
        out[n++] = alphabet[(triple >> 12) & 0x3F];
        if (i + 1 < len) out[n++] = alphabet[(triple >> 6) & 0x3F];
        if (i + 2 < len) out[n++] = alphabet[triple & 0x3F];
    }
    out[n] = '\0';
}
