/*
 * What differs between Windows and Linux: HTTP to the local backend, the
 * state files, and the elevated relaunch. platform_windows.c and
 * platform_linux.c each implement all of it.
 */

#ifndef SANDBOX_PLATFORM_H
#define SANDBOX_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rootherald.h"

#define DEFAULT_BACKEND_URL "http://127.0.0.1:47823"

void PlatformInit(void);

/* SANDBOX_URL when set, otherwise DEFAULT_BACKEND_URL. */
const char* ReadBackendUrl(void);

/*
 * POSTs body to backendUrl + route as application/json. Returns true when the
 * backend answered, with *httpStatus and the NUL-terminated *response, which
 * the caller frees. Returns false when there was no answer.
 */
_Success_(return)
bool PostJson(
    _In_z_ const char* backendUrl,
    _In_z_ const char* route,
    _In_reads_bytes_(bodyLen) const char* body, size_t bodyLen,
    _Out_ long* httpStatus,
    _Outptr_ char** response, _Out_ size_t* responseLen);

/* Files under SANDBOX_STATE_DIR, readable by this user only. */
_Success_(return)
bool ReadStateFile(_In_z_ const char* name, _Outptr_ uint8_t** data, _Out_ size_t* dataLen);

_Success_(return)
bool WriteStateFile(_In_z_ const char* name, _In_reads_bytes_(dataLen) const void* data, size_t dataLen);

void DeleteStateFile(_In_z_ const char* name);

/*
 * Starts this program again elevated with --complete-enrollment, waits for
 * it, and returns its exit code: the RH_STATUS of its RootHeraldEnrollComplete.
 * RH_ERR_ELEVATION_REQUIRED when the user declines the prompt.
 */
RH_STATUS RunElevatedEnrollmentStep(void);

#endif /* SANDBOX_PLATFORM_H */
