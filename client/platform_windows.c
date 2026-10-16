#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

void PlatformInit(void)
{
    /* The backend's result lines are UTF-8 and carry an em dash. */
    SetConsoleOutputCP(CP_UTF8);
}

const char* ReadBackendUrl(void)
{
    static char url[1024];
    WCHAR wideUrl[1024];

    DWORD length = GetEnvironmentVariableW(L"SANDBOX_URL", wideUrl, ARRAYSIZE(wideUrl));
    if (length == 0 || length >= ARRAYSIZE(wideUrl)) {
        return DEFAULT_BACKEND_URL;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, wideUrl, -1, url, sizeof(url), NULL, NULL) == 0) {
        return DEFAULT_BACKEND_URL;
    }
    return url;
}

bool PostJson(const char* backendUrl, const char* route, const char* body, size_t bodyLen,
              long* httpStatus, char** response, size_t* responseLen)
{
    bool answered = false;
    DWORD error = 0;
    WCHAR wideUrl[1024];
    WCHAR wideRoute[256];
    WCHAR host[256];
    URL_COMPONENTS parts = { sizeof(parts) };
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    char* buffer = NULL;
    size_t bufferLen = 0;
    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;

    MultiByteToWideChar(CP_UTF8, 0, backendUrl, -1, wideUrl, ARRAYSIZE(wideUrl));
    MultiByteToWideChar(CP_UTF8, 0, route, -1, wideRoute, ARRAYSIZE(wideRoute));
    parts.lpszHostName = host;
    parts.dwHostNameLength = ARRAYSIZE(host);
    if (!WinHttpCrackUrl(wideUrl, 0, 0, &parts)) {
        printf("SANDBOX_URL is not a URL: %s\n", backendUrl);
        goto cleanup;
    }

    session = WinHttpOpen(L"sandbox-client", WINHTTP_ACCESS_TYPE_NO_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == NULL) {
        error = GetLastError();
        goto cleanup;
    }
    WinHttpSetTimeouts(session, 30000, 30000, 30000, 30000);
    connection = WinHttpConnect(session, host, parts.nPort, 0);
    if (connection == NULL) {
        error = GetLastError();
        goto cleanup;
    }
    request = WinHttpOpenRequest(connection, L"POST", wideRoute, NULL,
                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (request == NULL) {
        error = GetLastError();
        goto cleanup;
    }
    WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    if (!WinHttpSendRequest(request, L"Content-Type: application/json\r\n", (DWORD)-1L,
                            (LPVOID)body, (DWORD)bodyLen, (DWORD)bodyLen, 0)) {
        error = GetLastError();
        goto cleanup;
    }
    if (!WinHttpReceiveResponse(request, NULL)) {
        error = GetLastError();
        goto cleanup;
    }
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
        error = GetLastError();
        goto cleanup;
    }

    buffer = malloc(1);
    if (buffer == NULL) {
        goto cleanup;
    }
    for (;;) {
        DWORD available = 0;
        DWORD read = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) {
            error = GetLastError();
            goto cleanup;
        }
        if (available == 0) {
            break;
        }
        char* grown = realloc(buffer, bufferLen + available + 1);
        if (grown == NULL) {
            goto cleanup;
        }
        buffer = grown;
        if (!WinHttpReadData(request, buffer + bufferLen, available, &read)) {
            error = GetLastError();
            goto cleanup;
        }
        bufferLen += read;
    }
    buffer[bufferLen] = '\0';

    *httpStatus = (long)status;
    *response = buffer;
    *responseLen = bufferLen;
    buffer = NULL;
    answered = true;

cleanup:
    if (error != 0) {
        printf("HTTP to %s%s failed: error %lu\n", backendUrl, route, error);
    }
    free(buffer);
    if (request != NULL) {
        WinHttpCloseHandle(request);
    }
    if (connection != NULL) {
        WinHttpCloseHandle(connection);
    }
    if (session != NULL) {
        WinHttpCloseHandle(session);
    }
    return answered;
}

static bool StatePath(const char* name, WCHAR* path, int cap)
{
    char narrow[MAX_PATH];

    snprintf(narrow, sizeof(narrow), "%s/%s", SANDBOX_STATE_DIR, name);
    return MultiByteToWideChar(CP_UTF8, 0, narrow, -1, path, cap) != 0;
}

bool ReadStateFile(const char* name, uint8_t** data, size_t* dataLen)
{
    bool loaded = false;
    WCHAR path[MAX_PATH];
    uint8_t* bytes = NULL;
    LARGE_INTEGER size;
    DWORD read = 0;
    HANDLE file = INVALID_HANDLE_VALUE;

    if (!StatePath(name, path, ARRAYSIZE(path))) {
        return false;
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    if (!GetFileSizeEx(file, &size)) {
        goto cleanup;
    }

    bytes = malloc(size.QuadPart > 0 ? (size_t)size.QuadPart : 1);
    if (bytes == NULL) {
        goto cleanup;
    }
    if (!ReadFile(file, bytes, (DWORD)size.QuadPart, &read, NULL) || read != (DWORD)size.QuadPart) {
        goto cleanup;
    }

    *data = bytes;
    *dataLen = (size_t)size.QuadPart;
    bytes = NULL;
    loaded = true;

cleanup:
    free(bytes);
    CloseHandle(file);
    return loaded;
}

bool WriteStateFile(const char* name, const void* data, size_t dataLen)
{
    WCHAR directory[MAX_PATH];
    WCHAR path[MAX_PATH];
    DWORD written = 0;

    MultiByteToWideChar(CP_UTF8, 0, SANDBOX_STATE_DIR, -1, directory, ARRAYSIZE(directory));
    if (!CreateDirectoryW(directory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("Cannot create %s: error %lu\n", SANDBOX_STATE_DIR, GetLastError());
        return false;
    }

    if (!StatePath(name, path, ARRAYSIZE(path))) {
        return false;
    }
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("Cannot write %s/%s: error %lu\n", SANDBOX_STATE_DIR, name, GetLastError());
        return false;
    }
    bool ok = WriteFile(file, data, (DWORD)dataLen, &written, NULL) && written == (DWORD)dataLen;
    CloseHandle(file);
    if (!ok) {
        printf("Cannot write %s/%s\n", SANDBOX_STATE_DIR, name);
    }
    return ok;
}

void DeleteStateFile(const char* name)
{
    WCHAR path[MAX_PATH];

    if (StatePath(name, path, ARRAYSIZE(path))) {
        DeleteFileW(path);
    }
}

RH_STATUS RunElevatedEnrollmentStep(void)
{
    WCHAR program[MAX_PATH];
    DWORD exitCode = RH_ERR_INTERNAL;
    SHELLEXECUTEINFOW launch = { sizeof(launch) };

    if (GetModuleFileNameW(NULL, program, ARRAYSIZE(program)) == 0) {
        return RH_ERR_INTERNAL;
    }
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    launch.lpVerb = L"runas";
    launch.lpFile = program;
    launch.lpParameters = L"--complete-enrollment";
    launch.nShow = SW_HIDE;

    if (!ShellExecuteExW(&launch)) {
        return GetLastError() == ERROR_CANCELLED ? RH_ERR_ELEVATION_REQUIRED : RH_ERR_INTERNAL;
    }
    WaitForSingleObject(launch.hProcess, INFINITE);
    GetExitCodeProcess(launch.hProcess, &exitCode);
    CloseHandle(launch.hProcess);
    return (RH_STATUS)exitCode;
}
