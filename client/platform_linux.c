#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>

#include "platform.h"

typedef struct {
    char*  data;
    size_t len;
} RESPONSE_BUFFER;

void PlatformInit(void)
{
}

const char* ReadBackendUrl(void)
{
    const char* url = getenv("SANDBOX_URL");
    return (url != NULL && url[0] != '\0') ? url : DEFAULT_BACKEND_URL;
}

static size_t AppendResponse(char* data, size_t size, size_t count, void* context)
{
    RESPONSE_BUFFER* buffer = context;
    size_t bytes = size * count;
    char* grown = realloc(buffer->data, buffer->len + bytes + 1);
    if (grown == NULL) {
        return 0;
    }
    memcpy(grown + buffer->len, data, bytes);
    buffer->data = grown;
    buffer->len += bytes;
    buffer->data[buffer->len] = '\0';
    return bytes;
}

bool PostJson(const char* backendUrl, const char* route, const char* body, size_t bodyLen,
              long* httpStatus, char** response, size_t* responseLen)
{
    bool answered = false;
    char url[1024];
    RESPONSE_BUFFER buffer = { NULL, 0 };
    struct curl_slist* headers = NULL;
    CURL* curl = curl_easy_init();
    if (curl == NULL) {
        goto cleanup;
    }

    snprintf(url, sizeof(url), "%s%s", backendUrl, route);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)bodyLen);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, AppendResponse);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

    CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        printf("HTTP to %s failed: %s\n", url, curl_easy_strerror(code));
        goto cleanup;
    }
    if (buffer.data == NULL) {
        buffer.data = calloc(1, 1);
        if (buffer.data == NULL) {
            goto cleanup;
        }
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, httpStatus);
    *response = buffer.data;
    *responseLen = buffer.len;
    buffer.data = NULL;
    answered = true;

cleanup:
    free(buffer.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return answered;
}

static void StatePath(const char* name, char* path, size_t cap)
{
    snprintf(path, cap, "%s/%s", SANDBOX_STATE_DIR, name);
}

bool ReadStateFile(const char* name, uint8_t** data, size_t* dataLen)
{
    bool loaded = false;
    char path[4096];
    uint8_t* bytes = NULL;
    struct stat info;

    StatePath(name, path, sizeof(path));
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    if (fstat(fd, &info) != 0) {
        goto cleanup;
    }

    size_t size = (size_t)info.st_size;
    bytes = malloc(size > 0 ? size : 1);
    if (bytes == NULL) {
        goto cleanup;
    }
    if (read(fd, bytes, size) != (ssize_t)size) {
        goto cleanup;
    }

    *data = bytes;
    *dataLen = size;
    bytes = NULL;
    loaded = true;

cleanup:
    free(bytes);
    close(fd);
    return loaded;
}

bool WriteStateFile(const char* name, const void* data, size_t dataLen)
{
    char path[4096];

    if (mkdir(SANDBOX_STATE_DIR, 0700) != 0 && errno != EEXIST) {
        printf("Cannot create %s: %s\n", SANDBOX_STATE_DIR, strerror(errno));
        return false;
    }

    StatePath(name, path, sizeof(path));
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("Cannot write %s: %s\n", path, strerror(errno));
        return false;
    }
    bool written = write(fd, data, dataLen) == (ssize_t)dataLen;
    if (close(fd) != 0) {
        written = false;
    }
    if (!written) {
        printf("Cannot write %s\n", path);
    }
    return written;
}

void DeleteStateFile(const char* name)
{
    char path[4096];

    StatePath(name, path, sizeof(path));
    unlink(path);
}

RH_STATUS RunElevatedEnrollmentStep(void)
{
    /* Only Windows answers RootHeraldEnrollComplete with RH_ERR_ELEVATION_REQUIRED. */
    return RH_ERR_ELEVATION_REQUIRED;
}
