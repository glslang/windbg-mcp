/* Deterministic VTL0 Secure Kernel call workload.
 *
 * Each labelled invocation creates, loads, initializes, terminates and deletes a debug VBS
 * enclave. Creating an empty reservation alone does not enter the Secure Kernel on current
 * Windows builds; loading and initializing a valid enclave image are the supported operations
 * that drive the VTL0-to-VTL1 service path observed at nt!VslpEnterIumSecureMode. This harness
 * depends on no private address or service ABI.
 *
 * Build with tools/build_skcall_guest_harness.ps1, copy the executable into the disposable guest,
 * and run:
 *
 *   skcall_guest_harness.exe <label> [count] [startup-delay-ms] [output-jsonl] [error-log]
 *                            [enclave-image]
 *
 * Output is one JSON line per invocation. Labels are intentionally restricted to a small ASCII
 * alphabet so the output needs no ambiguous JSON escaping and can be joined to the debugger trace
 * verbatim.
 */

#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <enclaveapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int valid_label(const wchar_t *label)
{
    size_t length = wcslen(label);
    if (length == 0 || length > 64) {
        return 0;
    }
    for (size_t i = 0; i < length; i++) {
        wchar_t c = label[i];
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
              (c >= L'0' && c <= L'9') || c == L'-' || c == L'_' || c == L'.')) {
            return 0;
        }
    }
    return 1;
}

static ULONGLONG qpc_us(void)
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER now;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&now);
    /* Split the quotient so a long host uptime cannot overflow the multiply. */
    return (ULONGLONG)(now.QuadPart / frequency.QuadPart) * 1000000ULL +
           (ULONGLONG)((now.QuadPart % frequency.QuadPart) * 1000000ULL /
                       frequency.QuadPart);
}

static int default_image_path(wchar_t *path, size_t capacity)
{
    DWORD length = GetModuleFileNameW(NULL, path, (DWORD)capacity);
    if (length == 0 || length >= capacity) {
        return 0;
    }
    wchar_t *slash = wcsrchr(path, L'\\');
    if (!slash) {
        return 0;
    }
    size_t prefix = (size_t)(slash + 1 - path);
    return wcscpy_s(path + prefix, capacity - prefix, L"spin_enclave.dll") == 0;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2 || argc > 7 || !valid_label(argv[1])) {
        fwprintf(stderr,
                 L"usage: %ls <label:[A-Za-z0-9_.-]{1,64}> [count:1-1000] "
                 L"[startup-delay-ms:0-30000] [output-jsonl] [error-log] [enclave-image]\n",
                 argv[0]);
        return 2;
    }

    /* A debugger stop must not retain a PowerShell Direct output pipe. The live qualification
     * passes owned files and launches through Win32_Process.Create, so redirect before sleeping
     * or making the first VBS call. */
    FILE *redirected = NULL;
    if (argc >= 6 && _wfreopen_s(&redirected, argv[5], L"w", stderr) != 0) {
        return 4;
    }
    if (argc >= 5 && _wfreopen_s(&redirected, argv[4], L"w", stdout) != 0) {
        fwprintf(stderr, L"could not open output JSONL file\n");
        return 4;
    }

    wchar_t *end = NULL;
    unsigned long count = (argc >= 3) ? wcstoul(argv[2], &end, 10) : 1;
    if (count == 0 || count > 1000 || (argc >= 3 && (!end || *end != L'\0'))) {
        fwprintf(stderr, L"count must be an integer from 1 through 1000\n");
        return 2;
    }
    end = NULL;
    unsigned long startup_delay_ms = (argc >= 4) ? wcstoul(argv[3], &end, 10) : 0;
    if (startup_delay_ms > 30000 || (argc >= 4 && (!end || *end != L'\0'))) {
        fwprintf(stderr, L"startup delay must be an integer from 0 through 30000 ms\n");
        return 2;
    }
    if (startup_delay_ms != 0) {
        Sleep(startup_delay_ms);
    }
    if (!IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS)) {
        fwprintf(stderr, L"VBS enclaves are not supported (Win32 %lu)\n", GetLastError());
        return 3;
    }
    wchar_t default_image[MAX_PATH];
    const wchar_t *image_path = argc >= 7 ? argv[6] : default_image;
    if (argc < 7 && !default_image_path(default_image, ARRAYSIZE(default_image))) {
        fwprintf(stderr, L"could not derive the adjacent VBS enclave image path\n");
        return 3;
    }
    if (GetFileAttributesW(image_path) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"VBS enclave image is missing: %ls (Win32 %lu)\n",
                 image_path, GetLastError());
        return 3;
    }
    ENCLAVE_CREATE_INFO_VBS info;
    ZeroMemory(&info, sizeof(info));
    info.Flags = ENCLAVE_VBS_FLAG_DEBUG;
    memset(info.OwnerID, 0x4D, sizeof(info.OwnerID));

    const SIZE_T enclave_size = 0x10000000; /* 256 MiB, reserve-only until an image is loaded. */
    DWORD process_id = GetCurrentProcessId();
    unsigned long failures = 0;
    for (unsigned long ordinal = 0; ordinal < count; ordinal++) {
        ULONGLONG guest_tick_ms = GetTickCount64();
        ULONGLONG started_us = qpc_us();
        SetLastError(ERROR_SUCCESS);
        void *base = CreateEnclave(GetCurrentProcess(), NULL, enclave_size, 0,
                                   ENCLAVE_TYPE_VBS, &info, sizeof(info), NULL);
        DWORD create_error = base ? ERROR_SUCCESS : GetLastError();
        BOOL loaded = FALSE;
        DWORD load_error = ERROR_SUCCESS;
        BOOL initialized = FALSE;
        DWORD initialize_error = ERROR_SUCCESS;
        DWORD enclave_error = ERROR_SUCCESS;
        BOOL terminated = FALSE;
        DWORD terminate_error = ERROR_SUCCESS;
        BOOL deleted = FALSE;
        DWORD delete_error = ERROR_SUCCESS;
        if (base) {
            SetLastError(ERROR_SUCCESS);
            loaded = LoadEnclaveImageW(base, image_path);
            if (!loaded) {
                load_error = GetLastError();
                failures++;
            }
        }
        if (loaded) {
            ENCLAVE_INIT_INFO_VBS initialize;
            ZeroMemory(&initialize, sizeof(initialize));
            initialize.Length = sizeof(initialize);
            initialize.ThreadCount = 1;
            SetLastError(ERROR_SUCCESS);
            initialized = InitializeEnclave(GetCurrentProcess(), base, &initialize,
                                            sizeof(initialize), &enclave_error);
            if (!initialized) {
                initialize_error = GetLastError();
                failures++;
            }
        }
        if (initialized) {
            SetLastError(ERROR_SUCCESS);
            terminated = TerminateEnclave(base, TRUE);
            if (!terminated) {
                terminate_error = GetLastError();
                failures++;
            }
        }
        if (base) {
            SetLastError(ERROR_SUCCESS);
            deleted = DeleteEnclave(base);
            if (!deleted) {
                delete_error = GetLastError();
                failures++;
            }
        } else {
            failures++;
        }
        ULONGLONG duration_us = qpc_us() - started_us;
        wprintf(
            L"{\"schema\":\"windbg-mcp.skcall-guest-workload.v1\","
            L"\"label\":\"%ls\",\"process_id\":%lu,\"ordinal\":%lu,"
            L"\"operation\":\"CreateEnclave+LoadEnclaveImage+InitializeEnclave+TerminateEnclave+DeleteEnclave\","
            L"\"guest_tick_ms\":%llu,\"duration_us\":%llu,"
            L"\"create_ok\":%ls,\"create_error\":%lu,"
            L"\"load_ok\":%ls,\"load_error\":%lu,"
            L"\"initialize_ok\":%ls,\"initialize_error\":%lu,"
            L"\"enclave_error\":%lu,"
            L"\"terminate_ok\":%ls,\"terminate_error\":%lu,"
            L"\"delete_ok\":%ls,\"delete_error\":%lu}\n",
            argv[1], process_id, ordinal, guest_tick_ms, duration_us,
            base ? L"true" : L"false", create_error,
            loaded ? L"true" : L"false", load_error,
            initialized ? L"true" : L"false", initialize_error, enclave_error,
            terminated ? L"true" : L"false", terminate_error,
            deleted ? L"true" : L"false", delete_error);
        fflush(stdout);
    }
    return failures ? 1 : 0;
}
