/*
 * kernel_address_probe.c - read-only Windows kernel address disclosure probe.
 *
 * This program does not open MessageManager, issue driver IOCTLs, modify memory,
 * or require a debugger.  It records enough token context to distinguish a
 * standard-user observation from an administrator/SeDebugPrivilege result, then
 * compares four address-producing system information classes:
 *
 *   11  SystemModuleInformation          kernel and driver image bases
 *   16  SystemHandleInformation          legacy kernel object pointers
 *   64  SystemExtendedHandleInformation  full-width kernel object pointers
 *   66  SystemBigPoolInformation         kernel pool allocation addresses
 *
 * Build from an x64 Developer Command Prompt:
 *   build.cmd kernel_address_probe.c
 *
 * Run from a newly-created, non-administrative account:
 *   kernel_address_probe.exe --require-standard
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW      ((NTSTATUS)0x80000005L)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)

#define SystemModuleInformation         11u
#define SystemHandleInformation         16u
#define SystemExtendedHandleInformation 64u
#define SystemBigPoolInformation        66u

#define MAX_QUERY_SIZE (512u * 1024u * 1024u)
#define DISPLAY_LIMIT 5u

typedef NTSTATUS(NTAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef LONG(WINAPI *PFN_RTL_GET_VERSION)(PVOID VersionInformation);
typedef BOOL(WINAPI *PFN_ENUM_DEVICE_DRIVERS)(LPVOID *ImageBase, DWORD Size,
                                               LPDWORD Needed);

typedef struct _RTL_OSVERSIONINFOW_LOCAL {
    ULONG Size;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
    ULONG PlatformId;
    WCHAR CsdVersion[128];
} RTL_OSVERSIONINFOW_LOCAL;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_LOCAL {
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION_LOCAL;

typedef struct _RTL_PROCESS_MODULES_LOCAL {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION_LOCAL Modules[1];
} RTL_PROCESS_MODULES_LOCAL;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL;

typedef struct _SYSTEM_HANDLE_INFORMATION_LOCAL {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL Handles[1];
} SYSTEM_HANDLE_INFORMATION_LOCAL;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX_LOCAL {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX_LOCAL;

typedef struct _SYSTEM_BIGPOOL_ENTRY_LOCAL {
    ULONG_PTR VirtualAddressAndFlags;
    ULONG_PTR SizeInBytes;
    UCHAR Tag[4];
} SYSTEM_BIGPOOL_ENTRY_LOCAL;

typedef struct _SYSTEM_BIGPOOL_INFORMATION_LOCAL {
    ULONG Count;
#ifdef _WIN64
    ULONG Alignment;
#endif
    SYSTEM_BIGPOOL_ENTRY_LOCAL AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION_LOCAL;

typedef struct _TOKEN_CONTEXT {
    BOOL Valid;
    BOOL AdminSidPresent;
    BOOL AdminSidEnabled;
    BOOL AdminSidDenyOnly;
    BOOL Elevated;
    BOOL Restricted;
    BOOL DebugPresent;
    BOOL DebugEnabled;
    TOKEN_ELEVATION_TYPE ElevationType;
    DWORD IntegrityRid;
} TOKEN_CONTEXT;

typedef struct _PROBE_RESULT {
    BOOL QuerySucceeded;
    ULONG Count;
    ULONG KernelPointerCount;
} PROBE_RESULT;

static PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformationFn;

static const char *yes_no(BOOL value) {
    return value ? "yes" : "no";
}

static const char *integrity_name(DWORD rid) {
    if (rid < SECURITY_MANDATORY_LOW_RID) return "untrusted";
    if (rid < SECURITY_MANDATORY_MEDIUM_RID) return "low";
    if (rid < SECURITY_MANDATORY_HIGH_RID) return "medium";
    if (rid < SECURITY_MANDATORY_SYSTEM_RID) return "high";
    if (rid < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) return "system";
    return "protected";
}

static const char *elevation_type_name(TOKEN_ELEVATION_TYPE type) {
    switch (type) {
    case TokenElevationTypeDefault:
        return "default";
    case TokenElevationTypeFull:
        return "full";
    case TokenElevationTypeLimited:
        return "limited";
    default:
        return "unknown";
    }
}

static BOOL looks_like_kernel_pointer(const void *pointer) {
    uintptr_t value = (uintptr_t)pointer;
#ifdef _WIN64
    return (value & UINT64_C(0xffff000000000000)) == UINT64_C(0xffff000000000000);
#else
    return value >= UINT32_C(0x80000000);
#endif
}

static void print_ntstatus(const char *label, NTSTATUS status) {
    printf("[%s] status=0x%08lx\n", label, (unsigned long)status);
}

static void *query_system_information(ULONG information_class, ULONG *result_length,
                                      NTSTATUS *result_status) {
    ULONG size = 64u * 1024u;
    ULONG returned = 0;
    void *buffer = NULL;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    unsigned int attempt;

    for (attempt = 0; attempt < 12; ++attempt) {
        buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        if (!buffer) {
            status = (NTSTATUS)0xC0000017L; /* STATUS_NO_MEMORY */
            break;
        }

        returned = 0;
        status = NtQuerySystemInformationFn(information_class, buffer, size, &returned);
        if (NT_SUCCESS(status)) {
            if (result_length) *result_length = returned ? returned : size;
            if (result_status) *result_status = status;
            return buffer;
        }

        HeapFree(GetProcessHeap(), 0, buffer);
        buffer = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL &&
            status != STATUS_BUFFER_OVERFLOW) {
            break;
        }

        if (returned > size) {
            size = returned;
        } else if (size <= MAX_QUERY_SIZE / 2u) {
            size *= 2u;
        } else {
            status = (NTSTATUS)0xC000009AL; /* STATUS_INSUFFICIENT_RESOURCES */
            break;
        }
        if (size > MAX_QUERY_SIZE) {
            status = (NTSTATUS)0xC000009AL;
            break;
        }
    }

    if (result_length) *result_length = returned;
    if (result_status) *result_status = status;
    return NULL;
}

static void *get_token_information_alloc(HANDLE token, TOKEN_INFORMATION_CLASS information_class,
                                         DWORD *result_length) {
    DWORD length = 0;
    void *buffer;

    GetTokenInformation(token, information_class, NULL, 0, &length);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || length == 0) return NULL;
    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length);
    if (!buffer) return NULL;
    if (!GetTokenInformation(token, information_class, buffer, length, &length)) {
        HeapFree(GetProcessHeap(), 0, buffer);
        return NULL;
    }
    if (result_length) *result_length = length;
    return buffer;
}

static void print_token_user(HANDLE token) {
    TOKEN_USER *user = (TOKEN_USER *)get_token_information_alloc(token, TokenUser, NULL);
    WCHAR account[256];
    WCHAR domain[256];
    DWORD account_length = ARRAYSIZE(account);
    DWORD domain_length = ARRAYSIZE(domain);
    SID_NAME_USE sid_type;

    if (!user) {
        printf("[token] account=<unavailable>\n");
        return;
    }
    if (LookupAccountSidW(NULL, user->User.Sid, account, &account_length, domain, &domain_length,
                          &sid_type)) {
        printf("[token] account=%ls\\%ls\n", domain, account);
    } else {
        printf("[token] account=<SID lookup failed:%lu>\n", GetLastError());
    }
    HeapFree(GetProcessHeap(), 0, user);
}

static TOKEN_CONTEXT inspect_token(void) {
    TOKEN_CONTEXT context;
    HANDLE token = NULL;
    BYTE admin_sid_buffer[SECURITY_MAX_SID_SIZE];
    DWORD admin_sid_size = sizeof(admin_sid_buffer);
    PSID admin_sid = (PSID)admin_sid_buffer;
    TOKEN_GROUPS *groups = NULL;
    TOKEN_PRIVILEGES *privileges = NULL;
    TOKEN_MANDATORY_LABEL *label = NULL;
    TOKEN_ELEVATION elevation;
    DWORD returned = 0;
    LUID debug_luid;
    DWORD index;

    ZeroMemory(&context, sizeof(context));
    context.ElevationType = TokenElevationTypeDefault;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        printf("[token] OpenProcessToken failed=%lu\n", GetLastError());
        return context;
    }
    context.Valid = TRUE;
    print_token_user(token);

    groups = (TOKEN_GROUPS *)get_token_information_alloc(token, TokenGroups, NULL);
    if (groups && CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid,
                                     &admin_sid_size)) {
        for (index = 0; index < groups->GroupCount; ++index) {
            DWORD attributes;
            if (!EqualSid(groups->Groups[index].Sid, admin_sid)) continue;
            attributes = groups->Groups[index].Attributes;
            context.AdminSidPresent = TRUE;
            context.AdminSidDenyOnly = (attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0;
            context.AdminSidEnabled = (attributes & SE_GROUP_ENABLED) != 0 &&
                                      !context.AdminSidDenyOnly;
            break;
        }
    }

    returned = sizeof(context.ElevationType);
    GetTokenInformation(token, TokenElevationType, &context.ElevationType, returned, &returned);
    ZeroMemory(&elevation, sizeof(elevation));
    returned = sizeof(elevation);
    if (GetTokenInformation(token, TokenElevation, &elevation, returned, &returned)) {
        context.Elevated = elevation.TokenIsElevated != 0;
    }
    context.Restricted = IsTokenRestricted(token);

    label = (TOKEN_MANDATORY_LABEL *)get_token_information_alloc(token, TokenIntegrityLevel, NULL);
    if (label && IsValidSid(label->Label.Sid)) {
        UCHAR count = *GetSidSubAuthorityCount(label->Label.Sid);
        if (count) context.IntegrityRid = *GetSidSubAuthority(label->Label.Sid, count - 1);
    }

    privileges =
        (TOKEN_PRIVILEGES *)get_token_information_alloc(token, TokenPrivileges, NULL);
    if (privileges && LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &debug_luid)) {
        for (index = 0; index < privileges->PrivilegeCount; ++index) {
            LUID_AND_ATTRIBUTES entry = privileges->Privileges[index];
            if (entry.Luid.LowPart != debug_luid.LowPart ||
                entry.Luid.HighPart != debug_luid.HighPart) {
                continue;
            }
            context.DebugPresent = TRUE;
            context.DebugEnabled = (entry.Attributes & SE_PRIVILEGE_ENABLED) != 0;
            break;
        }
    }

    printf("[token] integrity=%s rid=0x%lx elevation_type=%s elevated=%s restricted=%s\n",
           integrity_name(context.IntegrityRid), (unsigned long)context.IntegrityRid,
           elevation_type_name(context.ElevationType), yes_no(context.Elevated),
           yes_no(context.Restricted));
    printf("[token] administrators_sid=%s enabled=%s deny_only=%s\n",
           context.AdminSidPresent ? "present" : "absent", yes_no(context.AdminSidEnabled),
           yes_no(context.AdminSidDenyOnly));
    printf("[token] SeDebugPrivilege_present=%s enabled=%s\n", yes_no(context.DebugPresent),
           yes_no(context.DebugEnabled));

    if (groups) HeapFree(GetProcessHeap(), 0, groups);
    if (privileges) HeapFree(GetProcessHeap(), 0, privileges);
    if (label) HeapFree(GetProcessHeap(), 0, label);
    CloseHandle(token);
    return context;
}

static ULONG get_os_build(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_RTL_GET_VERSION rtl_get_version;
    RTL_OSVERSIONINFOW_LOCAL version;
    SYSTEM_INFO system_info;

    if (!ntdll) return 0;
    rtl_get_version = (PFN_RTL_GET_VERSION)GetProcAddress(ntdll, "RtlGetVersion");
    if (!rtl_get_version) return 0;
    ZeroMemory(&version, sizeof(version));
    version.Size = sizeof(version);
    if (rtl_get_version(&version) != 0) return 0;
    GetNativeSystemInfo(&system_info);
    printf("[system] version=%lu.%lu build=%lu architecture=%s pointer_bits=%u\n",
           (unsigned long)version.MajorVersion, (unsigned long)version.MinorVersion,
           (unsigned long)version.BuildNumber,
           system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
               ? "x64"
               : (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "arm64"
                                                                                      : "other"),
           (unsigned int)(sizeof(void *) * 8u));
    return version.BuildNumber;
}

static PROBE_RESULT probe_documented_modules(void) {
    PROBE_RESULT result;
    HMODULE module;
    PFN_ENUM_DEVICE_DRIVERS enum_drivers = NULL;
    LPVOID *bases = NULL;
    DWORD needed = 0;
    DWORD capacity = 256u * sizeof(LPVOID);
    DWORD index;

    ZeroMemory(&result, sizeof(result));
    module = GetModuleHandleW(L"kernel32.dll");
    if (module) {
        enum_drivers =
            (PFN_ENUM_DEVICE_DRIVERS)GetProcAddress(module, "K32EnumDeviceDrivers");
    }
    if (!enum_drivers) {
        module = LoadLibraryW(L"psapi.dll");
        if (module) {
            enum_drivers =
                (PFN_ENUM_DEVICE_DRIVERS)GetProcAddress(module, "EnumDeviceDrivers");
        }
    }
    if (!enum_drivers) {
        printf("[documented-modules] API unavailable\n");
        return result;
    }

    bases = (LPVOID *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity);
    if (!bases) return result;
    if (!enum_drivers(bases, capacity, &needed)) {
        printf("[documented-modules] call_failed=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, bases);
        return result;
    }
    if (needed > capacity) {
        HeapFree(GetProcessHeap(), 0, bases);
        capacity = needed;
        bases = (LPVOID *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity);
        if (!bases || !enum_drivers(bases, capacity, &needed)) {
            printf("[documented-modules] retry_failed=%lu\n", GetLastError());
            if (bases) HeapFree(GetProcessHeap(), 0, bases);
            return result;
        }
    }

    result.QuerySucceeded = TRUE;
    result.Count = needed / (DWORD)sizeof(LPVOID);
    for (index = 0; index < result.Count; ++index) {
        if (looks_like_kernel_pointer(bases[index])) ++result.KernelPointerCount;
    }
    printf("[documented-modules] count=%lu kernel_pointers=%lu first=%p\n",
           (unsigned long)result.Count, (unsigned long)result.KernelPointerCount,
           result.Count ? bases[0] : NULL);
    HeapFree(GetProcessHeap(), 0, bases);
    return result;
}

static PROBE_RESULT probe_direct_modules(void) {
    PROBE_RESULT result;
    RTL_PROCESS_MODULES_LOCAL *modules;
    ULONG length = 0;
    NTSTATUS status;
    size_t available;
    ULONG count;
    ULONG index;

    ZeroMemory(&result, sizeof(result));
    modules = (RTL_PROCESS_MODULES_LOCAL *)query_system_information(
        SystemModuleInformation, &length, &status);
    if (!modules) {
        print_ntstatus("direct-modules", status);
        return result;
    }
    result.QuerySucceeded = TRUE;
    available = length > offsetof(RTL_PROCESS_MODULES_LOCAL, Modules)
                    ? (length - offsetof(RTL_PROCESS_MODULES_LOCAL, Modules)) /
                          sizeof(modules->Modules[0])
                    : 0;
    count = modules->NumberOfModules < available ? modules->NumberOfModules : (ULONG)available;
    result.Count = count;
    for (index = 0; index < count; ++index) {
        RTL_PROCESS_MODULE_INFORMATION_LOCAL *entry = &modules->Modules[index];
        const char *name = (const char *)entry->FullPathName;
        if (entry->OffsetToFileName < sizeof(entry->FullPathName)) {
            name += entry->OffsetToFileName;
        }
        if (looks_like_kernel_pointer(entry->ImageBase)) ++result.KernelPointerCount;
        if (index < DISPLAY_LIMIT) {
            printf("[direct-modules] module[%lu] base=%p size=0x%lx name=%s\n",
                   (unsigned long)index, entry->ImageBase, (unsigned long)entry->ImageSize,
                   name);
        }
    }
    printf("[direct-modules] count=%lu kernel_pointers=%lu\n", (unsigned long)result.Count,
           (unsigned long)result.KernelPointerCount);
    HeapFree(GetProcessHeap(), 0, modules);
    return result;
}

static PROBE_RESULT probe_extended_handles(HANDLE process_handle, HANDLE thread_handle,
                                           HANDLE event_handle) {
    PROBE_RESULT result;
    SYSTEM_HANDLE_INFORMATION_EX_LOCAL *information;
    ULONG length = 0;
    NTSTATUS status;
    size_t available;
    ULONG_PTR count;
    ULONG_PTR index;
    DWORD pid = GetCurrentProcessId();
    ULONG matches = 0;

    ZeroMemory(&result, sizeof(result));
    information = (SYSTEM_HANDLE_INFORMATION_EX_LOCAL *)query_system_information(
        SystemExtendedHandleInformation, &length, &status);
    if (!information) {
        print_ntstatus("extended-handles", status);
        return result;
    }
    result.QuerySucceeded = TRUE;
    available = length > offsetof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles)
                    ? (length - offsetof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles)) /
                          sizeof(information->Handles[0])
                    : 0;
    count = information->NumberOfHandles < available ? information->NumberOfHandles : available;
    result.Count = count > ULONG_MAX ? ULONG_MAX : (ULONG)count;
    for (index = 0; index < count; ++index) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL *entry = &information->Handles[index];
        const char *kind = NULL;
        if (looks_like_kernel_pointer(entry->Object)) ++result.KernelPointerCount;
        if (entry->UniqueProcessId != (ULONG_PTR)pid) continue;
        if (entry->HandleValue == (ULONG_PTR)process_handle) kind = "self-process";
        if (entry->HandleValue == (ULONG_PTR)thread_handle) kind = "self-thread";
        if (entry->HandleValue == (ULONG_PTR)event_handle) kind = "event";
        if (!kind) continue;
        printf("[extended-handles] %s handle=%p object=%p kernel_pointer=%s\n", kind,
               (void *)entry->HandleValue, entry->Object,
               yes_no(looks_like_kernel_pointer(entry->Object)));
        ++matches;
    }
    printf("[extended-handles] count=%lu kernel_pointers=%lu matched_probe_handles=%lu\n",
           (unsigned long)result.Count, (unsigned long)result.KernelPointerCount,
           (unsigned long)matches);
    HeapFree(GetProcessHeap(), 0, information);
    return result;
}

static PROBE_RESULT probe_legacy_handles(HANDLE process_handle, HANDLE thread_handle,
                                         HANDLE event_handle) {
    PROBE_RESULT result;
    SYSTEM_HANDLE_INFORMATION_LOCAL *information;
    ULONG length = 0;
    NTSTATUS status;
    size_t available;
    ULONG count;
    ULONG index;
    DWORD pid = GetCurrentProcessId();
    ULONG matches = 0;

    ZeroMemory(&result, sizeof(result));
    information = (SYSTEM_HANDLE_INFORMATION_LOCAL *)query_system_information(
        SystemHandleInformation, &length, &status);
    if (!information) {
        print_ntstatus("legacy-handles", status);
        return result;
    }
    result.QuerySucceeded = TRUE;
    available = length > offsetof(SYSTEM_HANDLE_INFORMATION_LOCAL, Handles)
                    ? (length - offsetof(SYSTEM_HANDLE_INFORMATION_LOCAL, Handles)) /
                          sizeof(information->Handles[0])
                    : 0;
    count = information->NumberOfHandles < available ? information->NumberOfHandles
                                                      : (ULONG)available;
    result.Count = count;
    for (index = 0; index < count; ++index) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL *entry = &information->Handles[index];
        const char *kind = NULL;
        if (looks_like_kernel_pointer(entry->Object)) ++result.KernelPointerCount;
        if (entry->UniqueProcessId != (USHORT)pid || pid > USHRT_MAX) continue;
        if (entry->HandleValue == (USHORT)(ULONG_PTR)process_handle &&
            (ULONG_PTR)process_handle <= USHRT_MAX)
            kind = "self-process";
        if (entry->HandleValue == (USHORT)(ULONG_PTR)thread_handle &&
            (ULONG_PTR)thread_handle <= USHRT_MAX)
            kind = "self-thread";
        if (entry->HandleValue == (USHORT)(ULONG_PTR)event_handle &&
            (ULONG_PTR)event_handle <= USHRT_MAX)
            kind = "event";
        if (!kind) continue;
        printf("[legacy-handles] %s handle=0x%04x object=%p kernel_pointer=%s\n", kind,
               entry->HandleValue, entry->Object,
               yes_no(looks_like_kernel_pointer(entry->Object)));
        ++matches;
    }
    printf("[legacy-handles] count=%lu kernel_pointers=%lu matched_probe_handles=%lu\n",
           (unsigned long)result.Count, (unsigned long)result.KernelPointerCount,
           (unsigned long)matches);
    HeapFree(GetProcessHeap(), 0, information);
    return result;
}

static void printable_tag(const UCHAR source[4], char destination[5]) {
    unsigned int index;
    for (index = 0; index < 4; ++index) {
        destination[index] = source[index] >= 0x20 && source[index] <= 0x7e
                                 ? (char)source[index]
                                 : '.';
    }
    destination[4] = '\0';
}

static PROBE_RESULT probe_big_pool(void) {
    PROBE_RESULT result;
    SYSTEM_BIGPOOL_INFORMATION_LOCAL *information;
    ULONG length = 0;
    NTSTATUS status;
    size_t available;
    ULONG count;
    ULONG index;
    ULONG displayed = 0;

    ZeroMemory(&result, sizeof(result));
    information = (SYSTEM_BIGPOOL_INFORMATION_LOCAL *)query_system_information(
        SystemBigPoolInformation, &length, &status);
    if (!information) {
        print_ntstatus("big-pool", status);
        return result;
    }
    result.QuerySucceeded = TRUE;
    available = length > offsetof(SYSTEM_BIGPOOL_INFORMATION_LOCAL, AllocatedInfo)
                    ? (length - offsetof(SYSTEM_BIGPOOL_INFORMATION_LOCAL, AllocatedInfo)) /
                          sizeof(information->AllocatedInfo[0])
                    : 0;
    count = information->Count < available ? information->Count : (ULONG)available;
    result.Count = count;
    for (index = 0; index < count; ++index) {
        SYSTEM_BIGPOOL_ENTRY_LOCAL *entry = &information->AllocatedInfo[index];
        ULONG_PTR raw = entry->VirtualAddressAndFlags;
        void *address = (void *)(raw & ~(ULONG_PTR)1u);
        BOOL nonpaged = (raw & 1u) != 0;
        if (looks_like_kernel_pointer(address)) ++result.KernelPointerCount;
        if (displayed < DISPLAY_LIMIT && looks_like_kernel_pointer(address)) {
            char tag[5];
            printable_tag(entry->Tag, tag);
            printf("[big-pool] entry[%lu] address=%p size=0x%Ix nonpaged=%s tag=%s\n",
                   (unsigned long)index, address, entry->SizeInBytes, yes_no(nonpaged), tag);
            ++displayed;
        }
    }
    printf("[big-pool] count=%lu kernel_pointers=%lu\n", (unsigned long)result.Count,
           (unsigned long)result.KernelPointerCount);
    HeapFree(GetProcessHeap(), 0, information);
    return result;
}

static void print_usage(const char *program) {
    printf("usage: %s [--require-standard]\n", program);
    printf("  --require-standard  exit 2 before probing if the token belongs to an\n");
    printf("                      administrator or contains SeDebugPrivilege\n");
}

int main(int argc, char **argv) {
    BOOL require_standard = FALSE;
    BOOL standard_caller;
    ULONG build;
    TOKEN_CONTEXT token;
    HMODULE ntdll;
    HANDLE process_handle;
    HANDLE thread_handle;
    HANDLE event_handle;
    PROBE_RESULT documented_modules;
    PROBE_RESULT direct_modules;
    PROBE_RESULT legacy_handles;
    PROBE_RESULT extended_handles;
    PROBE_RESULT big_pool;
    int index;

    for (index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--require-standard") == 0) {
            require_standard = TRUE;
        } else if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("kernel_address_probe version=1\n");
    build = get_os_build();
    token = inspect_token();
    if (!token.Valid) return 1;
    standard_caller = !token.AdminSidPresent && !token.DebugPresent && !token.Elevated &&
                      token.ElevationType == TokenElevationTypeDefault;
    printf("[assessment] caller_class=%s\n",
           standard_caller ? "standard-non-admin" : "privileged-or-filtered-admin");
    if (require_standard && !standard_caller) {
        printf("[assessment] overall=REFUSED_PRIVILEGED_CALLER\n");
        return 2;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        printf("[error] ntdll unavailable\n");
        return 1;
    }
    NtQuerySystemInformationFn = (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(
        ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformationFn) {
        printf("[error] NtQuerySystemInformation unavailable\n");
        return 1;
    }

    process_handle =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    thread_handle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
    event_handle = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!process_handle || !thread_handle || !event_handle) {
        printf("[error] failed to create probe handles error=%lu\n", GetLastError());
        if (process_handle) CloseHandle(process_handle);
        if (thread_handle) CloseHandle(thread_handle);
        if (event_handle) CloseHandle(event_handle);
        return 1;
    }

    documented_modules = probe_documented_modules();
    direct_modules = probe_direct_modules();
    legacy_handles = probe_legacy_handles(process_handle, thread_handle, event_handle);
    extended_handles = probe_extended_handles(process_handle, thread_handle, event_handle);
    big_pool = probe_big_pool();

    CloseHandle(event_handle);
    CloseHandle(thread_handle);
    CloseHandle(process_handle);

    printf("[summary] build=%lu standard_caller=%s documented_module_pointers=%lu "
           "direct_module_pointers=%lu legacy_handle_pointers=%lu "
           "extended_handle_pointers=%lu big_pool_pointers=%lu\n",
           (unsigned long)build, yes_no(standard_caller),
           (unsigned long)documented_modules.KernelPointerCount,
           (unsigned long)direct_modules.KernelPointerCount,
           (unsigned long)legacy_handles.KernelPointerCount,
           (unsigned long)extended_handles.KernelPointerCount,
           (unsigned long)big_pool.KernelPointerCount);

    if (!standard_caller) {
        printf("[assessment] overall=INCONCLUSIVE_PRIVILEGED_CALLER\n");
    } else if (direct_modules.KernelPointerCount || legacy_handles.KernelPointerCount ||
               extended_handles.KernelPointerCount || big_pool.KernelPointerCount) {
        printf("[assessment] overall=POTENTIAL_KERNEL_ADDRESS_DISCLOSURE\n");
        if (build >= 26100 && direct_modules.KernelPointerCount) {
            printf("[assessment] candidate_24h2_module_base_disclosure=yes\n");
        }
        printf("[assessment] preserve this output and validate on a fully updated clean VM\n");
    } else {
        printf("[assessment] overall=NO_KERNEL_POINTERS_OBSERVED\n");
    }
    return 0;
}
