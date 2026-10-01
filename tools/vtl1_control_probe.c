/*
 * Build-locked owner-partition probe for a VTL1 kernel controlled stop.
 *
 * The controlled-stop mode creates a disposable VID partition, installs a
 * long-mode VTL0/VTL1 image, enters VTL1 with a targeted interrupt, and waits
 * for the #BP intercept raised by its selected VTL1 instruction. Its
 * Secure-Kernel mode maps a guarded securekernel.exe and calls that image's
 * int3;ret breakpoint stub through the same owned path. It never opens or
 * attaches to a Hyper-V managed VM.
 *
 * VID is private and its ABI changes. The signatures and offsets below are
 * specific to the guarded inbox vid.dll/Vid.sys pair. A different build is a
 * hard failure, not a best-effort run.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinHvPlatformDefs.h>
#include <objbase.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VID_SETUP_BYTES 0xCAE0u
#define VID_SETUP_VERSION_OFFSET 0x0000u
#define VID_SETUP_FLAGS_OFFSET 0x0020u
#define VID_SETUP_PROCESSOR_COUNT_OFFSET 0x0028u
#define VID_SETUP_NUMA_COUNT_OFFSET 0x0030u
#define VID_SETUP_VSM_POLICY_OFFSET 0xC8A8u

#define EXPECTED_VID_DLL_BUILD 26100u
#define EXPECTED_VID_DLL_FIXED_REVISION 5074u
#define EXPECTED_VID_DLL_SIZE 263552u
#define EXPECTED_VID_SYS_BUILD 26100u
#define EXPECTED_VID_SYS_FIXED_REVISION 9278u
#define EXPECTED_VID_SYS_SIZE 910816u
#define EXPECTED_SECURE_KERNEL_BUILD 26100u
#define EXPECTED_SECURE_KERNEL_FIXED_REVISION 9457u
#define EXPECTED_SECURE_KERNEL_SIZE 1385944u
#define VID_SETUP_PROCESS_LOCAL 0x02ull

#define GUEST_BYTES (2u * 1024u * 1024u)
#define GUEST_PAGES (GUEST_BYTES / 4096u)
#define PML4_GPA 0x1000ull
#define PDPT_GPA 0x2000ull
#define PD_GPA 0x3000ull
#define GDT_GPA 0x4000ull
#define IDT_GPA 0x5000ull
#define TSS_GPA 0x6000ull
#define SECURE_KERNEL_PD_GPA 0x7000ull
#define SECURE_KERNEL_PT_GPA 0x8000ull
#define VTL1_CODE_GPA 0x10000ull
#define VTL1_IDLE_GPA 0x10100ull
#define VTL0_CODE_GPA 0x11000ull
#define VTL1_WITNESS_GPA 0x12000ull
#define VTL0_WITNESS_GPA 0x12001ull
#define VTL1_RESUME_WITNESS_GPA 0x12002ull
#define SECURE_KERNEL_IMAGE_GPA 0x20000ull
#define VTL1_STACK_GPA 0x1D0000ull
#define VTL0_STACK_GPA 0x1F0000ull

#define SECURE_KERNEL_IMAGE_BASE 0x140000000ull
#define SECURE_KERNEL_IMAGE_SIZE 0x175000u
#define SECURE_KERNEL_BREAKPOINT_RVA 0x1FA70u
#define SECURE_KERNEL_BREAKPOINT_BYTES 2u
#define SECURE_KERNEL_PDPT_INDEX 5u
#define SECURE_KERNEL_PDB_AGE 1u

#define BREAKPOINT_VECTOR 3u
#define VTL_ENTRY_VECTOR 0x20u
#define TARGET_VTL 1u
#define HV_INPUT_VTL_EXPLICIT(vtl) (0x10u | (vtl))
#define MESSAGE_SLOT 0u
#define MESSAGE_TYPE_EXCEPTION 0x01000002u
#define MESSAGE_EXCEPTION_BYTES 0x10u
#define MESSAGE_TYPE_OFFSET 0x000u
#define MESSAGE_SIZE_OFFSET 0x004u
#define MESSAGE_CONTEXT_OFFSET 0x008u
#define MESSAGE_VP_OFFSET 0x010u
#define MESSAGE_VECTOR_OFFSET 0x020u
#define MESSAGE_RETURN_STATUS_OFFSET 0x140u
#define MESSAGE_ADVANCE_IP_OFFSET 0x148u
#define MESSAGE_CONTEXT_MARKER 0x56544C3153544F50ull
#define VTL1_WITNESS_VALUE 0xA5u
#define VTL0_WITNESS_VALUE 0xA0u
#define VTL1_RESUME_WITNESS_VALUE 0x5Au

#define VSM_CONFIG_BYTES 24u
#define VSM_ENABLED_VTL_SET_OFFSET 0u
#define VSM_MBEC_ENABLED_VTL_SET_OFFSET 4u
#define VSM_VTL1_TYPE_OFFSET 8u
#define VSM_VTL1_FLAGS_OFFSET 9u
#define VSM_VTL1_PROTECTION_OFFSET 12u
#define VSM_VTL1_VALUE_OFFSET 16u

#define MEMORY_BLOCK_VA_BACKED 0x08ull
#define MEMORY_BLOCK_VSM_CAPABLE 0x01ull
#define GPA_RANGE_APPLY_VTL_PROTECTIONS 0x08ull
#define INTERRUPT_TYPE_FIXED 0ull
#define GET_NEXT_MESSAGE_FLAGS 1u
#define COMPLETE_MESSAGE_FLAGS 2u
#define CANCEL_MESSAGE_WAIT_FLAGS 4u

enum HV_REGISTER_NAME_PRIVATE {
    HV_X64_REGISTER_RSP = 0x00020004,
    HV_X64_REGISTER_RIP = 0x00020010,
    HV_X64_REGISTER_RFLAGS = 0x00020011,
    HV_X64_REGISTER_ES = 0x00060000,
    HV_X64_REGISTER_CS = 0x00060001,
    HV_X64_REGISTER_SS = 0x00060002,
    HV_X64_REGISTER_DS = 0x00060003,
    HV_X64_REGISTER_FS = 0x00060004,
    HV_X64_REGISTER_GS = 0x00060005,
    HV_X64_REGISTER_LDTR = 0x00060006,
    HV_X64_REGISTER_TR = 0x00060007,
    HV_X64_REGISTER_IDTR = 0x00070000,
    HV_X64_REGISTER_GDTR = 0x00070001,
    HV_X64_REGISTER_EFER = 0x00080001,
    HV_X64_REGISTER_CR0 = 0x00040000,
    HV_X64_REGISTER_CR3 = 0x00040002,
    HV_X64_REGISTER_CR4 = 0x00040003,
    HV_X64_REGISTER_PAT = 0x00080004,
};

typedef HANDLE(WINAPI *PFN_VID_CREATE_PARTITION)(const wchar_t *name,
                                                  const wchar_t *friendly_name,
                                                  void *setup);
typedef void(WINAPI *PFN_VID_DELETE_PARTITION)(HANDLE partition);
typedef BOOL(WINAPI *PFN_VID_ATTACH_PARTITION)(HANDLE partition);
typedef BOOL(WINAPI *PFN_VID_GET_HV_PARTITION_ID)(HANDLE partition,
                                                   uint64_t *partition_id);
typedef BOOL(WINAPI *PFN_VID_VSM_SET_PARTITION_CONFIG)(HANDLE partition,
                                                       uint32_t input_bytes,
                                                       const void *input);
typedef BOOL(WINAPI *PFN_VID_CREATE_MEMORY_BLOCK)(HANDLE partition,
                                                  const void *descriptor,
                                                  uint64_t *memory_block);
typedef BOOL(WINAPI *PFN_VID_DESTROY_MEMORY_BLOCK)(HANDLE partition,
                                                   uint64_t memory_block);
typedef BOOL(WINAPI *PFN_VID_CREATE_VA_GPA_RANGE)(
    HANDLE partition, uint64_t start_page, uint64_t page_count,
    uint64_t memory_block, uint64_t flags, uint64_t *gpa_range);
typedef BOOL(WINAPI *PFN_VID_DESTROY_GPA_RANGE)(HANDLE partition,
                                                uint64_t gpa_range);
typedef BOOL(WINAPI *PFN_VID_READ_MEMORY_BLOCK_PAGE_RANGE)(
    HANDLE partition, uint64_t memory_block, uint64_t start_page,
    uint64_t page_count, void *buffer, uint64_t buffer_bytes);
typedef BOOL(WINAPI *PFN_VID_WRITE_MEMORY_BLOCK_PAGE_RANGE)(
    HANDLE partition, uint64_t memory_block, uint64_t start_page,
    uint64_t page_count, const void *buffer, uint64_t buffer_bytes);
typedef BOOL(WINAPI *PFN_VID_MAP_MEMORY_BLOCK_PAGE_RANGE)(
    HANDLE partition, uint64_t memory_block, uint64_t start_page,
    uint64_t page_count, uint32_t protection, void **mapped_address,
    uint64_t *mapping);
typedef BOOL(WINAPI *PFN_VID_UNMAP_MEMORY_BLOCK_PAGE_RANGE)(
    HANDLE partition, uint64_t mapping);
typedef BOOL(WINAPI *PFN_VID_SET_MEMORY_BLOCK_NOTIFICATION_QUEUE)(
    HANDLE partition, uint64_t memory_block, uint64_t queue_index);
typedef BOOL(WINAPI *PFN_VID_SETUP_MESSAGE_QUEUE)(HANDLE partition,
                                                  uint32_t slot_count);

typedef struct VID_MESSAGE_SLOT_HANDLE {
    volatile unsigned char *exchange_buffer;
    uint32_t slot_index;
    uint32_t padding;
} VID_MESSAGE_SLOT_HANDLE;

typedef BOOL(WINAPI *PFN_VID_MESSAGE_SLOT_MAP)(
    HANDLE partition, VID_MESSAGE_SLOT_HANDLE *slot, uint32_t slot_index);
typedef BOOL(WINAPI *PFN_VID_MESSAGE_SLOT_HANDLE_AND_GET_NEXT)(
    HANDLE partition, uint32_t slot_index, uint32_t flags, HANDLE event);
typedef BOOL(WINAPI *PFN_VID_REGISTER_EXCEPTION_HANDLER)(
    HANDLE partition, uint8_t vector, uint32_t flags, uint64_t user_context);
typedef BOOL(WINAPI *PFN_VID_VSM_ENABLE_VP_VTL)(
    HANDLE partition, uint32_t vp_index, uint8_t target_vtl,
    const WHV_INITIAL_VP_CONTEXT *context);
typedef BOOL(WINAPI *PFN_VID_START_VIRTUAL_PROCESSOR)(
    HANDLE partition, uint32_t vp_index, uint32_t flags,
    const WHV_INITIAL_VP_CONTEXT *context);
typedef BOOL(WINAPI *PFN_VID_SET_VIRTUAL_PROCESSOR_STATE_EX)(
    HANDLE partition, uint32_t vp_index, uint32_t input_vtl,
    const uint32_t *names, uint8_t count,
    const WHV_REGISTER_VALUE *values);
typedef BOOL(WINAPI *PFN_VID_GET_VIRTUAL_PROCESSOR_STATE_EX)(
    HANDLE partition, uint32_t vp_index, uint32_t input_vtl,
    const uint32_t *names, uint8_t count, WHV_REGISTER_VALUE *values);
typedef BOOL(WINAPI *PFN_VID_GET_VIRTUAL_PROCESSOR_RUNNING_STATUS)(
    HANDLE partition, uint32_t vp_index, uint32_t *running);
typedef BOOL(WINAPI *PFN_VID_STOP_VIRTUAL_PROCESSOR)(HANDLE partition,
                                                     uint32_t vp_index);
typedef BOOL(WINAPI *PFN_VID_ASSERT_VIRTUAL_PROCESSOR_INTERRUPT)(
    HANDLE partition, uint64_t interrupt_control, uint64_t destination,
    uint32_t vector, uint8_t target_vtl);

typedef struct VID_API {
    HMODULE module;
    PFN_VID_CREATE_PARTITION create_partition;
    PFN_VID_DELETE_PARTITION delete_partition;
    PFN_VID_ATTACH_PARTITION attach_partition;
    PFN_VID_GET_HV_PARTITION_ID get_hv_partition_id;
    PFN_VID_VSM_SET_PARTITION_CONFIG vsm_set_partition_config;
    PFN_VID_CREATE_MEMORY_BLOCK create_memory_block;
    PFN_VID_DESTROY_MEMORY_BLOCK destroy_memory_block;
    PFN_VID_CREATE_VA_GPA_RANGE create_va_gpa_range;
    PFN_VID_DESTROY_GPA_RANGE destroy_gpa_range;
    PFN_VID_READ_MEMORY_BLOCK_PAGE_RANGE read_memory_block_page_range;
    PFN_VID_WRITE_MEMORY_BLOCK_PAGE_RANGE write_memory_block_page_range;
    PFN_VID_MAP_MEMORY_BLOCK_PAGE_RANGE map_memory_block_page_range;
    PFN_VID_UNMAP_MEMORY_BLOCK_PAGE_RANGE unmap_memory_block_page_range;
    PFN_VID_SET_MEMORY_BLOCK_NOTIFICATION_QUEUE
        set_memory_block_notification_queue;
    PFN_VID_SETUP_MESSAGE_QUEUE setup_message_queue;
    PFN_VID_MESSAGE_SLOT_MAP message_slot_map;
    PFN_VID_MESSAGE_SLOT_HANDLE_AND_GET_NEXT
        message_slot_handle_and_get_next;
    PFN_VID_REGISTER_EXCEPTION_HANDLER register_exception_handler;
    PFN_VID_VSM_ENABLE_VP_VTL vsm_enable_vp_vtl;
    PFN_VID_START_VIRTUAL_PROCESSOR start_virtual_processor;
    PFN_VID_SET_VIRTUAL_PROCESSOR_STATE_EX set_virtual_processor_state_ex;
    PFN_VID_GET_VIRTUAL_PROCESSOR_STATE_EX get_virtual_processor_state_ex;
    PFN_VID_GET_VIRTUAL_PROCESSOR_RUNNING_STATUS
        get_virtual_processor_running_status;
    PFN_VID_STOP_VIRTUAL_PROCESSOR stop_virtual_processor;
    PFN_VID_ASSERT_VIRTUAL_PROCESSOR_INTERRUPT
        assert_virtual_processor_interrupt;
} VID_API;

typedef struct MESSAGE_RECEIVER {
    const VID_API *api;
    HANDLE partition;
    HANDLE ready;
    volatile LONG stop_requested;
    volatile LONG attempts;
    BOOL succeeded;
    DWORD error;
} MESSAGE_RECEIVER;

typedef struct MEMORY_BLOCK_DESCRIPTOR {
    uint64_t words[14];
} MEMORY_BLOCK_DESCRIPTOR;

typedef struct SECURE_KERNEL_IMAGE {
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t breakpoint_rva;
} SECURE_KERNEL_IMAGE;

typedef struct CODEVIEW_RSDS {
    uint32_t signature;
    GUID guid;
    uint32_t age;
    char pdb_name[1];
} CODEVIEW_RSDS;

#pragma pack(push, 1)
typedef struct IDT_GATE64 {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attributes;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved;
} IDT_GATE64;
#pragma pack(pop)

typedef enum MESSAGE_MATCH {
    MESSAGE_EMPTY,
    MESSAGE_EXPECTED,
    MESSAGE_UNEXPECTED
} MESSAGE_MATCH;

_Static_assert(sizeof(WHV_INITIAL_VP_CONTEXT) == 0xE0,
               "guarded VID ABI requires a 0xe0-byte initial VP context");
_Static_assert(sizeof(VID_MESSAGE_SLOT_HANDLE) == 16,
               "guarded VID ABI requires a 16-byte slot handle");
_Static_assert(sizeof(MEMORY_BLOCK_DESCRIPTOR) == 0x70,
               "guarded VID ABI requires a 0x70-byte memory descriptor");
_Static_assert(sizeof(IDT_GATE64) == 16, "x64 IDT gate size changed");
_Static_assert(offsetof(CODEVIEW_RSDS, pdb_name) == 24,
               "RSDS header layout changed");

static const GUID EXPECTED_SECURE_KERNEL_PDB_GUID = {
    0xC2C0D1A6,
    0x2E32,
    0x69F4,
    {0x0C, 0x69, 0xEA, 0x44, 0xFD, 0xB2, 0x30, 0xC4},
};

static void store_u16(unsigned char *buffer, size_t offset, uint16_t value)
{
    memcpy(buffer + offset, &value, sizeof(value));
}

static void store_u32(unsigned char *buffer, size_t offset, uint32_t value)
{
    memcpy(buffer + offset, &value, sizeof(value));
}

static void store_u64(unsigned char *buffer, size_t offset, uint64_t value)
{
    memcpy(buffer + offset, &value, sizeof(value));
}

static uint32_t load_u32(const unsigned char *buffer, size_t offset)
{
    uint32_t value;
    memcpy(&value, buffer + offset, sizeof(value));
    return value;
}

static uint64_t load_u64(const unsigned char *buffer, size_t offset)
{
    uint64_t value;
    memcpy(&value, buffer + offset, sizeof(value));
    return value;
}

static BOOL query_file_build(const wchar_t *path, DWORD *build,
                             DWORD *revision)
{
    DWORD ignored = 0;
    DWORD bytes = GetFileVersionInfoSizeW(path, &ignored);
    void *version = NULL;
    VS_FIXEDFILEINFO *fixed = NULL;
    UINT fixed_bytes = 0;
    BOOL ok = FALSE;

    if (bytes == 0) {
        return FALSE;
    }
    version = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (version == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    if (GetFileVersionInfoW(path, 0, bytes, version) &&
        VerQueryValueW(version, L"\\", (void **)&fixed, &fixed_bytes) &&
        fixed_bytes >= sizeof(*fixed)) {
        *build = HIWORD(fixed->dwFileVersionLS);
        *revision = LOWORD(fixed->dwFileVersionLS);
        ok = TRUE;
    }
    HeapFree(GetProcessHeap(), 0, version);
    return ok;
}

static BOOL guard_file(const wchar_t *path, DWORD expected_build,
                       DWORD expected_revision, DWORD expected_size)
{
    DWORD build = 0;
    DWORD revision = 0;
    WIN32_FILE_ATTRIBUTE_DATA attributes;

    if (!query_file_build(path, &build, &revision)) {
        fwprintf(stderr, L"cannot read %ls version (error %lu)\n", path,
                 GetLastError());
        return FALSE;
    }
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &attributes)) {
        fwprintf(stderr, L"cannot stat %ls (error %lu)\n", path,
                 GetLastError());
        return FALSE;
    }
    if (build != expected_build || revision != expected_revision ||
        attributes.nFileSizeHigh != 0 ||
        attributes.nFileSizeLow != expected_size) {
        fwprintf(stderr,
                 L"refusing unverified %ls fixed version %lu.%lu size %lu; "
                 L"expected %lu.%lu size %lu\n",
                 path, build, revision, attributes.nFileSizeLow,
                 expected_build, expected_revision, expected_size);
        SetLastError(ERROR_REVISION_MISMATCH);
        return FALSE;
    }
    return TRUE;
}

static BOOL range_within(size_t offset, size_t bytes, size_t total)
{
    return offset <= total && bytes <= total - offset;
}

static BOOL read_entire_file(const wchar_t *path, unsigned char **contents,
                             size_t *content_bytes)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size;
    unsigned char *buffer = NULL;
    DWORD read_bytes = 0;
    DWORD error = ERROR_SUCCESS;

    *contents = NULL;
    *content_bytes = 0;
    file = CreateFileW(path, GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        (uint64_t)size.QuadPart > MAXDWORD) {
        error = GetLastError();
        if (error == ERROR_SUCCESS) {
            error = ERROR_FILE_TOO_LARGE;
        }
        goto fail;
    }
    buffer = HeapAlloc(GetProcessHeap(), 0, (size_t)size.QuadPart);
    if (buffer == NULL) {
        error = ERROR_OUTOFMEMORY;
        goto fail;
    }
    if (!ReadFile(file, buffer, (DWORD)size.QuadPart, &read_bytes, NULL) ||
        read_bytes != (DWORD)size.QuadPart) {
        error = GetLastError();
        if (error == ERROR_SUCCESS) {
            error = ERROR_HANDLE_EOF;
        }
        goto fail;
    }
    CloseHandle(file);
    *contents = buffer;
    *content_bytes = (size_t)size.QuadPart;
    return TRUE;

fail:
    if (buffer != NULL) {
        HeapFree(GetProcessHeap(), 0, buffer);
    }
    CloseHandle(file);
    SetLastError(error);
    return FALSE;
}

static BOOL rva_to_raw_offset(const IMAGE_NT_HEADERS64 *nt,
                              const IMAGE_SECTION_HEADER *sections,
                              size_t file_bytes, uint32_t rva,
                              size_t requested_bytes, size_t *raw_offset)
{
    WORD index;

    if (rva < nt->OptionalHeader.SizeOfHeaders &&
        range_within((size_t)rva, requested_bytes, file_bytes)) {
        *raw_offset = (size_t)rva;
        return TRUE;
    }
    for (index = 0; index < nt->FileHeader.NumberOfSections; index++) {
        const IMAGE_SECTION_HEADER *section = &sections[index];
        uint64_t start = section->VirtualAddress;
        uint64_t end = start + section->SizeOfRawData;
        uint64_t request_start = rva;
        uint64_t request_end = request_start + requested_bytes;
        size_t offset;

        if (request_start < start || request_end > end) {
            continue;
        }
        offset = (size_t)section->PointerToRawData +
                 (size_t)(request_start - start);
        if (!range_within(offset, requested_bytes, file_bytes)) {
            return FALSE;
        }
        *raw_offset = offset;
        return TRUE;
    }
    return FALSE;
}

static BOOL verify_secure_kernel_pdb(const unsigned char *file,
                                     size_t file_bytes,
                                     const IMAGE_NT_HEADERS64 *nt,
                                     const IMAGE_SECTION_HEADER *sections)
{
    IMAGE_DATA_DIRECTORY directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    size_t debug_offset;
    size_t count;
    size_t index;

    if (directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0 ||
        !rva_to_raw_offset(nt, sections, file_bytes,
                           directory.VirtualAddress, directory.Size,
                           &debug_offset)) {
        return FALSE;
    }
    count = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (index = 0; index < count; index++) {
        const IMAGE_DEBUG_DIRECTORY *entry =
            (const IMAGE_DEBUG_DIRECTORY *)(file + debug_offset) + index;
        const CODEVIEW_RSDS *rsds;
        size_t name_bytes;

        if (entry->Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
            entry->SizeOfData < offsetof(CODEVIEW_RSDS, pdb_name) + 1 ||
            !range_within(entry->PointerToRawData, entry->SizeOfData,
                          file_bytes)) {
            continue;
        }
        rsds = (const CODEVIEW_RSDS *)(file + entry->PointerToRawData);
        name_bytes = entry->SizeOfData - offsetof(CODEVIEW_RSDS, pdb_name);
        if (rsds->signature == 0x53445352u &&
            IsEqualGUID(&rsds->guid, &EXPECTED_SECURE_KERNEL_PDB_GUID) &&
            rsds->age == SECURE_KERNEL_PDB_AGE &&
            memchr(rsds->pdb_name, '\0', name_bytes) != NULL &&
            _stricmp(rsds->pdb_name, "securekernel.pdb") == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL load_secure_kernel_image(const wchar_t *path,
                                     unsigned char *guest,
                                     SECURE_KERNEL_IMAGE *loaded)
{
    static const unsigned char breakpoint_bytes[SECURE_KERNEL_BREAKPOINT_BYTES] = {
        0xCC, 0xC3,
    };
    unsigned char *file = NULL;
    size_t file_bytes = 0;
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_SECTION_HEADER *sections;
    size_t nt_offset;
    size_t section_offset;
    size_t breakpoint_offset;
    uint32_t image_pages;
    WORD index;
    BOOL ok = FALSE;

    memset(loaded, 0, sizeof(*loaded));
    if (!guard_file(path, EXPECTED_SECURE_KERNEL_BUILD,
                    EXPECTED_SECURE_KERNEL_FIXED_REVISION,
                    EXPECTED_SECURE_KERNEL_SIZE) ||
        !read_entire_file(path, &file, &file_bytes)) {
        fwprintf(stderr, L"cannot read guarded Secure Kernel image %ls "
                         L"(error %lu)\n",
                 path, GetLastError());
        goto cleanup;
    }
    if (!range_within(0, sizeof(*dos), file_bytes)) {
        goto invalid;
    }
    dos = (const IMAGE_DOS_HEADER *)file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) {
        goto invalid;
    }
    nt_offset = (size_t)dos->e_lfanew;
    if (!range_within(nt_offset, sizeof(*nt), file_bytes)) {
        goto invalid;
    }
    nt = (const IMAGE_NT_HEADERS64 *)(file + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->FileHeader.NumberOfSections == 0 ||
        nt->FileHeader.SizeOfOptionalHeader !=
            sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.NumberOfRvaAndSizes <=
            IMAGE_DIRECTORY_ENTRY_DEBUG ||
        nt->OptionalHeader.ImageBase != SECURE_KERNEL_IMAGE_BASE ||
        nt->OptionalHeader.SizeOfImage != SECURE_KERNEL_IMAGE_SIZE ||
        nt->OptionalHeader.SectionAlignment != 0x1000u ||
        nt->OptionalHeader.SizeOfHeaders == 0 ||
        nt->OptionalHeader.SizeOfHeaders > file_bytes ||
        SECURE_KERNEL_IMAGE_GPA + nt->OptionalHeader.SizeOfImage >
            GUEST_BYTES) {
        goto invalid;
    }
    section_offset = nt_offset + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                     nt->FileHeader.SizeOfOptionalHeader;
    if (!range_within(section_offset,
                      (size_t)nt->FileHeader.NumberOfSections *
                          sizeof(IMAGE_SECTION_HEADER),
                      file_bytes)) {
        goto invalid;
    }
    sections = (const IMAGE_SECTION_HEADER *)(file + section_offset);
    if (!verify_secure_kernel_pdb(file, file_bytes, nt, sections) ||
        !rva_to_raw_offset(nt, sections, file_bytes,
                           SECURE_KERNEL_BREAKPOINT_RVA,
                           sizeof(breakpoint_bytes), &breakpoint_offset) ||
        memcmp(file + breakpoint_offset, breakpoint_bytes,
               sizeof(breakpoint_bytes)) != 0) {
        goto invalid;
    }

    memset(guest + SECURE_KERNEL_IMAGE_GPA, 0,
           nt->OptionalHeader.SizeOfImage);
    memcpy(guest + SECURE_KERNEL_IMAGE_GPA, file,
           nt->OptionalHeader.SizeOfHeaders);
    for (index = 0; index < nt->FileHeader.NumberOfSections; index++) {
        const IMAGE_SECTION_HEADER *section = &sections[index];
        size_t destination = SECURE_KERNEL_IMAGE_GPA +
                             section->VirtualAddress;

        if (section->SizeOfRawData == 0) {
            continue;
        }
        if (!range_within(section->PointerToRawData,
                          section->SizeOfRawData, file_bytes) ||
            section->VirtualAddress > nt->OptionalHeader.SizeOfImage ||
            section->SizeOfRawData >
                nt->OptionalHeader.SizeOfImage - section->VirtualAddress ||
            !range_within(destination, section->SizeOfRawData,
                          GUEST_BYTES)) {
            goto invalid;
        }
        memcpy(guest + destination, file + section->PointerToRawData,
               section->SizeOfRawData);
    }
    if (memcmp(guest + SECURE_KERNEL_IMAGE_GPA +
                   SECURE_KERNEL_BREAKPOINT_RVA,
               breakpoint_bytes, sizeof(breakpoint_bytes)) != 0) {
        goto invalid;
    }

    store_u64(guest,
              PDPT_GPA + SECURE_KERNEL_PDPT_INDEX * sizeof(uint64_t),
              SECURE_KERNEL_PD_GPA | 3);
    store_u64(guest, SECURE_KERNEL_PD_GPA, SECURE_KERNEL_PT_GPA | 3);
    image_pages =
        (nt->OptionalHeader.SizeOfImage + 4095u) / 4096u;
    for (index = 0; index < image_pages; index++) {
        store_u64(guest, SECURE_KERNEL_PT_GPA +
                             (size_t)index * sizeof(uint64_t),
                  SECURE_KERNEL_IMAGE_GPA +
                      (uint64_t)index * 4096u | 3);
    }

    loaded->image_base = nt->OptionalHeader.ImageBase;
    loaded->size_of_image = nt->OptionalHeader.SizeOfImage;
    loaded->breakpoint_rva = SECURE_KERNEL_BREAKPOINT_RVA;
    ok = TRUE;
    goto cleanup;

invalid:
    fwprintf(stderr,
             L"refusing Secure Kernel image whose PE layout, PDB identity, "
             L"or DbgBreakPointWithStatus bytes do not match the guarded "
             L"build\n");
    SetLastError(ERROR_REVISION_MISMATCH);

cleanup:
    if (file != NULL) {
        SecureZeroMemory(file, file_bytes);
        HeapFree(GetProcessHeap(), 0, file);
    }
    return ok;
}

static FARPROC require_export(HMODULE module, const char *name)
{
    FARPROC proc = GetProcAddress(module, name);
    if (proc == NULL) {
        fwprintf(stderr, L"missing vid.dll export %hs (error %lu)\n", name,
                 GetLastError());
    }
    return proc;
}

#define RESOLVE(api, field, type, name)                                         \
    do {                                                                        \
        (api)->field = (type)require_export((api)->module, (name));             \
        if ((api)->field == NULL) {                                              \
            goto fail;                                                          \
        }                                                                       \
    } while (0)

static BOOL load_vid(VID_API *api)
{
    wchar_t system[MAX_PATH];
    wchar_t dll_path[MAX_PATH];
    wchar_t driver_path[MAX_PATH];

    memset(api, 0, sizeof(*api));
    if (GetSystemDirectoryW(system, ARRAYSIZE(system)) == 0 ||
        swprintf_s(dll_path, ARRAYSIZE(dll_path), L"%ls\\vid.dll", system) < 0 ||
        swprintf_s(driver_path, ARRAYSIZE(driver_path),
                   L"%ls\\drivers\\Vid.sys", system) < 0) {
        fwprintf(stderr, L"cannot form inbox VID paths (error %lu)\n",
                 GetLastError());
        return FALSE;
    }
    if (!guard_file(dll_path, EXPECTED_VID_DLL_BUILD,
                    EXPECTED_VID_DLL_FIXED_REVISION, EXPECTED_VID_DLL_SIZE) ||
        !guard_file(driver_path, EXPECTED_VID_SYS_BUILD,
                    EXPECTED_VID_SYS_FIXED_REVISION, EXPECTED_VID_SYS_SIZE)) {
        return FALSE;
    }

    api->module = LoadLibraryExW(dll_path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (api->module == NULL) {
        fwprintf(stderr, L"LoadLibraryExW(%ls) failed (error %lu)\n", dll_path,
                 GetLastError());
        return FALSE;
    }
    RESOLVE(api, create_partition, PFN_VID_CREATE_PARTITION,
            "VidCreatePartition");
    RESOLVE(api, delete_partition, PFN_VID_DELETE_PARTITION,
            "VidDeletePartition");
    RESOLVE(api, attach_partition, PFN_VID_ATTACH_PARTITION,
            "VidAttachPartition");
    RESOLVE(api, get_hv_partition_id, PFN_VID_GET_HV_PARTITION_ID,
            "VidGetHvPartitionId");
    RESOLVE(api, vsm_set_partition_config,
            PFN_VID_VSM_SET_PARTITION_CONFIG, "VidVsmSetPartitionConfig");
    RESOLVE(api, create_memory_block, PFN_VID_CREATE_MEMORY_BLOCK,
            "VidCreateMemoryBlock");
    RESOLVE(api, destroy_memory_block, PFN_VID_DESTROY_MEMORY_BLOCK,
            "VidDestroyMemoryBlock");
    RESOLVE(api, create_va_gpa_range, PFN_VID_CREATE_VA_GPA_RANGE,
            "VidCreateVaGpaRange");
    RESOLVE(api, destroy_gpa_range, PFN_VID_DESTROY_GPA_RANGE,
            "VidDestroyGpaRange");
    RESOLVE(api, read_memory_block_page_range,
            PFN_VID_READ_MEMORY_BLOCK_PAGE_RANGE,
            "VidReadMemoryBlockPageRange");
    RESOLVE(api, write_memory_block_page_range,
            PFN_VID_WRITE_MEMORY_BLOCK_PAGE_RANGE,
            "VidWriteMemoryBlockPageRange");
    RESOLVE(api, map_memory_block_page_range,
            PFN_VID_MAP_MEMORY_BLOCK_PAGE_RANGE,
            "VidMapMemoryBlockPageRange");
    RESOLVE(api, unmap_memory_block_page_range,
            PFN_VID_UNMAP_MEMORY_BLOCK_PAGE_RANGE,
            "VidUnmapMemoryBlockPageRange");
    RESOLVE(api, set_memory_block_notification_queue,
            PFN_VID_SET_MEMORY_BLOCK_NOTIFICATION_QUEUE,
            "VidSetMemoryBlockNotificationQueue");
    RESOLVE(api, setup_message_queue, PFN_VID_SETUP_MESSAGE_QUEUE,
            "VidSetupMessageQueue");
    RESOLVE(api, message_slot_map, PFN_VID_MESSAGE_SLOT_MAP,
            "VidMessageSlotMap");
    RESOLVE(api, message_slot_handle_and_get_next,
            PFN_VID_MESSAGE_SLOT_HANDLE_AND_GET_NEXT,
            "VidMessageSlotHandleAndGetNext");
    RESOLVE(api, register_exception_handler,
            PFN_VID_REGISTER_EXCEPTION_HANDLER, "VidRegisterExceptionHandler");
    RESOLVE(api, vsm_enable_vp_vtl, PFN_VID_VSM_ENABLE_VP_VTL,
            "VidVsmEnableVpVtl");
    RESOLVE(api, start_virtual_processor, PFN_VID_START_VIRTUAL_PROCESSOR,
            "VidStartVirtualProcessor");
    RESOLVE(api, set_virtual_processor_state_ex,
            PFN_VID_SET_VIRTUAL_PROCESSOR_STATE_EX,
            "VidSetVirtualProcessorStateEx");
    RESOLVE(api, get_virtual_processor_state_ex,
            PFN_VID_GET_VIRTUAL_PROCESSOR_STATE_EX,
            "VidGetVirtualProcessorStateEx");
    RESOLVE(api, get_virtual_processor_running_status,
            PFN_VID_GET_VIRTUAL_PROCESSOR_RUNNING_STATUS,
            "VidGetVirtualProcessorRunningStatus");
    RESOLVE(api, stop_virtual_processor, PFN_VID_STOP_VIRTUAL_PROCESSOR,
            "VidStopVirtualProcessor");
    RESOLVE(api, assert_virtual_processor_interrupt,
            PFN_VID_ASSERT_VIRTUAL_PROCESSOR_INTERRUPT,
            "VidAssertVirtualProcessorInterrupt");
    return TRUE;

fail:
    FreeLibrary(api->module);
    memset(api, 0, sizeof(*api));
    return FALSE;
}

#undef RESOLVE

static void unload_vid(VID_API *api)
{
    if (api->module != NULL) {
        FreeLibrary(api->module);
    }
    memset(api, 0, sizeof(*api));
}

static void initialize_setup(unsigned char *setup)
{
    memset(setup, 0, VID_SETUP_BYTES);
    store_u32(setup, VID_SETUP_VERSION_OFFSET, 0x600);
    /* vmwp sets the process-local partition bit for its ordinary VM path. */
    store_u64(setup, VID_SETUP_FLAGS_OFFSET, VID_SETUP_PROCESS_LOCAL);
    store_u32(setup, VID_SETUP_PROCESSOR_COUNT_OFFSET, 1);
    store_u32(setup, VID_SETUP_NUMA_COUNT_OFFSET, 1);

    /* Bits 0x30 clear make this guarded Vid.sys grant VSM capability 0x10. */
    store_u32(setup, VID_SETUP_VSM_POLICY_OFFSET, 0);

}

static void initialize_vsm_config(unsigned char *config)
{
    memset(config, 0, VSM_CONFIG_BYTES);
    store_u32(config, VSM_ENABLED_VTL_SET_OFFSET, 3);
    store_u32(config, VSM_MBEC_ENABLED_VTL_SET_OFFSET, 0);
    config[VSM_VTL1_TYPE_OFFSET] = 0;
    config[VSM_VTL1_FLAGS_OFFSET] = 0;

    /* R, W, kernel execute, and user execute are allowed by default. */
    store_u32(config, VSM_VTL1_PROTECTION_OFFSET, 0xF);
    store_u64(config, VSM_VTL1_VALUE_OFFSET, 0);
}

static void initialize_memory_descriptor(MEMORY_BLOCK_DESCRIPTOR *descriptor)
{
    memset(descriptor, 0, sizeof(*descriptor));
    descriptor->words[0] = GUEST_PAGES;
    descriptor->words[1] = GUEST_PAGES;
    descriptor->words[2] =
        MEMORY_BLOCK_VA_BACKED | MEMORY_BLOCK_VSM_CAPABLE;
}

static WHV_X64_SEGMENT_REGISTER segment(uint16_t selector,
                                        uint16_t attributes, uint64_t base,
                                        uint32_t limit)
{
    WHV_X64_SEGMENT_REGISTER value;
    memset(&value, 0, sizeof(value));
    value.Base = base;
    value.Limit = limit;
    value.Selector = selector;
    value.Attributes = attributes;
    return value;
}

static void set_idt_gate(unsigned char *image, uint8_t vector,
                         uint64_t handler)
{
    IDT_GATE64 gate;
    memset(&gate, 0, sizeof(gate));
    gate.offset_low = (uint16_t)handler;
    gate.selector = 8;
    gate.type_attributes = 0x8E;
    gate.offset_middle = (uint16_t)(handler >> 16);
    gate.offset_high = (uint32_t)(handler >> 32);
    memcpy(image + IDT_GPA + (size_t)vector * sizeof(gate), &gate,
           sizeof(gate));
}

static void initialize_context(WHV_INITIAL_VP_CONTEXT *context,
                               uint64_t rip, uint64_t rsp)
{
    WHV_X64_SEGMENT_REGISTER data;
    memset(context, 0, sizeof(*context));
    context->Rip = rip;
    context->Rsp = rsp;
    context->Rflags = 0x202;
    context->Cs = segment(8, 0xA09B, 0, 0xFFFFFFFFu);
    data = segment(0x10, 0xC093, 0, 0xFFFFFFFFu);
    context->Ds = data;
    context->Es = data;
    context->Fs = data;
    context->Gs = data;
    context->Ss = data;
    context->Tr = segment(0x18, 0x008B, TSS_GPA, 0x67);
    context->Idtr.Base = IDT_GPA;
    context->Idtr.Limit = 4095;
    context->Gdtr.Base = GDT_GPA;
    context->Gdtr.Limit = 39;
    context->Efer = 0x500;
    context->Cr0 = 0x80010033;
    context->Cr3 = PML4_GPA;
    context->Cr4 = 0x20;
    context->MsrCrPat = 0x0007040600070406ull;
}

static void build_guest_image(unsigned char *image,
                              WHV_INITIAL_VP_CONTEXT *vtl0,
                              WHV_INITIAL_VP_CONTEXT *vtl1)
{
    uint64_t tss_low;
    uint64_t tss_high;

    memset(image, 0, GUEST_BYTES);
    store_u64(image, PML4_GPA, PDPT_GPA | 3);
    store_u64(image, PDPT_GPA, PD_GPA | 3);
    store_u64(image, PD_GPA, 0x83);

    store_u64(image, GDT_GPA + 8, 0x00AF9B000000FFFFull);
    store_u64(image, GDT_GPA + 16, 0x00CF93000000FFFFull);
    tss_low = 0x67ull | ((TSS_GPA & 0xFFFFFFull) << 16) |
              (0x8Bull << 40) | (((TSS_GPA >> 24) & 0xFFull) << 56);
    tss_high = TSS_GPA >> 32;
    store_u64(image, GDT_GPA + 24, tss_low);
    store_u64(image, GDT_GPA + 32, tss_high);

    store_u64(image, TSS_GPA + 4, VTL1_STACK_GPA);
    store_u16(image, TSS_GPA + 102, 0x68);

    set_idt_gate(image, VTL_ENTRY_VECTOR, VTL1_CODE_GPA);
    set_idt_gate(image, BREAKPOINT_VECTOR, VTL1_CODE_GPA + 9);

    /* VTL1 handler: write a direct witness, select INT3, then halt. */
    image[VTL1_CODE_GPA + 0] = 0xC6;
    image[VTL1_CODE_GPA + 1] = 0x04;
    image[VTL1_CODE_GPA + 2] = 0x25;
    store_u32(image, VTL1_CODE_GPA + 3, (uint32_t)VTL1_WITNESS_GPA);
    image[VTL1_CODE_GPA + 7] = VTL1_WITNESS_VALUE;
    image[VTL1_CODE_GPA + 8] = 0xCC;
    image[VTL1_CODE_GPA + 9] = 0xF4;
    image[VTL1_CODE_GPA + 10] = 0xEB;
    image[VTL1_CODE_GPA + 11] = 0xFD;

    /* VTL0 records entry, then waits for the host's VTL1 interrupt. */
    image[VTL0_CODE_GPA + 0] = 0xC6;
    image[VTL0_CODE_GPA + 1] = 0x04;
    image[VTL0_CODE_GPA + 2] = 0x25;
    store_u32(image, VTL0_CODE_GPA + 3, (uint32_t)VTL0_WITNESS_GPA);
    image[VTL0_CODE_GPA + 7] = VTL0_WITNESS_VALUE;
    image[VTL0_CODE_GPA + 8] = 0xFB;
    image[VTL0_CODE_GPA + 9] = 0xF4;
    image[VTL0_CODE_GPA + 10] = 0xEB;
    image[VTL0_CODE_GPA + 11] = 0xFD;

    initialize_context(vtl0, VTL0_CODE_GPA, VTL0_STACK_GPA);
    initialize_context(vtl1, VTL1_CODE_GPA + 9, VTL1_STACK_GPA);
}

static void configure_secure_kernel_breakpoint(
    unsigned char *image, WHV_INITIAL_VP_CONTEXT *vtl1,
    const SECURE_KERNEL_IMAGE *secure_kernel)
{
    uint64_t breakpoint =
        secure_kernel->image_base + secure_kernel->breakpoint_rva;

    memset(image + VTL1_CODE_GPA, 0xCC, 0x200);
    set_idt_gate(image, VTL_ENTRY_VECTOR, VTL1_CODE_GPA);

    /*
     * The interrupt handler calls the shipping image's cc;ret stub as an
     * ordinary function. Completing #BP advances to ret; the handler records
     * that return and uses iretq to restore the interrupted VTL1 context.
     */
    image[VTL1_CODE_GPA + 0] = 0xC6;
    image[VTL1_CODE_GPA + 1] = 0x04;
    image[VTL1_CODE_GPA + 2] = 0x25;
    store_u32(image, VTL1_CODE_GPA + 3,
              (uint32_t)VTL1_WITNESS_GPA);
    image[VTL1_CODE_GPA + 7] = VTL1_WITNESS_VALUE;
    image[VTL1_CODE_GPA + 8] = 0x48;
    image[VTL1_CODE_GPA + 9] = 0xB8;
    store_u64(image, VTL1_CODE_GPA + 10, breakpoint);
    image[VTL1_CODE_GPA + 18] = 0xFF;
    image[VTL1_CODE_GPA + 19] = 0xD0;
    image[VTL1_CODE_GPA + 20] = 0xC6;
    image[VTL1_CODE_GPA + 21] = 0x04;
    image[VTL1_CODE_GPA + 22] = 0x25;
    store_u32(image, VTL1_CODE_GPA + 23,
              (uint32_t)VTL1_RESUME_WITNESS_GPA);
    image[VTL1_CODE_GPA + 27] = VTL1_RESUME_WITNESS_VALUE;
    image[VTL1_CODE_GPA + 28] = 0x48;
    image[VTL1_CODE_GPA + 29] = 0xCF;

    image[VTL1_IDLE_GPA + 0] = 0xFB;
    image[VTL1_IDLE_GPA + 1] = 0xF4;
    image[VTL1_IDLE_GPA + 2] = 0xEB;
    image[VTL1_IDLE_GPA + 3] = 0xFD;
    vtl1->Rip = VTL1_IDLE_GPA;
}

static uint32_t volatile_u32(const volatile unsigned char *buffer,
                             size_t offset)
{
    return *(const volatile uint32_t *)(buffer + offset);
}

static uint64_t volatile_u64(const volatile unsigned char *buffer,
                             size_t offset)
{
    return *(const volatile uint64_t *)(buffer + offset);
}

static MESSAGE_MATCH match_message(const volatile unsigned char *message)
{
    uint32_t type = volatile_u32(message, MESSAGE_TYPE_OFFSET);
    if (type == 0) {
        return MESSAGE_EMPTY;
    }
    MemoryBarrier();
    if (type != MESSAGE_TYPE_EXCEPTION ||
        volatile_u32(message, MESSAGE_SIZE_OFFSET) !=
            MESSAGE_EXCEPTION_BYTES ||
        volatile_u64(message, MESSAGE_CONTEXT_OFFSET) !=
            MESSAGE_CONTEXT_MARKER ||
        volatile_u32(message, MESSAGE_VP_OFFSET) != 0 ||
        message[MESSAGE_VECTOR_OFFSET] != BREAKPOINT_VECTOR) {
        return MESSAGE_UNEXPECTED;
    }
    return MESSAGE_EXPECTED;
}

static BOOL report_call(BOOL ok, const wchar_t *operation)
{
    if (!ok) {
        fwprintf(stderr, L"%ls failed: win32=%lu\n", operation,
                 GetLastError());
    }
    return ok;
}

static DWORD WINAPI receive_message(void *parameter)
{
    MESSAGE_RECEIVER *receiver = parameter;

    SetEvent(receiver->ready);
    for (;;) {
        InterlockedIncrement(&receiver->attempts);
        SetLastError(ERROR_SUCCESS);
        receiver->succeeded =
            receiver->api->message_slot_handle_and_get_next(
                receiver->partition, MESSAGE_SLOT, GET_NEXT_MESSAGE_FLAGS,
                NULL);
        receiver->error = receiver->succeeded ? ERROR_SUCCESS : GetLastError();
        if (receiver->succeeded ||
            receiver->error != ERROR_OPERATION_ABORTED ||
            InterlockedCompareExchange(&receiver->stop_requested, 0, 0) != 0) {
            return receiver->error;
        }
    }
}

static HANDLE start_message_receiver(const VID_API *api, HANDLE partition,
                                     HANDLE ready,
                                     MESSAGE_RECEIVER *receiver)
{
    HANDLE thread;

    memset(receiver, 0, sizeof(*receiver));
    receiver->api = api;
    receiver->partition = partition;
    receiver->ready = ready;
    ResetEvent(ready);
    thread = CreateThread(NULL, 0, receive_message, receiver, 0, NULL);
    if (thread == NULL) {
        fwprintf(stderr,
                 L"CreateThread(message receiver) failed: win32=%lu\n",
                 GetLastError());
        return NULL;
    }
    if (WaitForSingleObject(ready, 5000) != WAIT_OBJECT_0) {
        fwprintf(stderr, L"message receiver did not become ready\n");
        InterlockedExchange(&receiver->stop_requested, 1);
        api->message_slot_handle_and_get_next(
            partition, MESSAGE_SLOT, CANCEL_MESSAGE_WAIT_FLAGS, NULL);
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
        SetLastError(WAIT_TIMEOUT);
        return NULL;
    }
    while (InterlockedCompareExchange(&receiver->attempts, 0, 0) == 0) {
        Sleep(1);
    }
    return thread;
}

static void report_vp_state_at_vtl(const VID_API *api, HANDLE partition,
                                   uint8_t vtl)
{
    const uint32_t names[] = {
        HV_X64_REGISTER_RIP, HV_X64_REGISTER_RFLAGS,
        HV_X64_REGISTER_CR0, HV_X64_REGISTER_CR3,
        HV_X64_REGISTER_CR4,
    };
    WHV_REGISTER_VALUE values[ARRAYSIZE(names)];

    memset(values, 0, sizeof(values));
    if (api->get_virtual_processor_state_ex(
            partition, 0, HV_INPUT_VTL_EXPLICIT(vtl), names,
            (uint8_t)ARRAYSIZE(names), values)) {
        fwprintf(stderr,
                 L"stopped VTL%u state: rip=0x%llx rflags=0x%llx "
                 L"cr0=0x%llx cr3=0x%llx cr4=0x%llx\n",
                 (unsigned int)vtl,
                 (unsigned long long)values[0].Reg64,
                 (unsigned long long)values[1].Reg64,
                 (unsigned long long)values[2].Reg64,
                 (unsigned long long)values[3].Reg64,
                 (unsigned long long)values[4].Reg64);
    }
    else {
        fwprintf(stderr,
                 L"VidGetVirtualProcessorStateEx(VTL%u) failed: win32=%lu\n",
                 (unsigned int)vtl, GetLastError());
    }
}

static void report_vp_state(const VID_API *api, HANDLE partition)
{
    report_vp_state_at_vtl(api, partition, 0);
    report_vp_state_at_vtl(api, partition, TARGET_VTL);
}

static BOOL verify_vtl1_breakpoint_state(const VID_API *api,
                                         HANDLE partition,
                                         uint64_t expected_rip,
                                         uint64_t *observed_rip,
                                         uint64_t *observed_rsp)
{
    const uint32_t names[] = {
        HV_X64_REGISTER_RIP,
        HV_X64_REGISTER_RSP,
        HV_X64_REGISTER_CS,
    };
    WHV_REGISTER_VALUE values[ARRAYSIZE(names)];
    uint64_t rip;

    memset(values, 0, sizeof(values));
    if (!api->get_virtual_processor_state_ex(
            partition, 0, HV_INPUT_VTL_EXPLICIT(TARGET_VTL), names,
            (uint8_t)ARRAYSIZE(names), values)) {
        fwprintf(stderr,
                 L"cannot read the pending VTL1 breakpoint state: "
                 L"win32=%lu\n",
                 GetLastError());
        return FALSE;
    }
    rip = values[0].Reg64;
    wprintf(L"pending breakpoint state: vtl=1 cpl=%u rip=0x%llx "
            L"rsp=0x%llx\n",
            (unsigned int)values[2].Segment.DescriptorPrivilegeLevel,
            (unsigned long long)rip,
            (unsigned long long)values[1].Reg64);
    if (values[2].Segment.DescriptorPrivilegeLevel != 0 ||
        (rip != expected_rip && rip != expected_rip + 1)) {
        fwprintf(stderr,
                 L"refusing breakpoint state outside the selected VTL1 "
                 L"CPL0 instruction: expected rip 0x%llx or 0x%llx\n",
                 (unsigned long long)expected_rip,
                 (unsigned long long)(expected_rip + 1));
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    *observed_rip = rip;
    *observed_rsp = values[1].Reg64;
    return TRUE;
}

static BOOL verify_secure_kernel_breakpoint_memory(
    const VID_API *api, HANDLE partition, uint64_t memory_block,
    const SECURE_KERNEL_IMAGE *secure_kernel)
{
    static const unsigned char expected[] = {0xCC, 0xC3};
    unsigned char page[4096];
    uint64_t physical =
        SECURE_KERNEL_IMAGE_GPA + secure_kernel->breakpoint_rva;
    size_t offset = (size_t)(physical & 0xFFFu);

    memset(page, 0, sizeof(page));
    if (!api->read_memory_block_page_range(
            partition, memory_block, physical / 4096u, 1, page,
            sizeof(page))) {
        fwprintf(stderr,
                 L"Secure Kernel breakpoint readback failed: win32=%lu\n",
                 GetLastError());
        return FALSE;
    }
    if (!range_within(offset, sizeof(expected), sizeof(page)) ||
        memcmp(page + offset, expected, sizeof(expected)) != 0) {
        fwprintf(stderr,
                 L"Secure Kernel breakpoint bytes changed while stopped\n");
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    return TRUE;
}

static void report_live_vp_diagnostics(const VID_API *api, HANDLE partition)
{
    uint32_t running = UINT32_MAX;

    if (api->get_virtual_processor_running_status(partition, 0, &running)) {
        fwprintf(stderr, L"live VP status: running=%lu\n",
                 (unsigned long)running);
    }
    else {
        fwprintf(stderr,
                 L"VidGetVirtualProcessorRunningStatus failed: win32=%lu\n",
                 GetLastError());
    }
}

static void cancel_message_receiver(const VID_API *api, HANDLE partition,
                                    MESSAGE_RECEIVER *receiver,
                                    HANDLE receiver_thread)
{
    DWORD wait;

    if (receiver_thread == NULL) {
        return;
    }
    wait = WaitForSingleObject(receiver_thread, 0);
    if (wait == WAIT_TIMEOUT) {
        InterlockedExchange(&receiver->stop_requested, 1);
        if (!api->message_slot_handle_and_get_next(
                partition, MESSAGE_SLOT, CANCEL_MESSAGE_WAIT_FLAGS, NULL) &&
            GetLastError() != ERROR_OPERATION_ABORTED) {
            fwprintf(stderr,
                     L"cleanup cancel message wait failed: win32=%lu\n",
                     GetLastError());
        }
        wait = WaitForSingleObject(receiver_thread, 5000);
        if (wait != WAIT_OBJECT_0) {
            fwprintf(stderr,
                     L"message receiver did not exit after cancellation: "
                     L"wait=%lu\n",
                     wait);
        }
    }
}

static BOOL read_execution_witnesses(const VID_API *api, HANDLE partition,
                                     uint64_t memory_block,
                                     unsigned char *vtl0_witness,
                                     unsigned char *vtl1_witness,
                                     unsigned char *resume_witness)
{
    unsigned char page[4096];

    memset(page, 0, sizeof(page));
    if (!api->read_memory_block_page_range(
            partition, memory_block, VTL1_WITNESS_GPA / 4096, 1, page,
            sizeof(page))) {
        fwprintf(stderr, L"witness read failed: win32=%lu\n",
                 GetLastError());
        return FALSE;
    }
    *vtl0_witness = page[VTL0_WITNESS_GPA & 0xFFF];
    *vtl1_witness = page[VTL1_WITNESS_GPA & 0xFFF];
    if (resume_witness != NULL) {
        *resume_witness = page[VTL1_RESUME_WITNESS_GPA & 0xFFF];
    }
    return TRUE;
}

static void report_execution_witnesses(const VID_API *api, HANDLE partition,
                                       uint64_t memory_block)
{
    unsigned char vtl0_witness = 0;
    unsigned char vtl1_witness = 0;
    unsigned char resume_witness = 0;

    if (read_execution_witnesses(api, partition, memory_block,
                                 &vtl0_witness, &vtl1_witness,
                                 &resume_witness)) {
        fwprintf(stderr,
                 L"execution witnesses: vtl0=0x%02x vtl1=0x%02x "
                 L"resume=0x%02x\n",
                 vtl0_witness, vtl1_witness, resume_witness);
    }
}

static BOOL wait_for_resume_witness(const VID_API *api, HANDLE partition,
                                    uint64_t memory_block,
                                    DWORD timeout_ms)
{
    ULONGLONG deadline = GetTickCount64() + timeout_ms;

    for (;;) {
        unsigned char vtl0_witness = 0;
        unsigned char vtl1_witness = 0;
        unsigned char resume_witness = 0;

        if (!read_execution_witnesses(api, partition, memory_block,
                                      &vtl0_witness, &vtl1_witness,
                                      &resume_witness)) {
            return FALSE;
        }
        if (resume_witness == VTL1_RESUME_WITNESS_VALUE) {
            return TRUE;
        }
        if (GetTickCount64() >= deadline) {
            fwprintf(stderr,
                     L"timed out waiting for the VTL1 post-breakpoint "
                     L"resume witness: vtl0=0x%02x vtl1=0x%02x "
                     L"resume=0x%02x\n",
                     vtl0_witness, vtl1_witness, resume_witness);
            SetLastError(WAIT_TIMEOUT);
            return FALSE;
        }
        Sleep(1);
    }
}

static BOOL set_vtl0_context(const VID_API *api, HANDLE partition,
                             const WHV_INITIAL_VP_CONTEXT *context)
{
    const uint32_t names[] = {
        HV_X64_REGISTER_RIP,   HV_X64_REGISTER_RSP,
        HV_X64_REGISTER_RFLAGS, HV_X64_REGISTER_CS,
        HV_X64_REGISTER_DS,    HV_X64_REGISTER_ES,
        HV_X64_REGISTER_FS,    HV_X64_REGISTER_GS,
        HV_X64_REGISTER_SS,    HV_X64_REGISTER_TR,
        HV_X64_REGISTER_LDTR,  HV_X64_REGISTER_IDTR,
        HV_X64_REGISTER_GDTR,  HV_X64_REGISTER_EFER,
        HV_X64_REGISTER_CR0,   HV_X64_REGISTER_CR3,
        HV_X64_REGISTER_CR4,   HV_X64_REGISTER_PAT,
    };
    WHV_REGISTER_VALUE values[ARRAYSIZE(names)];
    size_t index = 0;

    memset(values, 0, sizeof(values));
    values[index++].Reg64 = context->Rip;
    values[index++].Reg64 = context->Rsp;
    values[index++].Reg64 = context->Rflags;
    values[index++].Segment = context->Cs;
    values[index++].Segment = context->Ds;
    values[index++].Segment = context->Es;
    values[index++].Segment = context->Fs;
    values[index++].Segment = context->Gs;
    values[index++].Segment = context->Ss;
    values[index++].Segment = context->Tr;
    values[index++].Segment = context->Ldtr;
    values[index++].Table = context->Idtr;
    values[index++].Table = context->Gdtr;
    values[index++].Reg64 = context->Efer;
    values[index++].Reg64 = context->Cr0;
    values[index++].Reg64 = context->Cr3;
    values[index++].Reg64 = context->Cr4;
    values[index++].Reg64 = context->MsrCrPat;

    if (index != ARRAYSIZE(names)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    return api->set_virtual_processor_state_ex(
        partition, 0, HV_INPUT_VTL_EXPLICIT(0), names,
        (uint8_t)ARRAYSIZE(names), values);
}

static BOOL is_hex_digit(wchar_t value)
{
    return (value >= L'0' && value <= L'9') ||
           (value >= L'a' && value <= L'f') ||
           (value >= L'A' && value <= L'F');
}

static BOOL is_bare_guid_name(const wchar_t *name)
{
    size_t index;

    if (name == NULL || wcslen(name) != 36) {
        return FALSE;
    }
    for (index = 0; index < 36; index++) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (name[index] != L'-') {
                return FALSE;
            }
        }
        else if (!is_hex_digit(name[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL make_partition_name(wchar_t *name, size_t name_chars)
{
    GUID guid;
    wchar_t braced[39];
    HRESULT result;

    if (name_chars < 37) {
        return FALSE;
    }
    result = CoCreateGuid(&guid);
    if (FAILED(result)) {
        fwprintf(stderr, L"CoCreateGuid failed: hresult=0x%08lX\n",
                 (unsigned long)result);
        return FALSE;
    }
    if (StringFromGUID2(&guid, braced, ARRAYSIZE(braced)) !=
        ARRAYSIZE(braced)) {
        fwprintf(stderr, L"StringFromGUID2 returned an unexpected length\n");
        return FALSE;
    }
    memcpy(name, braced + 1, 36 * sizeof(*name));
    name[36] = L'\0';
    return is_bare_guid_name(name);
}

static HANDLE create_owner_partition(const VID_API *api,
                                     unsigned char *setup)
{
    wchar_t name[37];
    HANDLE partition;

    initialize_setup(setup);
    if (!make_partition_name(name, ARRAYSIZE(name))) {
        fwprintf(stderr, L"cannot make a valid VID partition name\n");
        SetLastError(ERROR_INVALID_NAME);
        return INVALID_HANDLE_VALUE;
    }
    SetLastError(ERROR_SUCCESS);
    partition = api->create_partition(name, L"windbg-mcp VTL1 control probe",
                                      setup);
    if (partition == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        fwprintf(stderr,
                 L"VidCreatePartition failed: win32=%lu setup_version=0x600 "
                 L"processors=1 numa=1\n",
                 error);
        if (error == ERROR_ACCESS_DENIED) {
            fwprintf(stderr,
                     L"the guarded VID device requires an elevated token\n");
        }
    }
    else if (!api->attach_partition(partition)) {
        DWORD error = GetLastError();
        fwprintf(stderr, L"VidAttachPartition failed: win32=%lu\n", error);
        api->delete_partition(partition);
        SetLastError(error);
        partition = INVALID_HANDLE_VALUE;
    }
    return partition;
}

static int run_create_only(const VID_API *api, unsigned char *setup)
{
    HANDLE partition = create_owner_partition(api, setup);
    uint64_t partition_id = 0;
    int result = 1;

    if (partition == INVALID_HANDLE_VALUE) {
        return 1;
    }
    if (!report_call(api->get_hv_partition_id(partition, &partition_id),
                     L"VidGetHvPartitionId")) {
        goto cleanup;
    }
    wprintf(L"created owner partition: handle=0x%p hv_partition_id=0x%llx\n",
            partition, (unsigned long long)partition_id);
    result = 0;

cleanup:
    api->delete_partition(partition);
    wprintf(L"deleted owner partition\n");
    return result;
}

static int run_controlled_stop(const VID_API *api, unsigned char *setup,
                               DWORD timeout_ms, DWORD hold_ms,
                               const wchar_t *secure_kernel_path)
{
    HANDLE partition = INVALID_HANDLE_VALUE;
    unsigned char vsm_config[VSM_CONFIG_BYTES];
    unsigned char *guest = NULL;
    unsigned char verify_page[4096];
    MEMORY_BLOCK_DESCRIPTOR memory_descriptor;
    VID_MESSAGE_SLOT_HANDLE slot;
    WHV_INITIAL_VP_CONTEXT vtl0;
    WHV_INITIAL_VP_CONTEXT vtl1;
    SECURE_KERNEL_IMAGE secure_kernel;
    uint64_t partition_id = 0;
    uint64_t memory_block = 0;
    uint64_t gpa_range = UINT64_MAX;
    uint64_t memory_mapping = UINT64_MAX;
    void *mapped_guest = NULL;
    HANDLE receiver_ready = NULL;
    HANDLE receiver_thread = NULL;
    MESSAGE_RECEIVER receiver;
    BOOL vp_started = FALSE;
    BOOL abandon_partition = FALSE;
    BOOL diagnose_vp = FALSE;
    MESSAGE_MATCH match;
    unsigned char vtl0_witness = 0;
    unsigned char vtl1_witness = 0;
    uint64_t breakpoint_rip = VTL1_CODE_GPA + 8;
    uint64_t first_rip = 0;
    uint64_t first_rsp = 0;
    uint64_t held_rip = 0;
    uint64_t held_rsp = 0;
    ULONGLONG stopped_at;
    int result = 1;

    initialize_memory_descriptor(&memory_descriptor);
    memset(&slot, 0, sizeof(slot));
    memset(&receiver, 0, sizeof(receiver));
    memset(&secure_kernel, 0, sizeof(secure_kernel));
    guest = VirtualAlloc(NULL, GUEST_BYTES, MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE);
    if (guest == NULL) {
        fwprintf(stderr, L"guest image allocation failed: win32=%lu\n",
                 GetLastError());
        return 1;
    }
    build_guest_image(guest, &vtl0, &vtl1);
    if (secure_kernel_path != NULL) {
        if (!load_secure_kernel_image(secure_kernel_path, guest,
                                      &secure_kernel)) {
            goto cleanup;
        }
        configure_secure_kernel_breakpoint(guest, &vtl1,
                                           &secure_kernel);
        breakpoint_rip =
            secure_kernel.image_base + secure_kernel.breakpoint_rva;
        wprintf(L"loaded guarded Secure Kernel image: %ls "
                L"base=0x%llx size=0x%lx "
                L"DbgBreakPointWithStatus=0x%llx\n",
                secure_kernel_path,
                (unsigned long long)secure_kernel.image_base,
                (unsigned long)secure_kernel.size_of_image,
                (unsigned long long)breakpoint_rip);
    }
    initialize_vsm_config(vsm_config);

    partition = create_owner_partition(api, setup);
    if (partition == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    if (!report_call(api->get_hv_partition_id(partition, &partition_id),
                     L"VidGetHvPartitionId")) {
        goto cleanup;
    }
    wprintf(L"owner partition 0x%llx created\n",
            (unsigned long long)partition_id);

    if (!report_call(api->vsm_set_partition_config(
                         partition, VSM_CONFIG_BYTES, vsm_config),
                     L"VidVsmSetPartitionConfig")) {
        goto cleanup;
    }

    if (!report_call(api->create_memory_block(
                         partition, &memory_descriptor, &memory_block),
                     L"VidCreateMemoryBlock")) {
        goto cleanup;
    }
    if (!report_call(api->setup_message_queue(partition, 1),
                     L"VidSetupMessageQueue") ||
        !report_call(api->set_memory_block_notification_queue(
                         partition, memory_block, MESSAGE_SLOT),
                     L"VidSetMemoryBlockNotificationQueue")) {
        goto cleanup;
    }
    if (!report_call(api->create_va_gpa_range(
                         partition, 0, GUEST_PAGES, memory_block,
                         GPA_RANGE_APPLY_VTL_PROTECTIONS,
                         &gpa_range),
                     L"VidCreateVaGpaRange")) {
        goto cleanup;
    }
    if (!report_call(api->map_memory_block_page_range(
                         partition, memory_block, 0, GUEST_PAGES, 2,
                         &mapped_guest, &memory_mapping),
                     L"VidMapMemoryBlockPageRange")) {
        goto cleanup;
    }
    memcpy(mapped_guest, guest, GUEST_BYTES);
    MemoryBarrier();
    if (!report_call(api->write_memory_block_page_range(
                         partition, memory_block, 0, GUEST_PAGES, guest,
                         GUEST_BYTES),
                     L"VidWriteMemoryBlockPageRange")) {
        goto cleanup;
    }
    memset(verify_page, 0, sizeof(verify_page));
    if (!report_call(api->read_memory_block_page_range(
                         partition, memory_block, VTL0_CODE_GPA / 4096, 1,
                         verify_page, sizeof(verify_page)),
                     L"VidReadMemoryBlockPageRange")) {
        goto cleanup;
    }
    if (memcmp(verify_page, guest + VTL0_CODE_GPA,
               sizeof(verify_page)) != 0) {
        fwprintf(stderr, L"VID memory readback differs from the guest image\n");
        SetLastError(ERROR_INVALID_DATA);
        goto cleanup;
    }
    if (!report_call(api->unmap_memory_block_page_range(partition,
                                                         memory_mapping),
                     L"VidUnmapMemoryBlockPageRange")) {
        goto cleanup;
    }
    memory_mapping = UINT64_MAX;
    mapped_guest = NULL;

    if (!report_call(api->message_slot_map(partition, &slot, MESSAGE_SLOT),
                     L"VidMessageSlotMap")) {
        goto cleanup;
    }
    if (slot.exchange_buffer == NULL || slot.slot_index != MESSAGE_SLOT) {
        fwprintf(stderr, L"VidMessageSlotMap returned an invalid slot\n");
        SetLastError(ERROR_INVALID_DATA);
        goto cleanup;
    }

    if (!report_call(api->register_exception_handler(
                         partition, BREAKPOINT_VECTOR, 0,
                         MESSAGE_CONTEXT_MARKER),
                     L"VidRegisterExceptionHandler(#BP)")) {
        goto cleanup;
    }

    if (!report_call(set_vtl0_context(api, partition, &vtl0),
                     L"VidSetVirtualProcessorStateEx(VTL0)")) {
        goto cleanup;
    }
    if (!report_call(api->vsm_enable_vp_vtl(partition, 0, TARGET_VTL,
                                             &vtl1),
                     L"VidVsmEnableVpVtl")) {
        goto cleanup;
    }
    if (!report_call(api->start_virtual_processor(partition, 0, 0, NULL),
                     L"VidStartVirtualProcessor")) {
        goto cleanup;
    }
    vp_started = TRUE;

    /*
     * A GET_NEXT request owns the VP dispatch loop.
     */
    receiver_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (receiver_ready == NULL) {
        fwprintf(stderr, L"CreateEvent(message receiver) failed: win32=%lu\n",
                 GetLastError());
        goto cleanup;
    }
    receiver_thread = start_message_receiver(api, partition, receiver_ready,
                                             &receiver);
    if (receiver_thread == NULL) {
        goto cleanup;
    }

    if (!report_call(api->assert_virtual_processor_interrupt(
                         partition, INTERRUPT_TYPE_FIXED, 0,
                         VTL_ENTRY_VECTOR, TARGET_VTL),
                     L"VidAssertVirtualProcessorInterrupt(VTL1)")) {
        goto cleanup;
    }

    if (WaitForSingleObject(receiver_thread, timeout_ms) != WAIT_OBJECT_0) {
        report_execution_witnesses(api, partition, memory_block);
        fwprintf(stderr, L"message receiver attempts: %ld\n",
                 InterlockedCompareExchange(&receiver.attempts, 0, 0));
        report_live_vp_diagnostics(api, partition);
        report_vp_state(api, partition);
        diagnose_vp = TRUE;
        fwprintf(stderr,
                  L"timed out after %lu ms waiting for the VTL1 breakpoint\n",
                 timeout_ms);
        SetLastError(WAIT_TIMEOUT);
        goto cleanup;
    }
    if (!receiver.succeeded) {
        fwprintf(stderr, L"message receive failed: win32=%lu\n",
                 receiver.error);
        SetLastError(receiver.error);
        goto cleanup;
    }
    match = match_message(slot.exchange_buffer);
    if (match == MESSAGE_EMPTY) {
        fwprintf(stderr, L"message receive completed with an empty slot\n");
        SetLastError(ERROR_INVALID_DATA);
        goto cleanup;
    }
    if (match == MESSAGE_UNEXPECTED) {
        fwprintf(stderr,
                 L"refusing unexpected VID message: type=0x%08lx size=0x%lx "
                 L"context=0x%llx vp=%lu vector=%u\n",
                 (unsigned long)volatile_u32(slot.exchange_buffer,
                                             MESSAGE_TYPE_OFFSET),
                 (unsigned long)volatile_u32(slot.exchange_buffer,
                                             MESSAGE_SIZE_OFFSET),
                 (unsigned long long)volatile_u64(slot.exchange_buffer,
                                                  MESSAGE_CONTEXT_OFFSET),
                 (unsigned long)volatile_u32(slot.exchange_buffer,
                                             MESSAGE_VP_OFFSET),
                 (unsigned int)slot.exchange_buffer[MESSAGE_VECTOR_OFFSET]);
        abandon_partition = TRUE;
        SetLastError(ERROR_INVALID_DATA);
        goto cleanup;
    }
    if (!read_execution_witnesses(api, partition, memory_block,
                                  &vtl0_witness, &vtl1_witness, NULL) ||
        vtl1_witness != VTL1_WITNESS_VALUE) {
        fwprintf(stderr,
                 L"refusing breakpoint without the VTL1 execution witness: "
                 L"vtl0=0x%02x vtl1=0x%02x\n",
                 vtl0_witness, vtl1_witness);
        abandon_partition = TRUE;
        SetLastError(ERROR_INVALID_DATA);
        goto cleanup;
    }
    if (!verify_vtl1_breakpoint_state(api, partition, breakpoint_rip,
                                      &first_rip, &first_rsp) ||
        (secure_kernel_path != NULL &&
         !verify_secure_kernel_breakpoint_memory(
             api, partition, memory_block, &secure_kernel))) {
        abandon_partition = TRUE;
        goto cleanup;
    }

    stopped_at = GetTickCount64();
    if (secure_kernel_path != NULL) {
        wprintf(L"controlled Secure Kernel stop: partition=0x%llx "
                L"vtl=1 cpl=0 vp=0 vector=3 image_rip=0x%llx\n",
                (unsigned long long)partition_id,
                (unsigned long long)breakpoint_rip);
    }
    else {
        wprintf(L"controlled stop: partition=0x%llx vtl=1 vp=0 vector=3 "
                L"instruction_gpa=0x%llx\n",
                (unsigned long long)partition_id,
                (unsigned long long)breakpoint_rip);
    }
    if (hold_ms != 0) {
        Sleep(hold_ms);
    }
    if (!verify_vtl1_breakpoint_state(api, partition, breakpoint_rip,
                                      &held_rip, &held_rsp) ||
        held_rip != first_rip || held_rsp != first_rsp ||
        (secure_kernel_path != NULL &&
         !verify_secure_kernel_breakpoint_memory(
             api, partition, memory_block, &secure_kernel))) {
        fwprintf(stderr,
                 L"refusing a breakpoint whose VTL1 state or selected "
                 L"memory changed during the hold\n");
        abandon_partition = TRUE;
        SetLastError(ERROR_INVALID_DATA);
        goto cleanup;
    }
    wprintf(L"held pending intercept for %llu ms\n",
            (unsigned long long)(GetTickCount64() - stopped_at));

    *(volatile uint32_t *)(slot.exchange_buffer +
                          MESSAGE_RETURN_STATUS_OFFSET) = 0;
    slot.exchange_buffer[MESSAGE_ADVANCE_IP_OFFSET] = 1;
    MemoryBarrier();
    if (!report_call(api->message_slot_handle_and_get_next(
                         partition, MESSAGE_SLOT, COMPLETE_MESSAGE_FLAGS, NULL),
                     L"VidMessageSlotHandleAndGetNext")) {
        abandon_partition = TRUE;
        goto cleanup;
    }
    wprintf(L"completed the owned VTL1 breakpoint intercept\n");
    if (secure_kernel_path != NULL) {
        CloseHandle(receiver_thread);
        receiver_thread = start_message_receiver(
            api, partition, receiver_ready, &receiver);
        if (receiver_thread == NULL) {
            abandon_partition = TRUE;
            goto cleanup;
        }
        if (!wait_for_resume_witness(api, partition, memory_block,
                                     timeout_ms)) {
            report_live_vp_diagnostics(api, partition);
            report_vp_state(api, partition);
            abandon_partition = TRUE;
            goto cleanup;
        }
        cancel_message_receiver(api, partition, &receiver,
                                receiver_thread);
        if (receiver.succeeded) {
            fwprintf(stderr,
                     L"refusing an unexpected VID message while proving "
                     L"post-breakpoint resume\n");
            abandon_partition = TRUE;
            SetLastError(ERROR_INVALID_DATA);
            goto cleanup;
        }
        wprintf(L"Secure Kernel breakpoint returned and VTL1 resumed "
                L"through the interrupt frame\n");
    }
    result = 0;

cleanup:
    if (partition != INVALID_HANDLE_VALUE) {
        cancel_message_receiver(api, partition, &receiver, receiver_thread);
        if (!abandon_partition) {
            if (vp_started &&
                !api->stop_virtual_processor(partition, 0)) {
                fwprintf(stderr,
                         L"cleanup VidStopVirtualProcessor failed: win32=%lu\n",
                         GetLastError());
                result = 1;
            }
            else if (vp_started && diagnose_vp) {
                report_vp_state(api, partition);
            }
            if (memory_mapping != UINT64_MAX &&
                !api->unmap_memory_block_page_range(partition,
                                                     memory_mapping)) {
                fwprintf(stderr,
                         L"cleanup VidUnmapMemoryBlockPageRange failed: "
                         L"win32=%lu\n",
                         GetLastError());
                result = 1;
            }
            if (gpa_range != UINT64_MAX &&
                !api->destroy_gpa_range(partition, gpa_range)) {
                fwprintf(stderr,
                         L"cleanup VidDestroyGpaRange failed: win32=%lu\n",
                         GetLastError());
                result = 1;
            }
            if (memory_block != 0 &&
                !api->destroy_memory_block(partition, memory_block)) {
                fwprintf(stderr,
                         L"cleanup VidDestroyMemoryBlock failed: win32=%lu\n",
                         GetLastError());
                result = 1;
            }
        }
        api->delete_partition(partition);
        wprintf(L"deleted owner partition\n");
    }
    if (receiver_thread != NULL) {
        CloseHandle(receiver_thread);
    }
    if (receiver_ready != NULL) {
        CloseHandle(receiver_ready);
    }
    SecureZeroMemory(&vtl0, sizeof(vtl0));
    SecureZeroMemory(&vtl1, sizeof(vtl1));
    if (guest != NULL) {
        SecureZeroMemory(guest, GUEST_BYTES);
        VirtualFree(guest, 0, MEM_RELEASE);
    }
    return result;
}

static BOOL expect(BOOL condition, const wchar_t *description)
{
    if (!condition) {
        fwprintf(stderr, L"self-test failed: %ls\n", description);
        return FALSE;
    }
    return TRUE;
}

static int self_test(void)
{
    unsigned char *setup = NULL;
    unsigned char config[VSM_CONFIG_BYTES];
    unsigned char *guest = NULL;
    unsigned char message[0x200];
    WHV_INITIAL_VP_CONTEXT vtl0;
    WHV_INITIAL_VP_CONTEXT vtl1;
    MEMORY_BLOCK_DESCRIPTOR memory_descriptor;
    SECURE_KERNEL_IMAGE secure_kernel;
    IDT_GATE64 gate;
    wchar_t partition_name[37];
    BOOL ok = TRUE;

    setup = VirtualAlloc(NULL, VID_SETUP_BYTES, MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE);
    guest = VirtualAlloc(NULL, GUEST_BYTES, MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE);
    if (setup == NULL || guest == NULL) {
        fwprintf(stderr, L"self-test allocation failed: win32=%lu\n",
                 GetLastError());
        ok = FALSE;
        goto cleanup;
    }

    initialize_setup(setup);
    ok &= expect(make_partition_name(partition_name,
                                     ARRAYSIZE(partition_name)) &&
                     is_bare_guid_name(partition_name),
                 L"bare GUID partition name");
    ok &= expect(load_u32(setup, VID_SETUP_VERSION_OFFSET) == 0x600,
                 L"setup version");
    ok &= expect(load_u64(setup, VID_SETUP_FLAGS_OFFSET) ==
                     VID_SETUP_PROCESS_LOCAL,
                 L"setup flags");
    ok &= expect(load_u32(setup, VID_SETUP_PROCESSOR_COUNT_OFFSET) == 1,
                 L"processor count");
    ok &= expect(load_u32(setup, VID_SETUP_NUMA_COUNT_OFFSET) == 1,
                 L"NUMA count");

    initialize_vsm_config(config);
    ok &= expect(load_u32(config, VSM_ENABLED_VTL_SET_OFFSET) == 3,
                 L"VTL0/VTL1 enabled set");
    ok &= expect(load_u32(config, VSM_MBEC_ENABLED_VTL_SET_OFFSET) == 0,
                 L"MBEC disabled set");
    ok &= expect(load_u32(config, VSM_VTL1_PROTECTION_OFFSET) == 0xF,
                 L"VTL1 default protection");

    initialize_memory_descriptor(&memory_descriptor);
    ok &= expect(memory_descriptor.words[0] == GUEST_PAGES &&
                     memory_descriptor.words[1] == GUEST_PAGES &&
                     memory_descriptor.words[2] ==
                         (MEMORY_BLOCK_VA_BACKED |
                          MEMORY_BLOCK_VSM_CAPABLE) &&
                     memory_descriptor.words[10] == 0 &&
                     memory_descriptor.words[11] == 0 &&
                     GUEST_PAGES == 0x200,
                 L"VSM-capable VA-backed memory block descriptor");

    build_guest_image(guest, &vtl0, &vtl1);
    ok &= expect(load_u64(guest, PML4_GPA) == (PDPT_GPA | 3),
                 L"PML4 entry");
    ok &= expect(load_u64(guest, PDPT_GPA) == (PD_GPA | 3),
                 L"PDPT entry");
    ok &= expect(load_u64(guest, PD_GPA) == 0x83, L"2 MiB PDE");
    ok &= expect(guest[VTL1_CODE_GPA] == 0xC6 &&
                     guest[VTL1_CODE_GPA + 7] == VTL1_WITNESS_VALUE &&
                     guest[VTL1_CODE_GPA + 8] == 0xCC,
                 L"selected VTL1 instruction");
    memcpy(&gate, guest + IDT_GPA + VTL_ENTRY_VECTOR * sizeof(gate),
           sizeof(gate));
    ok &= expect(gate.selector == 8 && gate.type_attributes == 0x8E &&
                     gate.offset_low ==
                         (uint16_t)(VTL1_CODE_GPA & 0xFFFFull) &&
                     gate.offset_middle ==
                         (uint16_t)((VTL1_CODE_GPA >> 16) & 0xFFFFull),
                 L"VTL1 entry-interrupt gate");
    ok &= expect(vtl0.Rip == VTL0_CODE_GPA &&
                     vtl0.Cr0 == 0x80010033 &&
                     vtl0.Cr3 == PML4_GPA && vtl0.Cs.Long == 1 &&
                     vtl0.Cs.Default == 0,
                 L"VTL0 initial context");
    ok &= expect(vtl1.Rip == VTL1_CODE_GPA + 9 &&
                     vtl1.Idtr.Base == IDT_GPA &&
                     vtl1.Cs.DescriptorPrivilegeLevel == 0 &&
                     vtl1.Cs.Long == 1 && vtl1.Cs.Default == 0 &&
                     vtl1.Tr.Attributes == 0x008B &&
                     vtl1.Efer == 0x500 &&
                     vtl1.Cr0 == 0x80010033 &&
                     vtl1.Cr3 == PML4_GPA && vtl1.Cr4 == 0x20,
                 L"VTL1 kernel context");

    secure_kernel.image_base = SECURE_KERNEL_IMAGE_BASE;
    secure_kernel.size_of_image = SECURE_KERNEL_IMAGE_SIZE;
    secure_kernel.breakpoint_rva = SECURE_KERNEL_BREAKPOINT_RVA;
    configure_secure_kernel_breakpoint(guest, &vtl1, &secure_kernel);
    ok &= expect(guest[VTL1_CODE_GPA] == 0xC6 &&
                     load_u64(guest, VTL1_CODE_GPA + 10) ==
                         SECURE_KERNEL_IMAGE_BASE +
                             SECURE_KERNEL_BREAKPOINT_RVA &&
                     guest[VTL1_CODE_GPA + 18] == 0xFF &&
                     guest[VTL1_CODE_GPA + 19] == 0xD0 &&
                     guest[VTL1_CODE_GPA + 28] == 0x48 &&
                     guest[VTL1_CODE_GPA + 29] == 0xCF &&
                     vtl1.Rip == VTL1_IDLE_GPA,
                 L"Secure Kernel call/return trampoline");

    memset(message, 0, sizeof(message));
    ok &= expect(match_message(message) == MESSAGE_EMPTY,
                 L"empty message remains empty");
    store_u32(message, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_EXCEPTION);
    store_u32(message, MESSAGE_SIZE_OFFSET, MESSAGE_EXCEPTION_BYTES);
    store_u64(message, MESSAGE_CONTEXT_OFFSET, MESSAGE_CONTEXT_MARKER);
    store_u32(message, MESSAGE_VP_OFFSET, 0);
    message[MESSAGE_VECTOR_OFFSET] = BREAKPOINT_VECTOR;
    ok &= expect(match_message(message) == MESSAGE_EXPECTED,
                 L"exact breakpoint message accepted");
    message[MESSAGE_VECTOR_OFFSET] = 6;
    ok &= expect(match_message(message) == MESSAGE_UNEXPECTED,
                 L"wrong exception rejected");
    message[MESSAGE_VECTOR_OFFSET] = BREAKPOINT_VECTOR;
    store_u64(message, MESSAGE_CONTEXT_OFFSET, 0);
    ok &= expect(match_message(message) == MESSAGE_UNEXPECTED,
                 L"wrong handler marker rejected");

cleanup:
    SecureZeroMemory(&vtl0, sizeof(vtl0));
    SecureZeroMemory(&vtl1, sizeof(vtl1));
    if (guest != NULL) {
        SecureZeroMemory(guest, GUEST_BYTES);
        VirtualFree(guest, 0, MEM_RELEASE);
    }
    if (setup != NULL) {
        SecureZeroMemory(setup, VID_SETUP_BYTES);
        VirtualFree(setup, 0, MEM_RELEASE);
    }
    if (!ok) {
        return 1;
    }
    wprintf(L"self-test passed: ABI sizes, configs, guest image, and message "
            L"filter\n");
    return 0;
}

static BOOL parse_dword(const wchar_t *text, DWORD *value)
{
    wchar_t *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = wcstoul(text, &end, 10);
    if (errno != 0 || end == text || *end != L'\0' || parsed > MAXDWORD) {
        return FALSE;
    }
    *value = (DWORD)parsed;
    return TRUE;
}

static void usage(const wchar_t *program)
{
    fwprintf(stderr,
             L"usage:\n"
             L"  %ls --self-test\n"
             L"  %ls --create-only\n"
             L"  %ls --controlled-stop [--timeout-ms N] [--hold-ms N]\n"
             L"  %ls --securekernel-breakpoint [--image PATH] "
             L"[--timeout-ms N] [--hold-ms N]\n",
             program, program, program, program);
}

int wmain(int argc, wchar_t **argv)
{
    VID_API api;
    unsigned char *setup = NULL;
    DWORD timeout_ms = 10000;
    DWORD hold_ms = 250;
    BOOL controlled_stop = FALSE;
    BOOL secure_kernel_breakpoint = FALSE;
    wchar_t secure_kernel_default[MAX_PATH];
    const wchar_t *secure_kernel_path = NULL;
    int result;
    int i;

    if (argc == 2 && wcscmp(argv[1], L"--self-test") == 0) {
        return self_test();
    }
    if (argc >= 2 &&
        (wcscmp(argv[1], L"--controlled-stop") == 0 ||
         wcscmp(argv[1], L"--securekernel-breakpoint") == 0)) {
        controlled_stop = TRUE;
        secure_kernel_breakpoint =
            wcscmp(argv[1], L"--securekernel-breakpoint") == 0;
        for (i = 2; i < argc; i++) {
            if (wcscmp(argv[i], L"--timeout-ms") == 0 && i + 1 < argc) {
                if (!parse_dword(argv[++i], &timeout_ms) || timeout_ms == 0) {
                    usage(argv[0]);
                    return 2;
                }
            }
            else if (wcscmp(argv[i], L"--hold-ms") == 0 && i + 1 < argc) {
                if (!parse_dword(argv[++i], &hold_ms) || hold_ms > 60000) {
                    usage(argv[0]);
                    return 2;
                }
            }
            else if (secure_kernel_breakpoint &&
                     wcscmp(argv[i], L"--image") == 0 && i + 1 < argc) {
                secure_kernel_path = argv[++i];
            }
            else {
                usage(argv[0]);
                return 2;
            }
        }
    }
    else if (argc != 2 || wcscmp(argv[1], L"--create-only") != 0) {
        usage(argv[0]);
        return 2;
    }

    if (secure_kernel_breakpoint && secure_kernel_path == NULL) {
        wchar_t system[MAX_PATH];

        if (GetSystemDirectoryW(system, ARRAYSIZE(system)) == 0 ||
            swprintf_s(secure_kernel_default,
                       ARRAYSIZE(secure_kernel_default),
                       L"%ls\\securekernel.exe", system) < 0) {
            fwprintf(stderr,
                     L"cannot form the inbox Secure Kernel path "
                     L"(error %lu)\n",
                     GetLastError());
            return 2;
        }
        secure_kernel_path = secure_kernel_default;
    }

    if (!load_vid(&api)) {
        return 2;
    }
    setup = VirtualAlloc(NULL, VID_SETUP_BYTES, MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE);
    if (setup == NULL) {
        fwprintf(stderr, L"setup allocation failed: win32=%lu\n",
                 GetLastError());
        unload_vid(&api);
        return 2;
    }

    if (controlled_stop) {
        result = run_controlled_stop(
            &api, setup, timeout_ms, hold_ms,
            secure_kernel_breakpoint ? secure_kernel_path : NULL);
    }
    else {
        result = run_create_only(&api, setup);
    }

    SecureZeroMemory(setup, VID_SETUP_BYTES);
    VirtualFree(setup, 0, MEM_RELEASE);
    unload_vid(&api);
    return result;
}
