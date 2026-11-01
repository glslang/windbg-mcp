/*
 * h3probe.sys -- gate H3 of docs/secure-kernel-hypercall-feasibility.md
 *
 * Question: may a ROOT partition read a CHILD partition's VTL1 registers?
 *
 * H0 established from the TLFS that HvCallGetVpRegisters (0x0050) is callable
 * by "the parent of the partition specified by PartitionId" and carries a
 * TargetVtl at input offset 12.  What the TLFS does NOT say is that a parent
 * may name a child's VTL1 specifically -- that is an absence of prohibition,
 * not a permission, and this driver exists to convert it into a fact.
 *
 * Every constant here is from Microsoft's published TLFS, not from any
 * GPL-licensed header.  See the feasibility plan's clean-room note.
 *
 * The VTL0 read is the positive control and is not optional: if BOTH VTLs are
 * refused the finding is about privilege or plumbing and says nothing about
 * VTL1, and the two failures must not be reported as one.
 */

#include <ntddk.h>
#include <ntimage.h>   /* PE structures for the winhvr.sys export walk (S5q) */
#include <aux_klib.h>  /* AuxKlibQueryModuleInformation, to find it (S5q)    */
#include <wdmsec.h>    /* IoCreateDeviceSecure, SDDL_DEVOBJ_SYS_ALL_ADM_ALL  */

#define H3_DEVICE_NAME   L"\\Device\\H3Probe"

/* The class IoCreateDeviceSecure files the device under, so an administrator can override its
   security in the registry. Invented for this driver; it names no real device class. */
static const GUID H3_DEVICE_CLASS =
    { 0xf0650770, 0x266f, 0x4d66, { 0x80, 0xdb, 0x56, 0x6a, 0x46, 0xff, 0xbc, 0xb9 } };
#define H3_SYMLINK_NAME  L"\\DosDevices\\H3Probe"
#define IOCTL_H3_RUN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_H3_READGPA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_H3_CALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* --- TLFS constants ---------------------------------------------------- */

#define HvCallGetNextChildPartition   0x0047  /* Simple */
#define HvCallGetVpRegisters          0x0050  /* Rep    */
#define HvCallSetVpRegisters          0x0051  /* Rep    */
/*
 * HYPOTHESIS, not documentation.  The TLFS on Learn does not publish a page
 * for a GPA read; 0x0053 was suggested by a secondary source and sits
 * adjacent to TranslateVirtualAddress (0x0052).  It is tested rather than
 * trusted: a wrong code returns HV_STATUS_INVALID_HYPERCALL_CODE harmlessly,
 * and a right one is confirmed by reading a GPA whose contents we can already
 * predict -- the VTL0 CR3 measured in H3, which must look like a PML4.
 */
#define HvCallReadGpa_HYPOTHESIS      0x0053

#define HvX64RegisterCr3              0x00040002
#define HvX64RegisterCr0              0x00040000
#define HvRegisterVsmVpStatus         0x000D0003
#define HvRegisterVsmPartitionStatus  0x000D0004

#define HV_PARTITION_ID_SELF          ((ULONG64)-1)
#define HV_PARTITION_ID_INVALID       ((ULONG64)0)

/* HV_INPUT_VTL: TargetVtl:4, UseTargetVtl:1 */
#define HV_INPUT_VTL(vtl)             ((UCHAR)(((vtl) & 0xF) | 0x10))

#define HV_STATUS_SUCCESS             0x0000

/* --- results reported to user mode -------------------------------------- */

#pragma pack(push, 1)
typedef struct _H3_VP_RESULT {
    ULONG64 PartitionId;
    ULONG   VpIndex;

    ULONG   Vtl0Status;      /* HV_STATUS from the VTL0 read (the control) */
    ULONG64 Vtl0Cr3;

    ULONG   Vtl1Status;      /* HV_STATUS from the VTL1 read (the test)    */
    ULONG64 Vtl1Cr3;

    ULONG   VsmVpStatusStatus;
    ULONG64 VsmVpStatus;     /* ActiveVtl:4, ActiveMbecEnabled:1, EnabledVtlSet:16 */

    ULONG   VsmPartStatusStatus;
    ULONG64 VsmPartitionStatus;
} H3_VP_RESULT;

typedef struct _H3_RESULTS {
    ULONG        Version;
    ULONG        EnumStatus;       /* HV_STATUS of the last enumeration call */
    ULONG        ChildCount;
    ULONG        Reserved;
    H3_VP_RESULT Vp[8];
} H3_RESULTS;
#pragma pack(pop)

/* --- hypercall plumbing -------------------------------------------------- */

typedef ULONG64 (*PFN_HVL_INVOKE_HYPERCALL)(ULONG64 InputValue,
                                            ULONG64 InputPa,
                                            ULONG64 OutputPa);

static PFN_HVL_INVOKE_HYPERCALL g_HvlInvokeHypercall;
static PVOID   g_InputVa,  g_OutputVa;
static ULONG64 g_InputPa,  g_OutputPa;
static PDEVICE_OBJECT g_Device;
/* Every handle shares the two hypercall pages. Keep composing, issuing and copying one call under
   the same lock so providers in different processes cannot splice their inputs and outputs. */
static FAST_MUTEX g_HypercallMutex;

/* A rep hypercall returns the completion count in status bits 43:32. */
#define HV_STATUS_CODE(r)  ((ULONG)((r) & 0xFFFF))

static ULONG64 H3Hypercall(ULONG64 Control)
{
    return g_HvlInvokeHypercall(Control, g_InputPa, g_OutputPa);
}

/*
 * One HvCallGetVpRegisters rep call for a single register name at a given VTL.
 * Input layout per TLFS: PartitionId(0,8) VpIndex(8,4) TargetVtl(12,1)
 * RsvdZ(13,3) then rep elements of HV_REGISTER_NAME (4 bytes each).
 * Output: rep elements of HV_REGISTER_VALUE (16 bytes each).
 */
static ULONG H3GetVpRegister(ULONG64 PartitionId, ULONG VpIndex, UCHAR InputVtl,
                             ULONG RegisterName, ULONG64 *Value)
{
    ULONG64 result;
    UCHAR  *in  = (UCHAR *)g_InputVa;
    UCHAR  *out = (UCHAR *)g_OutputVa;

    ExAcquireFastMutex(&g_HypercallMutex);
    RtlZeroMemory(g_InputVa, PAGE_SIZE);
    RtlZeroMemory(g_OutputVa, PAGE_SIZE);

    *(ULONG64 *)(in + 0)  = PartitionId;
    *(ULONG   *)(in + 8)  = VpIndex;
    *(UCHAR   *)(in + 12) = InputVtl;
    *(ULONG   *)(in + 16) = RegisterName;      /* first rep element */

    /* control = call code | rep count 1 at bits 43:32 */
    result = H3Hypercall((ULONG64)HvCallGetVpRegisters | (1ULL << 32));

    if (HV_STATUS_CODE(result) == HV_STATUS_SUCCESS)
        *Value = *(ULONG64 *)(out + 0);        /* low 64 of HV_REGISTER_VALUE */
    else
        *Value = 0;

    ExReleaseFastMutex(&g_HypercallMutex);
    return HV_STATUS_CODE(result);
}

static ULONG H3GetNextChild(ULONG64 Previous, ULONG64 *Next)
{
    ULONG64 result;
    UCHAR  *in  = (UCHAR *)g_InputVa;
    UCHAR  *out = (UCHAR *)g_OutputVa;

    ExAcquireFastMutex(&g_HypercallMutex);
    RtlZeroMemory(g_InputVa, PAGE_SIZE);
    RtlZeroMemory(g_OutputVa, PAGE_SIZE);

    *(ULONG64 *)(in + 0) = HV_PARTITION_ID_SELF;
    *(ULONG64 *)(in + 8) = Previous;

    result = H3Hypercall((ULONG64)HvCallGetNextChildPartition);

    *Next = (HV_STATUS_CODE(result) == HV_STATUS_SUCCESS)
          ? *(ULONG64 *)(out + 0) : HV_PARTITION_ID_INVALID;

    ExReleaseFastMutex(&g_HypercallMutex);
    return HV_STATUS_CODE(result);
}

static void H3Run(H3_RESULTS *r)
{
    ULONG64 prev = HV_PARTITION_ID_INVALID, next = 0;
    ULONG   n = 0;

    RtlZeroMemory(r, sizeof(*r));
    r->Version = 1;

    while (n < RTL_NUMBER_OF(r->Vp)) {
        r->EnumStatus = H3GetNextChild(prev, &next);
        if (r->EnumStatus != HV_STATUS_SUCCESS)
            break;
        if (next == HV_PARTITION_ID_INVALID || next == 0)
            break;

        r->Vp[n].PartitionId = next;
        r->Vp[n].VpIndex     = 0;

        /* Locals, not addresses of packed members: &packed is potentially
           unaligned and writing through it is undefined. */
        {
            ULONG64 cr3Vtl0 = 0, cr3Vtl1 = 0, vsmVp = 0, vsmPart = 0;
            ULONG   stVtl0, stVtl1, stVsmVp, stVsmPart;

            /* control first: VTL0 must succeed for a VTL1 refusal to mean anything */
            stVtl0 = H3GetVpRegister(next, 0, HV_INPUT_VTL(0),
                                     HvX64RegisterCr3, &cr3Vtl0);
            /* the actual test */
            stVtl1 = H3GetVpRegister(next, 0, HV_INPUT_VTL(1),
                                     HvX64RegisterCr3, &cr3Vtl1);
            /* independent corroboration that VTL1 exists on this VP at all */
            stVsmVp = H3GetVpRegister(next, 0, HV_INPUT_VTL(0),
                                      HvRegisterVsmVpStatus, &vsmVp);
            stVsmPart = H3GetVpRegister(next, 0, HV_INPUT_VTL(0),
                                        HvRegisterVsmPartitionStatus, &vsmPart);

            r->Vp[n].Vtl0Status          = stVtl0;
            r->Vp[n].Vtl0Cr3             = cr3Vtl0;
            r->Vp[n].Vtl1Status          = stVtl1;
            r->Vp[n].Vtl1Cr3             = cr3Vtl1;
            r->Vp[n].VsmVpStatusStatus   = stVsmVp;
            r->Vp[n].VsmVpStatus         = vsmVp;
            r->Vp[n].VsmPartStatusStatus = stVsmPart;
            r->Vp[n].VsmPartitionStatus  = vsmPart;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "h3probe: part=0x%llX vtl0=%u/0x%llX vtl1=%u/0x%llX vsmvp=%u/0x%llX\n",
                   next, r->Vp[n].Vtl0Status, r->Vp[n].Vtl0Cr3,
                   r->Vp[n].Vtl1Status, r->Vp[n].Vtl1Cr3,
                   r->Vp[n].VsmVpStatusStatus, r->Vp[n].VsmVpStatus);

        prev = next;
        n++;
    }
    r->ChildCount = n;
}

/*
 * Input layout is also hypothesised, by analogy with other partition-targeted
 * calls: PartitionId(0,8) VpIndex(8,4) ByteCount(12,4) BaseGpa(16,8)
 * ControlFlags(24,8).  Output assumed AccessResult(0,8) then Data[16] at 8.
 * If the layout is wrong the hypervisor answers INVALID_HYPERCALL_INPUT or
 * INVALID_ALIGNMENT, which is a different answer from INVALID_HYPERCALL_CODE
 * -- so the two mistakes are distinguishable rather than conflated.
 */
static ULONG H3ReadGpa(ULONG64 PartitionId, ULONG64 Gpa, ULONG ByteCount,
                       UCHAR *Data, ULONG64 *AccessResult)
{
    ULONG64 result;
    UCHAR  *in  = (UCHAR *)g_InputVa;
    UCHAR  *out = (UCHAR *)g_OutputVa;

    ExAcquireFastMutex(&g_HypercallMutex);
    RtlZeroMemory(g_InputVa, PAGE_SIZE);
    RtlZeroMemory(g_OutputVa, PAGE_SIZE);

    *(ULONG64 *)(in + 0)  = PartitionId;
    *(ULONG   *)(in + 8)  = 0;              /* VpIndex */
    *(ULONG   *)(in + 12) = ByteCount;
    *(ULONG64 *)(in + 16) = Gpa;
    *(ULONG64 *)(in + 24) = 0;              /* ControlFlags */

    result = H3Hypercall((ULONG64)HvCallReadGpa_HYPOTHESIS);

    *AccessResult = *(ULONG64 *)(out + 0);
    RtlCopyMemory(Data, out + 8, 16);
    ExReleaseFastMutex(&g_HypercallMutex);
    return HV_STATUS_CODE(result);
}

/*
 * The raw probe. Everything the caller supplies is a parameter, and the
 * output page is POISONED rather than zeroed before the call.
 *
 * That is the whole point. H3ReadGpa above zeroes the output page, so a page
 * that comes back zero cannot be told apart from a page the hypervisor never
 * wrote -- which is exactly the ambiguity H4 is stuck on. With 0xAA in it,
 * a byte that is still 0xAA was not written, a byte that changed was, and
 * the boundary between them IS the output layout. No header is trusted and
 * no oracle is needed: the measurement answers for itself.
 */
#pragma pack(push, 1)
typedef struct _H3_RAW_IN {
    ULONG64 PartitionId;
    ULONG64 Gpa;
    ULONG   ByteCount;
    ULONG   VpIndex;
    ULONG64 ControlFlags;
    ULONG   CallCode;
    ULONG   RepCount;          /* 0 => simple call, no rep bits set */
} H3_RAW_IN;

typedef struct _H3_RAW_OUT {
    ULONG64 RawResult;         /* the whole return value, not just the status */
    UCHAR   Poison;            /* the byte the page was filled with */
    UCHAR   Pad[7];
    UCHAR   Out[64];           /* first 64 bytes of the output page, verbatim */
} H3_RAW_OUT;
#pragma pack(pop)

#define H3_POISON 0xAA

static ULONG64 H3RawGpa(const H3_RAW_IN *q, UCHAR *OutBytes)
{
    ULONG64 result, control;
    UCHAR  *in  = (UCHAR *)g_InputVa;

    ExAcquireFastMutex(&g_HypercallMutex);
    RtlZeroMemory(g_InputVa, PAGE_SIZE);
    RtlFillMemory(g_OutputVa, PAGE_SIZE, H3_POISON);

    *(ULONG64 *)(in + 0)  = q->PartitionId;
    *(ULONG   *)(in + 8)  = q->VpIndex;
    *(ULONG   *)(in + 12) = q->ByteCount;
    *(ULONG64 *)(in + 16) = q->Gpa;
    *(ULONG64 *)(in + 24) = q->ControlFlags;

    control = (ULONG64)q->CallCode;
    if (q->RepCount)
        control |= ((ULONG64)q->RepCount << 32);

    result = H3Hypercall(control);

    RtlCopyMemory(OutBytes, g_OutputVa, 64);
    ExReleaseFastMutex(&g_HypercallMutex);
    return result;
}

/*
 * HvCallWriteGpa. The input layout is NOT guessed and NOT taken from a header:
 * it was read instruction by instruction out of winhvr.sys!WinHvWriteGpa on
 * this build, which is the same wrapper family that confirmed the read side.
 *
 *   +0x00 PartitionId   (8)    mov [rcx],rbp
 *   +0x08 VpIndex       (4)    mov [rcx+8],esi
 *   +0x0C ByteCount     (4)    mov [rcx+0Ch],ebx    -- capped at 16
 *   +0x10 BaseGpa       (8)    mov [rcx+10h],rdi
 *   +0x18 ControlFlags  (8)    mov [rcx+18h],rax
 *   +0x20 Data[16]             add rcx,20h ; memcpy
 *
 * Getting this wrong writes the right bytes to the wrong place, which is why it
 * comes from the disassembly rather than from the 2010 header that agrees with
 * it. The call code is a parameter so that 0x0054 is stated by the caller and
 * visible in the log, never hardcoded next to a read.
 */
#pragma pack(push, 1)
typedef struct _H3_WRITE_IN {
    ULONG64 PartitionId;
    ULONG64 Gpa;
    ULONG   ByteCount;
    ULONG   VpIndex;
    ULONG64 ControlFlags;
    ULONG   CallCode;
    ULONG   Reserved;
    UCHAR   Data[16];
} H3_WRITE_IN;

typedef struct _H3_WRITE_OUT {
    ULONG64 RawResult;
    UCHAR   Poison;
    UCHAR   Pad[7];
    UCHAR   Out[64];
} H3_WRITE_OUT;
#pragma pack(pop)

static ULONG64 H3WriteGpa(const H3_WRITE_IN *q, UCHAR *OutBytes)
{
    ULONG64 result;
    UCHAR  *in = (UCHAR *)g_InputVa;

    ExAcquireFastMutex(&g_HypercallMutex);
    RtlZeroMemory(g_InputVa, PAGE_SIZE);
    RtlFillMemory(g_OutputVa, PAGE_SIZE, H3_POISON);

    *(ULONG64 *)(in + 0)  = q->PartitionId;
    *(ULONG   *)(in + 8)  = q->VpIndex;
    *(ULONG   *)(in + 12) = q->ByteCount;
    *(ULONG64 *)(in + 16) = q->Gpa;
    *(ULONG64 *)(in + 24) = q->ControlFlags;
    RtlCopyMemory(in + 32, q->Data, 16);

    result = H3Hypercall((ULONG64)q->CallCode);

    RtlCopyMemory(OutBytes, g_OutputVa, 64);
    ExReleaseFastMutex(&g_HypercallMutex);
    return result;
}

#pragma pack(push, 1)
typedef struct _H3_READGPA_IN {
    ULONG64 PartitionId;
    ULONG64 Gpa;
    ULONG   ByteCount;
    ULONG   Reserved;
} H3_READGPA_IN;

typedef struct _H3_READGPA_OUT {
    ULONG   HvStatus;
    ULONG   Reserved;
    ULONG64 AccessResult;
    UCHAR   Data[16];
} H3_READGPA_OUT;
#pragma pack(pop)

/*
 * A bounded register hypercall. The built-in providers need only
 * HvCallGetVpRegisters and HvCallSetVpRegisters; every other call is refused by the dispatch path
 * before this function can issue it.
 */
#pragma pack(push, 1)
typedef struct _H3_CALL_IN {
    ULONG64 Control;           /* call code, plus any fast/rep bits the caller wants */
    ULONG   InputBytes;        /* how much of In[] to present; the rest of the page is zero */
    ULONG   Reserved;
    UCHAR   In[64];
} H3_CALL_IN;

typedef struct _H3_CALL_OUT {
    ULONG64 RawResult;         /* the whole return value, not just the status */
    UCHAR   Poison;
    UCHAR   Pad[7];
    UCHAR   Out[64];
} H3_CALL_OUT;
#pragma pack(pop)

static ULONG64 H3Call(const H3_CALL_IN *q, UCHAR *OutBytes)
{
    ULONG64 result;
    ULONG   n = q->InputBytes > sizeof(q->In) ? (ULONG)sizeof(q->In) : q->InputBytes;

    ExAcquireFastMutex(&g_HypercallMutex);
    RtlZeroMemory(g_InputVa, PAGE_SIZE);
    RtlFillMemory(g_OutputVa, PAGE_SIZE, H3_POISON);
    RtlCopyMemory(g_InputVa, q->In, n);

    result = H3Hypercall(q->Control);

    RtlCopyMemory(OutBytes, g_OutputVa, 64);
    ExReleaseFastMutex(&g_HypercallMutex);
    return result;
}

/* --- winhvr.sys export resolution (gate S5q) ------------------------------
 *
 * The receiver S5q needs lives in `winhvr.sys`, and there is no way to link
 * against it: the WDK ships NO kernel-mode import library for that module --
 * the only WinHv* libraries in 10.0.26100.0 are the user-mode
 * WinHvPlatform/WinHvEmulation pair, which is the WHP *Exo* family that S5m
 * already established is a different mechanism.  And MmGetSystemRoutineAddress,
 * which is how this driver resolves nt!HvlInvokeHypercall above, is documented
 * to resolve routines in ntoskrnl and hal only.
 *
 * So the driver finds the module and parses its export directory itself.  This
 * is the one piece of S5q with no precedent in h3probe, which is why it has an
 * IOCTL of its own: it is exercised, and its answer read, before anything
 * installs an intercept or chains a routine.  A resolver that silently returned
 * a wrong pointer would fault inside Hyper-V's dispatch path, and that is a
 * HOST bug check rather than a guest one.
 *
 * Failure here is deliberately NOT fatal to the load.  The first job of this
 * code is to REPORT what it could resolve on a given build; a driver that
 * refuses to load tells the operator far less than one that loads and answers
 * "six of eight, and here are which".  Every consumer checks its pointer.
 */

#define H3_WINHV_EXPORT_COUNT 8

/* Order is the wire contract with the client; append only. */
static const CHAR *const g_WinHvExportNames[H3_WINHV_EXPORT_COUNT] = {
    "WinHvSetInterceptRoutine",
    "WinHvCompleteIntercept",
    "WinHvInstallIntercept",
    "WinHvGetSintMessage",
    "WinHvSetEndOfMessage",
    "WinHvCreatePort",
    "WinHvConnectPort",
    "WinHvAllocatePartitionSintIndex",
};

#pragma pack(push, 1)
typedef struct _H3_RESOLVE_OUT {
    ULONG   Version;
    ULONG   Status;        /* NTSTATUS of the walk as a whole */
    ULONG64 ModuleBase;
    ULONG   ModuleSize;
    ULONG   Resolved;      /* how many of H3_WINHV_EXPORT_COUNT were found */
    ULONG64 Address[H3_WINHV_EXPORT_COUNT];
} H3_RESOLVE_OUT;
#pragma pack(pop)

static PVOID   g_WinHvBase;
static ULONG   g_WinHvSize;
static NTSTATUS g_ResolveStatus = STATUS_UNSUCCESSFUL;
static PVOID   g_WinHvExport[H3_WINHV_EXPORT_COUNT];

/* Vid.sys, for item 103 step 9's read.  Found the same way winhvr.sys is, and
   used for two things only: bounding the build check, and verifying that the
   routine Hyper-V has registered for a partition really does land inside this
   image before its context is walked as a VID partition object. */
static PVOID   g_VidBase;
static ULONG   g_VidSize;
static NTSTATUS g_VidStatus = STATUS_UNSUCCESSFUL;

#define H3_POOL_TAG 'bp3h'

/*
 * Case-insensitive compare of an ANSI file name.  AuxKlib gives the full path
 * with FileNameOffset pointing at the leaf, so only the leaf is compared -- the
 * directory differs between a boot-loaded and a demand-loaded driver and is not
 * part of the identity we mean.
 */
static BOOLEAN H3AnsiLeafEquals(const UCHAR *Leaf, const CHAR *Want)
{
    SIZE_T i;
    for (i = 0; Want[i] != '\0'; i++) {
        CHAR a = (CHAR)Leaf[i];
        CHAR b = Want[i];
        if (a >= 'A' && a <= 'Z') a = (CHAR)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (CHAR)(b - 'A' + 'a');
        if (a != b) return FALSE;
    }
    return Leaf[i] == '\0';
}

static NTSTATUS H3FindModule(const CHAR *Leaf, PVOID *Base, ULONG *Size)
{
    NTSTATUS st;
    ULONG bytes = 0, count, i;
    AUX_MODULE_EXTENDED_INFO *mods;

    *Base = NULL;
    *Size = 0;

    st = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(st) || bytes == 0) {
        return NT_SUCCESS(st) ? STATUS_NOT_FOUND : st;
    }
    mods = (AUX_MODULE_EXTENDED_INFO *)ExAllocatePool2(POOL_FLAG_PAGED, bytes, H3_POOL_TAG);
    if (!mods) return STATUS_INSUFFICIENT_RESOURCES;

    st = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), mods);
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(mods, H3_POOL_TAG);
        return st;
    }

    count = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);
    st = STATUS_NOT_FOUND;
    for (i = 0; i < count; i++) {
        USHORT off = mods[i].FileNameOffset;
        if (off >= sizeof(mods[i].FullPathName)) continue;
        if (H3AnsiLeafEquals(&mods[i].FullPathName[off], Leaf)) {
            *Base = mods[i].BasicInfo.ImageBase;
            *Size = mods[i].ImageSize;
            st = STATUS_SUCCESS;
            break;
        }
    }
    ExFreePoolWithTag(mods, H3_POOL_TAG);
    return st;
}

static BOOLEAN H3AnsiEquals(const CHAR *A, const CHAR *B)
{
    SIZE_T i;
    for (i = 0; A[i] != '\0' && B[i] != '\0'; i++) {
        if (A[i] != B[i]) return FALSE;
    }
    return A[i] == B[i];
}

/*
 * Export lookup over a LOADED image, so every RVA is directly addressable from
 * the base and no section mapping arithmetic is needed.
 *
 * Every RVA is bounded against ImageSize before it is dereferenced.  This is
 * not defensive habit: these structures come from a file on disk, the walk runs
 * in the root kernel, and an out-of-range read here bug checks the HOST.  A
 * forwarded export -- one whose function RVA falls back inside the export
 * directory, where the value is a "Dll.Name" string rather than code -- is
 * REFUSED rather than returned, because calling a forwarder string is exactly
 * the wrong-pointer fault this gate cannot afford.
 */
static PVOID H3FindExport(PVOID Base, ULONG Size, const CHAR *Name)
{
    PUCHAR b = (PUCHAR)Base;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY dd;
    PIMAGE_EXPORT_DIRECTORY exp;
    PULONG names, funcs;
    PUSHORT ords;
    ULONG i;

    if (!Base || Size < sizeof(IMAGE_DOS_HEADER)) return NULL;
    dos = (PIMAGE_DOS_HEADER)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > Size) return NULL;

    nt = (PIMAGE_NT_HEADERS64)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return NULL;

    dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dd.VirtualAddress == 0 || dd.Size == 0) return NULL;
    if (dd.VirtualAddress + dd.Size > Size) return NULL;

    exp = (PIMAGE_EXPORT_DIRECTORY)(b + dd.VirtualAddress);
    if (exp->AddressOfNames == 0 || exp->AddressOfNameOrdinals == 0 ||
        exp->AddressOfFunctions == 0) {
        return NULL;
    }
    if (exp->AddressOfNames + (ULONG64)exp->NumberOfNames * 4 > Size) return NULL;
    if (exp->AddressOfNameOrdinals + (ULONG64)exp->NumberOfNames * 2 > Size) return NULL;
    if (exp->AddressOfFunctions + (ULONG64)exp->NumberOfFunctions * 4 > Size) return NULL;

    names = (PULONG)(b + exp->AddressOfNames);
    ords  = (PUSHORT)(b + exp->AddressOfNameOrdinals);
    funcs = (PULONG)(b + exp->AddressOfFunctions);

    for (i = 0; i < exp->NumberOfNames; i++) {
        ULONG nameRva = names[i];
        USHORT ord;
        ULONG fnRva;
        if (nameRva == 0 || nameRva >= Size) continue;
        if (!H3AnsiEquals((const CHAR *)(b + nameRva), Name)) continue;

        ord = ords[i];
        if (ord >= exp->NumberOfFunctions) return NULL;
        fnRva = funcs[ord];
        if (fnRva == 0 || fnRva >= Size) return NULL;
        /* A forwarder, not code. Refuse rather than hand back a string. */
        if (fnRva >= dd.VirtualAddress && fnRva < dd.VirtualAddress + dd.Size) return NULL;
        return b + fnRva;
    }
    return NULL;
}

static void H3ResolveWinHv(void)
{
    ULONG i;

    g_ResolveStatus = H3FindModule("winhvr.sys", &g_WinHvBase, &g_WinHvSize);
    if (!NT_SUCCESS(g_ResolveStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "h3probe: winhvr.sys not in the module list (0x%08X)\n",
                   g_ResolveStatus);
        return;
    }
    for (i = 0; i < H3_WINHV_EXPORT_COUNT; i++) {
        g_WinHvExport[i] = H3FindExport(g_WinHvBase, g_WinHvSize, g_WinHvExportNames[i]);
        if (!g_WinHvExport[i]) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "h3probe: winhvr!%s not resolved\n", g_WinHvExportNames[i]);
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "h3probe: winhvr.sys base=%p size=0x%X\n", g_WinHvBase, g_WinHvSize);

    /* Non-fatal on purpose, exactly as a missing export is: a probe that says
       "Vid.sys not found, and here is the status" tells the operator more than
       one that refuses to load. Every consumer checks g_VidBase itself. */
    g_VidStatus = H3FindModule("Vid.sys", &g_VidBase, &g_VidSize);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "h3probe: Vid.sys base=%p size=0x%X status=0x%08X\n",
               g_VidBase, g_VidSize, g_VidStatus);
}

static void H3Resolve(H3_RESOLVE_OUT *Out)
{
    ULONG i;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->Version    = 1;
    Out->Status     = (ULONG)g_ResolveStatus;
    Out->ModuleBase = (ULONG64)(ULONG_PTR)g_WinHvBase;
    Out->ModuleSize = g_WinHvSize;
    for (i = 0; i < H3_WINHV_EXPORT_COUNT; i++) {
        Out->Address[i] = (ULONG64)(ULONG_PTR)g_WinHvExport[i];
        if (g_WinHvExport[i]) Out->Resolved++;
    }
}

/* --- winhvr partition table, READ ONLY (gate S5q, step 2) -----------------
 *
 * Reads the routine/context pair that Hyper-V currently has registered for each
 * partition, and writes nothing.  It exists so that chaining -- which replaces
 * that pair -- is the SECOND surprise rather than the first.
 *
 * Layout, read out of this build's own code rather than taken from a note.
 * `WinHvpReferencePartition` (+0x2B40) and `WinHvpOnInterception` (+0x4438)
 * agree on all of it:
 *
 *     WinHvpPartitionArray  ->  [0x00] ULONG  Count
 *                               [0x08] { ULONG64 PartitionId; PVOID Object; }[]
 *
 *     Object  ->  [0x00] ULONG  RefCount      (`lock inc [rbx]`)
 *                 [0x10] PVOID  Routine
 *                 [0x18] PVOID  Context
 *
 * and the dispatch is  Routine(Context, Message)  -- context in rcx, message in
 * rdx -- reached through `guard_dispatch_icall`, i.e. a CFG-guarded indirect
 * call.  That matters for the chaining step and not for this one: a callback we
 * supply has to be an acceptable indirect-call target, which on an HVCI host is
 * a real constraint and on this bench is not, HVCI being off (test-signed
 * drivers load here, which is the behavioural test -- `SecurityServicesRunning`
 * is a field this record has already caught being wrong).
 *
 * WinHvpPartitionArray is NOT exported, so its RVA is a build-specific constant
 * and using it on another build would read arbitrary kernel memory.  The IOCTL
 * therefore refuses unless the loaded image's TimeDateStamp AND SizeOfImage
 * match the build the RVA was read from.  This is the whole safety argument;
 * without it the constant is a loaded gun.
 *
 * The same shared push lock `WinHvpReferencePartition` takes is taken here, for
 * the same reason it does: a partition can be torn down concurrently, and a
 * stale Object pointer dereferenced at +0x10 faults in the ROOT kernel.
 */

/* Read from C:\Windows\System32\drivers\winhvr.sys 10.0.26100.8972 on the bench
   host, 2026-09-29, and checked against the loaded image before use. */
#define H3_WHV_TIMESTAMP      0x31B98FBAUL
#define H3_WHV_SIZEOFIMAGE    0x29000UL
#define H3_WHV_PARTARRAY_RVA  0x152D0UL
#define H3_WHV_PARTLOCK_RVA   0x152C8UL

#define H3_WHVPART_MAX 8
/* A count larger than this is not a table we understand; refuse rather than
   walk it. The host runs a handful of partitions, not thousands. */
#define H3_WHVPART_SANE_COUNT 1024

#pragma pack(push, 1)
typedef struct _H3_WHVPART_ENTRY {
    ULONG64 PartitionId;
    ULONG64 Object;
    ULONG64 Routine;
    ULONG64 Context;
    ULONG   RefCount;
    ULONG   Reserved;
} H3_WHVPART_ENTRY;

typedef struct _H3_WHVPART_OUT {
    ULONG   Version;
    ULONG   Status;          /* NTSTATUS; the build check failing shows up here */
    ULONG64 ArrayPtr;
    ULONG   Count;           /* as the header reports */
    ULONG   Returned;        /* entries actually filled */
    ULONG   TimeDateStamp;   /* of the LOADED image, so the client sees the check */
    ULONG   SizeOfImage;
    H3_WHVPART_ENTRY Entry[H3_WHVPART_MAX];
} H3_WHVPART_OUT;
#pragma pack(pop)

typedef VOID (*PFN_EX_ACQ_PUSH_SHARED)(PVOID Lock, PVOID Flags);
typedef VOID (*PFN_EX_REL_PUSH_SHARED)(PVOID Lock, PVOID Flags);
static PFN_EX_ACQ_PUSH_SHARED g_ExAcquirePushLockSharedEx;
static PFN_EX_REL_PUSH_SHARED g_ExReleasePushLockSharedEx;

static NTSTATUS H3CheckWinHvBuild(ULONG *Stamp, ULONG *Size)
{
    PUCHAR b = (PUCHAR)g_WinHvBase;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;

    *Stamp = 0;
    *Size = 0;
    if (!g_WinHvBase || g_WinHvSize < sizeof(IMAGE_DOS_HEADER)) return STATUS_NOT_FOUND;
    dos = (PIMAGE_DOS_HEADER)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > g_WinHvSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    nt = (PIMAGE_NT_HEADERS64)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    *Stamp = nt->FileHeader.TimeDateStamp;
    *Size  = nt->OptionalHeader.SizeOfImage;
    if (*Stamp != H3_WHV_TIMESTAMP || *Size != H3_WHV_SIZEOFIMAGE) {
        /* Not the build the RVA came from. Say so; do not guess. */
        return STATUS_REVISION_MISMATCH;
    }
    if (H3_WHV_PARTARRAY_RVA + sizeof(PVOID) > g_WinHvSize) return STATUS_INVALID_IMAGE_FORMAT;
    return STATUS_SUCCESS;
}

static void H3WhvPart(H3_WHVPART_OUT *Out)
{
    PVOID *arrayCell;
    PUCHAR array;
    PVOID lock;
    ULONG count, i;
    KIRQL irql;
    BOOLEAN locked = FALSE;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->Version = 1;

    Out->Status = (ULONG)H3CheckWinHvBuild(&Out->TimeDateStamp, &Out->SizeOfImage);
    if (Out->Status != STATUS_SUCCESS) return;

    if (!g_ExAcquirePushLockSharedEx || !g_ExReleasePushLockSharedEx) {
        /* Refuse rather than read the table unlocked: the whole point of this
           step is that nothing downstream inherits an unexamined risk. */
        Out->Status = (ULONG)STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    arrayCell = (PVOID *)((PUCHAR)g_WinHvBase + H3_WHV_PARTARRAY_RVA);
    lock      = (PVOID)((PUCHAR)g_WinHvBase + H3_WHV_PARTLOCK_RVA);

    irql = KeGetCurrentIrql();
    if (irql >= APC_LEVEL) {
        Out->Status = (ULONG)STATUS_INVALID_LEVEL;
        return;
    }
    KeEnterCriticalRegion();
    g_ExAcquirePushLockSharedEx(lock, NULL);
    locked = TRUE;

    array = (PUCHAR)*arrayCell;
    Out->ArrayPtr = (ULONG64)(ULONG_PTR)array;
    if (array) {
        count = *(ULONG *)array;
        Out->Count = count;
        if (count <= H3_WHVPART_SANE_COUNT) {
            for (i = 0; i < count && Out->Returned < H3_WHVPART_MAX; i++) {
                PUCHAR e = array + 8 + (SIZE_T)i * 16;
                PUCHAR obj = *(PUCHAR *)(e + 8);
                H3_WHVPART_ENTRY *o = &Out->Entry[Out->Returned++];
                o->PartitionId = *(ULONG64 *)e;
                o->Object = (ULONG64)(ULONG_PTR)obj;
                if (obj) {
                    o->RefCount = *(ULONG *)obj;
                    o->Routine  = (ULONG64)(ULONG_PTR)(*(PVOID *)(obj + 0x10));
                    o->Context  = (ULONG64)(ULONG_PTR)(*(PVOID *)(obj + 0x18));
                }
            }
        } else {
            Out->Status = (ULONG)STATUS_INVALID_PARAMETER;
        }
    }

    if (locked) {
        g_ExReleasePushLockSharedEx(lock, NULL);
        KeLeaveCriticalRegion();
    }
}

/* --- arm 0: the null receiver (gate S5q, step 3) --------------------------
 *
 * Chains a routine of ours into Hyper-V's per-partition intercept dispatch and
 * FORWARDS EVERYTHING.  It handles nothing, decodes nothing and installs no
 * exception vector -- so the standing constraint about install/remove pairs
 * does not reach it, and the only thing it tests is the one thing that cannot
 * be tested any other way: our code executing inside `WinHvpOnInterception`,
 * in the ROOT, where a fault is a host bug check rather than a guest one.
 *
 * The ABI, read out of this build rather than assumed:
 *
 *   WinHvSetInterceptRoutine(rcx = PartitionId, rdx = Routine, r8 = Context)
 *       rax = WinHvpReferencePartition(PartitionId)
 *       if (!rax) return 0xC035000D          -- no such partition
 *       [rax+0x10] = Routine ; [rax+0x18] = Context
 *       WinHvpDereferencePartition(rax) ; return 0
 *
 *   WinHvpOnInterception: rax = [obj+0x10]; rcx = [obj+0x18]; rdx = message;
 *                         call guard_dispatch_icall  -- i.e. Routine(Context, Message),
 *                         and ITS return value is what WinHvpOnInterception returns.
 *
 * Two consequences drive the design.  **It does not return the previous pair**,
 * so the old routine and context have to be read first -- and between that read
 * and the set there is a window in which another party could register.  Nothing
 * in the ABI closes it (there is no exchange and no query), so it is documented
 * rather than defended: on this bench no other party registers.
 *
 * **And the context identifies the partition, not the routine.**  Vid binds one
 * routine, `VidInterceptIsrCallback`, for every partition and distinguishes them
 * by context.  So forwarding must pass the SAVED context, never ours -- a chain
 * that forwarded its own would have Vid dereference the wrong partition object.
 * That is the whole reason the read-only step came first.
 *
 * The chain records are a STATIC array, never pool: the address we register as
 * a context outlives every allocation decision, so an unchain that failed
 * cannot leave Hyper-V holding a pointer into freed memory.  It can still leave
 * it holding a pointer into an unloaded image, which is why H3Unload unchains
 * before anything else and says so loudly if it cannot.
 */

#define H3_CHAIN_SLOTS 4
#define H3_WHV_SET_INTERCEPT_ROUTINE 0   /* index into g_WinHvExport */

typedef ULONG_PTR (*PFN_WHV_INTERCEPT_ROUTINE)(PVOID Context, PVOID Message);
typedef NTSTATUS  (*PFN_WHV_SET_INTERCEPT_ROUTINE)(ULONG64 PartitionId,
                                                   PVOID Routine,
                                                   PVOID Context);

typedef struct _H3_CHAIN {
    volatile LONG             Active;
    ULONG64                   PartitionId;
    PFN_WHV_INTERCEPT_ROUTINE SavedRoutine;
    PVOID                     SavedContext;
    volatile LONG64           Forwarded;
} H3_CHAIN;

static H3_CHAIN g_Chain[H3_CHAIN_SLOTS];

#pragma pack(push, 1)
typedef struct _H3_CHAIN_IN {
    ULONG64 PartitionId;
} H3_CHAIN_IN;

typedef struct _H3_CHAIN_OUT {
    ULONG   Status;
    ULONG   Slot;
    ULONG64 SavedRoutine;
    ULONG64 SavedContext;
    ULONG64 Forwarded;
} H3_CHAIN_OUT;

typedef struct _H3_CHAINSTAT_ENTRY {
    ULONG   Active;
    ULONG   Reserved;
    ULONG64 PartitionId;
    ULONG64 SavedRoutine;
    ULONG64 SavedContext;
    ULONG64 Forwarded;
} H3_CHAINSTAT_ENTRY;

typedef struct _H3_CHAINSTAT_OUT {
    ULONG Version;
    ULONG Slots;
    H3_CHAINSTAT_ENTRY Entry[H3_CHAIN_SLOTS];
} H3_CHAINSTAT_OUT;
#pragma pack(pop)

/*
 * The callback.  Deliberately the smallest thing that can be written: one
 * counter and one forward.  It runs at whatever IRQL Hyper-V dispatches at --
 * the routine it replaces is named `VidInterceptIsrCallback`, so assume high --
 * which is why there is no logging, no allocation and no paged access in it.
 *
 * The counter is not decoration.  Without it a clean arm 0 is indistinguishable
 * from an arm 0 in which no intercept was ever dispatched, and "nothing broke"
 * would be reported as "our code ran and nothing broke".
 */
static ULONG_PTR H3ChainedRoutine(PVOID Context, PVOID Message)
{
    H3_CHAIN *c = (H3_CHAIN *)Context;

    if (!c || !c->SavedRoutine) {
        /* Cannot forward. Returning 0 is the least-bad option; it is also a
           state this driver should never reach, because a slot is only
           registered after SavedRoutine is set. */
        return 0;
    }
    InterlockedIncrement64(&c->Forwarded);
    return c->SavedRoutine(c->SavedContext, Message);
}

/*
 * Read the pair currently registered for one partition.  Same build check and
 * same shared push lock as H3WhvPart -- see that comment for why both.
 * The lock is RELEASED before the caller calls WinHvSetInterceptRoutine, which
 * takes its own reference (and therefore the same lock) on the way in.
 */
static NTSTATUS H3ReadPair(ULONG64 PartitionId,
                           PFN_WHV_INTERCEPT_ROUTINE *Routine,
                           PVOID *Context)
{
    ULONG stamp, size, count, i;
    PUCHAR array;
    PVOID lock;
    NTSTATUS st;

    *Routine = NULL;
    *Context = NULL;

    st = H3CheckWinHvBuild(&stamp, &size);
    if (!NT_SUCCESS(st)) return st;
    if (!g_ExAcquirePushLockSharedEx || !g_ExReleasePushLockSharedEx) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    if (KeGetCurrentIrql() >= APC_LEVEL) return STATUS_INVALID_LEVEL;

    lock = (PVOID)((PUCHAR)g_WinHvBase + H3_WHV_PARTLOCK_RVA);
    KeEnterCriticalRegion();
    g_ExAcquirePushLockSharedEx(lock, NULL);

    st = STATUS_NOT_FOUND;
    array = (PUCHAR)*(PVOID *)((PUCHAR)g_WinHvBase + H3_WHV_PARTARRAY_RVA);
    if (array) {
        count = *(ULONG *)array;
        if (count <= H3_WHVPART_SANE_COUNT) {
            for (i = 0; i < count; i++) {
                PUCHAR e = array + 8 + (SIZE_T)i * 16;
                if (*(ULONG64 *)e != PartitionId) continue;
                {
                    PUCHAR obj = *(PUCHAR *)(e + 8);
                    if (obj) {
                        *Routine = *(PFN_WHV_INTERCEPT_ROUTINE *)(obj + 0x10);
                        *Context = *(PVOID *)(obj + 0x18);
                        st = STATUS_SUCCESS;
                    }
                }
                break;
            }
        } else {
            st = STATUS_INVALID_PARAMETER;
        }
    }

    g_ExReleasePushLockSharedEx(lock, NULL);
    KeLeaveCriticalRegion();
    return st;
}

static H3_CHAIN *H3FindChain(ULONG64 PartitionId)
{
    ULONG i;
    for (i = 0; i < H3_CHAIN_SLOTS; i++) {
        if (g_Chain[i].Active && g_Chain[i].PartitionId == PartitionId) return &g_Chain[i];
    }
    return NULL;
}

static NTSTATUS H3ChainPartition(ULONG64 PartitionId, H3_CHAIN_OUT *Out)
{
    PFN_WHV_SET_INTERCEPT_ROUTINE set;
    PFN_WHV_INTERCEPT_ROUTINE saved;
    PVOID savedCtx;
    H3_CHAIN *slot = NULL;
    NTSTATUS st;
    ULONG i;

    set = (PFN_WHV_SET_INTERCEPT_ROUTINE)g_WinHvExport[H3_WHV_SET_INTERCEPT_ROUTINE];
    if (!set) return STATUS_PROCEDURE_NOT_FOUND;
    if (H3FindChain(PartitionId)) return STATUS_ALREADY_REGISTERED;

    st = H3ReadPair(PartitionId, &saved, &savedCtx);
    if (!NT_SUCCESS(st)) return st;
    /* Refuse to chain onto nothing: forwarding would have no destination, and a
       null here means the premise of this arm (Vid is bound) does not hold. */
    if (!saved) return STATUS_NOT_FOUND;
    /* Refuse to chain onto ourselves -- idempotence protects against a double
       chain leaving an unbreakable loop in Hyper-V's dispatch. */
    if (saved == H3ChainedRoutine) return STATUS_ALREADY_REGISTERED;

    for (i = 0; i < H3_CHAIN_SLOTS; i++) {
        if (!g_Chain[i].Active) { slot = &g_Chain[i]; break; }
    }
    if (!slot) return STATUS_INSUFFICIENT_RESOURCES;

    slot->PartitionId  = PartitionId;
    slot->SavedRoutine = saved;
    slot->SavedContext = savedCtx;
    slot->Forwarded    = 0;
    /* Published before the registration, so the callback can never observe a
       half-filled slot if it fires on the very next instruction. */
    InterlockedExchange(&slot->Active, 1);

    st = set(PartitionId, (PVOID)H3ChainedRoutine, (PVOID)slot);
    if (!NT_SUCCESS(st)) {
        InterlockedExchange(&slot->Active, 0);
        return st;
    }

    Out->Slot         = (ULONG)(slot - g_Chain);
    Out->SavedRoutine = (ULONG64)(ULONG_PTR)saved;
    Out->SavedContext = (ULONG64)(ULONG_PTR)savedCtx;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "h3probe: chained partition 0x%llX, saved %p/%p\n",
               PartitionId, saved, savedCtx);
    return STATUS_SUCCESS;
}

static NTSTATUS H3UnchainSlot(H3_CHAIN *slot, ULONG64 *Forwarded)
{
    PFN_WHV_SET_INTERCEPT_ROUTINE set;
    NTSTATUS st;

    set = (PFN_WHV_SET_INTERCEPT_ROUTINE)g_WinHvExport[H3_WHV_SET_INTERCEPT_ROUTINE];
    if (!set) return STATUS_PROCEDURE_NOT_FOUND;
    if (!slot->Active) return STATUS_NOT_FOUND;

    st = set(slot->PartitionId, (PVOID)slot->SavedRoutine, slot->SavedContext);
    if (Forwarded) *Forwarded = (ULONG64)slot->Forwarded;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "h3probe: unchain partition 0x%llX -> 0x%08X, forwarded %lld\n",
               slot->PartitionId, st, slot->Forwarded);
    if (!NT_SUCCESS(st)) {
        /* Leave Active set: the slot is still registered with Hyper-V and the
           driver must not unload. Saying so is all this code can do. */
        return st;
    }
    InterlockedExchange(&slot->Active, 0);
    return STATUS_SUCCESS;
}

/*
 * Called from H3Unload BEFORE the device goes away.  If Hyper-V still holds a
 * pointer to H3ChainedRoutine when this image unloads, the next intercept for
 * that partition calls into freed code -- a host bug check arriving minutes
 * after a run that looked clean.  There is no way to refuse an unload, so the
 * only defence is to restore here and to be loud when that fails.
 */
static void H3UnchainAll(void)
{
    ULONG i;
    for (i = 0; i < H3_CHAIN_SLOTS; i++) {
        if (g_Chain[i].Active) {
            NTSTATUS st = H3UnchainSlot(&g_Chain[i], NULL);
            if (!NT_SUCCESS(st)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "h3probe: *** UNCHAIN FAILED on unload for partition "
                           "0x%llX (0x%08X) -- Hyper-V still points into this image ***\n",
                           g_Chain[i].PartitionId, st);
            }
        }
    }
}

static void H3ChainStat(H3_CHAINSTAT_OUT *Out)
{
    ULONG i;
    RtlZeroMemory(Out, sizeof(*Out));
    Out->Version = 1;
    Out->Slots = H3_CHAIN_SLOTS;
    for (i = 0; i < H3_CHAIN_SLOTS; i++) {
        Out->Entry[i].Active       = (ULONG)g_Chain[i].Active;
        Out->Entry[i].PartitionId  = g_Chain[i].PartitionId;
        Out->Entry[i].SavedRoutine = (ULONG64)(ULONG_PTR)g_Chain[i].SavedRoutine;
        Out->Entry[i].SavedContext = (ULONG64)(ULONG_PTR)g_Chain[i].SavedContext;
        Out->Entry[i].Forwarded    = (ULONG64)g_Chain[i].Forwarded;
    }
}

/* --- VID per-VP markers, READ ONLY (item 103 step 9) ----------------------
 *
 * Step 9 asks whether an intercept message is delivered to the root's VID at
 * all.  The answer does not need a patch or a breakpoint, because
 * `Vid!VidInterceptPreprocess` STORES what it received before it branches on
 * anything: it copies the whole HV_MESSAGE to [VP+0x30], timestamps [VP+0x208]
 * with KeQueryPerformanceCounter, and the type switch then leaves the handler
 * it selected at [VP+0x158] and that handler's reason index at [VP+0x200].  So
 * a delivered #BP is four values that name each other and this IOCTL reads
 * them.  It writes nothing, anywhere.
 *
 * Offsets read out of Vid.sys 10.0.26100.9278, SHA-256 6611BCD7...B06697,
 * opened as a DbgEng image target with its public PDB.  The full derivation is
 * the step 9 feasibility section of
 * docs/secure-kernel/secure-kernel-hypercall-feasibility.md in windbg-mcp.
 *
 * THREE THINGS KEEP THIS FROM BEING AN ARBITRARY KERNEL READ, which in the
 * ROOT would be a host bug check rather than a guest one:
 *
 *   1. The caller names a PARTITION ID, never a pointer.  The object walked is
 *      the context Hyper-V itself has registered, read under the same push
 *      lock H3ReadPair takes -- so it is a pointer the hypervisor holds, not
 *      one a user-mode process invented.
 *   2. The registered ROUTINE must land inside the loaded Vid.sys.  If it does
 *      not, the context is not a VID partition object and these offsets mean
 *      nothing; the read is refused rather than attempted.
 *   3. Every dereference goes through H3SafeRead: canonical kernel address,
 *      MmIsAddressValid per page, and SEH.  A failed read stops the walk and
 *      is reported, rather than being retried or guessed past.
 *
 * And the VP walk validates ITSELF: [VP+0x00] is a back-pointer to the
 * partition -- Vid!VidHandleExceptionIntercept opens by loading it -- so an
 * entry whose back-pointer is not the partition we started from is marked
 * invalid and its markers are not to be believed.
 */

/* From Vid.sys 10.0.26100.9711, SHA-256 633171F0...D6AD369.  The owner
 * comparison in VidIoControlPreProcess is still [partition+0x3780] at RVAs
 * 0x2BF87 and 0x2E93B; the constructor stores PsGetCurrentProcess there at
 * RVA 0xC70D.  Checked before any build-specific offset is used. */
#define H3_VID_TIMESTAMP      0xD2E40B4AUL
#define H3_VID_SIZEOFIMAGE    0x000DC000UL

/* Partition object (the context Hyper-V holds for VidInterceptIsrCallback). */
#define H3_VID_P_VPCOUNT      0x0AA8   /* ULONG,  Vid!VidVpLookup refuses > 0x800 */
#define H3_VID_P_VPARRAY      0x0AB0   /* PVOID                                   */
#define H3_VID_P_CLIENTS      0x0B58   /* PVOID, stride 0xB0                      */
#define H3_VID_P_VECTORTABLE  0x0B68   /* PUCHAR, indexed by exception vector     */
#define H3_VID_VP_STRIDE      0x0980

/* Per-VP structure. */
#define H3_VID_V_PARTITION    0x0000   /* back-pointer; the validity check */
#define H3_VID_V_MESSAGE      0x0030   /* HV_MESSAGE copy                  */
#define H3_VID_V_VECTOR       0x0068   /* exception vector in the payload  */
#define H3_VID_V_HANDLER      0x0158
#define H3_VID_V_REASON       0x0200
#define H3_VID_V_STAMP        0x0208

#define H3_VIDVP_MAX      8
#define H3_VIDVP_MSGBYTES 0x40
#define H3_VIDVP_VECTORS  8            /* 0..7; index 3 is #BP, the rest are free */
#define H3_VID_SANE_VPS   0x800        /* Vid's own bound, not one invented here  */

#pragma pack(push, 1)
typedef struct _H3_VIDVP_IN {
    ULONG64 PartitionId;
} H3_VIDVP_IN;

typedef struct _H3_VIDVP_ENTRY {
    ULONG64 Vp;
    ULONG64 BackPointer;     /* [VP+0x00] */
    ULONG   Valid;           /* BackPointer == Partition */
    ULONG   MessageType;     /* [VP+0x30] */
    ULONG   PayloadSize;     /* [VP+0x34], a byte, widened */
    ULONG   Vector;          /* [VP+0x68], a byte, widened */
    ULONG   Reason;          /* [VP+0x200] */
    ULONG   ReadFailed;      /* which read stopped, 0 when all of them landed */
    ULONG64 Handler;         /* [VP+0x158] */
    ULONG64 Stamp;           /* [VP+0x208] */
    UCHAR   Message[H3_VIDVP_MSGBYTES];
} H3_VIDVP_ENTRY;

typedef struct _H3_VIDVP_OUT {
    ULONG   Version;
    ULONG   Status;
    ULONG   VidTimeDateStamp;   /* of the LOADED image, so the client sees the check */
    ULONG   VidSizeOfImage;
    ULONG64 VidBase;
    ULONG64 Partition;          /* the context Hyper-V holds */
    ULONG64 Routine;            /* and the routine, so a client can see it is Vid's */
    ULONG   RoutineInVid;
    ULONG   VpCount;            /* [P+0xAA8] as read */
    ULONG64 VpArray;            /* [P+0xAB0] */
    ULONG64 VectorTable;        /* [P+0xB68] */
    ULONG64 ClientArray;        /* [P+0xB58] */
    ULONG   VectorRead;         /* 1 when VectorByte below is meaningful */
    ULONG   FromChainSlot;      /* 1 when the pair came from our own chain record */
    ULONG   Returned;
    ULONG   Reserved;
    UCHAR   VectorByte[H3_VIDVP_VECTORS];
    H3_VIDVP_ENTRY Vp[H3_VIDVP_MAX];
} H3_VIDVP_OUT;
#pragma pack(pop)

/* ---------------------------------------------------------------------------
 * S7: VID's IOCTL gate is a process-identity check, not a handle check.
 *
 * Ghidra on Vid.sys 10.0.26100.9278, VidIoControlPreProcess (rva 0x2e600),
 * immediately after the driver's own ETW event "VidIoControlPartitionIsAllowed"
 * from onecore\vm\vid\sys\driver\vidiocontrol.c:
 *
 *     if (((puVar10[0x6f0] != PsGetCurrentProcess()) && (code != 0x2210ef))
 *          && (code != 0x2211e3))  ->  0xC0000022 STATUS_ACCESS_DENIED
 *
 * puVar10 is the partition (the file object's FsContext, masked & ~3) as a
 * ULONGLONG*, so [0x6f0] is byte offset 0x3780.  A handle duplicated out of
 * vmwp.exe is refused because OUR PROCESS is not the owner -- no access mask
 * on the handle could change that.  Kernel code can: attach to the owner and
 * PsGetCurrentProcess() returns it.
 *
 * These three are declared here rather than by including ntifs.h, which does
 * not mix with the ntddk.h this driver already uses.  KAPC_STATE is 48 bytes on
 * x64; the opaque 64 is slack, and ULONG64[] to force 8-byte alignment.
 * ------------------------------------------------------------------------- */
#define H3_VID_P_OWNERPROC   0x3780   /* PEPROCESS; the gate's own field */
#define H3_VID_REGISTER      0x221148 /* in 16B {u8 Vec; u8 pad[3]; u32 Param; u64 Ctx}, out 8 */
#define H3_VID_UNREGISTER    0x2211E8 /* in 8B {u64 Handle}, out 0                             */
#define H3_VIDREG_POISON     0xAAAAAAAAAAAAAAAAULL
#define H3_VIDREG_NOTRUN     0xFFFFFFFFUL

typedef struct _H3_APC_STATE { ULONG64 Opaque[8]; } H3_APC_STATE;

NTKERNELAPI void NTAPI KeStackAttachProcess(PVOID Process, PVOID ApcState);
NTKERNELAPI void NTAPI KeUnstackDetachProcess(PVOID ApcState);
NTKERNELAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE ProcessId, PVOID *Process);

/* For the METHOD_NEITHER control code (0x221107): its input must be a USER address, because
   the driver probes it and ProbeForRead refuses kernel addresses.  Allocated in whichever
   process we are attached to, which is the owner. */
NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(HANDLE Process, PVOID *Base, ULONG_PTR Bits,
                                                PSIZE_T Size, ULONG Type, ULONG Protect);
NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(HANDLE Process, PVOID *Base, PSIZE_T Size, ULONG Type);
#define H3_CURPROC ((HANDLE)(LONG_PTR)-1)

#pragma pack(push, 1)
typedef struct _H3_VIDREG_IN {
    ULONG   OwnerPid;          /* the vmwp.exe the partition belongs to   */
    ULONG   Vector;            /* exception vector; 3 (#BP) on this bench */
    ULONG64 PartitionHandle;   /* a handle value valid IN THAT process     */
} H3_VIDREG_IN;

typedef struct _H3_VIDREG_OUT {
    ULONG   VidTimeDateStamp;
    ULONG   VidSizeOfImage;
    ULONG   BuildStatus;       /* the 0x3780 offset is build-specific      */
    ULONG   LookupStatus;      /* PsLookupProcessByProcessId               */
    ULONG   Attached;          /* 1 once KeStackAttachProcess has run      */
    ULONG   OwnerRead;         /* 1 when OwnerField below is meaningful    */
    ULONG64 OwnerField;        /* [partition+0x3780] as read               */
    ULONG64 AttachedProcess;   /* what we attached to, to compare against  */
    ULONG   OwnerMatched;      /* OwnerField == AttachedProcess            */
    ULONG   RegisterStatus;    /* NTSTATUS from 0x221148 -- THE ANSWER     */
    ULONG   UnregisterStatus;  /* NTSTATUS from 0x2211E8, or NOTRUN        */
    ULONG   Reserved;
    ULONG64 HandleOut;         /* the 8 bytes the receiver returned        */
} H3_VIDREG_OUT;
#pragma pack(pop)

/* ---------------------------------------------------------------------------
 * S7: the VidMessageSlot* half.
 *
 * VidMessageSlotMap returns the user-mode VA of a VP's message slot IN THE
 * CALLING PROCESS.  Attached to the owner, that is vmwp's address space, so the
 * VA is only meaningful while still attached -- read it before detaching or not
 * at all.
 *
 * ONE-WAY: vid.dll exports no unmap for it.  A slot mapped here stays mapped in
 * vmwp for the life of that process.
 *
 * VidMessageSlotHandleAndGetNext (0x221107) is deliberately NOT issued by this
 * driver.  It completes the current intercept -- Vid.sys reaches
 * WinHvCompleteIntercept through it -- and vmwp is already servicing these VPs,
 * so a second completer races it.  Receiving properly wants a partition with
 * one client, which is item 103 step 8's territory.
 * ------------------------------------------------------------------------- */
#define H3_VID_SLOTMAP       0x221108
#define H3_VIDSLOT_BYTES     0x40      /* HV_MESSAGE header + the start of its payload */

#pragma pack(push, 1)
typedef struct _H3_VIDSLOT_IN {
    ULONG   OwnerPid;
    ULONG   VpIndex;
    ULONG64 PartitionHandle;
} H3_VIDSLOT_IN;

typedef struct _H3_VIDSLOT_OUT {
    ULONG   BuildStatus;
    ULONG   LookupStatus;
    ULONG   Attached;
    ULONG   OwnerMatched;
    ULONG64 OwnerField;
    ULONG64 AttachedProcess;
    ULONG   MapStatus;         /* NTSTATUS from 0x221108 -- THE ANSWER */
    ULONG   SlotRead;          /* 1 when Slot[] below is meaningful    */
    ULONG64 SlotVa;            /* what the map handed back             */
    UCHAR   Slot[H3_VIDSLOT_BYTES];
} H3_VIDSLOT_OUT;
#pragma pack(pop)

/* ---------------------------------------------------------------------------
 * S7: the whole receive loop -- map, arm, consume, disarm -- in one attached
 * window, so the intercept cannot outlive the call that installed it.
 *
 * The register arm before this one wedged both lab guests: it armed vector 3
 * and nothing ever completed the intercepts, so the first #BP after it had an
 * exit with no consumer and the partition was reset.  Whether a consumer is
 * what was missing is exactly what this measures.
 * ------------------------------------------------------------------------- */
#define H3_VID_SLOTNEXT      0x221107
#define H3_VIDLOOP_MAXMSG    256
#define H3_VIDLOOP_CAPTURE   0x40

#pragma pack(push, 1)
typedef struct _H3_VIDLOOP_IN {
    ULONG   OwnerPid;
    ULONG   VpIndex;
    ULONG64 PartitionHandle;
    ULONG   Vector;
    ULONG   Flags;          /* passed straight through as HandleAndGetNext's second dword */
    ULONG   MaxMessages;    /* clamped to H3_VIDLOOP_MAXMSG */
    ULONG   TimeoutMs;      /* whole-loop deadline */
    ULONG   SkipArm;        /* 1 = map and call the completion only, never register.
                               The completion does not need the intercept armed, and not
                               arming is what makes a parameter sweep free: the guest is
                               only ever lost by arming without a working consumer. */
} H3_VIDLOOP_IN;

typedef struct _H3_VIDLOOP_OUT {
    ULONG   BuildStatus;
    ULONG   LookupStatus;
    ULONG   Attached;
    ULONG   OwnerMatched;
    ULONG   MapStatus;
    ULONG   RegisterStatus;
    ULONG64 SlotVa;
    ULONG64 RegHandle;
    ULONG   Messages;            /* completions that returned success      */
    ULONG   Polls;               /* slot reads that found MessageType == 0 */
    ULONG   LastCompleteStatus;
    ULONG   UnregisterStatus;
    ULONG   DeadlineHit;
    ULONG   FirstType;
    ULONG   FirstPayloadSize;
    ULONG   LastType;
    ULONG   UserBufStatus;
    UCHAR   First[H3_VIDLOOP_CAPTURE];
} H3_VIDLOOP_OUT;
#pragma pack(pop)

/* ---------------------------------------------------------------------------
 * S7/S8: may a caller name an arbitrary VTL1 entry context?
 *
 * vid.dll!VidVsmEnableVpVtl sends IOCTL 0x221214, METHOD_BUFFERED, 0xE8 bytes:
 *     { ULONG VpIndex; UCHAR TargetVtl; pad[3]; UCHAR Context[0xE0] }
 * and Vid.sys's handler, decompiled, checks ONLY the buffer length before
 * handing the context straight to WinHvEnableVpVtl.  So VID imposes nothing on
 * the context, and the only gate left is the hypervisor's own.
 *
 * This calls the wrapper directly so that gate can be reached without owning a
 * partition first.  224 bytes is the size shape of HV_INITIAL_VP_CONTEXT.
 * ------------------------------------------------------------------------- */
#define H3_VTL_CONTEXT_BYTES 0xE0

typedef NTSTATUS (*PFN_H3_ENABLEVPVTL)(ULONG64 PartitionId, ULONG VpIndex,
                                       ULONG64 TargetVtl, PVOID Context);

#pragma pack(push, 1)
typedef struct _H3_VTLENABLE_IN {
    ULONG64 PartitionId;
    ULONG   VpIndex;
    ULONG   TargetVtl;
    ULONG   UseZeroContext;   /* 1 = zero the context here, the safe default */
    ULONG   Reserved;
    UCHAR   Context[H3_VTL_CONTEXT_BYTES];
} H3_VTLENABLE_IN;

typedef struct _H3_VTLENABLE_OUT {
    ULONG   ResolveStatus;    /* did winhvr!WinHvEnableVpVtl resolve */
    ULONG   Called;
    ULONG64 ExportVa;
    ULONG   CallStatus;       /* what the hypervisor said -- THE ANSWER */
    ULONG   Reserved;
} H3_VTLENABLE_OUT;
#pragma pack(pop)

/* ---------------------------------------------------------------------------
 * The ordering gate: partition-level VTL1 must be enabled before a VP's can be.
 *
 * WinHvEnablePartitionVtl has NO user-mode export -- vid.dll ships only
 * VidDisablePartitionVtl -- so VID turns it on internally.  Its only caller,
 * Vid!VsmmVsmpEnablePartitionVtl, decompiles to:
 *
 *   WinHvEnablePartitionVtl(*(partition + 0x288),   // the HV partition id
 *                           targetVtl,
 *                           flags & 0xffffff01,
 *                           (flags >> 1) & 1,
 *                           (flags >> 2) & 1);
 *
 * VID also refuses unless [partition+0x10] carries 0x10 for VTL1 (0x20 for
 * VTL2), with 0xC00000BB, and refuses a VTL already in [partition+0x30f0] with
 * 0xC000000D.  Calling the wrapper directly bypasses both of VID's checks and
 * leaves only the hypervisor's, which is the point.
 * ------------------------------------------------------------------------- */
/* ---------------------------------------------------------------------------
 * Phase 1 of docs/h3probe-only-plan.md: the in-vmwp VID page read, measured.
 * These two controls are measurement probes, not the product memory ABI.
 *
 * Ghidra and cdb on Vid.sys 10.0.26100.9711 (SHA-256 633171F0...D6AD369) with
 * its public PDB, and on that build's vid.dll and vmwp.exe:
 *
 *   0x2211C7  VidIoControlFastPartition.  In: 8 bytes, a guest PAGE NUMBER.
 *             Out: 32 bytes {non-memory range context, [MB+0xB0], memory-block
 *             page index, [range+0x124] & 0x1FF}.  The range test is
 *             start <= in <= end, and VsmmCreateMemoryBlockGpaRange stores
 *             end = start + pages - 1, so both bounds count pages; vmwp's own
 *             GPA paths shift by 12 before translating.  A GPA sent unshifted
 *             is a page number 4096 times too large, which is why the first
 *             live run resolved 0x0 and 0x1000 and nothing above 4 GiB.
 *   0x22113F  VsmmIoctlReadWriteMemoryBlockPageRange.  In: 0x40 bytes {handle,
 *             block page, pages, buffer, buffer bytes, aux, aux bytes, flags}.
 *             Out: 8 bytes, the bytes copied (pages << 12).  The handle is not a
 *             pointer: VidHandleTableLookupEntry indexes the partition's table
 *             at +0xAC8 with it, and VsmmMemoryBlockHandleTableInsert writes the
 *             same index to [MB+0x18] when the block is created.
 *
 * Both codes are METHOD_NEITHER, so their buffers are user addresses in the
 * attached owner; VID probes them.  VidIoControlFast (the FastIoDeviceControl
 * entry) derives the partition as FsContext & ~3, the object this file already
 * reads the owner from.
 * ------------------------------------------------------------------------- */
#define IOCTL_H3_VIDTRANSLATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define H3_VID_TRANSLATE_GPN 0x2211C7 /* METHOD_NEITHER: in 8, out 32 */
#define H3_VID_READ_PAGES    0x22113F /* METHOD_NEITHER: in 0x40, out 8 */
#define H3_VID_PAGE_BYTES    0x1000

#define H3_VID_P_MBTABLE     0x0AC8   /* {PVOID *Entry; ULONG Count;}            */
#define H3_VID_MB_PARTITION  0x0008   /* back-pointer to the partition            */
#define H3_VID_MB_HANDLE     0x0018   /* the table index handed to user mode      */
#define H3_VID_MB_STATE      0x0020   /* LONG; the read refuses a nonzero state   */
#define H3_VID_MB_PAGES      0x0030   /* page count; the read's own bound         */
#define H3_VID_MB_USERCTX    0x00B0   /* translate's second field                 */
#define H3_VID_MB_RECORD     0x00B8
#define H3_VID_MBTABLE_MAX   0x1000   /* a sanity bound on the walk, not VID's    */

/* Typed answers.  IDENTITY is kept apart from the GPA results so a wrong vmwp,
 * handle or build can never be read as a property of guest memory. */
#define H3_MEM_OK          0
#define H3_MEM_NOT_PRESENT 1   /* no GPA range holds the page                    */
#define H3_MEM_REFUSED     2   /* a range holds it, but not as memory-block RAM  */
#define H3_MEM_ERROR       3
#define H3_MEM_IDENTITY    4   /* build, process, handle or owner did not match  */

#define H3_VIDMEM_PROBE_VERSION 2

NTSYSAPI NTSTATUS NTAPI ZwCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes,
                                      EVENT_TYPE EventType, BOOLEAN InitialState);
NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
                                              PLARGE_INTEGER Timeout);

typedef NTSTATUS (*PFN_H3_ENABLEPARTVTL)(ULONG64 PartitionId, ULONG64 TargetVtl,
                                         ULONG64 Flags, ULONG64 Arg4, ULONG64 Arg5);

#pragma pack(push, 1)
typedef struct _H3_PARTVTL_IN {
    ULONG64 PartitionId;
    ULONG   TargetVtl;
    ULONG   Flags;
    ULONG   Arg4;
    ULONG   Arg5;
} H3_PARTVTL_IN;

typedef struct _H3_PARTVTL_OUT {
    ULONG   ResolveStatus;
    ULONG   Called;
    ULONG64 ExportVa;
    ULONG   CallStatus;      /* the hypervisor's own answer */
    ULONG   Reserved;
} H3_PARTVTL_OUT;

typedef struct _H3_VIDTRANSLATE_IN {
    ULONG   OwnerPid;
    ULONG   Reserved;
    ULONG64 PartitionHandle;
    ULONG64 Gpa;               /* a byte address; the driver sends Gpa >> 12 */
} H3_VIDTRANSLATE_IN;

/* Who answered: the exact build, the named vmwp, and its own partition. */
typedef struct _H3_VIDIDENT {
    ULONG   VidTimeDateStamp;
    ULONG   VidSizeOfImage;
    ULONG   BuildStatus;
    ULONG   LookupStatus;
    ULONG   Attached;
    ULONG   OwnerRead;
    ULONG   OwnerMatched;
    ULONG   HandleStatus;
    ULONG64 OwnerField;
    ULONG64 AttachedProcess;
} H3_VIDIDENT;

typedef struct _H3_VIDTRANSLATE_OUT {
    ULONG       Version;           /* H3_VIDMEM_PROBE_VERSION */
    ULONG       UserBufferStatus;
    H3_VIDIDENT Id;
    ULONG64     Gpn;
    ULONG       TranslateStatus;
    ULONG       Reserved;
    ULONG64     IoInformation;
    ULONG64     Field[4];
} H3_VIDTRANSLATE_OUT;

typedef H3_VIDTRANSLATE_IN H3_VIDREADPROBE_IN;

typedef struct _H3_VIDREADPROBE_OUT {
    ULONG       Version;           /* H3_VIDMEM_PROBE_VERSION */
    ULONG       Result;            /* H3_MEM_* */
    H3_VIDIDENT Id;
    ULONG64     Gpn;
    ULONG       UserBufferStatus;
    ULONG       TranslateStatus;
    ULONG64     TranslateInformation;
    ULONG64     TranslateField[4];
    ULONG       ScanStatus;
    ULONG       TableCount;
    ULONG       TableMatches;
    ULONG       ReadStatus;
    ULONG64     MemoryBlockHandle;
    ULONG64     MemoryBlockPages;
    ULONG64     ReadInformation;
    ULONG64     Completion;
    ULONG       RecheckStatus;     /* the second translate, after the read */
    ULONG       DataLength;
    ULONG64     RecheckField[4];
    UCHAR       Data[H3_VID_PAGE_BYTES];
} H3_VIDREADPROBE_OUT;
#pragma pack(pop)

C_ASSERT(sizeof(H3_VIDTRANSLATE_IN) == 24);
C_ASSERT(sizeof(H3_VIDIDENT) == 48);
C_ASSERT(sizeof(H3_VIDTRANSLATE_OUT) == 112);
C_ASSERT(sizeof(H3_VIDREADPROBE_OUT) == 200 + H3_VID_PAGE_BYTES);

/* ---------------------------------------------------------------------------
 * The memory operation (Phases 2 and 4 of docs/h3probe-only-plan.md).
 *
 * Built only on what H3VidReadProbe measured: the same identity, translate,
 * table lookup and VID page IOCTL, plus VID's own write of the same request
 * (0x2211EF, VsmmIoctlReadWriteMemoryBlockPageRange with its write flag) and
 * VidGetHvPartitionId's control (0x2210C3, out 8), so the caller's partition ID
 * is checked against the handle's rather than trusted.
 *
 * One request is one byte range inside one guest page.  The caller supplies no
 * pointer of any kind: a PID, a handle value valid in that PID, a partition ID,
 * a GPA and a length.
 *
 * VID moves whole pages, so a write here is read, patch, write, read back.  The
 * read-back must equal the patched page exactly, or the answer is ERROR.  A
 * guest store to the same page between the read and the write would be lost,
 * so writers hold the guest paused; the write gate and the KD facade both do.
 * ------------------------------------------------------------------------- */
#define IOCTL_H3_MEMREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_H3_MEMWRITE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define H3_VID_WRITE_PAGES   0x2211EF /* METHOD_NEITHER: in 0x40, out 0 */
#define H3_VID_PARTITION_ID  0x2210C3 /* METHOD_NEITHER: in 0, out 8    */
#define H3_MEM_ABI_VERSION   1

/* Which step decided an answer other than OK. */
#define H3_MEM_STAGE_NONE       0
#define H3_MEM_STAGE_REQUEST    1
#define H3_MEM_STAGE_BUILD      2
#define H3_MEM_STAGE_PROCESS    3
#define H3_MEM_STAGE_HANDLE     4
#define H3_MEM_STAGE_OWNER      5
#define H3_MEM_STAGE_PARTITION  6
#define H3_MEM_STAGE_SCRATCH    7
#define H3_MEM_STAGE_TRANSLATE  8
#define H3_MEM_STAGE_BLOCK      9
#define H3_MEM_STAGE_READ       10
#define H3_MEM_STAGE_WRITE      11
#define H3_MEM_STAGE_VERIFY     12
#define H3_MEM_STAGE_RECHECK    13

#pragma pack(push, 1)
typedef struct _H3_MEM_REQUEST {
    ULONG   Version;           /* H3_MEM_ABI_VERSION */
    ULONG   OwnerPid;
    ULONG64 PartitionHandle;   /* valid in OwnerPid */
    ULONG64 PartitionId;       /* must be the handle's own */
    ULONG64 Gpa;
    ULONG   Length;            /* 1 .. bytes left in Gpa's page */
    ULONG   Reserved;          /* zero */
} H3_MEM_REQUEST;

typedef struct _H3_MEM_ANSWER {
    ULONG   Version;           /* H3_MEM_ABI_VERSION */
    ULONG   Result;            /* H3_MEM_* */
    ULONG   Stage;             /* H3_MEM_STAGE_* that decided it */
    ULONG   Status;            /* that step's NTSTATUS, 0 on OK */
    ULONG   Length;            /* the request's Length on OK, else 0 */
    ULONG   Reserved;
    ULONG64 Gpn;
} H3_MEM_ANSWER;

typedef struct _H3_MEM_READ_OUT {
    H3_MEM_ANSWER Answer;
    UCHAR         Data[H3_VID_PAGE_BYTES];   /* the first Answer.Length bytes */
} H3_MEM_READ_OUT;
/* A write's input is H3_MEM_REQUEST followed by exactly Length bytes; its
   output is one H3_MEM_ANSWER. */
#pragma pack(pop)

C_ASSERT(sizeof(H3_MEM_REQUEST) == 40);
C_ASSERT(sizeof(H3_MEM_ANSWER) == 32);
C_ASSERT(sizeof(H3_MEM_READ_OUT) == 32 + H3_VID_PAGE_BYTES);
/* A write's answer is written over the start of its own METHOD_BUFFERED input,
   so it must end before the data the driver is still to read. */
C_ASSERT(sizeof(H3_MEM_ANSWER) <= sizeof(H3_MEM_REQUEST));

/*
 * One read, with every guard this driver can apply to a kernel address it did
 * not allocate.  MmIsAddressValid is a reading at an instant and not a lease,
 * which is why the SEH is there as well and why neither is described as making
 * the read safe -- what they do is turn the likely failures into a reported
 * status instead of a bug check.
 */
static BOOLEAN H3SafeRead(const void *Src, void *Dst, SIZE_T Bytes)
{
    ULONG_PTR a = (ULONG_PTR)Src;
    ULONG_PTR end;
    ULONG_PTR page;

    if (!Src || !Bytes) return FALSE;
    /* Kernel half of the canonical address space only. A user-mode pointer
       here would be a caller mistake, and reading one would be worse. */
    if (a < 0xFFFF800000000000ULL) return FALSE;
    end = a + Bytes - 1;
    if (end < a) return FALSE;                     /* wrapped */
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    for (page = a & ~(ULONG_PTR)(PAGE_SIZE - 1); page <= end; page += PAGE_SIZE) {
        if (!MmIsAddressValid((PVOID)page)) return FALSE;
    }
    __try {
        RtlCopyMemory(Dst, Src, Bytes);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static NTSTATUS H3CheckVidBuild(ULONG *Stamp, ULONG *Size)
{
    PUCHAR b = (PUCHAR)g_VidBase;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;

    *Stamp = 0;
    *Size = 0;
    if (!g_VidBase || g_VidSize < sizeof(IMAGE_DOS_HEADER)) return STATUS_NOT_FOUND;
    dos = (PIMAGE_DOS_HEADER)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > g_VidSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    nt = (PIMAGE_NT_HEADERS64)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    *Stamp = nt->FileHeader.TimeDateStamp;
    *Size  = nt->OptionalHeader.SizeOfImage;
    if (*Stamp != H3_VID_TIMESTAMP || *Size != H3_VID_SIZEOFIMAGE) {
        /* Not the build the offsets came from. Say so; do not guess. */
        return STATUS_REVISION_MISMATCH;
    }
    return STATUS_SUCCESS;
}

static void H3VidVp(const H3_VIDVP_IN *In, H3_VIDVP_OUT *Out)
{
    PFN_WHV_INTERCEPT_ROUTINE routine = NULL;
    PVOID context = NULL;
    PUCHAR p;
    PUCHAR vparray = NULL;
    PUCHAR vectbl = NULL;
    NTSTATUS st;
    ULONG i;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->Version = 1;
    Out->VidBase = (ULONG64)(ULONG_PTR)g_VidBase;

    Out->Status = (ULONG)H3CheckVidBuild(&Out->VidTimeDateStamp, &Out->VidSizeOfImage);
    if (Out->Status != STATUS_SUCCESS) return;

    /* The pointer comes from Hyper-V's own table, under its own lock. */
    st = H3ReadPair(In->PartitionId, &routine, &context);
    if (!NT_SUCCESS(st)) {
        Out->Status = (ULONG)st;
        return;
    }

    /* ...unless WE have chained this partition, in which case the pair Hyper-V
       holds is OURS: the routine is H3ChainedRoutine and the context is a chain
       slot in this image, not the VID partition object.  Walking that would be
       walking our own bookkeeping, and the guard below correctly refused it --
       which is how this was found, by a combined arm reading a zeroed buffer.
       The saved pair is what Vid registered and what every offset here is
       about, so use it, and report which source answered so a caller can see
       which reading it has. */
    for (i = 0; i < H3_CHAIN_SLOTS; i++) {
        if (g_Chain[i].Active && g_Chain[i].PartitionId == In->PartitionId &&
            g_Chain[i].SavedRoutine) {
            routine = g_Chain[i].SavedRoutine;
            context = g_Chain[i].SavedContext;
            Out->FromChainSlot = 1;
            break;
        }
    }

    Out->Partition = (ULONG64)(ULONG_PTR)context;
    Out->Routine   = (ULONG64)(ULONG_PTR)routine;

    /* If the registered routine is not Vid's, the context is not a VID
       partition object and every offset below is meaningless. Refuse. */
    Out->RoutineInVid = (routine &&
                         (PUCHAR)routine >= (PUCHAR)g_VidBase &&
                         (PUCHAR)routine <  (PUCHAR)g_VidBase + g_VidSize) ? 1 : 0;
    if (!Out->RoutineInVid || !context) {
        Out->Status = (ULONG)STATUS_OBJECT_TYPE_MISMATCH;
        return;
    }

    p = (PUCHAR)context;

    if (!H3SafeRead(p + H3_VID_P_VPCOUNT, &Out->VpCount, sizeof(ULONG)) ||
        !H3SafeRead(p + H3_VID_P_VPARRAY, &vparray, sizeof(PVOID)) ||
        !H3SafeRead(p + H3_VID_P_VECTORTABLE, &vectbl, sizeof(PVOID)) ||
        !H3SafeRead(p + H3_VID_P_CLIENTS, &Out->ClientArray, sizeof(PVOID))) {
        Out->Status = (ULONG)STATUS_PARTIAL_COPY;
        return;
    }
    Out->VpArray     = (ULONG64)(ULONG_PTR)vparray;
    Out->VectorTable = (ULONG64)(ULONG_PTR)vectbl;

    /* The per-vector claim table. Index 3 is #BP; the neighbours come free and
       are what tell a reader whether this looks like a table of 0xFF at all. */
    if (vectbl && H3SafeRead(vectbl, Out->VectorByte, H3_VIDVP_VECTORS)) {
        Out->VectorRead = 1;
    }

    if (Out->VpCount > H3_VID_SANE_VPS || !vparray) {
        Out->Status = (ULONG)STATUS_INVALID_PARAMETER;
        return;
    }

    for (i = 0; i < Out->VpCount && Out->Returned < H3_VIDVP_MAX; i++) {
        H3_VIDVP_ENTRY *e = &Out->Vp[Out->Returned++];
        PUCHAR v = vparray + (SIZE_T)i * H3_VID_VP_STRIDE;
        PVOID back = NULL;
        UCHAR vector = 0;

        e->Vp = (ULONG64)(ULONG_PTR)v;

        if (!H3SafeRead(v + H3_VID_V_PARTITION, &back, sizeof(PVOID))) {
            e->ReadFailed = 1;
            continue;
        }
        e->BackPointer = (ULONG64)(ULONG_PTR)back;
        e->Valid = (back == context) ? 1 : 0;
        if (!e->Valid) continue;   /* the walk is wrong here; believe nothing */

        if (!H3SafeRead(v + H3_VID_V_MESSAGE, e->Message, H3_VIDVP_MSGBYTES)) {
            e->ReadFailed = 2;
            continue;
        }
        e->MessageType = *(ULONG *)&e->Message[0];
        e->PayloadSize = e->Message[4];

        if (!H3SafeRead(v + H3_VID_V_VECTOR, &vector, sizeof(UCHAR))) {
            e->ReadFailed = 3;
            continue;
        }
        e->Vector = vector;

        if (!H3SafeRead(v + H3_VID_V_HANDLER, &e->Handler, sizeof(ULONG64))) {
            e->ReadFailed = 4;
            continue;
        }
        if (!H3SafeRead(v + H3_VID_V_REASON, &e->Reason, sizeof(ULONG))) {
            e->ReadFailed = 5;
            continue;
        }
        if (!H3SafeRead(v + H3_VID_V_STAMP, &e->Stamp, sizeof(ULONG64))) {
            e->ReadFailed = 6;
            continue;
        }
    }
}

/* --- dispatch ------------------------------------------------------------ */


/*
 * Satisfy the process-identity gate and issue the receiver's own IOCTL.
 *
 * Paired throughout: attach/detach around everything, register/unregister
 * around the claim.  If the register succeeds we hold that vector's slot in a
 * LIVE partition until the unregister runs, so the unregister is not
 * conditional on anything but having been handed a handle.  The output is
 * poisoned first, so "wrote nothing" cannot read as a handle.
 *
 * Vid refuses a slot already claimed through Vid with STATUS_VID_DUPLICATE_HANDLER
 * (0xC0370001) before touching the hypervisor, so that outcome mutates nothing.
 * The hazard this cannot see is a RAW WinHvInstallIntercept holder on the same
 * vector: the duplicate check reads [P+0xB68], which only sees Vid registrations,
 * and the unregister clears the shared unrefcounted hypervisor bit.  One
 * installer per vector per partition.
 */
static void H3VidReg(const H3_VIDREG_IN *In, H3_VIDREG_OUT *Out)
{
    H3_APC_STATE apc;
    PVOID proc = NULL;
    PFILE_OBJECT fileObj = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st;
    ULONG64 got = H3_VIDREG_POISON;
    struct { UCHAR Vector; UCHAR Pad[3]; ULONG Parameter; ULONG64 Context; } reg;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->UnregisterStatus = H3_VIDREG_NOTRUN;
    Out->RegisterStatus = H3_VIDREG_NOTRUN;
    Out->HandleOut = got;

    Out->BuildStatus = (ULONG)H3CheckVidBuild(&Out->VidTimeDateStamp, &Out->VidSizeOfImage);
    if (Out->BuildStatus != STATUS_SUCCESS) return;
    if (In->Vector > 0xFF) return;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)In->OwnerPid, &proc);
    Out->LookupStatus = (ULONG)st;
    if (!NT_SUCCESS(st) || !proc) return;
    Out->AttachedProcess = (ULONG64)(ULONG_PTR)proc;

    reg.Vector = (UCHAR)In->Vector;
    reg.Pad[0] = 0; reg.Pad[1] = 0; reg.Pad[2] = 0;
    reg.Parameter = 0;
    reg.Context = 0x5337;          /* a recognisable sentinel, not a real context */

    KeStackAttachProcess(proc, &apc);
    Out->Attached = 1;

    /* Verify the gate's own field before trying to pass it: the handle is valid
       in this process now, so the file object resolves and FsContext is the
       partition.  This is what makes the arm check the static reading rather
       than assume it. */
    if (NT_SUCCESS(ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)In->PartitionHandle, 0,
                                             *IoFileObjectType, KernelMode,
                                             (PVOID *)&fileObj, NULL))) {
        ULONG_PTR part = (ULONG_PTR)fileObj->FsContext & ~(ULONG_PTR)3;
        ULONG64 owner = 0;
        if (part && H3SafeRead((PUCHAR)part + H3_VID_P_OWNERPROC, &owner, sizeof(owner))) {
            Out->OwnerField = owner;
            Out->OwnerRead = 1;
            Out->OwnerMatched = (owner == Out->AttachedProcess) ? 1 : 0;
        }
        ObDereferenceObject(fileObj);
    }

    st = ZwDeviceIoControlFile((HANDLE)(ULONG_PTR)In->PartitionHandle, NULL, NULL, NULL,
                               &iosb, H3_VID_REGISTER, &reg, sizeof(reg), &got, sizeof(got));
    Out->RegisterStatus = (ULONG)st;
    Out->HandleOut = got;

    if (NT_SUCCESS(st) && got != H3_VIDREG_POISON && got != 0) {
        ULONG64 h = got;
        Out->UnregisterStatus =
            (ULONG)ZwDeviceIoControlFile((HANDLE)(ULONG_PTR)In->PartitionHandle, NULL, NULL,
                                         NULL, &iosb, H3_VID_UNREGISTER, &h, sizeof(h), NULL, 0);
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
}


/*
 * Read a user-mode VA from kernel mode, while attached to the process that owns
 * it.  H3SafeRead deliberately refuses user addresses, which is right for every
 * other caller here, so this is its counterpart and is used for nothing else.
 */
static BOOLEAN H3SafeReadUser(const void *Src, void *Dst, SIZE_T Bytes)
{
    ULONG_PTR a = (ULONG_PTR)Src;

    if (!Src || !Bytes) return FALSE;
    if (a >= 0x0000800000000000ULL) return FALSE;      /* user half only */
    if (a + Bytes - 1 < a) return FALSE;               /* wrapped */
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    __try {
        ProbeForRead((PVOID)Src, Bytes, 1);
        RtlCopyMemory(Dst, Src, Bytes);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/*
 * Map a VP's message slot through the owner's identity, and read what is in it.
 * Nothing is armed and nothing is completed: this establishes only whether the
 * receive surface is reachable once the process-identity gate is satisfied.
 */
static void H3VidSlot(const H3_VIDSLOT_IN *In, H3_VIDSLOT_OUT *Out)
{
    H3_APC_STATE apc;
    PVOID proc = NULL;
    PFILE_OBJECT fileObj = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st;
    ULONG vp;
    ULONG64 slotVa = 0;
    ULONG stampIgnored, sizeIgnored;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->MapStatus = 0xFFFFFFFFUL;

    Out->BuildStatus = (ULONG)H3CheckVidBuild(&stampIgnored, &sizeIgnored);
    if (Out->BuildStatus != STATUS_SUCCESS) return;
    if (In->VpIndex >= H3_VID_SANE_VPS) return;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)In->OwnerPid, &proc);
    Out->LookupStatus = (ULONG)st;
    if (!NT_SUCCESS(st) || !proc) return;
    Out->AttachedProcess = (ULONG64)(ULONG_PTR)proc;

    vp = In->VpIndex;

    KeStackAttachProcess(proc, &apc);
    Out->Attached = 1;

    if (NT_SUCCESS(ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)In->PartitionHandle, 0,
                                             *IoFileObjectType, KernelMode,
                                             (PVOID *)&fileObj, NULL))) {
        ULONG_PTR part = (ULONG_PTR)fileObj->FsContext & ~(ULONG_PTR)3;
        ULONG64 owner = 0;
        if (part && H3SafeRead((PUCHAR)part + H3_VID_P_OWNERPROC, &owner, sizeof(owner))) {
            Out->OwnerField = owner;
            Out->OwnerMatched = (owner == Out->AttachedProcess) ? 1 : 0;
        }
        ObDereferenceObject(fileObj);
    }

    st = ZwDeviceIoControlFile((HANDLE)(ULONG_PTR)In->PartitionHandle, NULL, NULL, NULL,
                               &iosb, H3_VID_SLOTMAP, &vp, sizeof(vp),
                               &slotVa, sizeof(slotVa));
    Out->MapStatus = (ULONG)st;
    Out->SlotVa = slotVa;

    /* The VA lives in the process we are attached to, so it must be read here. */
    if (NT_SUCCESS(st) && slotVa) {
        if (H3SafeReadUser((const void *)(ULONG_PTR)slotVa, Out->Slot, H3_VIDSLOT_BYTES)) {
            Out->SlotRead = 1;
        }
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
}


/*
 * Map, arm, consume, disarm -- all while attached, so nothing survives the call.
 *
 * The unregister is in the tail and runs on every path that armed, including the
 * deadline path: an intercept left standing is what reset two guests, and this
 * driver must not be able to leave one.
 */
static void H3VidLoop(const H3_VIDLOOP_IN *In, H3_VIDLOOP_OUT *Out)
{
    H3_APC_STATE apc;
    PVOID proc = NULL;
    PFILE_OBJECT fileObj = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st;
    ULONG vp, maxMsg, stampIgnored, sizeIgnored;
    ULONG64 slotVa = 0, regHandle = H3_VIDREG_POISON;
    LARGE_INTEGER start, freq, now;
    LONGLONG deadlineTicks;
    struct { UCHAR Vector; UCHAR Pad[3]; ULONG Parameter; ULONG64 Context; } reg;
    UCHAR hdr[H3_VIDLOOP_CAPTURE];
    PVOID userIn = NULL;          /* 0x221107 is METHOD_NEITHER: its input must be USER memory */
    SIZE_T userInSize = 0x1000;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->MapStatus = 0xFFFFFFFFUL;
    Out->RegisterStatus = 0xFFFFFFFFUL;
    Out->UnregisterStatus = 0xFFFFFFFFUL;
    Out->LastCompleteStatus = 0xFFFFFFFFUL;

    Out->BuildStatus = (ULONG)H3CheckVidBuild(&stampIgnored, &sizeIgnored);
    if (Out->BuildStatus != STATUS_SUCCESS) return;
    if (In->VpIndex >= H3_VID_SANE_VPS || In->Vector > 0xFF) return;

    maxMsg = In->MaxMessages;
    if (maxMsg == 0 || maxMsg > H3_VIDLOOP_MAXMSG) maxMsg = H3_VIDLOOP_MAXMSG;
    vp = In->VpIndex;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)In->OwnerPid, &proc);
    Out->LookupStatus = (ULONG)st;
    if (!NT_SUCCESS(st) || !proc) return;

    reg.Vector = (UCHAR)In->Vector;
    reg.Pad[0] = 0; reg.Pad[1] = 0; reg.Pad[2] = 0;
    reg.Parameter = 0;
    reg.Context = 0x5337;
    KeStackAttachProcess(proc, &apc);
    Out->Attached = 1;

    if (NT_SUCCESS(ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)In->PartitionHandle, 0,
                                             *IoFileObjectType, KernelMode,
                                             (PVOID *)&fileObj, NULL))) {
        ULONG_PTR part = (ULONG_PTR)fileObj->FsContext & ~(ULONG_PTR)3;
        ULONG64 owner = 0;
        if (part && H3SafeRead((PUCHAR)part + H3_VID_P_OWNERPROC, &owner, sizeof(owner))) {
            Out->OwnerMatched = (owner == (ULONG64)(ULONG_PTR)proc) ? 1 : 0;
        }
        ObDereferenceObject(fileObj);
    }

    /* 0. the METHOD_NEITHER input buffer, in the attached process's user space */
    st = ZwAllocateVirtualMemory(H3_CURPROC, &userIn, 0, &userInSize,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Out->UserBufStatus = (ULONG)st;
    if (!NT_SUCCESS(st) || !userIn) goto detach;
    __try {
        ((ULONG *)userIn)[0] = vp;
        ((ULONG *)userIn)[1] = In->Flags;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Out->UserBufStatus = (ULONG)STATUS_ACCESS_VIOLATION;
        goto freebuf;
    }

    /* 1. the slot first, so there is a consumer before anything is armed */
    st = ZwDeviceIoControlFile((HANDLE)(ULONG_PTR)In->PartitionHandle, NULL, NULL, NULL,
                               &iosb, H3_VID_SLOTMAP, &vp, sizeof(vp), &slotVa, sizeof(slotVa));
    Out->MapStatus = (ULONG)st;
    Out->SlotVa = slotVa;
    if (!NT_SUCCESS(st) || !slotVa) goto freebuf;

    /* 2. arm -- unless this is a parameter probe, which must not arm anything */
    if (In->SkipArm) {
        /* One completion attempt, whatever the slot holds: we are only after its status. */
        if (H3SafeReadUser((const void *)(ULONG_PTR)slotVa, hdr, H3_VIDLOOP_CAPTURE)) {
            RtlCopyMemory(&Out->FirstType, hdr, sizeof(ULONG));
            Out->FirstPayloadSize = hdr[4];
            RtlCopyMemory(Out->First, hdr, H3_VIDLOOP_CAPTURE);
        }
        st = ZwDeviceIoControlFile((HANDLE)(ULONG_PTR)In->PartitionHandle, NULL, NULL, NULL,
                                   &iosb, H3_VID_SLOTNEXT, userIn, 8, NULL, 0);
        Out->LastCompleteStatus = (ULONG)st;
        if (NT_SUCCESS(st)) Out->Messages = 1;
        goto freebuf;
    }

    st = ZwDeviceIoControlFile((HANDLE)(ULONG_PTR)In->PartitionHandle, NULL, NULL, NULL,
                               &iosb, H3_VID_REGISTER, &reg, sizeof(reg),
                               &regHandle, sizeof(regHandle));
    Out->RegisterStatus = (ULONG)st;
    Out->RegHandle = regHandle;
    if (!NT_SUCCESS(st)) goto freebuf;

    /* 3. consume, bounded two ways */
    freq.QuadPart = 0;
    start = KeQueryPerformanceCounter(&freq);
    deadlineTicks = (freq.QuadPart / 1000) * (LONGLONG)In->TimeoutMs;

    while (Out->Messages < maxMsg) {
        ULONG type = 0;
        now = KeQueryPerformanceCounter(NULL);
        if (now.QuadPart - start.QuadPart > deadlineTicks) { Out->DeadlineHit = 1; break; }

        /* Only call the completion when a message is actually there: it completes the
           current one and then WAITS for the next, so calling it on an empty slot can
           block this thread while attached to vmwp. */
        if (!H3SafeReadUser((const void *)(ULONG_PTR)slotVa, hdr, H3_VIDLOOP_CAPTURE)) break;
        RtlCopyMemory(&type, hdr, sizeof(type));
        if (type == 0) {
            LARGE_INTEGER d;
            Out->Polls++;
            d.QuadPart = -10000;                       /* 1 ms */
            KeDelayExecutionThread(KernelMode, FALSE, &d);
            continue;
        }

        if (Out->Messages == 0) {
            RtlCopyMemory(Out->First, hdr, H3_VIDLOOP_CAPTURE);
            Out->FirstType = type;
            Out->FirstPayloadSize = hdr[4];
        }
        Out->LastType = type;

        st = ZwDeviceIoControlFile((HANDLE)(ULONG_PTR)In->PartitionHandle, NULL, NULL, NULL,
                                   &iosb, H3_VID_SLOTNEXT, userIn, 8, NULL, 0);
        Out->LastCompleteStatus = (ULONG)st;
        if (!NT_SUCCESS(st)) break;
        Out->Messages++;
    }

    /* 4. disarm, on every path that armed */
    if (regHandle != H3_VIDREG_POISON && regHandle != 0) {
        ULONG64 h = regHandle;
        Out->UnregisterStatus =
            (ULONG)ZwDeviceIoControlFile((HANDLE)(ULONG_PTR)In->PartitionHandle, NULL, NULL,
                                         NULL, &iosb, H3_VID_UNREGISTER, &h, sizeof(h), NULL, 0);
    }

freebuf:
    if (userIn) {
        SIZE_T z = 0;
        ZwFreeVirtualMemory(H3_CURPROC, &userIn, &z, MEM_RELEASE);
    }

detach:
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
}


/*
 * The identity every VID memory probe starts from: the exact Vid.sys build, the
 * named vmwp, attached, and a handle in that process to a partition whose
 * object records that process as its owner -- VidIoControlPreProcess's own
 * gate, so a call made from here is one VID would accept from vmwp itself.
 *
 * On TRUE the caller is attached and holds references on *Proc and *FileObj;
 * on FALSE it may still be attached (Id->Attached says so).  Either way
 * H3VidOwnerRelease undoes exactly what was taken.
 */
static BOOLEAN H3VidOwnerAttach(ULONG OwnerPid, ULONG64 PartitionHandle, H3_VIDIDENT *Id,
                                H3_APC_STATE *Apc, PVOID *Proc, PFILE_OBJECT *FileObj,
                                ULONG_PTR *Partition)
{
    NTSTATUS st;
    ULONG_PTR part;
    ULONG64 owner = 0;

    *Proc = NULL;
    *FileObj = NULL;
    *Partition = 0;
    Id->LookupStatus = 0xFFFFFFFFUL;
    Id->HandleStatus = 0xFFFFFFFFUL;
    Id->BuildStatus = (ULONG)H3CheckVidBuild(&Id->VidTimeDateStamp, &Id->VidSizeOfImage);
    if (Id->BuildStatus != STATUS_SUCCESS) return FALSE;
    if (OwnerPid == 0 || PartitionHandle == 0) {
        Id->LookupStatus = (ULONG)STATUS_INVALID_PARAMETER;
        return FALSE;
    }

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)OwnerPid, Proc);
    Id->LookupStatus = (ULONG)st;
    if (!NT_SUCCESS(st) || !*Proc) {
        *Proc = NULL;
        return FALSE;
    }
    Id->AttachedProcess = (ULONG64)(ULONG_PTR)*Proc;

    KeStackAttachProcess(*Proc, Apc);
    Id->Attached = 1;

    /* The reference below is KernelMode, which would look a kernel handle up in the kernel's own
       table.  Only a handle in the named process is meant, so a value with the kernel bit, or one
       wider than any handle table, is refused rather than resolved. */
    if ((LONG64)PartitionHandle < 0 || PartitionHandle > 0xFFFFFFFFULL) {
        Id->HandleStatus = (ULONG)STATUS_INVALID_HANDLE;
        return FALSE;
    }

    /* Held until release: the walk and both calls below use the partition. */
    st = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)PartitionHandle, 0,
                                   *IoFileObjectType, KernelMode, (PVOID *)FileObj, NULL);
    Id->HandleStatus = (ULONG)st;
    if (!NT_SUCCESS(st) || !*FileObj) {
        *FileObj = NULL;
        return FALSE;
    }
    part = (ULONG_PTR)(*FileObj)->FsContext & ~(ULONG_PTR)3;
    if (!part || !H3SafeRead((PUCHAR)part + H3_VID_P_OWNERPROC, &owner, sizeof(owner))) {
        return FALSE;
    }
    Id->OwnerField = owner;
    Id->OwnerRead = 1;
    Id->OwnerMatched = (owner == Id->AttachedProcess) ? 1 : 0;
    if (!Id->OwnerMatched) return FALSE;
    *Partition = part;
    return TRUE;
}

static void H3VidOwnerRelease(H3_VIDIDENT *Id, H3_APC_STATE *Apc, PVOID Proc,
                              PFILE_OBJECT FileObj)
{
    if (FileObj) ObDereferenceObject(FileObj);
    if (Id->Attached) KeUnstackDetachProcess(Apc);
    if (Proc) ObDereferenceObject(Proc);
}


/*
 * One METHOD_NEITHER VID call from the attached owner, waited to completion.
 * VidIoControlFast completes METHOD_NEITHER codes inline, but vid.dll still
 * waits when it sees STATUS_PENDING and so does this, without a timeout: the
 * caller's buffers and the IO_STATUS_BLOCK must outlive the request, and there
 * is no earlier point at which freeing them would be safe.
 */
static NTSTATUS H3VidCall(HANDLE PartitionHandle, ULONG Code, PVOID In, ULONG InBytes,
                          PVOID Out, ULONG OutBytes, ULONG64 *Information)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE ev = NULL;
    NTSTATUS st;

    *Information = 0;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateEvent(&ev, EVENT_ALL_ACCESS, &oa, NotificationEvent, FALSE);
    if (!NT_SUCCESS(st)) return st;

    RtlZeroMemory(&iosb, sizeof(iosb));
    st = ZwDeviceIoControlFile(PartitionHandle, ev, NULL, NULL, &iosb, Code,
                               In, InBytes, Out, OutBytes);
    if (st == STATUS_PENDING) {
        ZwWaitForSingleObject(ev, FALSE, NULL);
        st = iosb.Status;
    }
    *Information = (ULONG64)iosb.Information;
    ZwClose(ev);
    return st;
}

/* Translate one page number into Out[4], through a scratch qword pair in the owner. */
static NTSTATUS H3VidTranslateGpn(HANDLE PartitionHandle, PUCHAR Scratch, ULONG64 Gpn,
                                  ULONG64 Out[4], ULONG64 *Information)
{
    NTSTATUS st;

    RtlZeroMemory(Out, 4 * sizeof(ULONG64));
    __try {
        RtlZeroMemory(Scratch, 0x28);
        *(ULONG64 *)Scratch = Gpn;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *Information = 0;
        return STATUS_ACCESS_VIOLATION;
    }
    st = H3VidCall(PartitionHandle, H3_VID_TRANSLATE_GPN, Scratch, sizeof(ULONG64),
                   Scratch + 8, 4 * sizeof(ULONG64), Information);
    if (!NT_SUCCESS(st)) return st;
    if (*Information != 4 * sizeof(ULONG64)) return STATUS_INFO_LENGTH_MISMATCH;
    if (!H3SafeReadUser(Scratch + 8, Out, 4 * sizeof(ULONG64))) return STATUS_PARTIAL_COPY;
    return STATUS_SUCCESS;
}


/*
 * Ask the partition how one GPA is represented, without reading or mapping the
 * page.  The input is a byte address and is sent as the page number VID
 * expects; Out->Gpn says which one was asked.  Nothing is retained.
 */
static void H3VidTranslate(const H3_VIDTRANSLATE_IN *In, H3_VIDTRANSLATE_OUT *Out)
{
    H3_APC_STATE apc;
    PVOID proc = NULL;
    PFILE_OBJECT fileObj = NULL;
    ULONG_PTR part = 0;
    PVOID user = NULL;
    SIZE_T userSize = PAGE_SIZE;
    NTSTATUS st;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->Version = H3_VIDMEM_PROBE_VERSION;
    Out->UserBufferStatus = 0xFFFFFFFFUL;
    Out->TranslateStatus = 0xFFFFFFFFUL;
    Out->Gpn = In->Gpa >> 12;
    if (!H3VidOwnerAttach(In->OwnerPid, In->PartitionHandle, &Out->Id, &apc,
                          &proc, &fileObj, &part)) {
        goto release_translate;
    }

    st = ZwAllocateVirtualMemory(H3_CURPROC, &user, 0, &userSize,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Out->UserBufferStatus = (ULONG)st;
    if (!NT_SUCCESS(st) || !user) goto release_translate;

    Out->TranslateStatus = (ULONG)H3VidTranslateGpn(
        (HANDLE)(ULONG_PTR)In->PartitionHandle, (PUCHAR)user, Out->Gpn, Out->Field,
        &Out->IoInformation);

    {
        SIZE_T zero = 0;
        ZwFreeVirtualMemory(H3_CURPROC, &user, &zero, MEM_RELEASE);
    }

release_translate:
    H3VidOwnerRelease(&Out->Id, &apc, proc, fileObj);
}


/*
 * Which memory-block handle names the block translate returned?  Translate
 * reports the block by its user context [MB+0xB0]; the read wants the handle.
 * The partition's own table maps one to the other, and an entry is believed only
 * if it agrees with itself: a kernel pointer (VidHandleTableLookupEntry's own
 * test), whose back-pointer is this partition and whose recorded handle is its
 * own index.  Exactly one entry may match.
 *
 * This reads VID's table without VID's lock, so it is a selection, not a lease.
 * The read IOCTL looks the handle up again under the lock, and the caller
 * translates again afterwards to show the block did not change underneath.
 */
static NTSTATUS H3VidFindMemoryBlock(ULONG_PTR Partition, ULONG64 UserContext,
                                     ULONG64 *Handle, ULONG64 *Pages,
                                     ULONG *Count, ULONG *Matches)
{
    ULONG_PTR table = 0;
    ULONG count = 0;
    ULONG i;

    *Handle = 0;
    *Pages = 0;
    *Count = 0;
    *Matches = 0;
    if (!UserContext) return STATUS_INVALID_PARAMETER;
    if (!H3SafeRead((PUCHAR)Partition + H3_VID_P_MBTABLE, &table, sizeof(table)) ||
        !H3SafeRead((PUCHAR)Partition + H3_VID_P_MBTABLE + sizeof(PVOID), &count,
                    sizeof(count))) {
        return STATUS_PARTIAL_COPY;
    }
    *Count = count;
    if (!table || count > H3_VID_MBTABLE_MAX) return STATUS_INVALID_DEVICE_STATE;

    for (i = 1; i < count; i++) {
        ULONG_PTR mb = 0;
        UCHAR rec[H3_VID_MB_RECORD];

        if (!H3SafeRead((PUCHAR)table + (SIZE_T)i * sizeof(PVOID), &mb, sizeof(mb))) {
            return STATUS_PARTIAL_COPY;
        }
        if ((LONG_PTR)mb >= 0) continue;           /* a free slot */
        if (!H3SafeRead((PVOID)mb, rec, sizeof(rec))) continue;
        if (*(ULONG_PTR *)(rec + H3_VID_MB_PARTITION) != Partition) continue;
        if (*(ULONG64 *)(rec + H3_VID_MB_HANDLE) != i) continue;
        if (*(ULONG64 *)(rec + H3_VID_MB_USERCTX) != UserContext) continue;
        (*Matches)++;
        *Handle = i;
        *Pages = *(ULONG64 *)(rec + H3_VID_MB_PAGES);
    }
    if (*Matches == 0) return STATUS_NOT_FOUND;
    if (*Matches != 1) return STATUS_OBJECT_NAME_COLLISION;
    return STATUS_SUCCESS;
}


/*
 * The measured read: one page, by GPA, through vmwp's own partition handle.
 *
 *   1. translate the page number: no range is NOT_PRESENT, a range that is not
 *      memory-block RAM is REFUSED -- typed here, so an all-zero page that is
 *      RAM can never be confused with no page;
 *   2. find the block's handle in the partition's table;
 *   3. read one block page into a poisoned buffer in the owner, through the
 *      same IOCTL vid.dll!VidReadMemoryBlockPageRange sends;
 *   4. translate again and require the same four fields.
 *
 * Read-only.  The two scratch pages are the only change to vmwp, and are freed
 * before detaching.  This is a measurement control rather than the product ABI.
 */
static void H3VidReadProbe(const H3_VIDREADPROBE_IN *In, H3_VIDREADPROBE_OUT *Out)
{
    H3_APC_STATE apc;
    PVOID proc = NULL;
    PFILE_OBJECT fileObj = NULL;
    ULONG_PTR part = 0;
    PVOID user = NULL;
    SIZE_T userSize = H3_VID_PAGE_BYTES * 2;
    HANDLE ph = (HANDLE)(ULONG_PTR)In->PartitionHandle;
    PUCHAR scratch, readIn, readOut, page;
    ULONG64 completion = H3_VIDREG_POISON;
    ULONG64 recheckInformation = 0;
    NTSTATUS st;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->Version = H3_VIDMEM_PROBE_VERSION;
    Out->Result = H3_MEM_IDENTITY;
    Out->UserBufferStatus = 0xFFFFFFFFUL;
    Out->TranslateStatus = 0xFFFFFFFFUL;
    Out->ScanStatus = 0xFFFFFFFFUL;
    Out->ReadStatus = 0xFFFFFFFFUL;
    Out->RecheckStatus = 0xFFFFFFFFUL;
    Out->Completion = H3_VIDREG_POISON;
    Out->Gpn = In->Gpa >> 12;
    if ((In->Gpa & (H3_VID_PAGE_BYTES - 1)) != 0) {
        Out->Result = H3_MEM_ERROR;
        return;
    }
    if (!H3VidOwnerAttach(In->OwnerPid, In->PartitionHandle, &Out->Id, &apc,
                          &proc, &fileObj, &part)) {
        goto release_read_probe;
    }
    Out->Result = H3_MEM_ERROR;

    st = ZwAllocateVirtualMemory(H3_CURPROC, &user, 0, &userSize,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Out->UserBufferStatus = (ULONG)st;
    if (!NT_SUCCESS(st) || !user) goto release_read_probe;
    scratch = (PUCHAR)user;
    readIn = (PUCHAR)user + 0x100;
    readOut = (PUCHAR)user + 0x200;
    page = (PUCHAR)user + H3_VID_PAGE_BYTES;

    st = H3VidTranslateGpn(ph, scratch, Out->Gpn, Out->TranslateField,
                           &Out->TranslateInformation);
    Out->TranslateStatus = (ULONG)st;
    if (!NT_SUCCESS(st)) goto free_read_probe;
    if (Out->TranslateField[1] == 0) {
        Out->Result = Out->TranslateField[0] ? H3_MEM_REFUSED : H3_MEM_NOT_PRESENT;
        goto free_read_probe;
    }

    st = H3VidFindMemoryBlock(part, Out->TranslateField[1], &Out->MemoryBlockHandle,
                              &Out->MemoryBlockPages, &Out->TableCount, &Out->TableMatches);
    Out->ScanStatus = (ULONG)st;
    if (!NT_SUCCESS(st)) goto free_read_probe;
    if (Out->TranslateField[2] >= Out->MemoryBlockPages) {
        Out->ScanStatus = (ULONG)STATUS_INVALID_DEVICE_STATE;
        goto free_read_probe;
    }

    __try {
        ULONG64 *request = (ULONG64 *)readIn;
        RtlFillMemory(page, H3_VID_PAGE_BYTES, 0xAA);
        *(ULONG64 *)readOut = completion;
        request[0] = Out->MemoryBlockHandle;
        request[1] = Out->TranslateField[2];
        request[2] = 1;
        request[3] = (ULONG64)(ULONG_PTR)page;
        request[4] = H3_VID_PAGE_BYTES;
        request[5] = 0;
        request[6] = 0;
        request[7] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Out->ReadStatus = (ULONG)STATUS_ACCESS_VIOLATION;
        goto free_read_probe;
    }

    st = H3VidCall(ph, H3_VID_READ_PAGES, readIn, 0x40, readOut, sizeof(completion),
                   &Out->ReadInformation);
    Out->ReadStatus = (ULONG)st;
    if (!NT_SUCCESS(st)) {
        if (st == STATUS_ACCESS_DENIED) Out->Result = H3_MEM_REFUSED;
        goto free_read_probe;
    }
    if (Out->ReadInformation != sizeof(completion) ||
        !H3SafeReadUser(readOut, &completion, sizeof(completion))) {
        goto free_read_probe;
    }
    Out->Completion = completion;
    if (completion != H3_VID_PAGE_BYTES) goto free_read_probe;
    if (!H3SafeReadUser(page, Out->Data, H3_VID_PAGE_BYTES)) goto free_read_probe;

    st = H3VidTranslateGpn(ph, scratch, Out->Gpn, Out->RecheckField,
                           &recheckInformation);
    Out->RecheckStatus = (ULONG)st;
    if (!NT_SUCCESS(st)) goto free_read_probe;
    if (RtlCompareMemory(Out->RecheckField, Out->TranslateField,
                         sizeof(Out->TranslateField)) != sizeof(Out->TranslateField)) {
        Out->RecheckStatus = (ULONG)STATUS_DATA_NOT_ACCEPTED;
        goto free_read_probe;
    }
    Out->DataLength = H3_VID_PAGE_BYTES;
    Out->Result = H3_MEM_OK;

free_read_probe:
    {
        SIZE_T zero = 0;
        ZwFreeVirtualMemory(H3_CURPROC, &user, &zero, MEM_RELEASE);
    }
    if (Out->Result != H3_MEM_OK) {
        Out->DataLength = 0;
        RtlZeroMemory(Out->Data, sizeof(Out->Data));
    }

release_read_probe:
    H3VidOwnerRelease(&Out->Id, &apc, proc, fileObj);
}


/*
 * One block page through VID's own page IOCTL: read it into Page, or write Page
 * over it.  Request is 0x48 bytes of the owner's scratch: the 0x40-byte request
 * and the read's 8-byte completion.  A read must report the whole page; VID's
 * write reports no count, and the caller proves it by reading the page back.
 */
static NTSTATUS H3VidPageIo(HANDLE PartitionHandle, PUCHAR Request, ULONG64 BlockHandle,
                            ULONG64 BlockPage, PUCHAR Page, BOOLEAN Write)
{
    ULONG64 information = 0;
    ULONG64 bytes = H3_VIDREG_POISON;
    NTSTATUS st;

    __try {
        ULONG64 *q = (ULONG64 *)Request;
        q[0] = BlockHandle;
        q[1] = BlockPage;
        q[2] = 1;
        q[3] = (ULONG64)(ULONG_PTR)Page;
        q[4] = H3_VID_PAGE_BYTES;
        q[5] = 0;
        q[6] = 0;
        q[7] = 0;
        q[8] = H3_VIDREG_POISON;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
    if (Write) {
        return H3VidCall(PartitionHandle, H3_VID_WRITE_PAGES, Request, 0x40, NULL, 0,
                         &information);
    }
    st = H3VidCall(PartitionHandle, H3_VID_READ_PAGES, Request, 0x40, Request + 0x40,
                   sizeof(bytes), &information);
    if (!NT_SUCCESS(st)) return st;
    if (information != sizeof(bytes) ||
        !H3SafeReadUser(Request + 0x40, &bytes, sizeof(bytes)) ||
        bytes != H3_VID_PAGE_BYTES) {
        return STATUS_PARTIAL_COPY;
    }
    return STATUS_SUCCESS;
}

static void H3MemAnswer(H3_MEM_ANSWER *Ans, ULONG Result, ULONG Stage, NTSTATUS Status)
{
    Ans->Result = Result;
    Ans->Stage = Stage;
    Ans->Status = (ULONG)Status;
}

/*
 * The memory operation: read Req->Length bytes into Out, or, with Patch, write
 * them.  Every path that attached detaches, every reference taken is dropped,
 * and the owner's three scratch pages are freed before the answer is returned.
 */
static void H3MemPage(const H3_MEM_REQUEST *Req, const UCHAR *Patch, H3_MEM_ANSWER *Ans,
                      UCHAR *Out)
{
    H3_VIDIDENT id;
    H3_APC_STATE apc;
    PVOID proc = NULL;
    PFILE_OBJECT fileObj = NULL;
    ULONG_PTR part = 0;
    PVOID user = NULL;
    SIZE_T userSize = H3_VID_PAGE_BYTES * 3;
    HANDLE ph = (HANDLE)(ULONG_PTR)Req->PartitionHandle;
    PUCHAR scratch, request, page, verify;
    ULONG64 fields[4], recheck[4];
    ULONG64 information = 0, handle = 0, pages = 0, partitionId = 0;
    ULONG count = 0, matches = 0;
    ULONG offset = (ULONG)(Req->Gpa & (H3_VID_PAGE_BYTES - 1));
    NTSTATUS st;

    RtlZeroMemory(Ans, sizeof(*Ans));
    RtlZeroMemory(&id, sizeof(id));
    Ans->Version = H3_MEM_ABI_VERSION;
    Ans->Gpn = Req->Gpa >> 12;
    if (Req->Version != H3_MEM_ABI_VERSION || Req->Reserved != 0 || Req->Length == 0 ||
        Req->Length > H3_VID_PAGE_BYTES - offset) {
        H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_REQUEST, STATUS_INVALID_PARAMETER);
        return;
    }

    if (!H3VidOwnerAttach(Req->OwnerPid, Req->PartitionHandle, &id, &apc, &proc, &fileObj,
                          &part)) {
        if (id.BuildStatus != STATUS_SUCCESS) {
            H3MemAnswer(Ans, H3_MEM_IDENTITY, H3_MEM_STAGE_BUILD, (NTSTATUS)id.BuildStatus);
        } else if (id.LookupStatus != STATUS_SUCCESS) {
            H3MemAnswer(Ans, H3_MEM_IDENTITY, H3_MEM_STAGE_PROCESS, (NTSTATUS)id.LookupStatus);
        } else if (id.HandleStatus != STATUS_SUCCESS) {
            H3MemAnswer(Ans, H3_MEM_IDENTITY, H3_MEM_STAGE_HANDLE, (NTSTATUS)id.HandleStatus);
        } else {
            H3MemAnswer(Ans, H3_MEM_IDENTITY, H3_MEM_STAGE_OWNER, STATUS_ACCESS_DENIED);
        }
        goto release_mem;
    }

    st = ZwAllocateVirtualMemory(H3_CURPROC, &user, 0, &userSize,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !user) {
        user = NULL;
        H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_SCRATCH, st);
        goto release_mem;
    }
    scratch = (PUCHAR)user;
    request = (PUCHAR)user + 0x100;
    page = (PUCHAR)user + H3_VID_PAGE_BYTES;
    verify = (PUCHAR)user + 2 * H3_VID_PAGE_BYTES;

    /* The caller's partition ID is an assertion about the handle; check it. */
    st = H3VidCall(ph, H3_VID_PARTITION_ID, NULL, 0, scratch, sizeof(partitionId),
                   &information);
    if (NT_SUCCESS(st) && (information != sizeof(partitionId) ||
                           !H3SafeReadUser(scratch, &partitionId, sizeof(partitionId)))) {
        st = STATUS_PARTIAL_COPY;
    }
    if (!NT_SUCCESS(st)) {
        H3MemAnswer(Ans, H3_MEM_IDENTITY, H3_MEM_STAGE_PARTITION, st);
        goto free_mem;
    }
    if (partitionId != Req->PartitionId) {
        H3MemAnswer(Ans, H3_MEM_IDENTITY, H3_MEM_STAGE_PARTITION, STATUS_OBJECT_TYPE_MISMATCH);
        goto free_mem;
    }

    st = H3VidTranslateGpn(ph, scratch, Ans->Gpn, fields, &information);
    if (!NT_SUCCESS(st)) {
        H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_TRANSLATE, st);
        goto free_mem;
    }
    if (fields[1] == 0) {
        H3MemAnswer(Ans, fields[0] ? H3_MEM_REFUSED : H3_MEM_NOT_PRESENT,
                    H3_MEM_STAGE_TRANSLATE, STATUS_SUCCESS);
        goto free_mem;
    }

    st = H3VidFindMemoryBlock(part, fields[1], &handle, &pages, &count, &matches);
    if (NT_SUCCESS(st) && fields[2] >= pages) st = STATUS_INVALID_DEVICE_STATE;
    if (!NT_SUCCESS(st)) {
        H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_BLOCK, st);
        goto free_mem;
    }

    __try {
        RtlFillMemory(page, H3_VID_PAGE_BYTES, 0xAA);
        RtlFillMemory(verify, H3_VID_PAGE_BYTES, 0xAA);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_SCRATCH, STATUS_ACCESS_VIOLATION);
        goto free_mem;
    }
    st = H3VidPageIo(ph, request, handle, fields[2], page, FALSE);
    if (!NT_SUCCESS(st)) {
        H3MemAnswer(Ans, st == STATUS_ACCESS_DENIED ? H3_MEM_REFUSED : H3_MEM_ERROR,
                    H3_MEM_STAGE_READ, st);
        goto free_mem;
    }

    if (Patch) {
        BOOLEAN same = FALSE;

        __try {
            RtlCopyMemory(page + offset, Patch, Req->Length);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_WRITE, STATUS_ACCESS_VIOLATION);
            goto free_mem;
        }
        st = H3VidPageIo(ph, request, handle, fields[2], page, TRUE);
        if (!NT_SUCCESS(st)) {
            H3MemAnswer(Ans, st == STATUS_ACCESS_DENIED ? H3_MEM_REFUSED : H3_MEM_ERROR,
                        H3_MEM_STAGE_WRITE, st);
            goto free_mem;
        }
        /* From here the guest page may have changed, so every failure is ERROR. */
        st = H3VidPageIo(ph, request, handle, fields[2], verify, FALSE);
        if (NT_SUCCESS(st)) {
            __try {
                same = RtlCompareMemory(page, verify, H3_VID_PAGE_BYTES) == H3_VID_PAGE_BYTES;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                st = STATUS_ACCESS_VIOLATION;
            }
            if (NT_SUCCESS(st) && !same) st = STATUS_DATA_ERROR;
        }
        if (!NT_SUCCESS(st)) {
            H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_VERIFY, st);
            goto free_mem;
        }
    } else if (!H3SafeReadUser(page + offset, Out, Req->Length)) {
        H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_READ, STATUS_PARTIAL_COPY);
        goto free_mem;
    }

    st = H3VidTranslateGpn(ph, scratch, Ans->Gpn, recheck, &information);
    if (NT_SUCCESS(st) &&
        RtlCompareMemory(recheck, fields, sizeof(fields)) != sizeof(fields)) {
        st = STATUS_DATA_NOT_ACCEPTED;
    }
    if (!NT_SUCCESS(st)) {
        H3MemAnswer(Ans, H3_MEM_ERROR, H3_MEM_STAGE_RECHECK, st);
        goto free_mem;
    }
    H3MemAnswer(Ans, H3_MEM_OK, H3_MEM_STAGE_NONE, STATUS_SUCCESS);
    Ans->Length = Req->Length;

free_mem:
    {
        SIZE_T zero = 0;
        ZwFreeVirtualMemory(H3_CURPROC, &user, &zero, MEM_RELEASE);
    }

release_mem:
    H3VidOwnerRelease(&id, &apc, proc, fileObj);
    if (Ans->Result != H3_MEM_OK && Out) RtlZeroMemory(Out, H3_VID_PAGE_BYTES);
}


/*
 * Reach the hypervisor's own gate on a VTL1 entry context.
 *
 * Nothing here is undoable: if the hypervisor accepts a zero context the target
 * VP's VTL1 is enabled and that guest is very probably finished.  The lab exists
 * for that, and the zero context is chosen so acceptance cannot also mean
 * arbitrary code started running.
 */
static void H3VtlEnable(const H3_VTLENABLE_IN *In, H3_VTLENABLE_OUT *Out)
{
    PFN_H3_ENABLEVPVTL fn;
    UCHAR ctx[H3_VTL_CONTEXT_BYTES];

    RtlZeroMemory(Out, sizeof(*Out));
    Out->CallStatus = 0xFFFFFFFFUL;

    if (!g_WinHvBase || !g_WinHvSize) {
        Out->ResolveStatus = (ULONG)STATUS_NOT_FOUND;
        return;
    }
    fn = (PFN_H3_ENABLEVPVTL)H3FindExport(g_WinHvBase, g_WinHvSize, "WinHvEnableVpVtl");
    if (!fn) {
        Out->ResolveStatus = (ULONG)STATUS_PROCEDURE_NOT_FOUND;
        return;
    }
    Out->ResolveStatus = (ULONG)STATUS_SUCCESS;
    Out->ExportVa = (ULONG64)(ULONG_PTR)fn;

    if (In->UseZeroContext) {
        RtlZeroMemory(ctx, sizeof(ctx));
    } else {
        RtlCopyMemory(ctx, In->Context, sizeof(ctx));
    }

    Out->Called = 1;
    Out->CallStatus = (ULONG)fn(In->PartitionId, In->VpIndex,
                                (ULONG64)(In->TargetVtl & 0xFF), ctx);
}


/*
 * Enable partition-level VTL on a partition, straight at the hypervisor.
 *
 * Not undoable from here: vid.dll exports a disable, but this driver resolves
 * only what it calls, and a partition left with a VTL enabled and nothing in it
 * is a state the guest was not built for.  The lab exists for that.
 */
static void H3PartVtl(const H3_PARTVTL_IN *In, H3_PARTVTL_OUT *Out)
{
    PFN_H3_ENABLEPARTVTL fn;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->CallStatus = 0xFFFFFFFFUL;

    if (!g_WinHvBase || !g_WinHvSize) {
        Out->ResolveStatus = (ULONG)STATUS_NOT_FOUND;
        return;
    }
    fn = (PFN_H3_ENABLEPARTVTL)H3FindExport(g_WinHvBase, g_WinHvSize, "WinHvEnablePartitionVtl");
    if (!fn) {
        Out->ResolveStatus = (ULONG)STATUS_PROCEDURE_NOT_FOUND;
        return;
    }
    Out->ResolveStatus = (ULONG)STATUS_SUCCESS;
    Out->ExportVa = (ULONG64)(ULONG_PTR)fn;

    Out->Called = 1;
    Out->CallStatus = (ULONG)fn(In->PartitionId,
                                (ULONG64)(In->TargetVtl & 0xFF),
                                (ULONG64)In->Flags,
                                (ULONG64)In->Arg4,
                                (ULONG64)In->Arg5);
}

static NTSTATUS H3Dispatch(PDEVICE_OBJECT Device, PIRP Irp)
{
    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS st = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(Device);

    if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
        s->Parameters.DeviceIoControl.IoControlCode == IOCTL_H3_RUN) {
        if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(H3_RESULTS)) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            H3Run((H3_RESULTS *)Irp->AssociatedIrp.SystemBuffer);
            info = sizeof(H3_RESULTS);
        }
    } else if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
               s->Parameters.DeviceIoControl.IoControlCode == IOCTL_H3_READGPA) {
        if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(H3_READGPA_IN) ||
            s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(H3_READGPA_OUT)) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            H3_READGPA_IN q = *(H3_READGPA_IN *)Irp->AssociatedIrp.SystemBuffer;
            H3_READGPA_OUT *o = (H3_READGPA_OUT *)Irp->AssociatedIrp.SystemBuffer;
            ULONG64 acc = 0;
            UCHAR data[16] = {0};
            ULONG hv = H3ReadGpa(q.PartitionId, q.Gpa, q.ByteCount, data, &acc);
            RtlZeroMemory(o, sizeof(*o));
            o->HvStatus = hv;
            o->AccessResult = acc;
            RtlCopyMemory(o->Data, data, 16);
            info = sizeof(H3_READGPA_OUT);
        }
    } else if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
               s->Parameters.DeviceIoControl.IoControlCode == IOCTL_H3_CALL) {
        if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(H3_CALL_IN) ||
            s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(H3_CALL_OUT)) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            H3_CALL_IN   q = *(H3_CALL_IN *)Irp->AssociatedIrp.SystemBuffer;
            ULONG callCode = (ULONG)(q.Control & 0xFFFF);
            if (callCode != HvCallGetVpRegisters && callCode != HvCallSetVpRegisters) {
                st = STATUS_INVALID_DEVICE_REQUEST;
            } else {
                H3_CALL_OUT *o = (H3_CALL_OUT *)Irp->AssociatedIrp.SystemBuffer;
                UCHAR raw[64];
                ULONG64 rr = H3Call(&q, raw);
                RtlZeroMemory(o, sizeof(*o));
                o->RawResult = rr;
                o->Poison = H3_POISON;
                RtlCopyMemory(o->Out, raw, 64);
                info = sizeof(H3_CALL_OUT);
            }
        }
    } else if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
               s->Parameters.DeviceIoControl.IoControlCode == IOCTL_H3_VIDTRANSLATE) {
        if (s->Parameters.DeviceIoControl.InputBufferLength < sizeof(H3_VIDTRANSLATE_IN) ||
            s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(H3_VIDTRANSLATE_OUT)) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            H3_VIDTRANSLATE_IN q = *(H3_VIDTRANSLATE_IN *)Irp->AssociatedIrp.SystemBuffer;
            H3VidTranslate(&q, (H3_VIDTRANSLATE_OUT *)Irp->AssociatedIrp.SystemBuffer);
            info = sizeof(H3_VIDTRANSLATE_OUT);
        }
    } else if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
               s->Parameters.DeviceIoControl.IoControlCode == IOCTL_H3_MEMREAD) {
        /* Exactly one request in.  The whole output is zeroed first, so nothing but the bytes
           read follows the answer, whatever the system buffer held before. */
        if (s->Parameters.DeviceIoControl.InputBufferLength != sizeof(H3_MEM_REQUEST)) {
            st = STATUS_INFO_LENGTH_MISMATCH;
        } else if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(H3_MEM_READ_OUT)) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            H3_MEM_REQUEST q = *(H3_MEM_REQUEST *)Irp->AssociatedIrp.SystemBuffer;
            H3_MEM_READ_OUT *out = (H3_MEM_READ_OUT *)Irp->AssociatedIrp.SystemBuffer;
            RtlZeroMemory(out, sizeof(*out));
            H3MemPage(&q, NULL, &out->Answer, out->Data);
            info = sizeof(H3_MEM_READ_OUT);
        }
    } else if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
               s->Parameters.DeviceIoControl.IoControlCode == IOCTL_H3_MEMWRITE) {
        /* The request and exactly its Length bytes, no more and no fewer. */
        ULONG in = s->Parameters.DeviceIoControl.InputBufferLength;
        PUCHAR buffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        if (in < sizeof(H3_MEM_REQUEST) ||
            in > sizeof(H3_MEM_REQUEST) + H3_VID_PAGE_BYTES ||
            in != sizeof(H3_MEM_REQUEST) + ((H3_MEM_REQUEST *)buffer)->Length) {
            st = STATUS_INFO_LENGTH_MISMATCH;
        } else if (s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(H3_MEM_ANSWER)) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            H3_MEM_REQUEST q = *(H3_MEM_REQUEST *)buffer;
            H3MemPage(&q, buffer + sizeof(H3_MEM_REQUEST), (H3_MEM_ANSWER *)buffer, NULL);
            info = sizeof(H3_MEM_ANSWER);
        }
    } else if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        st = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = st;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

static void H3Unload(PDRIVER_OBJECT Driver)
{
    /* FIRST. If Hyper-V still points at H3ChainedRoutine when this image
       goes away, the next intercept calls into freed code -- a HOST bug
       check arriving long after the run looked clean. */
    H3UnchainAll();

    UNICODE_STRING link;
    RtlInitUnicodeString(&link, H3_SYMLINK_NAME);
    IoDeleteSymbolicLink(&link);
    if (g_Device) IoDeleteDevice(g_Device);
    if (g_InputVa)  MmFreeContiguousMemory(g_InputVa);
    if (g_OutputVa) MmFreeContiguousMemory(g_OutputVa);
    UNREFERENCED_PARAMETER(Driver);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING Registry)
{
    UNICODE_STRING devName, linkName, fnName;
    PHYSICAL_ADDRESS lo, hi, boundary;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(Registry);

    RtlInitUnicodeString(&fnName, L"HvlInvokeHypercall");
    g_HvlInvokeHypercall =
        (PFN_HVL_INVOKE_HYPERCALL)MmGetSystemRoutineAddress(&fnName);
    if (!g_HvlInvokeHypercall) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "h3probe: HvlInvokeHypercall not resolvable\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Hypercall input/output must be 8-byte aligned and must not cross a page
       boundary; a page-aligned contiguous page satisfies both. */
    lo.QuadPart = 0;
    hi.QuadPart = (LONGLONG)0xFFFFFFFFFFFFFFFFULL;
    boundary.QuadPart = 0;
    g_InputVa  = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lo, hi, boundary, MmCached);
    g_OutputVa = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lo, hi, boundary, MmCached);
    if (!g_InputVa || !g_OutputVa) {
        H3Unload(Driver);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_InputPa  = MmGetPhysicalAddress(g_InputVa).QuadPart;
    g_OutputPa = MmGetPhysicalAddress(g_OutputVa).QuadPart;
    ExInitializeFastMutex(&g_HypercallMutex);

    RtlInitUnicodeString(&devName, H3_DEVICE_NAME);
    /* SYSTEM and Administrators only. Every control code is FILE_ANY_ACCESS, so any handle at all
       can issue them, and IoCreateDevice's default descriptor gave Everyone read/write: measured
       2026-10-31, a medium-integrity token with Administrators disabled opened the device and
       reached H3Dispatch. FILE_DEVICE_SECURE_OPEN applies the descriptor to an open of a path
       under the device too. Without it \\.\H3Probe\x skipped the check, which the same
       measurement showed with the descriptor tightened at runtime. */
    st = IoCreateDeviceSecure(Driver, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                              FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, &H3_DEVICE_CLASS, &g_Device);
    if (!NT_SUCCESS(st)) { H3Unload(Driver); return st; }

    RtlInitUnicodeString(&linkName, H3_SYMLINK_NAME);
    st = IoCreateSymbolicLink(&linkName, &devName);
    if (!NT_SUCCESS(st)) { H3Unload(Driver); return st; }

    Driver->MajorFunction[IRP_MJ_CREATE]         = H3Dispatch;
    Driver->MajorFunction[IRP_MJ_CLOSE]          = H3Dispatch;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = H3Dispatch;
    Driver->DriverUnload = H3Unload;

    /* S5q. Both steps are non-fatal: this driver's existing gates do not need
       winhvr, and a probe that reports "resolved 6 of 8" is worth more to the
       operator than one that refuses to load. Every consumer checks its pointer. */
    {   /* Push-lock pair, so the partition table is read the way winhvr reads it. */
        UNICODE_STRING n;
        RtlInitUnicodeString(&n, L"ExAcquirePushLockSharedEx");
        g_ExAcquirePushLockSharedEx =
            (PFN_EX_ACQ_PUSH_SHARED)MmGetSystemRoutineAddress(&n);
        RtlInitUnicodeString(&n, L"ExReleasePushLockSharedEx");
        g_ExReleasePushLockSharedEx =
            (PFN_EX_REL_PUSH_SHARED)MmGetSystemRoutineAddress(&n);
    }

    st = AuxKlibInitialize();
    if (NT_SUCCESS(st)) {
        H3ResolveWinHv();
    } else {
        g_ResolveStatus = st;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "h3probe: AuxKlibInitialize failed 0x%08X\n", st);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "h3probe: loaded, HvlInvokeHypercall=%p inPa=0x%llX outPa=0x%llX\n",
               g_HvlInvokeHypercall, g_InputPa, g_OutputPa);
    return STATUS_SUCCESS;
}
