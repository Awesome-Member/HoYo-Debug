// https://yougame.biz/threads/393246/

#include <ntifs.h>
#include <ntimage.h>

#define LOG_INFO(fmt, ...) DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " fmt "\n", __VA_ARGS__)
#define LOG_ERR(fmt,  ...) DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] " fmt "\n", __VA_ARGS__)

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize);
extern "C" PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

UNICODE_STRING HoYoKProtect_suffix = RTL_CONSTANT_STRING(L"HoYoKProtect.sys");
UNICODE_STRING mhypbase_suffix = RTL_CONSTANT_STRING(L"mhypbase.dll");
UNICODE_STRING flushBuffer_suffix = RTL_CONSTANT_STRING(L"ZwFlushWriteBuffer");

constexpr ULONG k_setInformationThread = 0x474F0;
constexpr ULONG removeProcessDebug = 0x474D0;
constexpr ULONG terminateProcess = 0x48450; // iat
constexpr ULONG wr = 0x451E0; // 40 53 48 83 EC ? 48 8B D9 48 85 C9 74 ? 48 8B 49 ? BA
static const UCHAR ret[] = { 0x48, 0x31, 0xC0, 0xC3 }; // xor rax,rax; ret
constexpr ULONG context = 0x97ED0;
constexpr ULONG mhypFlag = 0xC4EFE1; // byte_180C4EFE1 (80 3D ? ? ? ? ? 74 ? 48 8B 05 ? ? ? ? 48 85 C0 74 ? 89 50)

typedef struct _OB_CONTEXT {
    volatile UINT8 Enabled; // byte_140097ED0
    UINT8  Padding[3];
    volatile LONG RefCount;
    PVOID  RegHandle;
    PVOID  Dispatcher;
    ULONG  InitFlags;
} OB_CONTEXT, * POB_CONTEXT;

static struct z {PEPROCESS process; PVOID imageBase;}g_z;

NTSTATUS RedirectNameSlot(PVOID Base, ULONG Rva, const VOID* Value, ULONG Size, KPROCESSOR_MODE Mode)
{
    PMDL mdl = IoAllocateMdl(static_cast<PUCHAR>(Base) + Rva, 0x20, FALSE, FALSE, nullptr);
    if (mdl == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID alias = nullptr;
    BOOLEAN locked = FALSE;
    __try
    {
        MmProbeAndLockPages(mdl, Mode, IoReadAccess);
        locked = TRUE;
        alias = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
        if (alias == nullptr) { status = STATUS_INSUFFICIENT_RESOURCES; __leave; }

        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) __leave;

        RtlCopyMemory(alias, Value, Size);
        KeMemoryBarrier();
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }

    if (alias != nullptr) MmUnmapLockedPages(alias, mdl);
    if (locked) MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return status;
}

VOID unhide(PVOID Ctx) {
    auto proc = static_cast<z*>(Ctx);
    const PEPROCESS process = proc->process;
    const PVOID imageBase = proc->imageBase;
    LARGE_INTEGER tickTh{};
    tickTh.QuadPart = -2000000;

    LARGE_INTEGER tickMhy{};
    tickMhy.QuadPart = -10000;

    if (imageBase != nullptr)
    {
        char* flagAddress = (char*)((PUCHAR)imageBase + mhypFlag);

        KAPC_STATE apcState;
        KeStackAttachProcess(process, &apcState);

        __try
        {
            for (;;)
            {
                if (PsGetProcessExitStatus(process) != STATUS_PENDING) break;
                if (InterlockedCompareExchange8(flagAddress, 0, 1) == 1)
                {
                    KeMemoryBarrier();
                    LOG_INFO("Mhypbase flag address %p changed!", flagAddress);
                    break;
                }
                KeDelayExecutionThread(KernelMode, FALSE, &tickMhy);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERR("Mhypbase flag access failed: 0x%08X", GetExceptionCode());
        }
        KeUnstackDetachProcess(&apcState);
    }

    LONG off = -1;
    PETHREAD self = PsGetCurrentThread();
    UCHAR sn[0x600];
    RtlCopyMemory(sn, self, sizeof(sn));
    ZwSetInformationThread(NtCurrentThread(), ThreadHideFromDebugger, nullptr, 0);

    for (ULONG i = 0; i + 4 <= sizeof(sn); i += 4)
    {
        if ((*(PULONG)(sn + i) ^ *(volatile PULONG)(reinterpret_cast<PUCHAR>(self) + i)) == 0x4)
        {
            off = static_cast<LONG>(i); break;
        }
    }

    if (off < 0)
    {
        ObDereferenceObject(process);
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    UNICODE_STRING fn = RTL_CONSTANT_STRING(L"ZwGetNextThread");
    const auto getNextThread = reinterpret_cast<NTSTATUS(*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE)>(MmGetSystemRoutineAddress(&fn));

    HANDLE hProc = nullptr;
    if (getNextThread == nullptr || !NT_SUCCESS(ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProc)))
    {
        ObDereferenceObject(process);
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    for (;;)
    {
        if (PsGetProcessExitStatus(process) != STATUS_PENDING) break;

        HANDLE prevThread = nullptr;
        HANDLE currThread = nullptr;

        while (NT_SUCCESS(getNextThread(hProc, prevThread, THREAD_QUERY_LIMITED_INFORMATION, OBJ_KERNEL_HANDLE, 0, &currThread))) {
            PETHREAD th = nullptr;

            if (NT_SUCCESS(ObReferenceObjectByHandle(currThread, 0, *PsThreadType, KernelMode, reinterpret_cast<PVOID*>(&th), nullptr)) && th != nullptr)
            {
                *(volatile PULONG)(reinterpret_cast<PUCHAR>(th) + off) &= ~4u; 
                ObDereferenceObject(th);
            }

            if (prevThread != nullptr) ZwClose(prevThread);
            prevThread = currThread;
        }
        if (prevThread != nullptr) ZwClose(prevThread);

        KeDelayExecutionThread(KernelMode, FALSE, &tickTh);
    }

    ZwClose(hProc);
    ObDereferenceObject(process);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID ImageLoad(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
VOID EnabledProtect(PVOID ImageBase)
{
    LARGE_INTEGER tick{};
    tick.QuadPart = -10000;

    // HoYoKProtect: POB_CONTEXT Enabled 1->0
    const auto ctx = reinterpret_cast<POB_CONTEXT>(static_cast<PUCHAR>(ImageBase) + context);
    __try {
        while (ctx->Enabled != 1) KeDelayExecutionThread(KernelMode, FALSE, &tick);

        ctx->Enabled = 0;
        LOG_INFO("HoYoKProtect flag changed!");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERR("Access failed: 0x%08X", GetExceptionCode());
    }
    PsRemoveLoadImageNotifyRoutine(ImageLoad);
    PsTerminateSystemThread(STATUS_SUCCESS);
}


VOID ImageLoad(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    ProcessId;

    if (ImageInfo == nullptr || ImageInfo->ImageBase == nullptr || FullImageName == nullptr || FullImageName->Buffer == nullptr) return;
    if (!ImageInfo->SystemModeImage && FullImageName != nullptr && FullImageName->Buffer != nullptr && RtlSuffixUnicodeString(&mhypbase_suffix, FullImageName, TRUE))
    {
        LOG_INFO("Mhypbase.dll base=%p size=0x%lX", ImageInfo->ImageBase, static_cast<ULONG>(ImageInfo->ImageSize));


        // mhypbase flag 1->0
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &g_z.process)))
        {
            g_z.imageBase = ImageInfo->ImageBase;

            HANDLE swthread = nullptr;
            NTSTATUS st = PsCreateSystemThread(&swthread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, unhide, &g_z);
            if (NT_SUCCESS(st)) ZwClose(swthread);
            else { ObDereferenceObject(g_z.process); LOG_ERR("Mhypbase thread failed: 0x%08X", st); }
        }
    }

    if (ImageInfo->SystemModeImage && RtlSuffixUnicodeString(&HoYoKProtect_suffix, FullImageName, TRUE))
    {
        LOG_INFO("HoYoKProtect.sys base=%p size=0x%lX", ImageInfo->ImageBase, static_cast<ULONG>(ImageInfo->ImageSize));

        // setInformationThread/removeProcessDebug -> NtFlushWriteBuffer
        NTSTATUS status = RedirectNameSlot(ImageInfo->ImageBase, removeProcessDebug, "NtFlushWriteBuffer", sizeof("NtFlushWriteBuffer"), KernelMode);
        if (NT_SUCCESS(status)) status = RedirectNameSlot(ImageInfo->ImageBase, k_setInformationThread, "NtFlushWriteBuffer", sizeof("NtFlushWriteBuffer"), KernelMode);
        if (!NT_SUCCESS(status))
        {
            LOG_ERR("Redirect failed: 0x%08X", status); return;
        }


        // POB_CONTEXT a1 1->0
        HANDLE thread = nullptr;
        status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, EnabledProtect, ImageInfo->ImageBase);
        if (NT_SUCCESS(status)) ZwClose(thread);
        else LOG_ERR("PsCreateSystemThread failed: 0x%08X", status);

        // ZwTerminateProcess(h, 0xD84FA)
        //PVOID stub = MmGetSystemRoutineAddress(&flushBuffer_suffix);
        //if (stub != nullptr) status = RedirectNameSlot(ImageInfo->ImageBase, terminateProcess, &stub, sizeof(stub));
        if (NT_SUCCESS(status)) status = RedirectNameSlot(ImageInfo->ImageBase, wr, ret, sizeof(ret), KernelMode);

        LOG_INFO("All slots redirected!");
    }
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DriverObject;
    RegistryPath;

    NTSTATUS status = PsSetLoadImageNotifyRoutine(ImageLoad);
    if (!NT_SUCCESS(status)) {
        LOG_ERR("PsSetLoadImageNotifyRoutine failed: 0x%08X", status);
        return status;
    }
    LOG_INFO("Yay, waiting...");
    return STATUS_SUCCESS;
}
