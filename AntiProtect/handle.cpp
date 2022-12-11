#include "handle.h"
#include "AntiProtect.h"
#include "import.h"
#include "Log.h"
#include <ntifs.h>

HANDLE g_TargetPid = 0;
HANDLE g_TargetHandle = 0;
HANDLE g_last_pid = 0;
//从指定进程复制一个句柄
NTSTATUS DupProcessAccessHandle(IRPData* irp_data, PHANDLE pHandle)
{
    CLIENT_ID ClientId = { 0 };
    ClientId.UniqueProcess = irp_data->pid;
    ClientId.UniqueThread = 0;
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    ObjectAttributes.SecurityDescriptor = 0;
    ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    ObjectAttributes.RootDirectory = 0;
    ObjectAttributes.Attributes = 0;
    ObjectAttributes.ObjectName = 0;
    HANDLE pProcessHandle = 0;
    NTSTATUS Status = ZwOpenProcess(&pProcessHandle, PROCESS_DUP_HANDLE, &ObjectAttributes, &ClientId);
    if (NT_SUCCESS(Status)) {
        Status = ZwDuplicateObject(pProcessHandle, irp_data->SourceHandle, NtCurrentProcess(), pHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
        NtClose(pProcessHandle);
    }
    return Status;

}

//get ObFindHandleForObject proc address
NTSTATUS GetObFindHandleForObjectProcAddress(PVOID* p_proc_address)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING szObFindHandleForObject;
    RtlInitUnicodeString(&szObFindHandleForObject, L"ObFindHandleForObject");
    PVOID pObFindHandleForObject = MmGetSystemRoutineAddress(&szObFindHandleForObject);
    if (NULL != pObFindHandleForObject) {
        //get call ObFindHandleForObject
        Log("ObFindHandleForObject address is: %p", pObFindHandleForObject);
        for (int i = 0; i < 0x100; i++) {
            PVOID p_call_opcode = (UCHAR*)pObFindHandleForObject + 1;
            if (0xE8 == *((UCHAR*)pObFindHandleForObject)) {
                Log("p_call_code address is: %p\n", p_call_opcode);
                *p_proc_address = (UCHAR*)pObFindHandleForObject + 5 + *(INT*)p_call_opcode;
                status = STATUS_SUCCESS;
                break;
            }
            pObFindHandleForObject = (UCHAR*)pObFindHandleForObject + 1;
        }
    }
    return status;
}


//ExEnumHandleTable Callback proc
BOOLEAN handle_call_back(
#if !defined(_WIN7_)
    IN PHANDLE_TABLE HandleTable,
#endif
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
)
{
    ASSERT(EnumParameter);
    BOOLEAN bResult = FALSE;
    //PIRPData data = (PIRPData)EnumParameter;
    Log("handle_call_back is calling\n");
    if (Handle == g_TargetHandle) {
        Log("Find target handle \n");
        Log("handle value is : %x", Handle);
        Log("g_TargetHandle value is : %x", g_TargetHandle);
        Log("HandleTableEntry address is %p", HandleTableEntry);
        Log("current handle's GrantedAccessBits %x", HandleTableEntry->GrantedAccessBits);
        HandleTableEntry->GrantedAccessBits = PROCESS_ALL_ACCESS;
        Log("new handle's GrantedAccessBits %x", HandleTableEntry->GrantedAccessBits);
        bResult = TRUE;
    }

#if !defined(_WIN7_)
    // Release implicit locks
    _InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
    if (HandleTable != NULL && HandleTable->HandleContentionEvent)
        ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
#endif
    return bResult;
}

//通过指定进程的句柄表提升对应句柄权限
NTSTATUS increase_handle_access(PIRPData irp_data)
{
    if (NULL == irp_data)    return STATUS_UNSUCCESSFUL;
    g_TargetPid = irp_data->pid;
    g_TargetHandle = irp_data->SourceHandle;
    Log("IOCTL_TEST_INCREASE_ACCESS pid: %d, handle: %p\n", irp_data->pid, irp_data->SourceHandle);
    //Enum EPROCESS.ObjectTable by process's private handle_table)
    PEPROCESS pEprocess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)irp_data->pid, &pEprocess);
    if (NT_SUCCESS(status)) {
        ObDereferenceObject(pEprocess);
        ObReferenceProcessHandleTableProc* MyObReferenceProcessHandleTable = NULL;
        status = GetObFindHandleForObjectProcAddress((PVOID*)&MyObReferenceProcessHandleTable);
        if (NT_SUCCESS(status)) {
            Log("ObReferenceProcessHandleTableProc address :%p", MyObReferenceProcessHandleTable);
            //get Handle Table
            if (MmIsAddressValid(MyObReferenceProcessHandleTable)) {
                PHANDLE_TABLE pTable = (PHANDLE_TABLE)MyObReferenceProcessHandleTable(pEprocess);
                Log("HandleTable is :%p", pTable);
                status = ExEnumHandleTable(pTable, &handle_call_back, irp_data, NULL);
                if (status == FALSE) {
                    Log("ExEnumHandleTable is error\n");
                }
            }
        }
    }
    return status;
}

//枚举隐藏进程和线程 by PspCidTable
//get PspCidTable address
NTSTATUS GetPspCidTableAddress(PVOID* PspCidTable)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING szPsLookupProcessByProcessId;
    RtlInitUnicodeString(&szPsLookupProcessByProcessId, L"PsLookupProcessByProcessId");
    PVOID pPsLookupProcessByProcessId = MmGetSystemRoutineAddress(&szPsLookupProcessByProcessId);
    if (NULL != pPsLookupProcessByProcessId) {
        //get call PspReferenceCidTableEntry
        Log("PsLookupProcessByProcessId address is: %p", pPsLookupProcessByProcessId);
        for (int i = 0; i < 0x100; i++) {
            PVOID p_call_opcode = (UCHAR*)pPsLookupProcessByProcessId + 1;
            if (0xE8 == *(UCHAR*)pPsLookupProcessByProcessId) {
                Log("p_call_code address is: %p\n", p_call_opcode);
                PVOID pPspReferenceCidTableEntry = (UCHAR*)pPsLookupProcessByProcessId + 5 + *(INT*)p_call_opcode;
                Log("PspReferenceCidTableEntry address is: %p\n", pPspReferenceCidTableEntry);
                for (int j = 0; j < 0x100; j++) {
                    if (0x48 == *(UCHAR*)pPspReferenceCidTableEntry &&
                        0x8b == *((UCHAR*)pPspReferenceCidTableEntry + 1) &&
                        0x05 == *((UCHAR*)pPspReferenceCidTableEntry + 2)) {
                        *PspCidTable = *((PHANDLE_TABLE*)(*(ULONG*)((UCHAR*)pPspReferenceCidTableEntry + 3) + ((UCHAR*)pPspReferenceCidTableEntry + 7)));
                        status = STATUS_SUCCESS;
                        goto exit;
                    }
                    pPspReferenceCidTableEntry = (UCHAR*)pPspReferenceCidTableEntry + 1;
                }

            }
            pPsLookupProcessByProcessId = (UCHAR*)pPsLookupProcessByProcessId + 1;
        }
    }
    exit:
    return status;
}


//ExEnumHandleTable Callback proc
BOOLEAN enum_all_process_thread_call_back(
#if !defined(_WIN7_)
    IN PHANDLE_TABLE HandleTable,
#endif
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
)
{
    
    ASSERT(EnumParameter);
    BOOLEAN bResult = FALSE;

    //需要先解锁，否则PsLookupXXX函数会陷入死锁状态
#if !defined(_WIN7_)
    // Release implicit locks
    _InterlockedExchangeAdd64(&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
    if (HandleTable != NULL && HandleTable->HandleContentionEvent)
        ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
#endif

    //check hide pid/tid
    for (ULONGLONG i = (ULONGLONG)g_last_pid; i < (ULONGLONG)Handle - 4; i = i + 4) {
        Log("PID/TID:%d possible is invalid\n", i + 4);
    }

    //get handle information
    PETHREAD pThread = NULL;
    PEPROCESS pEprocess = NULL;
    if (STATUS_SUCCESS == PsLookupProcessByProcessId(Handle, &pEprocess)) {
        g_last_pid = Handle;
        Log("%s | Process ID:%d\n", PsGetProcessImageFileName(pEprocess), Handle);
    }
    else if (STATUS_SUCCESS == PsLookupThreadByThreadId(Handle, &pThread)) {
        HANDLE pid = 0;
        g_last_pid = Handle;
        pEprocess = IoThreadToProcess(pThread);
        if (MmIsAddressValid(pEprocess)) {
            pid = PsGetProcessId(pEprocess);
        }
        Log("%s | Process ID:%d | Thread ID:%d\n", PsGetProcessImageFileName(pEprocess), pid, Handle);
    }
    else {
        g_last_pid = Handle;
        Log("Handle is error:%d\n", Handle);
    }
    return bResult;
}


NTSTATUS enum_all_process_thread(PIRPData irp_data)
{
    PHANDLE_TABLE My_PspCidTable = NULL;
    Log("start enum all process and thread\n");
    NTSTATUS Status = GetPspCidTableAddress((PVOID*) &My_PspCidTable);
    if (!NT_SUCCESS(Status)) {
        Log("get PspCidTable is error\n");
        return STATUS_UNSUCCESSFUL;
    }
    Log("PspCidTable :%p\n", My_PspCidTable);
    Status = ExEnumHandleTable(My_PspCidTable, &enum_all_process_thread_call_back, irp_data, NULL);
    if (FALSE == Status) {
        Log("ExEnumHandleTable is error\n");
    }
    return Status;
}