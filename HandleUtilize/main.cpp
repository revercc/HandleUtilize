#include "main.h"
#include "driver_control.h"
#include <stdio.h>
#include <process.h>
#include <psapi.h>
#pragma comment(lib, "ntdll.lib")

HANDLE g_hEvent_Query = 0;
POBJECT_NAME_INFORMATION g_object_name = NULL;
HANDLE g_hDriver = NULL;
HANDLE g_dup_handle = NULL;

// Get a Token Privilege
int GetTokenPrivilege(LPCWSTR lpName) {
    HANDLE process_handle;
    unsigned int ret;
    HANDLE TokenHandle;
    struct _LUID Luid;
    struct _TOKEN_PRIVILEGES NewState;

    process_handle = GetCurrentProcess();
    if (!OpenProcessToken(process_handle, 0x28u, &TokenHandle) || !LookupPrivilegeValueW(0i64, lpName, &Luid))
        return 0;
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = Luid;
    NewState.Privileges[0].Attributes = 2;
    ret = AdjustTokenPrivileges(TokenHandle, 0, &NewState, 0x10u, 0i64, 0i64);
    if (ret)
    {
        if (GetLastError())
            ret = 0;
    }
    CloseHandle(TokenHandle);
    return ret;
}

//从其他进程duplication 一个句柄
int DupOtherProcessHandle(IN SYSTEM_HANDLE handle, OUT PHANDLE DUP_HANDLE) {
    if (NULL == DUP_HANDLE)  return -1;
    *DUP_HANDLE = DriverDupHandle(g_hDriver, reinterpret_cast<HANDLE>(handle.ProcessId), reinterpret_cast<HANDLE>(handle.Handle));
    if (NULL != *DUP_HANDLE) {
        return 0;
    }
    return -1;
}

int thread_name_func(void* ThrdAddr)
{
    ULONG GuessSize = 256;
    ULONG RequiredSize = 0;
    g_object_name = (POBJECT_NAME_INFORMATION)malloc(GuessSize);
    while (
        NULL != g_object_name &&
        memset(g_object_name, 0, GuessSize),
        NtQueryObject(g_dup_handle, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, g_object_name, GuessSize, &RequiredSize) == STATUS_INFO_LENGTH_MISMATCH) {
        free(g_object_name);
        GuessSize = RequiredSize;
        g_object_name = (POBJECT_NAME_INFORMATION)malloc(GuessSize);
    }
    SetEvent(g_hEvent_Query);
    return 0;
}

//获取File对象对应的handle名称（线程函数为thread_type_func，防止死锁）
int GetFileHandleName(IN HANDLE DUP_HANDLE, OUT LPWSTR object_name, OUT size_t* size)
{
    int ret = -1;
    if (NULL == object_name || NULL == size)   return -1;
    g_dup_handle = DUP_HANDLE;
    g_object_name = NULL;
    g_hEvent_Query = NULL;
    g_hEvent_Query = CreateEventW(NULL, NULL, NULL, NULL);
    if (NULL == g_hEvent_Query)  return -1;
    unsigned int ThrdAddr = 0;
    HANDLE hThread = 0;
    hThread = (HANDLE)_beginthreadex(
        NULL,
        NULL,
        (_beginthreadex_proc_type)thread_name_func,
        0,
        0,
        &ThrdAddr);
    if (NULL != hThread) {
        WaitForSingleObject(g_hEvent_Query, 1000);
        //buffer larger enough 
        if (NULL != g_object_name) {
            if (g_object_name->Name.Length <= ((*size) / 2)) {
                wcsncpy_s(object_name, (*size) / 2, g_object_name->Name.Buffer, g_object_name->Name.Length);
            }
            free(g_object_name);
            ret = 0;
        }
        CloseHandle(hThread);
    }
    CloseHandle(g_hEvent_Query);
    return ret;
}
//获取句柄类型
int GetHandleType(IN HANDLE DUP_HANDLE, OUT LPWSTR object_type, OUT size_t* size)
{
    int ret = -1;
    if (NULL == object_type || NULL == size)   return -1;

    ULONG GuessSize = 256;
    ULONG RequiredSize = 0;
    POBJECT_TYPE_INFORMATION object_type_information = (POBJECT_TYPE_INFORMATION)malloc(GuessSize);
    while (
        NULL != object_type_information &&
        memset(object_type_information, 0, GuessSize),
        NtQueryObject(DUP_HANDLE, ObjectTypeInformation, object_type_information, GuessSize, &RequiredSize) == STATUS_INFO_LENGTH_MISMATCH) {
        free(object_type_information);
        GuessSize = RequiredSize;
        object_type_information = (POBJECT_TYPE_INFORMATION)malloc(GuessSize);
    }
    if (NULL != object_type_information) {
        if (object_type_information->Name.Length <= ((*size) / 2)) {
            wcsncpy_s(object_type, (*size) / 2, object_type_information->Name.Buffer, object_type_information->Name.Length);
        }
        free(object_type_information);
        ret = 0;
    }
    return ret;
}
//获取句柄名称
int GetHandleName(IN HANDLE DUP_HANDLE, OUT LPWSTR object_name, OUT size_t* size)
{
    int ret = -1;
    if (NULL == object_name || NULL == size)   return -1;

    ULONG GuessSize = 256;
    ULONG RequiredSize = 0;
    POBJECT_NAME_INFORMATION object_name_information = NULL;
    object_name_information = (POBJECT_NAME_INFORMATION)malloc(GuessSize);
    while (
        NULL != object_name_information &&
        memset(object_name_information, 0, GuessSize),
        NtQueryObject(DUP_HANDLE, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, object_name_information, GuessSize, &RequiredSize) == STATUS_INFO_LENGTH_MISMATCH) {
        free(object_name_information);
        GuessSize = RequiredSize;
        object_name_information = (POBJECT_NAME_INFORMATION)malloc(GuessSize);
    }
    if (NULL != object_name_information) {
        if (object_name_information->Name.Length <= ((*size) / 2)) {
            wcsncpy_s(object_name, (*size) / 2, object_name_information->Name.Buffer, object_name_information->Name.Length);
        }
        free(object_name_information);
        ret = 0;
    }
    return ret;
}

//得到系统中所有句柄的信息
void __stdcall GetSystemHandleInformation()
{
    PSYSTEM_HANDLE_INFORMATION HandleInformation = NULL;
    ULONG GuessSize = 0x1000;
    ULONG RequiredSize = 0;
    // Check Guess Size
    printf("Initialize size: %d\n", GuessSize);
    HandleInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(GuessSize);
    if (NULL == HandleInformation) {
        printf("malloc is error\n");
        return;
    }
    while (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, HandleInformation, GuessSize, &RequiredSize) == STATUS_INFO_LENGTH_MISMATCH)
    {
        free(HandleInformation);
        GuessSize = RequiredSize;
        HandleInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(GuessSize);
        if (NULL == HandleInformation) {
            return;
        }
    }
    printf("new size: %d\n", GuessSize);
    for (DWORD a = 0; a < HandleInformation->HandleCount; a++)
    {
        SYSTEM_HANDLE Handle = HandleInformation->Handles[a];
        HANDLE dup_handle = NULL;
        int ret = DupOtherProcessHandle(Handle, &dup_handle);
        printf("pid:%d\n", Handle.ProcessId);
        if (0 == ret && NULL != dup_handle && INVALID_HANDLE_VALUE != dup_handle) {

            size_t name_size = 0x1000;
            size_t type_size = 0x1000;
            LPWSTR p_handle_name = (LPWSTR)malloc(name_size);
            LPWSTR p_handle_type = (LPWSTR)malloc(type_size);
            if (NULL != p_handle_name && NULL != p_handle_type) {
                memset(p_handle_name, 0, name_size);
                memset(p_handle_type, 0, type_size);
                if (0 == GetHandleType(dup_handle, p_handle_type, &type_size)) {
                    DWORD uRetLength = DWORD(name_size / 2);
                    if (!_wcsicmp(p_handle_type, L"Process")) {
                        QueryFullProcessImageName(dup_handle, 0, p_handle_name, (PDWORD) &uRetLength);
                    }
                    else if (!_wcsicmp(p_handle_type, L"Thread")) {
                        THREAD_BASIC_INFORMATION thread_information = { 0 };
                        NTSTATUS status = NtQueryInformationThread(dup_handle, (THREADINFOCLASS)ThreadBasicInformation, &thread_information, sizeof(thread_information), &uRetLength);
                        wsprintf(p_handle_name, L"pid(%p)_tid(%p)", thread_information.ClientId.UniqueProcess, thread_information.ClientId.UniqueThread);
                    }
                    else if (!_wcsicmp(p_handle_type, L"token")) {
                        PSID TokenInformation[0x100] = { 0 };
                        GetTokenInformation(dup_handle, TokenUser, TokenInformation, sizeof(PVOID) * 0x100, &uRetLength);
                        WCHAR system_name[MAX_PATH + 1] = { 0 };
                        WCHAR Name[MAX_PATH + 1] = { 0 };
                        DWORD cchName = sizeof(WCHAR) * MAX_PATH;
                        WCHAR ReferencedDomainName[MAX_PATH + 1] = { 0 };
                        DWORD cchReferencedDomainName = sizeof(WCHAR) * MAX_PATH;
                        _SID_NAME_USE peUse;
                        if (NULL != TokenInformation[0] && 
                            LookupAccountSid(system_name, TokenInformation[0], Name, &cchName, ReferencedDomainName, &cchReferencedDomainName, &peUse)) {
                            _TOKEN_STATISTICS token_statistics = { 0 };
                            GetTokenInformation(dup_handle, TokenStatistics, &token_statistics, sizeof(_TOKEN_STATISTICS), &uRetLength);
                            cchReferencedDomainName = token_statistics.AuthenticationId.LowPart;
                            wsprintf(p_handle_name, L"%ls\\%ls:%x", ReferencedDomainName, Name, cchReferencedDomainName);
                            //wsprintf_s((char *const)p_handle_name, name_size, "%ls\\%ls:%x", ReferencedDomainName, Name, cchReferencedDomainName);
                        }
                    }
                    else if (!_wcsicmp(p_handle_type, L"File")) {
                        GetFileHandleName(dup_handle, p_handle_name, &name_size);
                    }
                    else {
                        GetHandleName(dup_handle, p_handle_name, &name_size);
                    }
                    printf("pid: %d,  handle：%x,  Type：%ls,  Name：%ls,  address：%p,  GrantedAccess：%x\n",
                        Handle.ProcessId, Handle.Handle, p_handle_type, p_handle_name, Handle.Object, (DWORD)Handle.GrantedAccess);
                }
                free(p_handle_name);
                free(p_handle_type);
            }
            CloseHandle(dup_handle);
        }
    }
    return;
}
//从cross进程的句柄中得到目标进程句柄
SYSTEM_HANDLE __stdcall GetTargetHandleForCsrss(LPCWSTR target_name)
{
    PSYSTEM_HANDLE_INFORMATION HandleInformation = NULL;
    ULONG GuessSize = 0x1000;
    ULONG RequiredSize = 0;
    HANDLE csrss_pid = 0;
    DWORD session_id = 0;
    SYSTEM_HANDLE retSystemHandle = { 0 };
    WCHAR p_ApiPort_name[MAX_PATH] = { 0 };
    ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
    wsprintf(p_ApiPort_name, L"\\Sessions\\%d\\Windows\\ApiPort", session_id);
    // Check Guess Size
    HandleInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(GuessSize);
    if (NULL == HandleInformation) {
        printf("malloc is error\n");
        return retSystemHandle;
    }
    while (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, HandleInformation, GuessSize, &RequiredSize) == STATUS_INFO_LENGTH_MISMATCH)
    {
        free(HandleInformation);
        GuessSize = RequiredSize;
        HandleInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(GuessSize);
        if (NULL == HandleInformation) {
            return retSystemHandle;
        }
    }
    for (DWORD a = 0; a < (HandleInformation->HandleCount) && (retSystemHandle.ProcessId == 0); a++)
    {
        SYSTEM_HANDLE Handle = HandleInformation->Handles[a];
        HANDLE dup_handle = NULL;
        int status = DupOtherProcessHandle(Handle, &dup_handle);
        if (0 == status && NULL != dup_handle && INVALID_HANDLE_VALUE != dup_handle) {
            size_t name_size = 0x1000;
            size_t type_size = 0x1000;
            LPWSTR p_handle_name = (LPWSTR)malloc(name_size);
            LPWSTR p_handle_type = (LPWSTR)malloc(type_size);
            if (NULL != p_handle_name && NULL != p_handle_type) {
                memset(p_handle_name, 0, name_size);
                memset(p_handle_type, 0, type_size);
                //获取句柄类型
                if (0 == GetHandleType(dup_handle, p_handle_type, &type_size)) {
                    //如果是Process类型
                    if (!_wcsicmp(p_handle_type, L"Process")) {
                        DWORD uRetLength = DWORD(name_size / 2);
                        QueryFullProcessImageName(dup_handle, 0, p_handle_name, (PDWORD)&uRetLength);
                        if (0 != csrss_pid &&
                            reinterpret_cast<HANDLE>(Handle.ProcessId) == csrss_pid &&
                            !_wcsicmp(target_name, p_handle_name)) {
                            //得到当前目标进程句柄信息
                            retSystemHandle = Handle;
                        }
                    }
                    //如果是ALPC Port类型
                    else if (!_wcsicmp(p_handle_type, L"ALPC Port")) {
                        if (0 == GetHandleName(dup_handle, p_handle_name, &name_size) && 
                            !_wcsicmp(p_handle_name, p_ApiPort_name)) {
                            //得到当前会话的csrss进程pid
                            csrss_pid = reinterpret_cast<HANDLE>(Handle.ProcessId);
                        } 
                    }
                    //其他类型不做处理
                }
                free(p_handle_name);
                free(p_handle_type);
            }
            CloseHandle(dup_handle);
        }
    }
    return retSystemHandle;
}

int kill_process(const char* process_path)
{
    if (NULL == process_path)    return 0;
    WCHAR target_process[MAX_PATH] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, process_path, strlen(process_path), target_process, strlen(process_path) * 2);
    //Get SeDebugPrivilege privilege
    GetTokenPrivilege(L"SeDebugPrivilege");
    //initialize Driver
    g_hDriver = InitializeDriver();
    if (NULL != g_hDriver) {
        //patch Object回调
        DWORD error = DriverKillProcessCallBack(g_hDriver);
        if (0 != error) {
            printf("kill process_call_back is error: %d\n", error);
            return 0;
        }
        SYSTEM_HANDLE target_system_handle = GetTargetHandleForCsrss(target_process);
        if (0 == target_system_handle.ProcessId) {
            return 0;
        }
        //将cross.exe句柄表中的wegame进程句柄拷贝到自己的进程句柄表中
        HANDLE target_handle = 0;
        int ret = DupOtherProcessHandle(target_system_handle, &target_handle);
        if (0 == ret && NULL != target_handle && INVALID_HANDLE_VALUE != target_handle) {
            printf("target handle is :%p\n", target_handle);
            printf("start kill the process\n");
            system("pause");
            TerminateProcess(target_handle, 0);
            CloseHandle(target_handle);
        }
    }
    return 0;
}

int kill_ppl()
{
    DWORD ret = 0;
    GetTokenPrivilege(L"SeDebugPrivilege");
    g_hDriver = InitializeDriver();
    if (NULL != g_hDriver) {
        ret = DriverKillPPL(g_hDriver);
    }
    if (0 != ret) {
        printf("kill PPL is error:%d\n", ret);
    }
    else {
        printf("kill is successfully\n");
    }
    return ret;
}

int enum_handle_information()
{
    GetTokenPrivilege(L"SeDebugPrivilege");
    g_hDriver = InitializeDriver();
    if (NULL != g_hDriver) {
        GetSystemHandleInformation();
    }
    return 0;
}

int enum_PspCidTable()
{
    DWORD ret = 0;
    GetTokenPrivilege(L"SeDebugPrivilege");
    g_hDriver = InitializeDriver();
    if (NULL != g_hDriver) {
        ret = DriverEnumPspCidTable(g_hDriver);
    }
    if (0 != ret) {
        printf("enum PspCidTable is error:%d\n", ret);
    }
    else {
        printf("enum PspCidTable is successfully\n");
    }
    return ret;
}
int main(int argc, char *argv[], char *envp[])
{
    if (argc == 2) {
        if (!strcmp(argv[1], "-killPPL")) {
            kill_ppl();
        }
        else if (!strcmp(argv[1], "-e")) {
            enum_handle_information();
        }
        else if (!strcmp(argv[1], "-CidTable")) {
            enum_PspCidTable();
        }
        else {
            printf("-killPPL\n");
            printf("-p <process path>\n");
            printf("-e\n");
        }
    }
    else if (argc == 3){
        if (!strcmp(argv[1], "-p") ||
            strlen(argv[2]) <= MAX_PATH) {
            kill_process(argv[2]);
        }
        else {
            printf("-killPPL\n");
            printf("-p <process path>\n");
            printf("-e\n");
        }
    }
    else {
        printf("-killPPL\n");
        printf("-p <process path>\n");
        printf("-e\n");
    }
    return 0;
}