#include "driver_control.h"
#include <stdio.h>

BOOL LoadNTDriver(LPCWSTR lpszDriverName, LPCWSTR lpszDriverPath)
{
    WCHAR szDriverImagePath[MAX_PATH];
    GetFullPathName(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);
    BOOL bRet = FALSE;
    SC_HANDLE hServiceMgr = NULL;
    SC_HANDLE hServiceDDK = NULL;
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == NULL) {
        bRet = FALSE;
        goto BeforeLeave;
    }
    hServiceDDK = CreateService(hServiceMgr,
        lpszDriverName, 
        lpszDriverName, 
        SERVICE_ALL_ACCESS, 
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, 
        SERVICE_ERROR_IGNORE, 
        szDriverImagePath, 
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    bRet = StartService(hServiceDDK, NULL, NULL);
    if (ERROR_SERVICE_EXISTS != (ULONGLONG)hServiceDDK) {
        bRet = TRUE;
    }
BeforeLeave:
    if (hServiceDDK) {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr) {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;
}

HANDLE InitializeDriver()
{
    //get current path
    WCHAR driver_path[MAX_PATH] = { 0 };
    GetCurrentDirectory(MAX_PATH, driver_path);
    wcscat_s(driver_path, L"\\AntiProtect.sys");
    if (FALSE == LoadNTDriver(L"AntiProtect", driver_path)) {
        printf("load driver is error\n");
        return 0;
    }
    HANDLE hDevice = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hDevice)
    {
        printf("Can't create this Device.\r\n");
        return 0;
    }
    return hDevice;
}

HANDLE DriverDupHandle(HANDLE hDevice, HANDLE pid, HANDLE SourceHandle) 
{
    DWORD dwRet = NULL;
    UCHAR outbuff[20] = { 0 };
    IRPData data = { 0 };
    data.pid = pid;
    /*data.SourceProcessHandle = SourceProcessHandle;*/
    data.SourceHandle = SourceHandle;
    DeviceIoControl(hDevice, IOCTL_TEST_DUPHANDLE, &data, sizeof(data), (LPVOID)outbuff, 20, &dwRet, NULL);  // message 1
    return *(PHANDLE)outbuff;
}

DWORD DriverKillProcessCallBack(HANDLE hDevice)
{
    DWORD dwRet = NULL;
    UCHAR outbuff[20] = { 0 };
    IRPData data = { 0 };
    DeviceIoControl(hDevice, IOCTL_TEST_SKIPCALLBACK, &data, sizeof(data), (LPVOID)outbuff, 20, &dwRet, NULL);  
    return GetLastError();
}

DWORD DriverKillPPL(HANDLE hDevice)
{
    DWORD dwRet = NULL;
    UCHAR outbuff[20] = { 0 };
    IRPData data = { 0 };
    DeviceIoControl(hDevice, IOCTL_TEST_KILLPPL, &data, sizeof(data), (LPVOID)outbuff, 20, &dwRet, NULL);
    return GetLastError();
}

DWORD DriverEnumPspCidTable(HANDLE hDevice)
{
    DWORD dwRet = NULL;
    UCHAR outbuff[20] = { 0 };
    IRPData data = { 0 };
    DeviceIoControl(hDevice, IOCTL_TEST_ENUMPSPCIDTABLE, &data, sizeof(data), (LPVOID)outbuff, 20, &dwRet, NULL);
    return GetLastError();
}