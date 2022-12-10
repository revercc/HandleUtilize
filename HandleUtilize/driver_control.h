#pragma once
#include <windows.h>
// device name:
#define DEVICE_NAME L"\\\\.\\AntiProtect"

#define IOCTL_TEST_DUPHANDLE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_TEST_SKIPCALLBACK     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_TEST_KILLPPL          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

typedef struct IRPData
{
    HANDLE SourceHandle;
    HANDLE pid;
}_IRPData, * PIRPData;

HANDLE InitializeDriver();
HANDLE DriverDupHandle(HANDLE hDevice, HANDLE pid, HANDLE SourceHandle);
DWORD DriverKillProcessCallBack(HANDLE hDevice);
DWORD DriverKillPPL(HANDLE hDevice);