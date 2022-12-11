#pragma once
#include "AntiProtect.h"

NTSTATUS DupProcessAccessHandle(IRPData* irp_data, PHANDLE pHandle);
NTSTATUS enum_all_process_thread(PIRPData irp_data);
typedef PVOID ObReferenceProcessHandleTableProc(PVOID);