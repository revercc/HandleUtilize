#pragma once
#include "AntiProtect.h"

NTSTATUS DupProcessAccessHandle(IRPData* irp_data, PHANDLE pHandle);

typedef PVOID ObReferenceProcessHandleTableProc(PVOID);