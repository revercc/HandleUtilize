#pragma once
#include <ntifs.h>

NTSTATUS enum_call_back_list();

//cut off CallbackList����
NTSTATUS uninstall_call_back_list();

//set CallbackList proc is disable�ر�
NTSTATUS disable_call_back_list();