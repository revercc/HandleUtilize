#pragma once
#include <ntifs.h>

NTSTATUS enum_call_back_list();

//cut off CallbackList∂œ¡¥
NTSTATUS uninstall_call_back_list();

//set CallbackList proc is disableπÿ±’
NTSTATUS disable_call_back_list();