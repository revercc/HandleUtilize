#include "process_call_back.h"
#include "Log.h"
#include "import.h"
#include <ntifs.h>

//enum call back
NTSTATUS enum_call_back_list()
{
    POBJECT_TYPE pObject_Type = *PsProcessType;
    OB_CALLBACK_ENTRY* p_call_back_entry = (OB_CALLBACK_ENTRY*)(pObject_Type->CallbackList.Flink);
    Log("OBJECT_TYPE: %p\n", pObject_Type);
    while (p_call_back_entry != (OB_CALLBACK_ENTRY*)(&(pObject_Type->CallbackList))) {
        Log("pre callback address: %p\n", p_call_back_entry->PreOperation);
        p_call_back_entry = (OB_CALLBACK_ENTRY*)(p_call_back_entry->CallbackList.Flink);
    };
    return STATUS_SUCCESS;
}

//cut off CallbackList断链
NTSTATUS uninstall_call_back_list()
{
    POBJECT_TYPE pObject_Type = *PsProcessType;
    pObject_Type->CallbackList.Flink = &(pObject_Type->CallbackList);
    pObject_Type->CallbackList.Blink = &(pObject_Type->CallbackList);
    return STATUS_SUCCESS;
}

//set CallbackList proc is disable关闭
NTSTATUS disable_call_back_list()
{
    POBJECT_TYPE pObject_Type = *PsProcessType;
    OB_CALLBACK_ENTRY* p_call_back_entry = (OB_CALLBACK_ENTRY*)(pObject_Type->CallbackList.Flink);
    Log("OBJECT_TYPE: %p\n", pObject_Type);
    while (p_call_back_entry != (OB_CALLBACK_ENTRY*)(&(pObject_Type->CallbackList))) {
        Log("pre callback address: %p\n", p_call_back_entry->PreOperation);
        p_call_back_entry->Enabled = 0;
        p_call_back_entry = (OB_CALLBACK_ENTRY*)(p_call_back_entry->CallbackList.Flink);
    };
    return STATUS_SUCCESS;
}
