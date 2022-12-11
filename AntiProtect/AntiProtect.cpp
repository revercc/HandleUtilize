#include "AntiProtect.h"
#include "process_call_back.h"
#include "handle.h"
#include "Log.h"
#include "ppl.h"

NTSTATUS DisPathRoutine(PDEVICE_OBJECT deviceObj, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObj);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR informaiton = 0;
    PVOID inputData = NULL;
    ULONG inputDataLength = 0;
    PVOID outputData = NULL;
    ULONG outputDataLength = 0;
    PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(irp);
    inputData = irp->AssociatedIrp.SystemBuffer;
    outputData = irp->AssociatedIrp.SystemBuffer;
    inputDataLength = pStack->Parameters.DeviceIoControl.InputBufferLength; // 输入缓冲大小
    outputDataLength = pStack->Parameters.DeviceIoControl.OutputBufferLength; // 输出缓冲大小
    ULONG ulcode = (ULONG)pStack->Parameters.DeviceIoControl.IoControlCode;
    switch (ulcode)
    {
    case IOCTL_TEST_DUPHANDLE:
        outputData = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
        Status = DupProcessAccessHandle((IRPData*)inputData, (PHANDLE)outputData);
        informaiton = sizeof(HANDLE);
        break;
    case IOCTL_TEST_KILLPPL:
        Status = skip_ppl_protection();
        break;
    case IOCTL_TEST_SKIPCALLBACK:
        Status = disable_call_back_list();
        break;
    case IOCTL_TEST_ENUMPSPCIDTABLE:
        Status = enum_all_process_thread((IRPData*)irp);
        break;
    default:
        break;
    }

    irp->IoStatus.Status = Status; 
    irp->IoStatus.Information = informaiton; 
    IoCompleteRequest(irp, IO_NO_INCREMENT); 
    return Status;
}

NTSTATUS CreateRoutine(PDEVICE_OBJECT deviceObj, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObj);
    UNREFERENCED_PARAMETER(irp);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT deviceObj, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObj);
    UNREFERENCED_PARAMETER(irp);
    NTSTATUS Status = STATUS_SUCCESS;
    return Status;
}

extern "C" void DriverUnload(PDRIVER_OBJECT driver)
{
    PDEVICE_OBJECT pDev;
    pDev = driver->DeviceObject;
    IoDeleteDevice(pDev);
    UNICODE_STRING linkName;
    RtlInitUnicodeString(&linkName, LNKNAME);
    IoDeleteSymbolicLink(&linkName);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING regPath)
{
    UNREFERENCED_PARAMETER(regPath);
    driver->DriverUnload = DriverUnload;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DisPathRoutine;
    driver->MajorFunction[IRP_MJ_CREATE] = CreateRoutine;
    driver->MajorFunction[IRP_MJ_READ] = DispatchRead;
    UNICODE_STRING DevName;
    UNICODE_STRING LnkName;
    RtlInitUnicodeString(&DevName, DEVNAME);
    RtlInitUnicodeString(&LnkName, LNKNAME);
    NTSTATUS status = STATUS_SUCCESS; // STATUS_UNSUCCESSFUL
    PDEVICE_OBJECT pDevObj = NULL;
    status = IoCreateDevice(driver,
        0,
        &DevName,
        FILE_DEVICE_UNKNOWN,
        0,
        TRUE,
        &pDevObj);
    if (!NT_SUCCESS(status))
    {
        Log("Can't CreateDevice.");
        return status;
    }
    Log("CreateDevice Success.");
    pDevObj->Flags |= DO_DIRECT_IO;
    pDevObj->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&LnkName, &DevName);
    if (!NT_SUCCESS(status))
    {
        Log("Can't Create SymbolLink.");
        IoDeleteDevice(pDevObj);
        return status;
    }
    return status;
}
