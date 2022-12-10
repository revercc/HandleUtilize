#include <ntifs.h>
#include <stdarg.h>
#include <stdio.h>
//print log
VOID Log(_In_ PCCH Format, _In_ ...)
{
    CHAR Message[512];
    va_list VaList;
    va_start(VaList, Format);
    CONST ULONG N = _vsnprintf_s(Message, sizeof(Message) - sizeof(CHAR), Format, VaList);
    Message[N] = '\0';
    vDbgPrintExWithPrefix("[AntiProtect] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Message, VaList);
    va_end(VaList);
}