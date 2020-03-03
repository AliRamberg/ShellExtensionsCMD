#include "Util.hpp"
#include <iostream>

DWORD ErrorMessage(LSTATUS ErrorCode);

VOID
ErrorCheck(LSTATUS ErrorCode)
{
    if(ErrorCode != ERROR_SUCCESS)
    {
        ErrorMessage(ErrorCode);
        ExitProcess(1);
    }
    return;
}

DWORD
ErrorMessage(LSTATUS ErrorCode)
{
    DWORD dw;
    LPVOID lpBuffer = NULL;
    if(ErrorCode == NULL)
        dw = GetLastError();
    else
        dw = ErrorCode;
    FormatMessage(
                        FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM | 
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpBuffer, 0, NULL);
    if (lpBuffer != NULL)
    {
        std::wcout << (LPTSTR) lpBuffer << std::endl;        
        LocalFree(lpBuffer);
        lpBuffer = NULL;
        return ERROR_SUCCESS;
    }
    return 0;
}
