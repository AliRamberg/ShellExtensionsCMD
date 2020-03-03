#ifndef UTIL_H
#define UTIL_H

#define UNICODE
#define _UNICODE

#define OUT_MSG(x) std::wcout << TEXT("[+]\t") << x << std::endl;
#define OUT_ERR(x, err) std::wcout << TEXT("[!]\t") << x << TEXT(", error code ") << err << std::endl;

#include <Windows.h>

VOID ErrorCheck(LSTATUS ErrorCode);
DWORD ErrorMessage(LSTATUS ErrorCode);

#endif /* UTIL_H */