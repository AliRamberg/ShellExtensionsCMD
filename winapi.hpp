#ifndef WINAPI_H
#define WINAPI_H

#include <Windows.h>

/* DEBUG - Converts SID to STRING, can print results */
BOOL GetAccountFromSID(PSID pSid, LPVOID *lpName, LPVOID *lpDomain);

/* Fills pTokenOwner with TokenHandle Owner; Must free when finished */
BOOL GetTokenOwner(HANDLE TokenHandle, PTOKEN_OWNER *pTokenOwner);

/* Enable Privilege on current process */
BOOL SetPrivilege(LPCWSTR lpSE_PRIVILEGE);

/* Check if privilege is enabled in hToken, current process if NULL */
BOOL IsPrivilegeEnabled(HANDLE hToken, LPCWSTR lpSE_PRIVILEGE);

/* Sets the Owner of the hKey with the TOKEN_OWNER provided; hKey needs to be open with WRITE_OWNER */
BOOL RegSetKeyOwner(HKEY hKey, PTOKEN_OWNER pTokenOwner);

/* Gets the Owner of the hKey and compare it with the provided TOKEN_OWNER */
BOOL RegGetKeyOwner(HKEY hKey, PTOKEN_OWNER pTokenOwner);

/* Fills pSD with Owner,Group,DACL,SACL of the provided registry key; Must free when finished */
BOOL GetKeySecurityDescriptor(HKEY hKey, LPCWSTR lpSubkey, PSECURITY_DESCRIPTOR *pSD);

/* Sets SET_VALUE permission for pRequiredSID for registry hKey */
BOOL RegSetKeyACE(HKEY hKey, PSID pRequiredSID);

/* Sets the Owner of the hKey back to TRUSTEDINSTALLER */
BOOL RegSetKeyDefaults(HKEY hKey);

#endif /* WINAPI_H */