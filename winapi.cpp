#define UNICODE
#define MAX_NAME 256

// Windows
#include <Windows.h>
#include <sddl.h>
#include <accctrl.h> // EXPLICIT_ACCESS struct
#include <AclAPI.h>  // SetEntriesInAcl

// Other sutff
#include <cstdio>
#include <conio.h>
#include <iostream>
#include <iomanip>
#include <strsafe.h>
#include <assert.h> // DEBUG

#include "Util.hpp"

BOOL static CreateAbsoluteSD(PSECURITY_DESCRIPTOR pSD, SECURITY_DESCRIPTOR **pAbsoluteSD);
VOID static FreeAbsoluteSD(SECURITY_DESCRIPTOR *pAbsoluteSD);

BOOL GetAccountFromSID(PSID pSid)
{
    LPWSTR lpName = NULL;
    LPWSTR lpDomain = NULL;
    DWORD dwSizeName = 0;
    DWORD dwSizeDomain = 0;
    SID_NAME_USE peUse;
    BOOL bRet = TRUE;

    LookupAccountSid(NULL, pSid, lpName, (LPDWORD)&dwSizeName, lpDomain, (LPDWORD)&dwSizeDomain, &peUse);
    BOOL dwRetError = GetLastError();

    if (dwRetError == ERROR_INSUFFICIENT_BUFFER)
    {
        lpName = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TCHAR) * dwSizeName);
        lpDomain = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TCHAR) * dwSizeDomain);
        if (!(lpName && lpDomain))
            return FALSE;
        LookupAccountSid(NULL, pSid, lpName, (LPDWORD)&dwSizeName, lpDomain, (LPDWORD)&dwSizeDomain, &peUse);
        dwRetError = GetLastError();
        if (dwRetError != ERROR_INSUFFICIENT_BUFFER)
        {
            printf("LookupAccountSid Failed: %d\n", dwRetError);
            bRet = FALSE;
        }
    }
    else if (dwRetError == ERROR_NONE_MAPPED)
    {
        // The SID is not in the current machine
        std::wcout << L"NO_DOMAIN\\NO_NAME";
        return FALSE;
    }
    else
    {
        printf("LookupAccountSid failed, error code %u\n", dwRetError);

        return FALSE;
    }
    std::wstring wDomain(lpDomain);
    std::wstring wName(lpName);
    std::wcout << wDomain + L'\\' + wName;

    HeapFree(GetProcessHeap(), 0, lpName);
    HeapFree(GetProcessHeap(), 0, lpDomain);
    lpName = nullptr;
    lpDomain = nullptr;

    return bRet;
}

BOOL GetTokenOwner(HANDLE TokenHandle, PTOKEN_OWNER *pTokenOwner)
{
    DWORD dwSize;

    if (!GetTokenInformation(TokenHandle, TokenOwner, NULL, 0, &dwSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        *pTokenOwner = (PTOKEN_OWNER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (!pTokenOwner)
            return FALSE;
        if (!GetTokenInformation(TokenHandle, TokenOwner, (LPVOID)*pTokenOwner, dwSize, (PDWORD)NULL))
        {
            HeapFree(GetProcessHeap(), 0, pTokenOwner);
            pTokenOwner = nullptr;
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief  Setting privilege on the current process token
 * @param  lpSE_PRIVILEGE: the privilege to enable, use the SE_* macros
 * @retval TRUE if the operation was successful
 */
BOOL SetPrivilege(LPCWSTR lpSE_PRIVILEGE)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, lpSE_PRIVILEGE, &luid))
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    OUT_MSG("Setting SeTakeOwnershipName privilege")
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief  Checking if the requested privilege is enabled in the hToken. 
 * 
 * @param  hToken: Handle to an open process token. if NULL the check is performed on the current process token
 * @param  lpSE_PRIVILEGE: A privilege to check. Use the SE_* macros
 * @retval TRUE if the privilege is enabled
 */
BOOL IsPrivilegeEnabled(HANDLE hToken, LPCWSTR lpSE_PRIVILEGE)
{
    BOOL bRet;
    DWORD dwSize;
    PRIVILEGE_SET ps;

    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpSE_PRIVILEGE, &luid))
        return FALSE;

    ps.PrivilegeCount = 1;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    ps.Privilege[0].Luid = luid;
    ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!(hToken || OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)))
    {
        return FALSE;
    }

    PrivilegeCheck(hToken, &ps, (LPBOOL)&bRet);

    return bRet;
}

/**
 * @brief  Creates a copy of the security descriptor of a registry key
 *         the new SD hold information of the key's Owner, Group, DACL and SACL
 *         ! must use HeapFree to free the sd
 * 
 * @param  hKey: one of the main Registry hives
 * @param  lpSubkey: registry sub key path
 * @param  pSD: pointer to a PSECURITY_DESCRIPTOR buffer that will fill with the required security information
 * @retval TRUE if the new SD is a valid SD and contains all the information above; FALSE otherwise
 */
BOOL GetKeySecurityDescriptor(HKEY hKey, LPCWSTR lpSubkey, PSECURITY_DESCRIPTOR *pSD)
{
    HKEY hRegKey;
    DWORD dwRetval, dwSize = 0;
    PSECURITY_DESCRIPTOR pTempSD = nullptr;

    SECURITY_INFORMATION siRequiredInfo = (SECURITY_INFORMATION)OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

    // Check for SE_SECURITY_NAME privilege on current process
    // tries to enable this privilege if possible
    if (!(IsPrivilegeEnabled(NULL, SE_SECURITY_NAME) || SetPrivilege(SE_SECURITY_NAME)))
    {
        printf("SE_SECURITY_NAME privilege required for SACL query\nTry running as administrator\n");
        return FALSE;
    }

    // Open Key
    if (RegOpenKeyEx(hKey, lpSubkey, 0, READ_CONTROL | ACCESS_SYSTEM_SECURITY, &hRegKey))
    {
        printf("RegOpenKeyEx failed, error code %u\n", dwRetval = GetLastError());
        if (dwRetval == ERROR_NOT_ALL_ASSIGNED)
            printf("Try running as administrator\n");
        return FALSE;
    }

    // Get a copy of the registry key security descriptor
    if (RegGetKeySecurity(hRegKey, siRequiredInfo, NULL, (LPDWORD)&dwSize) == ERROR_INSUFFICIENT_BUFFER) // Should fail, used to determine the required size for the allocation of pSD;
    {
        pTempSD = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        dwRetval = RegGetKeySecurity(hRegKey, siRequiredInfo, pTempSD, (LPDWORD)&dwSize);
        if (!dwRetval && IsValidSecurityDescriptor(pTempSD))
        {
            printf("Created a copy of the security descriptor of the required key\n");
            *pSD = pTempSD;
            RegCloseKey(hRegKey);
            return TRUE;
        }
    }

    printf("RegGetKeySecurity failed, error code %u\n", dwRetval);

    if (pTempSD)
        HeapFree(GetProcessHeap(), 0, pTempSD);
    RegCloseKey(hRegKey);

    return FALSE;
}

/**
 * @brief  Checks if the current owner of hKey is the same of pTokenOwner
 * @param  hKey: The registry to check ownership against
 * @param  pTokenOwner: PSID to compare owner SID againt
 * @retval TRUE if the current owner is the same as pTokenOwner
 */
BOOL RegGetKeyOwner(HKEY hKey, PTOKEN_OWNER pTokenOwner)
{
    PSECURITY_DESCRIPTOR pSd;
    LSTATUS r;
    DWORD dwRes, dwSize = 0;
    PSID Owner = NULL;
    BOOL fOwnerExists = FALSE;

    /* Get SD from registry key */
    if (r = RegGetKeySecurity(hKey, OWNER_SECURITY_INFORMATION, NULL, (LPDWORD)&dwSize))
    {
        if (r != ERROR_INSUFFICIENT_BUFFER)
            return FALSE;
        pSd = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        dwRes = RegGetKeySecurity(hKey, OWNER_SECURITY_INFORMATION, pSd, (LPDWORD)&dwSize);
        if (dwRes)
        {
            printf("RegGetKeySecurity failed, error code %u\n", dwRes);
            HeapFree(GetProcessHeap(), 0, pSd);
            return FALSE;
        }
    }

    /* Get owner of registry key from SD  */
    if (!GetSecurityDescriptorOwner(pSd, &Owner, &fOwnerExists))
    {
        HeapFree(GetProcessHeap(), 0, pSd);
        printf("GetSecurityDescriptorOwner failed, error code %u\n", GetLastError());
        return FALSE;
    }

    /* compare the owner of the registy with the provided token owner */
    if (EqualSid(Owner, pTokenOwner->Owner))
    {
        HeapFree(GetProcessHeap(), 0, pSd);
        return TRUE;
    }
    HeapFree(GetProcessHeap(), 0, pSd);
    return FALSE;
}

BOOL RegSetKeyOwner(HKEY hKey, PTOKEN_OWNER pTokenOwner)
{
    LSTATUS r;
    SECURITY_DESCRIPTOR sd;

    // Initializing a valid Security Descriptor
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        printf("InitializeSecurityDescriptor failed, error code %u\n", GetLastError());
        return FALSE;
    }

    // Setting the Owner of the new SD
    if (!SetSecurityDescriptorOwner(&sd, pTokenOwner->Owner, TRUE))
    {
        printf("SetSecurityDescriptorOwner failed, error code %u\n", GetLastError());
        return FALSE;
    }

    // Setting the new owner on the registry key
    if ((r = RegSetKeySecurity(hKey, OWNER_SECURITY_INFORMATION, &sd)))
    {
        printf("RegSetKeySecurity failed, error code %u\n", r);
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief  Sets on registry key SEV_VALUE permission in ACE of the pRequiredSID 
 * @param  hKey: Opened registry key handle to adjust permissions
 * @param  pRequiredSID: Pointer to SID to set ACE with permission value
 * @retval TRUE if operation performed correctly
 */
BOOL RegSetKeyACE(HKEY hKey, PSID pRequiredSID)
{
    PSECURITY_DESCRIPTOR sd = nullptr; // Security Descriptor to store info on reg key
    DWORD dwSize = 0;                  // Size required for sd
    DWORD dwResult;                    // function return value
    PACL pAcl = nullptr;               // pointer to the acl in sd
    PACCESS_ALLOWED_ACE pAce;          // pointer to an ace in the acl
    BOOL bDaclPresent = FALSE;         // Argument for GetSecurityDescriptorDacl
    BOOL bDaclDefaulted = FALSE;       // Argument for GetSecurityDescriptorDacl
    BOOL bFound = FALSE;               // Found pRequiredSID in pAcl
    LPWSTR StringSid;                  // stores the string representation of a SID
    PSID pSid;                         // SID of ACE

    // Get the current DACL struct of the hKey
    OUT_MSG("Getting DACL from key")
    dwResult = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, NULL, &dwSize);
    if (dwResult == ERROR_INSUFFICIENT_BUFFER)
    {
        sd = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (!sd)
            return FALSE;

        if (dwResult = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, sd, (LPDWORD)&dwSize))
        {
            OUT_ERR("RegGetKeySecurity failed", dwResult)
            HeapFree(GetProcessHeap(), 0, sd);
            sd = nullptr;
            return FALSE;
        }
    }
    else
    {
        OUT_ERR("Getting DACL from key failed", dwResult)
        return dwResult;
    }

    OUT_MSG("Getting PACL from DACL")
    if (!sd || !GetSecurityDescriptorDacl(sd, &bDaclPresent, &pAcl, &bDaclDefaulted))
    {
        dwResult = GetLastError();
        OUT_ERR("GetSecurityDescriptorDacl failed", dwResult)
        HeapFree(GetProcessHeap(), 0, sd);
        return dwResult;
    }

    /* Printing all the ACEs of the key */
    wprintf(L"\n\tThere are %u ACEs\n", pAcl->AceCount);
    for (size_t i = 0; i < pAcl->AceCount; i++)
    {

        GetAce(pAcl, i, (LPVOID *)&pAce);
        pSid = &((PACCESS_ALLOWED_ACE)pAce)->SidStart;
        ConvertSidToStringSid(pSid, &StringSid);

        BOOL bSid = EqualSid(pSid, pRequiredSID);
        LPWSTR lpEntry = bSid ? L"[+]" : L"[!]";

        std::wcout << std::left << std::setfill(L' ') << lpEntry << L"\tEntry " << i + 1 << L":" << L"\t\t" << std::setw(65);
        GetAccountFromSID(pSid);
        std::wcout << std::setw(55) << StringSid << std::endl;

        LocalFree(StringSid);
        StringSid = nullptr;

        if (bSid)
            bFound = TRUE;
        if (!bFound && i == pAcl->AceCount - 1)
        {
            OUT_ERR("SID is not configured in the ACL", -1)
            return FALSE;
        }
    }

    /* if one of the aces is of the sid of Administrators */
    if (bFound)
    {
        EXPLICIT_ACCESS ea;
        PACL pNewAcl = nullptr;
        wprintf(L"\n");
        OUT_MSG("Found the required SID, trying to adjust permissions for key rename")
        SecureZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

        ea.grfAccessPermissions = KEY_SET_VALUE; // Set Value is enough to change the value name
        ea.grfAccessMode = ACCESS_MODE::GRANT_ACCESS;
        ea.grfInheritance = CONTAINER_INHERIT_ACE;

        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        ea.Trustee.ptstrName = (LPTSTR)pRequiredSID;

        OUT_MSG("Building new ACL")
        if ((dwResult = SetEntriesInAcl(1, &ea, pAcl, &pNewAcl)))
        {
            OUT_ERR("Failed to set new ACE", dwResult)
            return FALSE;
        }

        OUT_MSG("Populating temporary Security Descriptor")
        SECURITY_DESCRIPTOR pSd;

        // Initializing absolute SD
        if (!InitializeSecurityDescriptor(&pSd, SECURITY_DESCRIPTOR_REVISION))
        {
            OUT_ERR("InitializeSecurityDescriptor on pAbsoluteSD failed", GetLastError())
            HeapFree(GetProcessHeap(), 0, sd);
            return FALSE;
        }

        // Setting DACL on new SD
        if (!SetSecurityDescriptorDacl(&pSd, TRUE, pNewAcl, FALSE))
        {
            OUT_ERR("Failed to set temp SD with new ACL", GetLastError())
            HeapFree(GetProcessHeap(), 0, sd);
            return FALSE;
        }

        // Updating DACL on registry key
        OUT_MSG("Setting the permissions in the registry DACL")
        if ((dwResult = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, &pSd)))
        {
            OUT_ERR("Failed to set new ACL in registry key", dwResult)
            HeapFree(GetProcessHeap(), 0, sd);
            return FALSE;
        }
    }

    OUT_MSG("Adjusted permissions successfully on required SID")
    HeapFree(GetProcessHeap(), 0, sd);
    return TRUE;
}

/**
 * @brief  Setting the ownership of a registry key to TrustedInstaller
 * @param  hKey: the registry key to set owner, key needs to be open with WRITE_OWNER
 * @retval true if operations completed successfuly
 */
BOOL RegSetKeyDefaults(HKEY hKey)
{
    SECURITY_DESCRIPTOR sd;
    PSID pSid = nullptr;
    DWORD dwRetval, cbSid = 0;
    DWORD cchReferencedDomainName = 0;
    PSID_NAME_USE psid_name_use = nullptr;
    dwRetval = LookupAccountName(NULL, L"NT SERVICE\\TrustedInstaller", pSid, (LPDWORD)&cbSid, L"NT SERVICE", (LPDWORD)&cchReferencedDomainName, psid_name_use);
    if (!dwRetval)
    {
        std::wcout << "LookupAccountName failed, error code " << GetLastError() << std::endl;
        return FALSE;
    }
    dwRetval = SetSecurityDescriptorOwner(&sd, pSid, TRUE);
    if (!dwRetval)
    {
        std::wcout << "SetSecurityDescriptorOwner failed, error code " << GetLastError() << std::endl;
        return FALSE;
    }
    return TRUE;
}

BOOL static CreateAbsoluteSD(PSECURITY_DESCRIPTOR pSd, SECURITY_DESCRIPTOR **pAbsoluteSD)
{
    DWORD lpdwAbsoluteSecurityDescriptorSize = 0;
    DWORD lpdwDaclSize = 0;
    DWORD lpdwSaclSize = 0;
    DWORD lpdwOwnerSize = 0;
    DWORD lpdwPrimaryGroupSize = 0;
    PACL pDacl = nullptr;
    PACL pSacl = nullptr;
    PSID pOwner = nullptr;
    PSID pPrimaryGroup = nullptr;

    MakeAbsoluteSD(pSd, *pAbsoluteSD, (LPDWORD)&lpdwAbsoluteSecurityDescriptorSize, pDacl, (LPDWORD)&lpdwDaclSize, pSacl, (LPDWORD)&lpdwSaclSize, pOwner, (LPDWORD)&lpdwOwnerSize, pPrimaryGroup, (LPDWORD)&lpdwPrimaryGroupSize);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        HANDLE hProcessHeap = GetProcessHeap();
        *pAbsoluteSD = (SECURITY_DESCRIPTOR *)HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, lpdwAbsoluteSecurityDescriptorSize);
        if (!*pAbsoluteSD)
        {
            return FALSE;
        }
        pDacl = (PACL)HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, lpdwDaclSize);
        if (!pDacl)
        {
            HeapFree(hProcessHeap, 0, *pAbsoluteSD);
            return FALSE;
        }
        pSacl = (PACL)HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, lpdwSaclSize);
        if (!pSacl)
        {
            HeapFree(hProcessHeap, 0, *pAbsoluteSD);
            HeapFree(hProcessHeap, 0, pDacl);
            return FALSE;
        }
        pOwner = (PSID)HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, lpdwOwnerSize);
        if (!pOwner)
        {
            HeapFree(hProcessHeap, 0, *pAbsoluteSD);
            HeapFree(hProcessHeap, 0, pDacl);
            HeapFree(hProcessHeap, 0, pSacl);
            return FALSE;
        }
        pPrimaryGroup = (PSID)HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, lpdwPrimaryGroupSize);
        if (!pPrimaryGroup)
        {
            HeapFree(hProcessHeap, 0, *pAbsoluteSD);
            HeapFree(hProcessHeap, 0, pDacl);
            HeapFree(hProcessHeap, 0, pSacl);
            HeapFree(hProcessHeap, 0, pOwner);
            return FALSE;
        }

        if (!MakeAbsoluteSD(pSd, *pAbsoluteSD, (LPDWORD)&lpdwAbsoluteSecurityDescriptorSize, pDacl, (LPDWORD)&lpdwDaclSize, pSacl, (LPDWORD)&lpdwSaclSize, pOwner, (LPDWORD)&lpdwOwnerSize, pPrimaryGroup, (LPDWORD)&lpdwPrimaryGroupSize))
        {
            wprintf(L"Failed to make absolute SD, error code %u\n", GetLastError());
            HeapFree(hProcessHeap, 0, *pAbsoluteSD);
            HeapFree(hProcessHeap, 0, pDacl);
            HeapFree(hProcessHeap, 0, pSacl);
            HeapFree(hProcessHeap, 0, pOwner);
            HeapFree(hProcessHeap, 0, pPrimaryGroup);
            return FALSE;
        }
        return TRUE;
    }
    wprintf(L"Failed to make absolute SD, error code %u\n", GetLastError());
    return FALSE;
}

VOID static FreeAbsoluteSD(SECURITY_DESCRIPTOR *pAbsoluteSD)
{
    HANDLE hProcessHeap = GetProcessHeap();
    if (pAbsoluteSD)
    {
        if (pAbsoluteSD->Dacl)
            HeapFree(hProcessHeap, 0, pAbsoluteSD->Dacl);
        if (pAbsoluteSD->Sacl)
            HeapFree(hProcessHeap, 0, pAbsoluteSD->Sacl);
        if (pAbsoluteSD->Group)
            HeapFree(hProcessHeap, 0, pAbsoluteSD->Group);
        if (pAbsoluteSD->Owner)
            HeapFree(hProcessHeap, 0, pAbsoluteSD->Owner);
        HeapFree(hProcessHeap, 0, pAbsoluteSD);
    }
}