/**
 * Enable CMD shell from current directory
 * and some other security functions for to have
 * @Ali                             05/02/2020
 */

#include "Util.hpp"
#include "winapi.hpp"
#include <sddl.h>
#include <conio.h>
#include <iostream>
#include <assert.h>

BOOL static RegOpenKeyAlt(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, PHKEY phkResult);
int static EnableShellCMD(LPCWSTR key);

int wmain()
{
    LPCWSTR Directories = TEXT("Directory\\shell\\cmd");
    LPCWSTR Background = TEXT("Directory\\Background\\shell\\cmd");

    std::wcout << "\n<<<< Setting CMD Shell Extension For Directory >>>>\n"
               << std::endl;
    if (EnableShellCMD(Directories))
        OUT_ERR("EnableShellCMD failed on directory", -1)

    std::wcout << std::endl
               << std::endl;

    std::wcout << "<<<< Setting CMD Shell Extension For Backgrounds >>>>\n"
               << std::endl;

    if (EnableShellCMD(Background))
        OUT_ERR("EnableShellCMD failed on background", -1)
    std::wcout << std::endl
               << std::endl;

    std::wcout << "CMD is available on every directory on this machine\n"
               << std::endl;
    return EXIT_SUCCESS;
}

int EnableShellCMD(LPCWSTR key)
{
    HKEY RegKey;
    DWORD dwErr;
    LSTATUS r;

    // Allowing current process taking ownership of objects
    OUT_MSG("Checking for SeTakeOwnershipName privilege")
    if (!(IsPrivilegeEnabled(NULL, SE_TAKE_OWNERSHIP_NAME) || SetPrivilege(SE_TAKE_OWNERSHIP_NAME)))
    {
        dwErr = GetLastError();
        OUT_ERR("Failed to enable SeTakeOwnershipName privilege", dwErr)
        return dwErr;
    }

    /* Open Registry Key */
    OUT_MSG("Trying to open Registry key with READ_CONTROL, KEY_QUERY_VALUE, WRITE_OWNER")
    RegOpenKeyAlt(HKEY_CLASSES_ROOT, key, KEY_QUERY_VALUE | READ_CONTROL | WRITE_OWNER, &RegKey);

    DWORD pvData_ShowValue;
    DWORD pvData_HideValue;
    DWORD dwSize = sizeof(DWORD);

    std::wcout << std::endl;
    OUT_MSG("Reading 'ShowBasedOnVelocityId' value")
    RegGetValue(RegKey, NULL, (LPCWSTR)TEXT("ShowBasedOnVelocityId"), RRF_RT_REG_DWORD | RRF_ZEROONFAILURE, NULL, (PVOID)&pvData_ShowValue, &dwSize);
    std::wcout << "\tShowBasedOnVelocityId: " << pvData_ShowValue << std::endl;
    OUT_MSG("Reading 'HideBasedOnVelocityId' value")
    RegGetValue(RegKey, NULL, (LPCWSTR)TEXT("HideBasedOnVelocityId"), RRF_RT_REG_DWORD | RRF_ZEROONFAILURE, NULL, (PVOID)&pvData_HideValue, &dwSize);
    std::wcout << "\tHideBasedOnVelocityId: " << pvData_HideValue << std::endl;

    /* if HideBasedOnVelocityId */
    if (pvData_HideValue)
    {
        /*                   **** Change Permissions ****                   */
        /*               Getting ownership of the registry key              */
        PTOKEN_OWNER pTokenOwner = nullptr;
        HANDLE hProcessToken;
        LPWSTR StringSid;

        /* Get current process token owner */
        hProcessToken = GetCurrentProcessToken();
        GetTokenOwner(hProcessToken, &pTokenOwner);

        /* Check Current Owner of Key */
        OUT_MSG("Checking current owner of key")
        if (!RegGetKeyOwner(RegKey, pTokenOwner))
        {
            OUT_MSG("Setting current process owner as the owner of the registry key")
            if (RegSetKeyOwner(RegKey, pTokenOwner))
            {
                dwErr = GetLastError();
                OUT_ERR("Setting registry key ownership failed", dwErr)
                RegCloseKey(RegKey);

                return dwErr;
            }
        }

        ConvertSidToStringSid(pTokenOwner->Owner, &StringSid);
        std::wcout << TEXT("\tCurrent process owner: ") << StringSid << std::endl;
        LocalFree(StringSid);
        StringSid = NULL;

        /* Reopen the RegKey with WRITE_DAC */
        RegCloseKey(RegKey);
        OUT_MSG("Reopening Registry key with READ_CONTROL and WRITE_DAC")
        RegOpenKeyAlt(HKEY_CLASSES_ROOT, key, READ_CONTROL | WRITE_DAC, &RegKey);

        /*           Setting ACE of registry key to Full Control           */
        if (!RegSetKeyACE(RegKey, pTokenOwner->Owner))
        {
            HeapFree(GetProcessHeap(), 0, (LPVOID)pTokenOwner);
            RegCloseKey(RegKey);
            return EXIT_FAILURE;
        }
        HeapFree(GetProcessHeap(), 0, (LPVOID)pTokenOwner);

        /*           Change Value Name           */
        /* Reopen RegKey with KEY_SET_VALUE */
        RegCloseKey(RegKey);
        OUT_MSG("Reopening Registry key with KEY_SET_VALUE")
        RegOpenKeyAlt(HKEY_CLASSES_ROOT, key, READ_CONTROL | KEY_SET_VALUE, &RegKey);

        std::wcout << std::endl;
        OUT_MSG("Setting new value ShowBasedOnVelocityId")
        RegSetValueEx(RegKey, (LPCWSTR)TEXT("ShowBasedOnVelocityId"), 0, REG_DWORD, (BYTE *)&pvData_HideValue, sizeof(pvData_HideValue));
        OUT_MSG("Deleting old value HideBasedOnVelocityId")
        RegDeleteValue(RegKey, (LPCWSTR)TEXT("HideBasedOnVelocityId"));

        /* **** Change Permissions Back **** */
        RegCloseKey(RegKey);
        OUT_MSG("Reopening Registry key with WRITE_OWNER")
        RegOpenKeyAlt(HKEY_CLASSES_ROOT, key, READ_CONTROL | WRITE_OWNER, &RegKey);
        RegSetKeyDefaults(RegKey);
    }

    std::wcout << TEXT("\nRegistry is configured correctly on current key.\nYou can open cmd.exe shell from every directory!") << std::endl;

    /* Exit */
    OUT_MSG("Closing registry key")
    RegCloseKey(RegKey);

    return EXIT_SUCCESS;
}

/* return the permissions - removing the setvalue and the ownership - maybe */
BOOL BackToNormal(HKEY hKey)
{
    return TRUE;
}

/* Cleaner way to open registry keys; just because */
BOOL static RegOpenKeyAlt(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, PHKEY phkResult)
{
    LSTATUS r;
    if ((r = RegOpenKeyEx(hKey, lpSubKey, 0, samDesired, phkResult)))
    {
        OUT_ERR("Failed to open the requested key", r)
        if (r == ERROR_ACCESS_DENIED)
        {
            OUT_ERR("Run the process again as administrator", r)
            return r;
        }
    }
    return TRUE;
}