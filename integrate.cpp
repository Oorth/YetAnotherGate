// cl.exe /D_AMD64_ /EHsc .\integrate.cpp .\YetAnotherGate.cpp /link /OUT:integrate.exe
#include "YetAnotherGate.h"
#include "DbgMacros.h"
#include <windows.h>
#include <winternl.h>

bool setup_syscall_engine()
{

    Sys_stb syscallEntries[MAX_SYSCALLS];
    size_t numSyscalls = 0;

    syscallEntries[numSyscalls++] = {"NtWriteFile", 0, 0, nullptr, nullptr};
    syscallEntries[numSyscalls++] = {"NtCreateFile", 0, 0, nullptr, nullptr};

    if(!InitSyscallGate(syscallEntries, numSyscalls))
    {
        fuk("Syscall Engine error");
        return false;
    }

    return true;
}

int main()
{

    if(!setup_syscall_engine()) { fuk("Something broke while setting up syscall engine"); return 1; }

    norm(YELLOW"\n==============================================\n");

    IO_STATUS_BLOCK ioStatusBlock = {};
    char buffer[] = "!!!! Hello world :) !!!\n";
    ULONG length = sizeof(buffer) - 1;


    void* status = SysFunction("NtWriteFile", GetStdHandle(((DWORD)-11)), nullptr, nullptr, nullptr, &ioStatusBlock, buffer, length, nullptr, nullptr);
    if(status == (void*)(~0ull))
    {
        fuk("SysFunction failed\n");
        return 1;
    }

    if((NTSTATUS)uintptr_t(status) == 0) ok("NtWriteFile call successful!");
    else
    {
        fuk("NtWriteFile call failed!",", Status; 0x", std::hex, status);
        return 1;
    }

    norm(YELLOW"\n==============================================\n");

    return 0;
}