// cl.exe /EHsc .\test.cpp /link /OUT:test.exe
#include "YetAnotherGate.h"
#include <Windows.h>

struct Sys_stb
{
    const char* function_name;
    DWORD SSN;
    size_t stubsize;
    void* pStubAddress;
    BYTE* pCleanSyscall;
};

int main()
{

    size_t numSyscalls = 0;
    Sys_stb syscallEntries[MAX_SYSCALLS];


    syscallEntries[numSyscalls++] = {"NtWriteFile", 0, 0, nullptr, nullptr};

    InitSyscallGate(syscallEntries, numSyscalls);


    return 0;
}