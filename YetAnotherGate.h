#pragma once

#define DEBUG 0
#define DEBUG_FILE 0
#define DEBUG_VECTOR 0

#define MAX_SYSCALLS 30
#define SIZE_OF_SYSCALL_CODE 64

#include <minwindef.h>

struct Sys_stb
{
    const char* function_name;

    // Do not touch
    DWORD SSN;
    size_t stubsize;
    void* pStubAddress;
    BYTE* pCleanSyscall;
};

bool InitSyscallGate(Sys_stb recieved_syscallEntries[], size_t numSyscalls);

void* SysFunction(const char* function_name, ...);