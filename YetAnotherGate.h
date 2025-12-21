#pragma once

#define DEBUG 1
#define DEBUG_FILE 0
#define DEBUG_VECTOR 0

#define MAX_SYSCALLS 30
#define SIZE_OF_SYSCALL_CODE 64

#include <minwindef.h>

struct Sys_stb
{
    const char* function_name;
    DWORD SSN;
    size_t stubsize;
    void* pStubAddress;
    BYTE* pCleanSyscall;
};

int main_entry(Sys_stb recieved_syscallEntries[], size_t numSyscalls);

void* SysFunction(const char* function_name, ...);