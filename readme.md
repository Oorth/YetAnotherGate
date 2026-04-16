# YetAnotherGate
> By **Oorth**
<pre align="center">

▓██   ██▓ ▄▄▄        ▄████  ▄▄▄     ▄▄▄█████▓▓█████ 
 ▒██  ██▒▒████▄     ██▒ ▀█▒▒████▄   ▓  ██▒ ▓▒▓█   ▀ 
  ▒██ ██░▒██  ▀█▄  ▒██░▄▄▄░▒██  ▀█▄ ▒ ▓██░ ▒░▒███   
  ░ ▐██▓░░██▄▄▄▄██ ░▓█  ██▓░██▄▄▄▄██░ ▓██▓ ░ ▒▓█  ▄ 
  ░ ██▒▓░ ▓█   ▓██▒░▒▓███▀▒ ▓█   ▓██▒ ▒██▒ ░ ░▒████▒
   ██▒▒▒  ▒▒   ▓▒█░ ░▒   ▒  ▒▒   ▓▒█░ ▒ ░░   ░░ ▒░ ░
 ▓██ ░▒░   ▒   ▒▒ ░  ░   ░   ▒   ▒▒ ░   ░     ░ ░  ░
 ▒ ▒ ░░    ░   ▒   ░ ░   ░   ░   ▒    ░         ░   
 ░ ░           ░  ░      ░       ░  ░           ░  ░
 ░ ░                                                

</pre>

**Read the full technical deep dive on how this polymorphism engine works:** [Polymorphic Syscall Engine](https://arth.imbeddex.com/malware/development/Polymorphic%20Syscall%20Engine)

## Overview

Hi, this project aims on bypassing every usermode AV/EDR via using syscall trampolines and generating dynamically obsfuscated syscall stubs....
Here I am taking the SSN numbers and Address of the syscall command for every function you desire..
It will then generate a syscall stub pool in memory, and every syscall stub will look different due to their dynamically obsfuscated nature (~2000 different possible stubs)
>~~Goodluck writing static rules for that script kiddies~~

## Usage
Implimenting it in your code is also very easy, all you have to do is add these to your code ->

```markdown
    struct Sys_stb
    {
        const char* function_name;
        DWORD SSN;
        size_t stubsize;
        void* pStubAddress;
        BYTE* pCleanSyscall;
    };

    size_t numSyscalls = 0;
    syscallEntries[numSyscalls++] = {"NtWriteFile", 0, 0, nullptr, nullptr};
    syscallEntries[numSyscalls++] = {"NtCreateFile", 0, 0, nullptr, nullptr};
                                    .
                                    .
                                    .
    
    AddStubToPool(syscallEntries, numSyscalls);
```

and to call the function all you have to do is..

```markdown
    void* status = SysFunction("NtWriteFile", GetStdHandle(STD_OUTPUT_HANDLE), nullptr, nullptr, nullptr, &ioStatusBlock, buffer, length, nullptr, nullptr);
```

just pass the correct ntfunction name and, the correct parameters, it will handle the dynamic number of parameters all by itself
function returns 
```markdown
>    (void*)(~0ull);
```
if anything goes wrong and also
```markdown
>    std::cout << "Status: 0x" << std::hex << status << std::endl;
```
If you messup somewhere :)

## LIMITATION

I ASSUME WE HAVE A CLEAN UNHOOKED NTDLL.DLL, WORKING ON WAYS TO GET THE UNHOOKED NTDLL SILENTLY SOMEHOW IN AN AV/EDR INFESTED ENVIRONMENTS.
ideas are welcomed..

Currently using methods to get clean unhooked ntdll.dll ->

    1) KnownDlls  [Done as a Fallback]
    2) Blind Side [Need to code]
    3) Guard Page fault and VEH [Exploring]
        -> Guard page fault seeme like higher probability if getting flagged they, generate conspicuous exception and ETW events that many EDRs will flag, especially when placed on system-image regions [https://redops.at/en/blog/edr-analysis-leveraging-fake-dlls-guard-pages-and-veh-for-enhanced-detection]
        Some EDRs Load fake ntdll.dll and KERNEL32.dll before the original ones..... and make an vectored exception handler
    4) Single-Step Tracing (FireWalker) ->
        A more general (but heavy) method is to single-step through the hooked function and recover its original code on the fly. The FireWalker technique, for example, sets the
        CPU’s trap flag so that the processor generates an exception after each instruction, and installs a VEH to catch each trap. The handler inspects the next instruction(s) of 
        the target function: if it sees a jump (the inline hook) or other hook sequence, it follows it and keeps single-stepping until it finds the untouched syscall stub.


## The End
So people have fun stay safe, If you have further ideas go on I am all ears.

