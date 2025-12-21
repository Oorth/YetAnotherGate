//cl.exe /EHsc .\YetAnotherGate.cpp /link /OUT:YetAnotherGate.exe
/*

    !NEED TO ADD A WAY TO GET A CLEAN NTDLL.DLL!

    Works

    size_t numSyscalls = 0;
    syscallEntries[numSyscalls++] = {"NtWriteFile", 0, 0, nullptr, nullptr};
    syscallEntries[numSyscalls++] = {"NtCreateFile", 0, 0, nullptr, nullptr};
    
    AddStubToPool(syscallEntries, numSyscalls);
    void* status = SysFunction("NtWriteFile", GetStdHandle(STD_OUTPUT_HANDLE), nullptr, nullptr, nullptr, &ioStatusBlock, buffer, length, nullptr, nullptr);

*/

#define LEAN_AND_MEAN
// #define DEBUG 1
// #define DEBUG_FILE 0
// #define DEBUG_VECTOR 0

// #define MAX_SYSCALLS 30
// #define SIZE_OF_SYSCALL_CODE 64

#include "YetAnotherGate.h"
#include <Windows.h>
#include <winternl.h>
#include "DbgMacros.h"
#include <string>
#if DEBUG | DEBUG_FILE
#include <iomanip>
#endif


#define HEX_K 0xFF
#define X_C(c) static_cast<wchar_t>((c) ^ HEX_K)

typedef enum _SECTION_INHERIT
{
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

////////////////////////////////////////////////////////////////////////////////

wchar_t obf_Ntd_32[] = { X_C(L'n'), X_C(L't'), X_C(L'd'), X_C(L'l'), X_C(L'l'), X_C(L'.'), X_C(L'd'), X_C(L'l'), X_C(L'l'), L'\0'};
wchar_t obf_Ker_32[] = { X_C(L'k'), X_C(L'e'), X_C(L'r'), X_C(L'n'), X_C(L'e'), X_C(L'l'), X_C(L'3'), X_C(L'2'), X_C(L'.'), X_C(L'd'), X_C(L'l'), X_C(L'l'), L'\0'};
wchar_t obf_KerB[] = { X_C(L'K'), X_C(L'E'), X_C(L'R'), X_C(L'N'), X_C(L'E'), X_C(L'L'), X_C(L'B'), X_C(L'A'), X_C(L'S'), X_C(L'E'), X_C(L'.'), X_C(L'd'), X_C(L'l'), X_C(L'l'), L'\0'};
wchar_t obf_Usr_32[] = { X_C(L'u'), X_C(L's'), X_C(L'e'), X_C(L'r'), X_C(L'3'), X_C(L'2'), X_C(L'.'), X_C(L'd'), X_C(L'l'), X_C(L'l'), L'\0'};

////////////////////////////////////////////////////////////////////////////////

typedef void* (__stdcall* GenericSyscallType)(...);
void* FindExportAddress(HMODULE, const char*);
void InitUnicodeString(UNICODE_STRING& , const wchar_t*);
NTSTATUS updateFunctions();

//===============================================================================

typedef BOOL (WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID (WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD (WINAPI* pGetLastError)(VOID);
typedef HANDLE (WINAPI* pGetCurrentProcess)(VOID);
typedef NTSTATUS (NTAPI* pNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS (NTAPI* pNtClose)(HANDLE);

////////////////////////////////////////////////////////////////////////////////

#pragma region Structures

//0x58 bytes (sizeof)
typedef struct _MY_PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
} _MY_PEB_LDR_DATA, *MY_PPEB_LDR_DATA;

//0x18 bytes (sizeof)
struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red:1;                                                    //0x10
            UCHAR Balance:2;                                                //0x10
        };
        ULONGLONG ParentValue;                                              //0x10
    };
}; 

//0x120 bytes (sizeof)
typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary:1;                                         //0x68
            ULONG MarkedForRemoval:1;                                       //0x68
            ULONG ImageDll:1;                                               //0x68
            ULONG LoadNotificationsSent:1;                                  //0x68
            ULONG TelemetryEntryProcessed:1;                                //0x68
            ULONG ProcessStaticImport:1;                                    //0x68
            ULONG InLegacyLists:1;                                          //0x68
            ULONG InIndexes:1;                                              //0x68
            ULONG ShimDll:1;                                                //0x68
            ULONG InExceptionTable:1;                                       //0x68
            ULONG ReservedFlags1:2;                                         //0x68
            ULONG LoadInProgress:1;                                         //0x68
            ULONG LoadConfigProcessed:1;                                    //0x68
            ULONG EntryProcessed:1;                                         //0x68
            ULONG ProtectDelayLoad:1;                                       //0x68
            ULONG ReservedFlags3:2;                                         //0x68
            ULONG DontCallForThreads:1;                                     //0x68
            ULONG ProcessAttachCalled:1;                                    //0x68
            ULONG ProcessAttachFailed:1;                                    //0x68
            ULONG CorDeferredValidate:1;                                    //0x68
            ULONG CorImage:1;                                               //0x68
            ULONG DontRelocate:1;                                           //0x68
            ULONG CorILOnly:1;                                              //0x68
            ULONG ChpeImage:1;                                              //0x68
            ULONG ReservedFlags5:2;                                         //0x68
            ULONG Redirected:1;                                             //0x68
            ULONG ReservedFlags6:2;                                         //0x68
            ULONG CompatDatabaseProcessed:1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
} MY_LDR_DATA_TABLE_ENTRY, *MY_PLDR_DATA_TABLE_ENTRY; 

struct _LIBS
{
    HMODULE hHookedNtdll;
    HMODULE hUnhookedNtdll;
    HMODULE hKERNEL32;
    HMODULE hKERNELBASE;
    HMODULE hUsr32;
}sLibs;

typedef struct _MY_FUNCTIONS
{
    pVirtualProtect MyVirtualProtect;
    pVirtualAlloc MyVirtualAlloc;
    pGetLastError MyGetLastError;
    pNtOpenSection MyNtOpenSection;
    pGetCurrentProcess MyGetCurrentProcess;
    pNtMapViewOfSection MyNtMapViewOfSection;
    pNtClose MyNtClose;

}_MY_FUNCTIONS;
_MY_FUNCTIONS fn;

#pragma endregion

////////////////////////////////////////////////////////////////////////////////

BYTE* g_pSyscallPool = nullptr;
Sys_stb g_syscallEntries[MAX_SYSCALLS] = {};

size_t stubCount = 0, stubOffset = 0;
HMODULE hHookedNtdll = nullptr;

////////////////////////////////////////////////////////////////////////////////

int GetHookedFunctions()
{
    norm("\n=====================GetHookedFunctions()=====================");

    HMODULE kernel32Base = NULL;
    HMODULE ntdllBase = NULL;

    #ifdef _M_IX86
        PEB* pPEB = (PEB*) __readgsqword(0x30);
    #else
        PEB* pPEB = (PEB*) __readgsqword(0x60);   
    #endif
    norm("\nPEB ->", CYAN" 0x", std::hex, (void*)pPEB);
    

    MY_PPEB_LDR_DATA pLdrData = (MY_PPEB_LDR_DATA)pPEB->Ldr;
    //norm("\nLDR ->", CYAN" 0x", std::hex, (void*)pLdr);
    
    //=======================================================================
    //norm(YELLOW"\n======================================================");
    for(int i = 0; obf_Ntd_32[i] != '\0'; ++i) obf_Ntd_32[i] ^= HEX_K;
    for(int i = 0; obf_Ker_32[i] != '\0'; ++i) obf_Ker_32[i] ^= HEX_K;
    for(int i = 0; obf_KerB[i] != '\0'; ++i) obf_KerB[i] ^= HEX_K;
    for(int i = 0; obf_Usr_32[i] != '\0'; ++i) obf_Usr_32[i] ^= HEX_K;
    
    auto head = &pLdrData->InLoadOrderModuleList;
    auto current = head->Flink;    // first entry is the EXE itself
    
    // walk load‑order
    while(current != head)
    {
        auto entry = CONTAINING_RECORD(current, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if(entry->BaseDllName.Buffer)
        {
            int len = entry->BaseDllName.Length / sizeof(WCHAR);
            std::wstring name(entry->BaseDllName.Buffer, len);
            // wprintf(L"\nModule: %.*ls -> " CYAN"0x%p" RESET"", len, entry->BaseDllName.Buffer, entry->DllBase);

            size_t pos = name.find_last_of(L"\\/");
            std::wstring fileName = (pos == std::wstring::npos) ? name : name.substr(pos + 1);

            // wprintf(L"\n[DEBUG] Scanned Module: %ls", fileName.c_str());

            if(_wcsicmp(fileName.c_str(), obf_Ker_32) == 0) sLibs.hKERNEL32 = (HMODULE)entry->DllBase;
            else if(_wcsicmp(fileName.c_str(), obf_KerB) == 0) sLibs.hKERNELBASE = (HMODULE)entry->DllBase;
            else if(_wcsicmp(fileName.c_str(), obf_Ntd_32) == 0) sLibs.hHookedNtdll    = (HMODULE)entry->DllBase;
        }
        current = current->Flink;
    }

    for(size_t i = 0; i < wcslen(obf_Ntd_32); ++i) obf_Ntd_32[i] = 0;
    for(size_t i = 0; i < wcslen(obf_Ker_32); ++i) obf_Ker_32[i] = 0;
    for(size_t i = 0; i < wcslen(obf_KerB); ++i) obf_KerB[i] = 0;
    for(size_t i = 0; i < wcslen(obf_Usr_32); ++i) obf_Usr_32[i] = 0;

    //=======================================================================
    // norm(YELLOW"\n======================================================");
    #if DEBUG
        printf("\nNTDLL : " CYAN"0x%p" RESET"", sLibs.hHookedNtdll); 
        printf("\nKernel32 : " CYAN"0x%p" RESET"", sLibs.hKERNEL32);
        printf("\nKernelBASE32 : " CYAN"0x%p" RESET"", sLibs.hKERNELBASE);
    #endif
    norm(YELLOW"\n======================================================");
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    if(sLibs.hKERNEL32 == 0 || sLibs.hHookedNtdll == 0)
    {
        norm("\n");fuk("Problems with Dlls");
        return 0;
    }
    norm("\nNTDLL DOS Header Magic: ", ((IMAGE_DOS_HEADER*)sLibs.hHookedNtdll)->e_magic == 0x5A4D ? GREEN"MZ" : RED"Invalid", "\n");
    norm("KERNEL32 DOS Header Magic: ", ((IMAGE_DOS_HEADER*)sLibs.hKERNEL32)->e_magic == 0x5A4D ? GREEN"MZ" : RED"Invalid", "\n");
    norm("KERNELBASE DOS Header Magic: ", ((IMAGE_DOS_HEADER*)sLibs.hKERNELBASE)->e_magic == 0x5A4D ? GREEN"MZ" : RED"Invalid", "\n");
    norm(YELLOW"======================================================");
    
    if(!sLibs.hKERNELBASE)
    {
        fuk("hKERNELBASE is null! You never found it in PEB walk!");
        return 0;
    }//printf("\n[DEBUG] KERNELBASE handle before FindExportAddress: 0x%p", sLibs.hKERNELBASE);

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    
    fn.MyVirtualProtect = (pVirtualProtect)FindExportAddress(sLibs.hKERNELBASE, "VirtualProtect");
    if(fn.MyVirtualProtect == nullptr)
    {
        fuk("Failed to get VirtualProtect address"); return 0;
    }norm(GREEN"\t[DONE]");

    fn.MyVirtualAlloc = (pVirtualAlloc)FindExportAddress(sLibs.hKERNELBASE, "VirtualAlloc");
    if(fn.MyVirtualAlloc == nullptr)
    {
        fuk("Failed to get VirtualAlloc address"); return 0;        
    }norm(GREEN"\t[DONE]");

    fn.MyGetLastError = (pGetLastError)FindExportAddress(sLibs.hKERNELBASE, "GetLastError");
    if(fn.MyGetLastError == nullptr)
    {
        fuk("Failed to get GetLastError address"); return 0;        
    }norm(GREEN"\t[DONE]");

    fn.MyGetCurrentProcess = (pGetCurrentProcess)FindExportAddress(sLibs.hKERNELBASE, "GetCurrentProcess");
    if(fn.MyGetCurrentProcess == nullptr)
    {
        fuk("Failed to get MyGetCurrentProcess address"); return 0;        
    }norm(GREEN"\t[DONE]");  
    
    fn.MyNtOpenSection = (pNtOpenSection)FindExportAddress(sLibs.hHookedNtdll, "NtOpenSection");
    if(fn.MyNtOpenSection == nullptr)
    {
        fuk("Failed to get MyNtOpenSection address"); return 0;        
    }norm(GREEN"\t[DONE]");

    fn.MyNtMapViewOfSection = (pNtMapViewOfSection)FindExportAddress(sLibs.hHookedNtdll, "NtMapViewOfSection");
    if(fn.MyNtMapViewOfSection == nullptr)
    {
        fuk("Failed to get MyNtMapViewOfSection address"); return 0;        
    }norm(GREEN"\t[DONE]");

    fn.MyNtClose = (pNtClose)FindExportAddress(sLibs.hHookedNtdll, "NtClose");
    if(fn.MyNtClose == nullptr)
    {
        fuk("Failed to get MyNtClose address"); return 0;        
    }norm(GREEN"\t[DONE]");

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    norm("\n=====================GetHookedFunctions()=====================\n");
    return 1;
}

NTSTATUS GetUnhookedDlls_BlindSide()
{

    return 1;
}

NTSTATUS GetUnhookedDlls_KnownDlls()
{
    // I hate this method
    norm("\n----------------------GetUnhookedDlls_KnownDlls()----------------------");

    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hSection = nullptr;
    PVOID base = nullptr;
    SIZE_T viewSize = 0;

    InitUnicodeString(usName, L"\\KnownDlls\\ntdll.dll");
    InitializeObjectAttributes(&objAttr, &usName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTSTATUS status = fn.MyNtOpenSection(&hSection, SECTION_MAP_EXECUTE | SECTION_MAP_READ, &objAttr);

    if(!NT_SUCCESS(status))
    {
        fuk("NtOpenSection failed: 0x%X", status);
        return 0;
    }

    status = fn.MyNtMapViewOfSection(hSection, fn.MyGetCurrentProcess(), &base, 0, 0, nullptr, &viewSize, ViewShare, 0, PAGE_EXECUTE_READ);
    
    if(!NT_SUCCESS(status))
    {
        fuk("MyNtMapViewOfSection Failed");
        return 0;
    }
    
    fn.MyNtClose(hSection);
    
    sLibs.hUnhookedNtdll = (HMODULE)base;
    norm("\nClean ntdll.dll address via fallback (KnownDlls :/ ) -> 0x", std::hex, CYAN"", sLibs.hUnhookedNtdll);

    if(!updateFunctions()) { fuk("MyNtMapViewOfSection Failed"); return 0; }

    norm("\n----------------------GetUnhookedDlls_KnownDlls()----------------------");
    return 1;
}

NTSTATUS updateFunctions()
{
    norm("\n\n================UpdateFunctions()================");
    fn.MyNtOpenSection = (pNtOpenSection)FindExportAddress(sLibs.hUnhookedNtdll, "NtOpenSection");
    if(fn.MyNtOpenSection == nullptr)
    {
        fuk("Failed to get MyNtOpenSection address"); return 0;        
    }norm(GREEN"\t[DONE]");

    fn.MyNtMapViewOfSection = (pNtMapViewOfSection)FindExportAddress(sLibs.hUnhookedNtdll, "NtMapViewOfSection");
    if(fn.MyNtMapViewOfSection == nullptr)
    {
        fuk("Failed to get MyNtMapViewOfSection address"); return 0;        
    }norm(GREEN"\t[DONE]");

    fn.MyNtClose = (pNtClose)FindExportAddress(sLibs.hUnhookedNtdll, "NtClose");
    if(fn.MyNtClose == nullptr)
    {
        fuk("Failed to get MyNtClose address"); return 0;        
    }norm(GREEN"\t[DONE]");

    ok("Updated all the funtions");
    norm("\n================UpdateFunctions()================");

    return 1;
}

BYTE* GenerateSyscallStub(Sys_stb* sEntry)
{
    BYTE* syscall_code = new BYTE[64]();
    BYTE nop[] = {0x90}, pushf[] = {0x9c}, popf[] = {0x9d};
    size_t Generate_Syscall_Offset = 0;
    
    // memcpy(syscall_code + Generate_Syscall_Offset, pushf, sizeof(pushf));
    // ++Generate_Syscall_Offset;
    //===============================================================================================

    //Add random Nops
    for(int i = 0; i < rand() % 3; ++i)                // Add random NOPs
    {
        memcpy(syscall_code + Generate_Syscall_Offset, nop, sizeof(nop));                      
        ++Generate_Syscall_Offset;
    }

    ///////////////////////////////////////////////SSN///////////////////////////////////////////////

    // switch(9)
    switch(rand() % 3)
    {  
        case 0:                                                     // HIGH_LOW
        {   
            norm(YELLOW"in 0 [SSN] "); 

            DWORD ssn = sEntry->SSN;
            BYTE lowByte = (BYTE)(ssn & 0xFF);
            DWORD highBytes = (ssn & 0xFFFFFF00);

            BYTE temp_code[] = 
            {
                0x31, 0xC0,                                         // xor eax, eax
                0xB0, 0x00,                                         // mov al, SSN_LOW
                0x81, 0xC0, 0x00, 0x00, 0x00, 0x00                  // add eax, SSN_HIGH_SHIFTED
            };
            *(BYTE*)(temp_code + 3) = lowByte;
            *(DWORD*)(temp_code + 6) = highBytes;

            memcpy(syscall_code + Generate_Syscall_Offset, temp_code, sizeof(temp_code));           
            Generate_Syscall_Offset += sizeof(temp_code);

            break;
        }

        case 1:                                                     // ADD_RANDOM
        {
            norm(YELLOW"IN 1 [SSN] ");
            BYTE randNum = (BYTE)(rand() % 0x50);

            BYTE temp_code[] =
            {
                0xB8, 0x00, 0x00, 0x00, 0x00,                    // mov eax, X
                0x05, 0x00, 0x00, 0x00, 0x00                     // add eax, Y
            };
            *(DWORD*)(temp_code + 1) = randNum;
            *(DWORD*)(temp_code + 6) = sEntry->SSN - randNum;

            memcpy(syscall_code + Generate_Syscall_Offset, temp_code, sizeof(temp_code));           
            Generate_Syscall_Offset += sizeof(temp_code);
            
            break;
        }

        case 2:                                                     // PUSH_POP
        {   
            norm(YELLOW"IN 2 [SSN] ");
            BYTE temp_code[] =
            {
                0x9C,                                        // pushfq (save flags)
                
                0x31, 0xC0,                                   // xor eax, eax
                0x68, 0x00, 0x00, 0x00, 0x00,                   // push SSN
                0x58,                                           // pop rax (SSN -> rax)

                0x9D,                                        // popfq (restore flags)
            };
            *(DWORD*)(temp_code + 4) = sEntry->SSN;
            
            memcpy(syscall_code + Generate_Syscall_Offset, temp_code, sizeof(temp_code));           
            Generate_Syscall_Offset += sizeof(temp_code);

            break;
        }

        default:
        {   norm(YELLOW"DEFAULT [SSN] ");
            BYTE temp_code[] =
            {
                0xB8, 0x00, 0x00, 0x00, 0x00                 // mov eax, SSN
            };
            *(DWORD*)(temp_code + 1) = sEntry->SSN;

            memcpy(syscall_code + Generate_Syscall_Offset, temp_code, sizeof(temp_code));
            Generate_Syscall_Offset += sizeof(temp_code);
        
            break;
        }
    }

    //===============================================================================================
    //Add random Nops
    for(int i = 0; i < rand() % 3; ++i)                // Add random NOPs
    {
        memcpy(syscall_code + Generate_Syscall_Offset, nop, sizeof(nop));                      
        ++Generate_Syscall_Offset;
    }

    ///////////////////////////////////////////////MOV/////////////////////////////////////////////// 

    //switch(9)
    switch(rand() % 4)
    {  
        case 0:                                                     // xor and mov
        {
            norm(YELLOW"in 0 [move] ");
            BYTE tempcode[] = 
            {
                0x4D, 0x31, 0xD2,                   // xor r10, r10
                0x49, 0x89, 0xCA                    // mov r10, rcx 
            };
            memcpy(syscall_code + Generate_Syscall_Offset, tempcode, sizeof(tempcode));
            Generate_Syscall_Offset += sizeof(tempcode);
        break;
        }

        case 1:                                                     // and then move
        {
            norm(YELLOW"in 1 [move] ");

            BYTE tempcode[] = 
            {
                0x9c,                                       // pushf
                0x49, 0x81, 0xE2, 0x00, 0x00, 0x00, 0x00,   // and r10, 0
                0x49, 0x89, 0xCA,                           // mov r10, rcx
                0x9d                                        // popf
            };
            memcpy(syscall_code + Generate_Syscall_Offset, tempcode, sizeof(tempcode));
            Generate_Syscall_Offset += sizeof(tempcode);
        
            break;
        }

        case 2:                                                     // push move pop
        {   
            norm(YELLOW"in 2 [move] ");                                                                             
            BYTE tempcode[] = 
            {
                0x9c,                                       // pushf
                0x51,                                       // push rcx
                0x4C, 0x8B, 0x14, 0x24,                     // mov r10, [rsp]
                0x59,                                       // pop rcx
                0x9d                                        // popf
            };
            memcpy(syscall_code + Generate_Syscall_Offset, tempcode, sizeof(tempcode));
            Generate_Syscall_Offset += sizeof(tempcode);
        
            break;
        }

        case 3:                                                     // push xor xchg pop
        {
            norm(YELLOW"in 3 [move] ");
            BYTE tempcode[] = 
            {
                0x9c,                           // pushf
                0x51,                           // push rcx
                0x49, 0x31, 0xD2,               // xor r10, r10
                0x4C, 0x87, 0x14, 0x24,         // xchg r10, [rsp]
                0x59,                           // pop rcx
                0x9d                            // popf
            };
            memcpy(syscall_code + Generate_Syscall_Offset, tempcode, sizeof(tempcode));
            Generate_Syscall_Offset += sizeof(tempcode);
        break;
        }

        default:                                                                             
        {   norm(YELLOW"in DEFAULT [MOV] ");                                                                             

            BYTE mov_r10_rcx[] =
            {
                0x4C, 0x8B, 0xD1                                    // mov r10, rcx
            };
            
            memcpy(syscall_code + Generate_Syscall_Offset, mov_r10_rcx, sizeof(mov_r10_rcx));
            Generate_Syscall_Offset += sizeof(mov_r10_rcx);
        
            break;
        }
    }

    //===============================================================================================
    //Add random Nops
    for(int i = 0; i < rand() % 3; ++i)                // Add random NOPs
    {
        memcpy(syscall_code + Generate_Syscall_Offset, nop, sizeof(nop));                      
        ++Generate_Syscall_Offset;
    }

    ///////////////////////////////////////////////JMP/////////////////////////////////////////////// 

    //switch(9)
    switch(rand() % 3)
    {
        case 0:                                                     // push and xchg
        {   
            norm(YELLOW"in 0 [jmp] \n");
            BYTE jmp_code[] =
            {
                0x50,                                                           // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, syscall_addr
                0x48, 0x87, 0x04, 0x24,                                         // xchg rax, [rsp]
                0xC3                                                            // ret
            };
            *(UINT64*)(jmp_code + 3) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + Generate_Syscall_Offset, jmp_code, sizeof(jmp_code));
            Generate_Syscall_Offset += sizeof(jmp_code);

            break;
        }

        case 1:                                                     // Push + ret technique
        {
            norm(YELLOW"in 1 [jmp] \n");
            BYTE jmp_code[] =
            {
                0x50,                                                           // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, syscall_addr
                0x48, 0x87, 0x04, 0x24,                                         // xchg rax, [rsp]
                0xC3                                                            // ret
            };
            *(UINT64*)(jmp_code + 3) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + Generate_Syscall_Offset, jmp_code, sizeof(jmp_code));
            Generate_Syscall_Offset += sizeof(jmp_code);

            break;
        }
        
        case 2:                                                     // Using Upper and Lower bits
        {
            norm(YELLOW"in 2 [jmp] \n");
            BYTE jmp_code[] =
            {
                0x9C,                               // pushf
                0x48, 0xC7, 0x04, 0x24,             // mov dword [rsp], imm32 (lower half)
                0x00, 0x00, 0x00, 0x00,
                0xC7, 0x44, 0x24, 0x04,             // mov dword [rsp+4], imm32 (upper half)
                0x00, 0x00, 0x00, 0x00,
                //0x9D,                               // popf
                0xC3,                               // ret
            };
            
            *(DWORD*)(jmp_code + 5) = (DWORD)((UINT64)sEntry->pCleanSyscall & 0xFFFFFFFF);
            *(DWORD*)(jmp_code + 13) = (DWORD)((UINT64)sEntry->pCleanSyscall >> 32);

            memcpy(syscall_code + Generate_Syscall_Offset, jmp_code, sizeof(jmp_code));
            Generate_Syscall_Offset += sizeof(jmp_code);

            break;
        }

        default:                                                                             
        {   norm(YELLOW"in DEFAULT [JMP] ");                                                                             

            BYTE jmp_code[] =
            {
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                // jmp [rip+0]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00     // syscall address
            };
            *(UINT64*)(jmp_code + 6) = (UINT64)sEntry->pCleanSyscall;
            
            memcpy(syscall_code + Generate_Syscall_Offset, jmp_code, sizeof(jmp_code));
            Generate_Syscall_Offset += sizeof(jmp_code);

            break;
        }
    }

    //===============================================================================================

    //Add random Nops
    for(int i = 0; i < rand() % 3; ++i)                // Add random NOPs
    {
        memcpy(syscall_code + Generate_Syscall_Offset, nop, sizeof(nop));                      
        ++Generate_Syscall_Offset;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////

    // memcpy(syscall_code + Generate_Syscall_Offset, popf, sizeof(popf));
    // ++Generate_Syscall_Offset;

    sEntry->stubsize = Generate_Syscall_Offset;

    #if DEBUG
        norm("Syscall Code Contents:");
        for(int i = 0; i < SIZE_OF_SYSCALL_CODE; ++i)
        {
            if(i % 16 == 0) std::cout << YELLOW"\n" << std::hex << std::setw(4) << std::setfill('0') << i << CYAN": ";
            std::cout << std::hex << std::setw(2) << std::setfill('0') << CYAN"" << std::setw(2) << std::setfill('0') << (int)syscall_code[i] << " ";
        }
        std::cout << RESET"\n";
    #endif

    return syscall_code;
}

void* AddStubToPool(Sys_stb* sEntry, size_t NumberOfElements, BYTE* pSyscallPool)
{
    BYTE* stubAddress = nullptr;

    if(stubCount >= MAX_SYSCALLS)
    {
        fuk("Max number of syscalls reached in pool");
        return (void*)(~0ull);
    }

    for(size_t j = 0; j < NumberOfElements; ++j)
    {
        void* vpfunction = FindExportAddress(sLibs.hHookedNtdll, sEntry[j].function_name);
        if(!vpfunction)
        {
            fuk("Couldn't find the function"); norm("\n");
            return (void*)(~0ull);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////

        BYTE* pBytes = reinterpret_cast<BYTE*>(vpfunction);
        if(pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1)
        {
            norm("\n");ok("Function ", sEntry[j].function_name," is Unhooked\n");
            for(int i = 0; i < 32; ++i)
            {
                if(sEntry[j].SSN != 0 && sEntry[j].pCleanSyscall != nullptr) break;
                if(!sEntry[j].SSN && i + 4 < 32 && pBytes[i] == 0xB8)
                {
                    sEntry[j].SSN = *(DWORD*)(pBytes + i + 1);
                    //norm("SSN:",CYAN" 0x", std::hex, sEntry[j].SSN, "\n"); 
                }

                if(!sEntry[j].pCleanSyscall && i + 1 < 32 && (pBytes[i] == 0x0F || pBytes[i+1] == 0x05))
                {
                    sEntry[j].pCleanSyscall = pBytes + i;
                    //norm("Address of the Syscall: ", CYAN"0x", std::hex, reinterpret_cast<void*>(sEntry[j].pCleanSyscall), "\n");
                }
            }

            if(sEntry[j].SSN == 0 || sEntry[j].pCleanSyscall == nullptr)
            {
                fuk("Couldn't find either the SSN or SYSCALL\n");
                return (void*)(~0ull);
            }
        }
        else
        {
            fuk("Function ", sEntry[j].function_name, " might be hooked\n");
            return (void*)(~0ull);
        }

        ok("Done ", sEntry[j].function_name, "\n");
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////

        BYTE* syscall_code = GenerateSyscallStub(&sEntry[j]);

        if(stubOffset + SIZE_OF_SYSCALL_CODE > MAX_SYSCALLS * SIZE_OF_SYSCALL_CODE)
        {
            fuk("The Syscall Pool is full");
            return (void*)(~0ull);
        }

        stubAddress = pSyscallPool + stubOffset;
        for (size_t i = 0; i < SIZE_OF_SYSCALL_CODE; ++i) stubAddress[i] = syscall_code[i];
        
        sEntry[j].pStubAddress = stubAddress;
        stubOffset += sEntry->stubsize;

        ++stubCount;
    }

    // Ensure memory is executable
    DWORD oldProtect;
    if(!fn.MyVirtualProtect(pSyscallPool, stubOffset, 0x20, &oldProtect))
    {
        fuk("Failed to set RX permissions for syscall stubs. -> ", fn.MyGetLastError());
        return (void*)(~0ull);
    } 
    ok("Memory is executable\n");

    return (void*)(1ull);
}

void* SysFunction(const char* function_name, ...)
{
    void* pExecMem = nullptr;

    for(int i = 0; i < stubCount; ++i)
    {
        if(strcmp(g_syscallEntries[i].function_name, function_name) == 0)
        {
            pExecMem = g_syscallEntries[i].pStubAddress;
            break;
        }
    }
    if(!pExecMem)
    {
        fuk("Syscall not found: ", function_name);
        return (void*)(~0ull);
    }


    GenericSyscallType syscallFunc = reinterpret_cast<GenericSyscallType>(pExecMem);

    va_list args;
    va_start(args, function_name);

    void* argList[16] = {};
    for(int i = 1; i < 16 ; ++i)
    {
        void* arg = va_arg(args, void*);
        if(arg) argList[i] = arg;
    }
    va_end(args);

    void* retValue = nullptr;
    retValue = syscallFunc(argList[1], argList[2], argList[3], argList[4], argList[5],
                            argList[6], argList[7], argList[8], argList[9], argList[10],
                            argList[11], argList[12], argList[13], argList[14], argList[15]
    );

    return retValue;
}

void InitUnicodeString(UNICODE_STRING& u, const wchar_t* s)
{
    size_t len = wcslen(s) * sizeof(wchar_t);
    u.Length        = (USHORT)len;
    u.MaximumLength = (USHORT)(len + sizeof(wchar_t));
    u.Buffer        = const_cast<wchar_t*>(s);
}

int main_entry(Sys_stb recieved_syscallEntries[], size_t numSyscalls)
{

    if(!GetHookedFunctions()) return 1;
    if(!GetUnhookedDlls_KnownDlls()) return 1;
    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    g_pSyscallPool = static_cast<BYTE*>(fn.MyVirtualAlloc(nullptr, MAX_SYSCALLS * 0x40, 0x00001000 | 0x00002000, 0x40));
    

    size_t dataSize = sizeof(Sys_stb) * MAX_SYSCALLS;
    memcpy(g_syscallEntries, recieved_syscallEntries, dataSize);

    AddStubToPool(g_syscallEntries, numSyscalls, g_pSyscallPool);

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    norm("\n==============================================\n");
    for(int i = 0; i < numSyscalls; ++i)
    {
        norm("Function Name: ", GREEN"", g_syscallEntries[i].function_name);
        norm("\nSSN: 0x", std::hex, CYAN"",g_syscallEntries[i].SSN);
        norm("\nStub Address: 0x", std::hex, CYAN"", g_syscallEntries[i].pStubAddress);
        norm("\nClean Syscall Address: 0x", std::hex, CYAN"", (void*)g_syscallEntries[i].pCleanSyscall);
        norm("\n------------------------\n");
    }

    #if DEBUG
        norm("\nSyscall Pool Contents:");
        for (int i = 0; i < SIZE_OF_SYSCALL_CODE * numSyscalls; ++i)
        {
            if(i % 16 == 0)
            {
                BYTE* addr = g_pSyscallPool + i;
                std::cout << YELLOW"\n" << "0x" << std::hex << std::setw(4) << std::setfill('0') << (void*)addr << CYAN": ";
            }
            else std::cout << std::hex << std::setw(2) << std::setfill('0') << CYAN"" << std::setw(2) << std::setfill('0') << (int)g_pSyscallPool[i] << " ";
        }
        std::cout << RESET"\n";
    #endif

    norm("DONE :)\n");
    #if DEBUG_FILE
        details::close_log_file();
    #endif
    return 0;
}

void* FindExportAddress(HMODULE hModule, const char* funcName)
{
    if(!hModule || !funcName) return nullptr;

    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    DWORD peOffset = dos->e_lfanew;
    DWORD peSig = *(DWORD*)(base + peOffset);
    
    // printf("\n[DEBUG] DOS e_lfanew: 0x%X", peOffset);
    // printf("\n[DEBUG] NT Signature: 0x%X", peSig);

    base = (BYTE*)hModule;
    dos = (IMAGE_DOS_HEADER*)base;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE){ fuk("Magic did not match"); return nullptr; }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE){ fuk("NT signature did not match"); return nullptr; }

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(dir.VirtualAddress == 0){ fuk("Optional header issue"); return nullptr; }

    // printf("\nExportDir VA: 0x%X, Size: 0x%X", dir.VirtualAddress, dir.Size);
    warn("Trying to resolve ",YELLOW"", funcName);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
    DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        char* name = (char*)(base + nameRVAs[i]);
        if(_stricmp(name, funcName) == 0)
        {
            DWORD funcRVA = functions[ordinals[i]];
            BYTE* addr = base + funcRVA;

            // Forwarded export check
            if(funcRVA >= dir.VirtualAddress && funcRVA < dir.VirtualAddress + dir.Size)
            {
                fuk("Forwarded export: ", funcName);
                return nullptr;
            }
            return (void*)addr;
        }
    }

    fuk("Function not found: ", funcName);
    return nullptr;
}