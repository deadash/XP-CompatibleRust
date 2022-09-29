#include <windows.h>
#include <intrin.h>

// TODO:
// from: https://github.com/Chuyu-Team/YY-Thunks/blob/master/ThunksList.md

// NT FUNCTION
// from: http://undocumented.ntinternals.net/index.html
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
#define POBJECT_ATTRIBUTES OBJECT_ATTRIBUTES*
typedef NTSTATUS (WINAPI* NTOPENKEYEDEVENT)(
    OUT PHANDLE KeyedEventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);
typedef NTSTATUS (WINAPI* NTRELEASEKEYEDEVENT)(
    IN HANDLE   KeyedEventHandle,
    IN PVOID    Key,
    IN BOOLEAN  Alertable,
    IN PLARGE_INTEGER   Timeout OPTIONAL
);
typedef NTSTATUS (WINAPI* NTWAITFORKEYEDEVENT)(
    IN HANDLE   KeyedEventHandle,
    IN PVOID    Key,
    IN BOOLEAN  Alertable,
    IN PLARGE_INTEGER   Timeout OPTIONAL
);
NTOPENKEYEDEVENT NtOpenKeyedEvent;
NTRELEASEKEYEDEVENT NtReleaseKeyedEvent;
NTWAITFORKEYEDEVENT NtWaitForKeyedEvent;

#define STATUS_RESOURCE_NOT_OWNED 0xC0000264

typedef struct __declspec(align(16)) SRWLOCK_WAIT_BLOCK
{
	struct SRWLOCK_WAIT_BLOCK* back;
	struct SRWLOCK_WAIT_BLOCK* notify;
	struct SRWLOCK_WAIT_BLOCK* next;
	volatile size_t shareCount;
	volatile size_t flag;
} SRWLOCK_WAIT_BLOCK;

#define SRW_LOCKED_BIT              0
#define SRW_WAITTING_BIT            1
#define SRW_WAKING_BIT              2
#define SRW_MULTIPLESHARED_BIT      3

#define SRWLOCK_Locked               0x00000001ul
#define SRWLOCK_Waiting              0x00000002ul
#define SRWLOCK_Waking               0x00000004ul
#define SRWLOCK_MultipleShared       0x00000008ul

#define SRWLOCK_MASK                ((size_t)(0xF))
#define SRWLOCK_BITS                4
#define SRWLOCK_GET_BLOCK(SRWLock) ((SRWLOCK_WAIT_BLOCK*)(SRWLock & (~SRWLOCK_MASK)))

#define SRWLockSpinCount 1024

static HANDLE _GlobalKeyedEventHandle = NULL;

// other struct
typedef DWORD uint32_t;
typedef INT32 int32_t;
typedef unsigned __int64 QWORD;
struct EXCEPTION_REGISTRATION_
{
    struct EXCEPTION_REGISTRATION_*    prev;
    void *                             handler;
};

struct CLIENT_ID_
{
    DWORD  ProcessId;
    DWORD  ThreadId;
};

struct PROCESSOR_NUMBER_
{
    WORD    Group;
    BYTE    Number;
    BYTE    Reserved;
};

struct GDI_TEB_BATCH_
{
    union
    {
        DWORD   Offset;
        struct
        {
            DWORD Offset                : 31;  //0x00:00  Win 8.1 Update 1+
            DWORD HasRenderingCommand   : 1;   //0x00:31  Win 8.1 Update 1+
        } bits;
    } dword0;
    DWORD   HDC;
    DWORD   Buffer[0x136];
};

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

// PEB
struct PEB_
{
    BOOLEAN                         InheritedAddressSpace;              //0x0000
    BOOLEAN                         ReadImageFileExecOptions;           //0x0001
    BOOLEAN                         BeingDebugged;                      //0x0002
    union
    {
        BOOLEAN                     SpareBool;                          //0x0003 (NT3.51-late WS03)
        struct
        {
            BYTE                    ImageUsesLargePages          : 1;   //0x0003:0 (WS03_SP1+)
            BYTE                    IsProtectedProcess           : 1;   //0x0003:1 (Vista+)
            BYTE                    IsLegacyProcess              : 1;   //0x0003:2 (Vista+)
            BYTE                    IsImageDynamicallyRelocated  : 1;   //0x0003:3 (Vista+)
            BYTE                    SkipPatchingUser32Forwarders : 1;   //0x0003:4 (Vista_SP1+)
            BYTE                    IsPackagedProcess            : 1;   //0x0003:5 (Win8_BETA+)
            BYTE                    IsAppContainer               : 1;   //0x0003:6 (Win8_RTM+)
            BYTE                    SpareBits                    : 1;   //0x0003:7
        } bits;
    } byte3;
    HANDLE                          Mutant;                             //0x0004
    void*                           ImageBaseAddress;                   //0x0008
    PEB_LDR_DATA*                   Ldr;                                //0x000C  (all loaded modules in process)
    RTL_USER_PROCESS_PARAMETERS*    ProcessParameters;                  //0x0010
    void*                           SubSystemData;                      //0x0014
    void*                           ProcessHeap;                        //0x0018
    RTL_CRITICAL_SECTION*           FastPebLock;                        //0x001C
    union
    {
        void*                       FastPebLockRoutine;                 //0x0020 (NT3.51-Win2k)
        void*                       SparePtr1;                          //0x0020 (early WS03)
        void*                       AtlThunkSListPtr;                   //0x0020 (late WS03+)
    } dword20;
    union
    {
        void*                       FastPebUnlockRoutine;               //0x0024 (NT3.51-XP)
        void*                       SparePtr2;                          //0x0024 (WS03)
        void*                       IFEOKey;                            //0x0024 (Vista+)
    } dword24;
    union
    {
        DWORD                       EnvironmentUpdateCount;             //0x0028 (NT3.51-WS03)
        struct
        {
            DWORD                   ProcessInJob            : 1;        //0x0028:0 (Vista+)
            DWORD                   ProcessInitializing     : 1;        //0x0028:1 (Vista+)
            DWORD                   ProcessUsingVEH         : 1;        //0x0028:2 (Vista_SP1+)
            DWORD                   ProcessUsingVCH         : 1;        //0x0028:3 (Vista_SP1+)
            DWORD                   ProcessUsingFTH         : 1;        //0x0028:4 (Win7_BETA+)
            DWORD                   ReservedBits0           : 27;       //0x0028:5 (Win7_BETA+)
        } vista_CrossProcessFlags;
    } struct28;
    union
    {
        void*                       KernelCallbackTable;                //0x002C (Vista+)
        void*                       UserSharedInfoPtr;                  //0x002C (Vista+)
    } dword2C;
    DWORD                           SystemReserved;                     //0x0030 (NT3.51-XP)
    //Microsoft seems to keep changing their mind with DWORD 0x34
    union
    {
        DWORD                       SystemReserved2;                    //0x0034 (NT3.51-Win2k)
        struct
        {
            DWORD                   ExecuteOptions          : 2;        //0x0034:0 (XP-early WS03)
            DWORD                   SpareBits               : 30;       //0x0034:2 (XP-early WS03)
        } xpBits;
        DWORD                       AtlThunkSListPtr32;                 //0x0034 (late XP,Win7+)
        DWORD                       SpareUlong;                         //0x0034 (late WS03-Vista)
        struct
        {
            DWORD                   HeapTracingEnabled      : 1;        //0x0034:0 (Win7_BETA)
            DWORD                   CritSecTracingEnabled   : 1;        //0x0034:1 (Win7_BETA)
            DWORD                   SpareTracingBits        : 30;       //0x0034:2 (Win7_BETA)
        } win7_TracingFlags;
    } dword34;
    union
    {
        struct PEB_FREE_BLOCK*      FreeList;                           //0x0038 (NT3.51-early Vista)
        DWORD                       SparePebPtr0;                       //0x0038 (last Vista)
        void*                       ApiSetMap;                          //0x0038 (Win7+)
    } dword38;
    DWORD                           TlsExpansionCounter;                //0x003C
    void*                           TlsBitmap;                          //0x0040
    DWORD                           TlsBitmapBits[2];                   //0x0044
    void*                           ReadOnlySharedMemoryBase;           //0x004C
    union
    {
        void*                       ReadOnlyShareMemoryHeap;            //0x0050 (NT3.51-WS03)
        void*                       HotpatchInformation;                //0x0050 (Vista+)
    } dword50;
    void*                          ReadOnlyStaticServerData;           //0x0054 really void**
    void*                           AnsiCodePageData;                   //0x0058
    void*                           OemCodePageData;                    //0x005C
    void*                           UnicodeCaseTableData;               //0x0060
    DWORD                           NumberOfProcessors;                 //0x0064
    DWORD                           NtGlobalFlag;                       //0x0068
    LARGE_INTEGER                   CriticalSectionTimeout;             //0x0070
    DWORD                           HeapSegmentReserve;                 //0x0078
    DWORD                           HeapSegmentCommit;                  //0x007C
    DWORD                           HeapDeCommitTotalFreeThreshold;     //0x0080
    DWORD                           HeapDeCommitFreeBlockThreshold;     //0x0084
    DWORD                           NumberOfHeaps;                      //0x0088
    DWORD                           MaximumNumberOfHeaps;               //0x008C
    void*                           ProcessHeaps;                       //0x0090 really void**
    void*                           GdiSharedHandleTable;               //0x0094

    //end of NT 3.51 members / members that follow available on NT 4.0 and up

    void*                           ProcessStarterHelper;               //0x0098
    DWORD                           GdiDCAttributeList;                 //0x009C
    union
    {
        struct
        {
            void*                   LoaderLock;                         //0x00A0 (NT4)
        } nt4;
        struct
        {
            RTL_CRITICAL_SECTION*   LoaderLock;                         //0x00A0 (Win2k+)
        } win2k;
    } dwordA0;
    DWORD                           OSMajorVersion;                     //0x00A4
    DWORD                           OSMinorVersion;                     //0x00A8
    WORD                            OSBuildNumber;                      //0x00AC
    WORD                            OSCSDVersion;                       //0x00AE
    DWORD                           OSPlatformId;                       //0x00B0
    DWORD                           ImageSubsystem;                     //0x00B4
    DWORD                           ImageSubsystemMajorVersion;         //0x00B8
    DWORD                           ImageSubsystemMinorVersion;         //0x00BC
    union
    {
        KAFFINITY                   ImageProcessAffinityMask;           //0x00C0 (NT4-early Vista)
        KAFFINITY                   ActiveProcessAffinityMask;          //0x00C0 (late Vista+)
    } dwordC0;
    DWORD                           GdiHandleBuffer[0x22];              //0x00C4
    void*                           PostProcessInitRoutine;             //0x014C / void (*PostProcessInitRoutine) (void);

    //members that follow available on Windows 2000 and up

    void*                           TlsExpansionBitmap;                 //0x0150
    DWORD                           TlsExpansionBitmapBits[0x20];       //0x0154
    DWORD                           SessionId;                          //0x01D4
    ULARGE_INTEGER                  AppCompatFlags;                     //0x01D8
    ULARGE_INTEGER                  AppCompatFlagsUser;                 //0x01E0
    void*                           pShimData;                          //0x01E8
    void*                           AppCompatInfo;                      //0x01EC
    UNICODE_STRING                  CSDVersion;                         //0x01F0

    //members that follow available on Windows XP and up

    struct ACTIVATION_CONTEXT_DATA* ActivationContextData;              //0x01F8
    struct ASSEMBLY_STORAGE_MAP*    ProcessAssemblyStorageMap;          //0x01FC
    struct ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData; //0x0200
    struct ASSEMBLY_STORAGE_MAP*    SystemAssemblyStorageMap;           //0x0204
    DWORD                           MinimumStackCommit;                 //0x0208

    //members that follow available on Windows Server 2003 and up

    struct FLS_CALLBACK_INFO*       FlsCallback;                        //0x020C
    LIST_ENTRY                      FlsListHead;                        //0x0210
    void*                           FlsBitmap;                          //0x0218
    DWORD                           FlsBitmapBits[4];                   //0x021C
    DWORD                           FlsHighIndex;                       //0x022C

    //members that follow available on Windows Vista and up

    void*                           WerRegistrationData;                //0x0230
    void*                           WerShipAssertPtr;                   //0x0234

    //members that follow available on Windows 7 BETA and up

    union
    {
        void*                       pContextData;                       //0x0238 (prior to Windows 8)
        void*                       pUnused;                            //0x0238 (Windows 8)
    } dword238;
    void*                           pImageHeaderHash;                   //0x023C

    //members that follow available on Windows 7 RTM and up

    struct //TracingFlags
    {
        DWORD                       HeapTracingEnabled       :1;        //0x0240:0
        DWORD                       CritSecTracingEnabled    :1;        //0x0240:1
        DWORD                       LibLoaderTracingEnabled  :1;        //0x0240:2
        DWORD                       SpareTracingBits         :29;       //0x0240:3
    } dword240;
    DWORD                           dummy02;                            //0x0244

    //members that follow available on Windows 8 and up

    QWORD                           CsrServerReadOnlySharedMemoryBase;  //0x0248

    //members that follow available by at least Windows 10 (possibly Windows 8)

    DWORD                           dwUnknown0250;                      //0x0250 (must exist at least by Windows 10)
    DWORD                           dwSystemCallMode;                   //0x0254 / set to 2 under 64-bit Windows in a 32-bit process (WOW64)
};

// TEB
struct TEB_
{
    struct EXCEPTION_REGISTRATION_*    ExceptionList;                              //0x0000 / Current Structured Exception Handling (SEH) frame
    void*                       StackBase;                                  //0x0004 / Bottom of stack (high address)
    void*                       StackLimit;                                 //0x0008 / Ceiling of stack (low address)
    void*                       SubSystemTib;                               //0x000C
    union
    {
        void*                   FiberData;                                  //0x0010
        DWORD                   Version;                                    //0x0010
    } dword10;
    void*                       ArbitraryUserPointer;                       //0x0014
    struct TEB_*                Self;                                       //0x0018
    //NT_TIB ends (NT subsystem independent part)

    void*                       EnvironmentPointer;                         //0x001C
    struct CLIENT_ID_           ClientId;                                   //0x0020
    //                          ClientId.ProcessId                          //0x0020 / value retrieved by GetCurrentProcessId()
    //                          ClientId.ThreadId                           //0x0024 / value retrieved by GetCurrentThreadId()
    void*                       ActiveRpcHandle;                            //0x0028
    void*                       ThreadLocalStoragePointer;                  //0x002C
    struct PEB_*                ProcessEnvironmentBlock;                    //0x0030
    DWORD                       LastErrorValue;                             //0x0034
    DWORD                       CountOfOwnedCriticalSections;               //0x0038
    void*                       CsrClientThread;                            //0x003C
    void*                       Win32ThreadInfo;                            //0x0040
    DWORD                       User32Reserved[0x1A];                       //0x0044
    DWORD                       UserReserved[5];                            //0x00AC
    void*                       WOW32Reserved;                              //0x00C0 / user-mode 32-bit (WOW64) -> 64-bit CONTEXT_ switch function prior to kernel-mode transition
    LCID                        CurrentLocale;                              //0x00C4
    DWORD                       FpSoftwareStatusRegister;                   //0x00C8
    union
    {
        DWORD                   SystemReserved1[0x36];                      //0x00CC (NT 3.51-Win8)
        struct
        {
            DWORD               Reserved1[0x16];                            //0x00CC
            void*               pKThread;                                   //0x0124 / pointer to KTHREAD (ETHREAD) structure
            DWORD               Reserved2[0x1F];                            //0x0128
        } kernelInfo;
        struct
        {
            DWORD               ReservedForDebuggerInstrumentation[0x10];   //0x00CC (Win10 PRE-RTM+)
            DWORD               SystemReserved1[0x26];                      //0x010C (Win10 PRE-RTM+)
        } win10;
    } dwordCC;
    int32_t /*NTSTATUS*/        ExceptionCode;                              //0x01A4
    union
    {
        BYTE                    SpareBytes1[0x2C];                          //0x01A8 (NT3.51-Win2k)
        struct
        {
            BYTE                ActivationContextStack[0x14];               //0x01A8 (XP-early WS03)
            BYTE                SpareBytes1[0x18];                          //0x01BC (XP-early WS03)
        } xp;
        struct
        {
            void*               ActivationContextStackPointer;              //0x01A8 (WS03+)
            union
            {
                BYTE            SpareBytes1[0x24];                          //0x01AC (WS03-Win8.1)
                struct
                {
                    void*       InstrumentationCallbackSp;                  //0x01AC (Win10+)
                    void*       InstrumentationCallbackPreviousPc;          //0x01B0 (Win10+)
                    void*       InstrumentationCallbackPreviousSp;          //0x01B4 (Win10+)
                    BOOLEAN     InstrumentationCallbackDisabled;            //0x01B8 (Win10+)
                    BYTE        SpareBytes[0x17];                           //0x01B9 (Win10+)
                } win10;
            } dword1AC;
            union
            {
                BYTE            SpareBytes2[4];                             //0x01D0 (WS03)
                DWORD           TxFsContext;                                //0x01D0 (Vista+)
            } dword1D0;
        } lateWs03;
    } dword1A8;
    struct GDI_TEB_BATCH_       GdiTebBatch;                                //0x01D4
    struct CLIENT_ID_           RealClientId;                               //0x06B4
    HANDLE                      GdiCachedProcessHandle;                     //0x06BC
    DWORD                       GdiClientPID;                               //0x06C0
    DWORD                       GdiClientTID;                               //0x06C4
    void*                       GdiThreadLocalInfo;                         //0x06C8
    DWORD                       Win32ClientInfo[0x3E];                      //0x06CC
    void*                       glDispatchTable[0xE9];                      //0x07C4
    DWORD                       glReserved1[0x1D];                          //0x0B68
    void*                       glReserved2;                                //0x0BDC
    void*                       glSectionInfo;                              //0x0BE0
    void*                       glSection;                                  //0x0BE4
    void*                       glTable;                                    //0x0BE8
    void*                       glCurrentRC;                                //0x0BEC
    void*                       glContext;                                  //0x0BF0
    int32_t /*NTSTATUS*/        LastStatusValue;                            //0x0BF4
    UNICODE_STRING              StaticUnicodeString;                        //0x0BF8
    WCHAR                       StaticUnicodeBuffer[0x105];                 //0x0C00
    void*                       DeallocationStack;                          //0x0E0C
    void*                       TlsSlots[0x40];                             //0x0E10
    LIST_ENTRY                  TlsLinks;                                   //0x0F10
    void*                       Vdm;                                        //0x0F18
    void*                       ReservedForNtRpc;                           //0x0F1C
    void*                       DbgSsReserved[2];                           //0x0F20

    //end of NT 3.51 members / members that follow available on NT 4.0 and up

    union
    {
        DWORD                   ThreadErrorMode;                            //0x0F28 (OS?) / RtlSetThreadErrorMode
        DWORD                   HardErrorsAreDisabled;                      //0x0F28 (NT4-XP)
        DWORD                   HardErrorMode;                              //0x0F28 (WS03+)
    } dwordF28;
    union
    {
        struct
        {
            DWORD               Instrumentation[0x10];                      //0x0F2C (NT4-early WS03)
        } nt;
        struct
        {
            union
            {
                struct
                {
                    DWORD       Instrumentation[0x0E];                      //0x0F2C (late WS03+)
                    void*       SubProcessTag;                              //0x0F64 (late WS03+)
                } beforeVista;
                struct
                {
                    DWORD       Instrumentation[9];                         //0x0F2C (Vista+)
                    GUID        ActivityId;                                 //0x0F50 (Vista+)
                    void*       SubProcessTag;                              //0x0F60 (Vista+)
                    union
                    {
                        DWORD   EtwLocalData;                               //0x0F64 (WIN8 PRE-RTM)
                        DWORD   PerflibData;                                //0x0F64 (WIN8 RTM+)
                    } win8;

                } vista;
            } dwordF2C;
            void*               EtwTraceData;                               //0x0F68 (late WS03+)
        } ws03;
    } dwordF2C;
    void*                       WinSockData;                                //0x0F6C
    DWORD                       GdiBatchCount;                              //0x0F70
    union
    {
        struct
        {
            union
            {
                struct
                {
                    BOOLEAN     InDbgPrint;                                 //0x0F74 (NT4-WS03)
                    BOOLEAN     FreeStackOnTermination;                     //0x0F75 (NT4-WS03)
                    BOOLEAN     HasFiberData;                               //0x0F76 (NT4-WS03)
                } beforeVista;
                union
                {
                    BOOLEAN     SpareBool0;                                 //0x0F74 (Vista)
                    BOOLEAN     SpareBool1;                                 //0x0F75 (Vista)
                    BOOLEAN     SpareBool2;                                 //0x0F76 (Vista)
                } vista;
            } u;
            BOOLEAN             IdealProcessor;                             //0x0F77 (NT4-Vista)
        } beforeWin7;
        struct PROCESSOR_NUMBER_ CurrentIdealProcessor;                      //0x0F74 (Win7+)
    } dwordF74;
    union
    {
        DWORD                   Spare3;                                     //0x0F78 (NT4-early WS03)
        DWORD                   GuaranteedStackBytes;                       //0x0F78 (late WS03+)
    } dwordF78;
    void*                       ReservedForPerf;                            //0x0F7C
    void*                       ReservedForOle;                             //0x0F80
    DWORD                       WaitingOnLoaderLock;                        //0x0F84

    //members that follow available on Windows 2000 and up

    union
    {
        struct
        {
            //Wx86ThreadState structure
            DWORD*              CallBx86Eip;                                //0x0F88 (Win2k-early WS03)
            void*               DeallocationCpu;                            //0x0F8C (Win2k-early WS03)
            BYTE                UseKnownWx86Dll;                            //0x0F90 (Win2k-early WS03)
            CHAR                OleStubInvoked;                             //0x0F91 (Win2k-early WS03)
            BYTE                Padding[2];                                 //0x0F92
        } beforeLateWs03;
        struct
        {
            union
            {
                void*           SparePointer1;                              //0x0F88 (late WS03)
                void*           SavedPriorityState;                         //0x0F88 (Vista+)
            } dwordF88;
            union
            {
                void*           SoftPatchPtr1;                              //0x0F8C (late WS03-Win7)
                void*           ReservedForCodeCoverage;                    //0x0F8C (Win8+)
            } dwordF8C;
            union
            {
                void*           SoftPatchPtr2;                              //0x0F90 (late WS03)
                void*           ThreadPoolData;                             //0x0F90 (Vista+)
            } dwordF90;
        } lateWs03;
    } dwordF88;
    void*                       TlsExpansionSlots;                          //0x0F94
    union
    {
        LCID                    ImpersonationLocale;                        //0x0F98 (Win2k-Vista)
        DWORD                   MuiGeneration;                              //0x0F98 (Win7+)
    } dwordF98;
    DWORD                       IsImpersonating;                            //0x0F9C
    void*                       NlsCache;                                   //0x0FA0

    //members that follow available on Windows XP and up

    void*                       pShimData;                                  //0x0FA4
    union
    {
        DWORD                   HeapVirtualAffinity;                        //0x0FA8 (XP-Win7)
        struct
        {
            WORD                HeapVirtualAffinity;                        //0x0FA8 (Win8+)
            WORD                LowFragHeapDataSlot;                        //0x0FAA (Win8+)
        } win8;
    } dwordFA8;
    HANDLE                      CurrentTransactionHandle;                   //0x0FAC
    void*                       ActiveFrame;                                //0x0FB0

    //members that follow available on Windows XP SP2 and up

    union
    {
        void*                   FlsData;                                    //0x0FB4 (WS03+)
        struct
        {
            BOOLEAN             SafeThunkCall;                              //0x0FB4 (XP SP2)
            BOOLEAN             BooleanSpare[3];                            //0x0FB5 (XP SP2)
        } xpSp2;
    } dwordFB4;
    union
    {
        struct
        {
            BOOLEAN             SafeThunkCall;                              //0x0FB8 (late WS03)
            BOOLEAN             BooleanSpare[3];                            //0x0FB9 (late WS03)
        } ws03;
        void*                   PreferredLanguages;                         //0x0FB8 (Vista+)
    } dwordFB8;

    //members that follow available on Windows Vista and up

    void*                       UserPrefLanguages;                          //0x0FBC
    void*                       MergedPrefLanguages;                        //0x0FC0
    DWORD                       MuiImpersonation;                           //0x0FC4
    union
    {
        volatile WORD           CrossTebFlags;                              //0x0FC8
        struct
        {
            WORD                SpareCrossTebBits : 16;                     //0x0FC8
        } bits;
    } wordFC8;
    union
    {
        WORD                    SameTebFlags;                               //0x0FCA
        struct
        {
            WORD                SafeThunkCall        : 1;                   //0x0FCA:0x00
            WORD                InDebugPrint         : 1;                   //0x0FCA:0x01
            WORD                HasFiberData         : 1;                   //0x0FCA:0x02
            WORD                SkipThreadAttach     : 1;                   //0x0FCA:0x03
            WORD                WerInShipAssertCode  : 1;                   //0x0FCA:0x04
            WORD                RanProcessInit       : 1;                   //0x0FCA:0x05
            WORD                ClonedThread         : 1;                   //0x0FCA:0x06
            WORD                SuppressDebugMsg     : 1;                   //0x0FCA:0x07
            WORD                DisableUserStackWalk : 1;                   //0x0FCA:0x08
            WORD                RtlExceptionAttached : 1;                   //0x0FCA:0x09
            WORD                InitialThread        : 1;                   //0x0FCA:0x0A
            WORD                SessionAware         : 1;                   //0x0FCA:0x0B
        } bits;
    } wordFCA;
    void*                       TxnScopeEnterCallback;                      //0x0FCC
    void*                       TxnScopeExitCallback;                       //0x0FD0
    void*                       TxnScopeContext;                            //0x0FD4
    DWORD                       LockCount;                                  //0x0FD8
    union
    {
        struct
        {
            DWORD               ProcessRundown;                             //0x0FDC (Vista)
            QWORD               LastSwitchTime;                             //0x0FE0 (Vista)
            QWORD               TotalSwitchOutTime;                         //0x0FE8 (Vista)
            LARGE_INTEGER       WaitReasonBitMap;                           //0x0FF0 (Vista)
        } vista;

        //end of Vista members

        struct
        {
            union
            {
                DWORD           SpareUlong0;                                //0x0FDC (Win7-Win8)
                INT32           WowTebOffset;                               //0x0FDC (Win10+)
            } dwordFDC;
            void*               ResourceRetValue;                           //0x0FE0 (Win7+)

            //end of Windows 7 members (TEB_ shrunk after Vista)

            void*               ReservedForWdf;                             //0x0FE4 (Win8+)

            //end of Windows 8 members

        } afterVista;
    } dwordFDC;

    //members that follow available on Windows 10 and up (currently unknown)

    BYTE                        ReservedForWin10[0x18];                     //0x0FE8
}; // struct TEB_

void __fastcall RaiseStatus(NTSTATUS Status)
{
    RaiseException(Status, EXCEPTION_NONCONTINUABLE, 0, NULL);
}

inline struct TEB_ *
NtTeb (VOID)
{
    return (struct TEB_ *)__readfsdword(0x18);
}

inline BOOL
IsXp()
{
    return NtTeb()->ProcessEnvironmentBlock->OSMajorVersion < 6;
}

HANDLE __fastcall GetGlobalKeyedEventHandle()
{
    if (IsXp() && _GlobalKeyedEventHandle == NULL)
    {
        static const wchar_t Name[] = L"\\KernelObjects\\CritSecOutOfMemoryEvent";
        UNICODE_STRING ObjectName = {sizeof(Name) - sizeof(wchar_t),sizeof(Name) - sizeof(wchar_t) ,(PWSTR)Name };
        OBJECT_ATTRIBUTES attr = { sizeof(attr), NULL, &ObjectName };
        HANDLE KeyedEventHandle;
        if (NtOpenKeyedEvent(&KeyedEventHandle, MAXIMUM_ALLOWED, &attr) < 0)
        {
            RaiseStatus(STATUS_RESOURCE_NOT_OWNED);
        }
        if (InterlockedCompareExchange((size_t*)&_GlobalKeyedEventHandle, (size_t)KeyedEventHandle, (size_t)NULL))
        {
            CloseHandle(KeyedEventHandle);
        }
    }
    return _GlobalKeyedEventHandle;
}

void __fastcall RtlpWakeSRWLock(SRWLOCK* SRWLock, size_t Status)
{
    HANDLE GlobalKeyedEventHandle = GetGlobalKeyedEventHandle();
    for (;;)
    {
        if ((Status & SRWLOCK_Locked) == 0)
        {
            SRWLOCK_WAIT_BLOCK* pWaitBlock = SRWLOCK_GET_BLOCK(Status);
            SRWLOCK_WAIT_BLOCK* notify;
            for (SRWLOCK_WAIT_BLOCK* pBlock = pWaitBlock; (notify = pBlock->notify) == NULL;)
            {
                SRWLOCK_WAIT_BLOCK* back = pBlock->back;
                back->next = pBlock;
                pBlock = back;
            }
            pWaitBlock->notify = notify;
            
            if (notify->next && (notify->flag & 1))
            {
                pWaitBlock->notify = notify->next;
                notify->next = NULL;
                _InterlockedAnd((volatile LONG_PTR*)SRWLock, ~((LONG_PTR)SRWLOCK_Waking));
                if (!InterlockedBitTestAndReset((volatile LONG*)&notify->flag, 1))
                {
                    NtReleaseKeyedEvent(GlobalKeyedEventHandle, notify, 0, NULL);
                }
                return;
            }
            else
            {
                size_t NewStatus = InterlockedCompareExchange((volatile size_t *)SRWLock, 0, Status);
                if (NewStatus == Status)
                {
                    for (; notify;)
                    {
                        SRWLOCK_WAIT_BLOCK* next = notify->next;
                        if (!InterlockedBitTestAndReset((volatile LONG*)&notify->flag, 1))
                        {
                            NtReleaseKeyedEvent(GlobalKeyedEventHandle, notify, 0, NULL);
                        }
                        notify = next;
                    }
                    return;
                }
                Status = NewStatus;
            }

            pWaitBlock->notify = notify;
        }
        else
        {
            size_t NewStatus = InterlockedCompareExchange((volatile LONG *)SRWLock, Status & ~SRWLOCK_Waking, Status);
            if (NewStatus == Status)
                return;

            Status = NewStatus;
        }
    }
}

void __fastcall RtlpOptimizeSRWLockList(SRWLOCK* SRWLock, size_t Status)
{
    for (;;)
    {
        if (Status & SRWLOCK_Locked)
        {
            SRWLOCK_WAIT_BLOCK* WaitBlock;
            if (WaitBlock = (SRWLOCK_WAIT_BLOCK*)(Status & (~SRWLOCK_MASK)))
            {
                SRWLOCK_WAIT_BLOCK* pBlock = WaitBlock;
                for (; pBlock->notify == NULL;)
                {
                    SRWLOCK_WAIT_BLOCK* back = pBlock->back;
                    back->next = pBlock;
                    pBlock = back;
                }
                WaitBlock->notify = pBlock->notify;
            }
            size_t CurrentStatus = InterlockedCompareExchange((volatile size_t *)SRWLock, Status - SRWLOCK_Waking, Status);
            if (CurrentStatus == Status)
                break;

            Status = CurrentStatus;
        }
        else
        {
            RtlpWakeSRWLock(SRWLock, Status);
            break;
        }
    }
}

VOID
WINAPI
ReleaseSRWLockExclusiveXP(__inout PSRWLOCK SRWLock)
{
    size_t old = InterlockedExchangeAdd((volatile size_t *)SRWLock, (size_t)(-1));
    if ((old & SRWLOCK_Locked) == 0 )
    {
        RaiseStatus(STATUS_RESOURCE_NOT_OWNED);
    }

    if ((old & SRWLOCK_Waiting) && (old & SRWLOCK_Waking) == 0)
    {
        old -= SRWLOCK_Locked;

        size_t new = old | SRWLOCK_Waking;
        size_t cur = InterlockedCompareExchange((volatile size_t *)SRWLock, new, old);

        if (cur == old)
            RtlpWakeSRWLock(SRWLock, new);
    }
}

VOID
WINAPI
ReleaseSRWLockSharedXP(_Inout_ PSRWLOCK SRWLock)
{
    size_t OldSRWLock = InterlockedCompareExchange((volatile size_t*)SRWLock, 0, (size_t)(0x11));
    if (OldSRWLock == (size_t)(0x11))
        return;

    if ((OldSRWLock & SRWLOCK_Locked) == 0)
    {
        RaiseStatus(STATUS_RESOURCE_NOT_OWNED);
    }

    for (;;)
    {
        if (OldSRWLock & SRWLOCK_Waiting)
        {
            if (OldSRWLock & SRWLOCK_MultipleShared)
            {
                SRWLOCK_WAIT_BLOCK* pLastNode = SRWLOCK_GET_BLOCK(OldSRWLock);
                for (; pLastNode->notify == NULL; pLastNode = pLastNode->back);
                if (InterlockedDecrement((volatile size_t *)&(pLastNode->notify->shareCount)) > 0)
                    return;
            }

            for (;;)
            {
                size_t NewSRWLock = OldSRWLock & (~(SRWLOCK_MultipleShared | SRWLOCK_Locked));
                size_t LastSRWLock;
                if (OldSRWLock & SRWLOCK_Waking)
                {
                    LastSRWLock = InterlockedCompareExchange((volatile size_t *)SRWLock, NewSRWLock, OldSRWLock);
                    if (LastSRWLock == OldSRWLock)
                        return;
                }
                else
                {
                    NewSRWLock |= SRWLOCK_Waking;
                    LastSRWLock = InterlockedCompareExchange((volatile size_t *)SRWLock, NewSRWLock, OldSRWLock);
                    if (LastSRWLock == OldSRWLock)
                    {
                        RtlpWakeSRWLock(SRWLock, NewSRWLock);
                        return;
                    }
                }
                OldSRWLock = LastSRWLock;
            }
            break;
        }
        else
        {
            size_t NewSRWLock = (size_t)(SRWLOCK_GET_BLOCK(OldSRWLock)) <= 0x10 ? 0 : OldSRWLock - 0x10;
            size_t LastSRWLock = InterlockedCompareExchange((volatile size_t *)SRWLock, NewSRWLock, OldSRWLock);
            if (LastSRWLock == OldSRWLock)
                break;
            OldSRWLock = LastSRWLock;
        }
    }
}

VOID
WINAPI
AcquireSRWLockSharedXP(_Inout_ PSRWLOCK SRWLock)
{
    SRWLOCK_WAIT_BLOCK StackWaitBlock;
	BOOL bOptimize;
    
    size_t OldSRWLock = InterlockedCompareExchange((volatile size_t*)SRWLock, (size_t)(0x11), 0);
    if (OldSRWLock == (size_t)(0))
        return;

    size_t NewSRWLock;
    for (;; OldSRWLock = *(volatile size_t *)SRWLock)
    {
        if ((OldSRWLock & SRWLOCK_Locked) && ((OldSRWLock & SRWLOCK_Waiting) || SRWLOCK_GET_BLOCK(OldSRWLock) == NULL))
        {
            StackWaitBlock.flag = 2;
            StackWaitBlock.shareCount = 0;
            StackWaitBlock.next = NULL;

            bOptimize = FALSE;
            if (OldSRWLock & SRWLOCK_Waiting)
            {
                StackWaitBlock.back = SRWLOCK_GET_BLOCK(OldSRWLock);
                StackWaitBlock.notify = NULL;
                NewSRWLock = (size_t)(&StackWaitBlock) | (OldSRWLock & SRWLOCK_MultipleShared) | (SRWLOCK_Waking | SRWLOCK_Waiting | SRWLOCK_Locked);
                if ((OldSRWLock & SRWLOCK_Waking) == 0)
                {
                    bOptimize = TRUE;
                }
            }
            else
            {
                StackWaitBlock.notify = &StackWaitBlock;
                NewSRWLock = (size_t)(&StackWaitBlock) | (SRWLOCK_Waiting | SRWLOCK_Locked);
            }
            if (InterlockedCompareExchange((volatile size_t *)SRWLock, NewSRWLock, OldSRWLock) == OldSRWLock)
            {
                if (bOptimize)
                {
                    RtlpOptimizeSRWLockList(SRWLock, NewSRWLock);
                }

                HANDLE GlobalKeyedEventHandle = GetGlobalKeyedEventHandle();
                for (DWORD SpinCount = SRWLockSpinCount; SpinCount; --SpinCount)
                {
                    if ((StackWaitBlock.flag & 2) == 0)
                        break;
                    YieldProcessor();
                }
                if (InterlockedBitTestAndReset((volatile LONG*)&StackWaitBlock.flag, 1))
                {
                    NtWaitForKeyedEvent(GlobalKeyedEventHandle, (PVOID)&StackWaitBlock, 0, NULL);
                }
                continue;
            }
        }
        else
        {
            if (OldSRWLock & SRWLOCK_Waiting)
            {
                NewSRWLock = OldSRWLock | SRWLOCK_Locked;
            }
            else
            {
                NewSRWLock = (OldSRWLock + 0x10) | SRWLOCK_Locked;
            }
            if (InterlockedCompareExchange((volatile size_t *)SRWLock, NewSRWLock, OldSRWLock) == OldSRWLock)
                return;
        }
        YieldProcessor();
    }
}

VOID
WINAPI
AcquireSRWLockExclusiveXP(_Inout_ PSRWLOCK SRWLock)
{
    SRWLOCK_WAIT_BLOCK StackWaitBlock;
    BOOL bOptimize;
    size_t OldBit = InterlockedBitTestAndSet((volatile LONG_PTR*)SRWLock, SRW_LOCKED_BIT);
    if (OldBit == FALSE)
        return;

    for (;;)
    {
        size_t SRWLockOld = *(volatile size_t*)SRWLock;
        if (SRWLOCK_Locked & SRWLockOld)
        {
            StackWaitBlock.next = NULL;
            StackWaitBlock.flag = 3;
            bOptimize = FALSE;
            size_t SRWLockNew;
            if (SRWLOCK_Waiting & SRWLockOld)
            {
                StackWaitBlock.notify = NULL;
                StackWaitBlock.shareCount = 0;
                StackWaitBlock.back = (SRWLOCK_WAIT_BLOCK*)(SRWLockOld & (~SRWLOCK_MASK));

                SRWLockNew = (size_t)(&StackWaitBlock) | (SRWLockOld & SRWLOCK_MultipleShared) | SRWLOCK_Waking | SRWLOCK_Waiting | SRWLOCK_Locked;
                if ((SRWLOCK_Waking & SRWLockOld) == 0)
                {
                    bOptimize = TRUE;
                }
            }
            else
            {
                StackWaitBlock.notify = (SRWLOCK_WAIT_BLOCK*)&StackWaitBlock;
                StackWaitBlock.shareCount = (SRWLockOld >> SRWLOCK_BITS);

                SRWLockNew = StackWaitBlock.shareCount > 1 ?
                    (size_t)(&StackWaitBlock) | SRWLOCK_MultipleShared | SRWLOCK_Waiting | SRWLOCK_Locked
                    : (size_t)(&StackWaitBlock) | SRWLOCK_Waiting | SRWLOCK_Locked;
            }

            if (InterlockedCompareExchange((volatile size_t*)SRWLock, SRWLockNew, SRWLockOld) != SRWLockOld)
            {
                YieldProcessor();
                continue;
            }

            if (bOptimize)
            {
                RtlpOptimizeSRWLockList(SRWLock, SRWLockNew);
            }

            HANDLE GlobalKeyedEventHandle = GetGlobalKeyedEventHandle();
            for (DWORD SpinCount = SRWLockSpinCount; SpinCount; --SpinCount)
            {
                if ((StackWaitBlock.flag & 2) == 0)
                    break;
                YieldProcessor();
            }
            if (InterlockedBitTestAndReset((volatile LONG*)&StackWaitBlock.flag, 1))
            {
                NtWaitForKeyedEvent(GlobalKeyedEventHandle, (PVOID)&StackWaitBlock, 0, NULL);
            }
        }
        else
        {
            if (InterlockedCompareExchange((volatile size_t*)SRWLock, SRWLockOld | SRWLOCK_Locked, SRWLockOld) == SRWLockOld)
            {
                return;
            }
            YieldProcessor();
        }
    }
}

BOOLEAN
WINAPI
TryAcquireSRWLockExclusiveXP(_Inout_ PSRWLOCK SRWLock)
{
    return InterlockedBitTestAndSet((volatile LONG_PTR*)SRWLock, SRW_LOCKED_BIT);
}

BOOL
WINAPI
SetThreadStackGuaranteeXP(ULONG *size)
{
    ULONG prev_size = NtTeb()->dwordF78.GuaranteedStackBytes;
    ULONG new_size = (*size + 4095) & ~4095;

    /* at least 2 pages on 64-bit */
    if (sizeof(void *) > sizeof(int) && new_size) new_size = max( new_size, 8192 );

    *size = prev_size;
    if (new_size >= (char *)NtTeb()->StackBase - (char *)NtTeb()->DeallocationStack)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    if (new_size > prev_size) NtTeb()->dwordF78.GuaranteedStackBytes = (new_size + 4095) & ~4095;
    return TRUE;
}

VOID WINAPI stub() { RaiseStatus(STATUS_ACCESS_VIOLATION); }

BOOL WINAPI DllMain(
    HINSTANCE _hinstDLL,  // handle to DLL module
    DWORD _fdwReason,     // reason for calling function
    LPVOID _lpReserved)   // reserved
{
    switch (_fdwReason) {
	case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        {
            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
            NtOpenKeyedEvent = (NTOPENKEYEDEVENT)GetProcAddress(ntdll, "NtOpenKeyedEvent");
            NtReleaseKeyedEvent = (NTRELEASEKEYEDEVENT)GetProcAddress(ntdll, "NtReleaseKeyedEvent");
            NtWaitForKeyedEvent = (NTWAITFORKEYEDEVENT)GetProcAddress(ntdll, "NtWaitForKeyedEvent");
        }
        break;
    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;
    case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
        break;
    }
    return TRUE; // Successful.
}