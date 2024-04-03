#include <windows.h>
#include <intrin.h>

typedef PRTL_RUN_ONCE LPINIT_ONCE;
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_INVALID_PARAMETER_2 0xC00000F0
#define STATUS_INVALID_PARAMETER_3 0xC00000F1
#define STATUS_INVALID_OWNER 0xC000005A
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035
#define STATUS_BUFFER_OVERFLOW 0x80000005

// TODO:
// from: https://github.com/Chuyu-Team/YY-Thunks/blob/master/ThunksList.md

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

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
typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
}OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,   // 2
	FileBothDirectoryInformation,   // 3
	FileBasicInformation,           // 4
	FileStandardInformation,        // 5
	FileInternalInformation,        // 6
	FileEaInformation,              // 7
	FileAccessInformation,          // 8
	FileNameInformation,            // 9
	FileRenameInformation,          // 10
	FileLinkInformation,            // 11
	FileNamesInformation,           // 12
	FileDispositionInformation,     // 13
	FilePositionInformation,        // 14
	FileFullEaInformation,          // 15
	FileModeInformation,            // 16
	FileAlignmentInformation,       // 17
	FileAllInformation,             // 18
	FileAllocationInformation,      // 19
	FileEndOfFileInformation,       // 20
	FileAlternateNameInformation,   // 21
	FileStreamInformation,          // 22
	FilePipeInformation,            // 23
	FilePipeLocalInformation,       // 24
	FilePipeRemoteInformation,      // 25
	FileMailslotQueryInformation,   // 26
	FileMailslotSetInformation,     // 27
	FileCompressionInformation,     // 28
	FileObjectIdInformation,        // 29
	FileCompletionInformation,      // 30
	FileMoveClusterInformation,     // 31
	FileQuotaInformation,           // 32
	FileReparsePointInformation,    // 33
	FileNetworkOpenInformation,     // 34
	FileAttributeTagInformation,    // 35
	FileTrackingInformation,        // 36
	FileIdBothDirectoryInformation, // 37
	FileIdFullDirectoryInformation, // 38
	FileValidDataLengthInformation, // 39
	FileShortNameInformation,       // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,       // 42
	FileIoPriorityHintInformation,           // 43
	FileSfioReserveInformation,              // 44
	FileSfioVolumeInformation,               // 45
	FileHardLinkInformation,                 // 46
	FileProcessIdsUsingFileInformation,      // 47
	FileNormalizedNameInformation,           // 48
	FileNetworkPhysicalNameInformation,      // 49
	FileIdGlobalTxDirectoryInformation,      // 50
	FileIsRemoteDeviceInformation,           // 51
	FileUnusedInformation,                   // 52
	FileNumaNodeInformation,                 // 53
	FileStandardLinkInformation,             // 54
	FileRemoteProtocolInformation,           // 55

	//
	//  These are special versions of these operations (defined earlier)
	//  which can be used by kernel mode drivers only to bypass security
	//  access checks for Rename and HardLink operations.  These operations
	//  are only recognized by the IOManager, a file system should never
	//  receive these.
	//
	FileRenameInformationBypassAccessCheck,  // 56
	FileLinkInformationBypassAccessCheck,    // 57
	FileVolumeNameInformation,               // 58
	FileIdInformation,                       // 59
	FileIdExtdDirectoryInformation,          // 60
	FileReplaceCompletionInformation,        // 61
	FileHardLinkFullIdInformation,           // 62
	FileIdExtdBothDirectoryInformation,      // 63
	FileMaximumInformation

} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;


typedef NTSTATUS (NTAPI *pNtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);
typedef NTSTATUS (NTAPI *pNtQueryInformationFile)(
    HANDLE FileHandle, 
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);
NTOPENKEYEDEVENT NtOpenKeyedEvent;
NTRELEASEKEYEDEVENT NtReleaseKeyedEvent;
NTWAITFORKEYEDEVENT NtWaitForKeyedEvent;
ULONG (NTAPI*RtlNtStatusToDosError)(IN NTSTATUS status);
pNtQueryObject NtQueryObject;
pNtQueryInformationFile NtQueryInformationFile;

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


typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

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

DWORD __fastcall NtStatusToDosError(
    _In_ NTSTATUS Status
)
{
    if (STATUS_TIMEOUT == Status)
    {
        return ERROR_TIMEOUT;
    }
    return RtlNtStatusToDosError(Status);
}

DWORD __fastcall BaseSetLastNTError(
    NTSTATUS Status
)
{
    auto lStatus = NtStatusToDosError(Status);
    SetLastError(lStatus);
    return lStatus;
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

size_t __fastcall RtlpRunOnceWaitForInit(
    size_t Current,
    LPINIT_ONCE lpInitOnce
)
{
    HANDLE GlobalKeyedEventHandle = GetGlobalKeyedEventHandle();
    do
    {
        const auto Old = Current;
        Current = Current & ~(size_t)(RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC);
        const auto New = ((size_t)(&Current) & ~ (size_t)(RTL_RUN_ONCE_ASYNC)) | RTL_RUN_ONCE_CHECK_ONLY;
        const auto Last = InterlockedCompareExchange((volatile size_t*)lpInitOnce, New, Old);
        if (Last == Old)
        {
            NtWaitForKeyedEvent(GlobalKeyedEventHandle, &Current, 0, NULL);
            Current = *(volatile size_t*)lpInitOnce;
        }
        else
        {
            Current = Last;
        }
    } while ((Current & (RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC)) == RTL_RUN_ONCE_CHECK_ONLY);
    return Current;
}

NTSTATUS __fastcall RtlRunOnceBeginInitialize(
    LPINIT_ONCE lpInitOnce,
    DWORD dwFlags,
    LPVOID* lpContext
)
{
    if ((dwFlags & ~(RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC))|| ((dwFlags- 1) & dwFlags))
    {
        return STATUS_INVALID_PARAMETER;
    }

    size_t Current = *(volatile size_t *)lpInitOnce;

    if ((Current & (RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC)) == RTL_RUN_ONCE_ASYNC)
    {
        InterlockedExchange((volatile size_t *)&lpInitOnce, dwFlags);
        if (lpContext)
            *lpContext = (LPVOID)(Current & ~(size_t)(RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC));

        return STATUS_SUCCESS;
    }

    if (dwFlags & RTL_RUN_ONCE_CHECK_ONLY)
    {
        return STATUS_UNSUCCESSFUL;
    }

    const size_t New = (dwFlags & RTL_RUN_ONCE_ASYNC) | RTL_RUN_ONCE_CHECK_ONLY;
    for (;;)
    {
        const size_t InitOnceData = Current & 3;
        if (InitOnceData == 0)
        {
            const size_t Last = InterlockedCompareExchange((volatile size_t *)lpInitOnce, New, Current);
            if (Last == Current)
                return STATUS_PENDING;

            Current = Last;
        }
        else if (InitOnceData == RTL_RUN_ONCE_CHECK_ONLY)
        {
            if (dwFlags & RTL_RUN_ONCE_ASYNC)
                return STATUS_INVALID_PARAMETER_2;

            Current = RtlpRunOnceWaitForInit(Current, lpInitOnce);
        }
        else
        {
            //疑惑？为什么微软要这样判断……
            if (Current != (RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC))
            {
                if (lpContext)
                    *lpContext = (LPVOID)(Current & ~(size_t)(RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC));

                return STATUS_SUCCESS;
            }

            return (dwFlags & RTL_RUN_ONCE_ASYNC) ? STATUS_PENDING : STATUS_INVALID_PARAMETER_2;
        }
    }
}

void __fastcall RtlpRunOnceWakeAll(size_t *pWake)
{
    HANDLE GlobalKeyedEventHandle = GetGlobalKeyedEventHandle();
    for (LPVOID WakeAddress = (LPVOID)(*pWake & ~(size_t)(RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC)); WakeAddress; )
    {
        LPVOID NextWakeAddress = *(LPVOID*)WakeAddress;
        NtReleaseKeyedEvent(GlobalKeyedEventHandle, WakeAddress, 0, NULL);
        WakeAddress = NextWakeAddress;
    }
}

LSTATUS __fastcall RtlRunOnceComplete(
    _Inout_ LPINIT_ONCE lpInitOnce,
    _In_ DWORD dwFlags,
    _In_opt_ LPVOID lpContext
)
{
    if ((dwFlags & ~(RTL_RUN_ONCE_ASYNC | RTL_RUN_ONCE_INIT_FAILED)) || ((dwFlags - 1) & dwFlags))
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    const auto dwNewFlags = (dwFlags ^ ~(dwFlags >> 1)) & 3 ^ dwFlags;

    if (lpContext && ((dwNewFlags & RTL_RUN_ONCE_ASYNC) == 0 || ((size_t)(lpContext) & (RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC))))
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    auto Current = *(volatile size_t*)lpInitOnce;
    auto New = ((size_t)(lpContext) & ~(size_t)(RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC)) | (dwNewFlags & RTL_RUN_ONCE_ASYNC);

    switch (Current & (RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC))
    {
    case RTL_RUN_ONCE_CHECK_ONLY:
        if ((dwNewFlags & RTL_RUN_ONCE_CHECK_ONLY) == 0)
        {
            return STATUS_INVALID_PARAMETER_2;
        }

        Current = InterlockedExchange((volatile size_t*)lpInitOnce, New);
        if ((Current & (RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC)) == RTL_RUN_ONCE_CHECK_ONLY)
        {
            RtlpRunOnceWakeAll(&Current);
            return STATUS_SUCCESS;
        }

        return STATUS_INVALID_OWNER;
        break;
    case RTL_RUN_ONCE_CHECK_ONLY | RTL_RUN_ONCE_ASYNC:
        if (dwNewFlags & RTL_RUN_ONCE_CHECK_ONLY)
        {
            return STATUS_INVALID_PARAMETER_2;
        }

        if (InterlockedCompareExchange((volatile size_t*)lpInitOnce, New, Current) == Current)
        {
            return STATUS_SUCCESS;
        }

        return STATUS_OBJECT_NAME_COLLISION;

        break;
    default:
        return STATUS_UNSUCCESSFUL;
        break;
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

BOOL
WINAPI
InitOnceBeginInitializeXP(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, LPVOID* lpContext)
{
    DWORD Status = RtlRunOnceBeginInitialize(lpInitOnce, dwFlags, lpContext);
    if (Status >= STATUS_SUCCESS)
    {
        *fPending = Status == STATUS_PENDING;
        return TRUE;
    }
    else
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }
}

BOOL
WINAPI
InitOnceCompleteXP(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext)
{
    DWORD Status = RtlRunOnceComplete(lpInitOnce, dwFlags, lpContext);
    if (Status >= 0)
    {
        return TRUE;
    }
    else
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }
}

static BOOL __fastcall BasepGetVolumeGUIDFromNTName(const UNICODE_STRING* NtName, wchar_t szVolumeGUID[MAX_PATH])
{
#define __szVolumeMountPointPrefix__ L"\\\\?\\GLOBALROOT"

    //一个设备名称 512 长度够多了吧？
    wchar_t szVolumeMountPoint[512];
    
    //检查缓冲区是否充足
    auto cbBufferNeed = sizeof(__szVolumeMountPointPrefix__) + NtName->Length;

    if (cbBufferNeed > sizeof(szVolumeMountPoint))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    
    memcpy(szVolumeMountPoint, __szVolumeMountPointPrefix__, sizeof(__szVolumeMountPointPrefix__) - sizeof(__szVolumeMountPointPrefix__[0]));
    memcpy((char*)szVolumeMountPoint + sizeof(__szVolumeMountPointPrefix__) - sizeof(__szVolumeMountPointPrefix__[0]), NtName->Buffer, NtName->Length);

    szVolumeMountPoint[cbBufferNeed / 2 - 1] = L'\0';

    return GetVolumeNameForVolumeMountPointW(szVolumeMountPoint, szVolumeGUID, MAX_PATH);

#undef __szVolumeMountPointPrefix__
}

static BOOL __fastcall BasepGetVolumeDosLetterNameFromNTName(const UNICODE_STRING* NtName, wchar_t szVolumeDosLetter[MAX_PATH])
{
    wchar_t szVolumeName[MAX_PATH];

    if (!BasepGetVolumeGUIDFromNTName(NtName, szVolumeName))
    {
        return FALSE;
    }

    DWORD cchVolumePathName = 0;

    if (!GetVolumePathNamesForVolumeNameW(szVolumeName, szVolumeDosLetter + 4, MAX_PATH - 4, &cchVolumePathName))
    {
        return FALSE;
    }

    szVolumeDosLetter[0] = L'\\';
    szVolumeDosLetter[1] = L'\\';
    szVolumeDosLetter[2] = L'?';
    szVolumeDosLetter[3] = L'\\';

    return TRUE;
}

BOOL
WINAPI
GetQueuedCompletionStatusExXP(HANDLE CompletionPort, LPOVERLAPPED_ENTRY lpCompletionPortEntries, ULONG ulCount, PULONG ulNumEntriesRemoved, DWORD dwMilliseconds, BOOL fAlertable)
{
    if (ulCount == 0 || lpCompletionPortEntries == 0 || ulNumEntriesRemoved == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *ulNumEntriesRemoved = 0;

    OVERLAPPED_ENTRY _Entry = lpCompletionPortEntries[0];
    
    if (fAlertable)
    {
        // 使用 WaitForSingleObjectEx 进行等待触发 APC
        DWORD _uStartTick = GetTickCount();
        for (;;)
        {
            const DWORD _uResult = WaitForSingleObjectEx(CompletionPort, dwMilliseconds, TRUE);
            if (_uResult == WAIT_OBJECT_0)
            {
                // 完成端口有数据了
                DWORD _bRet = GetQueuedCompletionStatus(CompletionPort, &_Entry.dwNumberOfBytesTransferred, &_Entry.lpCompletionKey, &_Entry.lpOverlapped, 0);
                if (_bRet)
                {
                    *ulNumEntriesRemoved = 1;
                    break;
                }

                if (GetLastError() != WAIT_TIMEOUT)
                {
                    return FALSE;
                }

                // 无限等待时无脑继续等即可。
                if (dwMilliseconds == INFINITE)
                {
                    continue;
                }

                // 计算剩余等待时间，如果剩余等待时间归零则返回
                const DWORD _uTickSpan = GetTickCount() - _uStartTick;
                if (_uTickSpan >= dwMilliseconds)
                {
                    SetLastError(WAIT_TIMEOUT);
                    return FALSE;
                }
                dwMilliseconds -= _uTickSpan;
                _uStartTick += _uTickSpan;
                continue;
            }
            else if (_uResult == WAIT_IO_COMPLETION || _uResult == WAIT_TIMEOUT)
            {
                // 很奇怪，微软原版遇到 APC唤醒直接会设置 LastError WAIT_IO_COMPLETION
                // 遇到超时，LastError WAIT_TIMEOUT（注意不是预期的 ERROR_TIMEOUT）不知道是故意还是有意。
                SetLastError(_uResult);
                return FALSE;
            }
            else if (_uResult == WAIT_ABANDONED)
            {
                SetLastError(ERROR_ABANDONED_WAIT_0);
                return FALSE;
            }
            else if (_uResult == WAIT_FAILED)
            {
                // LastError
                return FALSE;
            }
            else
            {
                // LastError ???
                return FALSE;
            }
        }

        return TRUE;
    }
    else
    {
        DWORD _bRet = GetQueuedCompletionStatus(CompletionPort, &_Entry.dwNumberOfBytesTransferred, &_Entry.lpCompletionKey, &_Entry.lpOverlapped, dwMilliseconds);
        if (_bRet)
        {
            *ulNumEntriesRemoved = 1;
        }
        return _bRet;
    }
}

BOOL
WINAPI
SetFileCompletionNotificationModesXP(HANDLE FileHandle, UCHAR Flags)
{
    // 初步看起来没有什么的，只是会降低完成端口的效率。
    // 至少需要 Vista才支持 FileIoCompletionNotificationInformation
    // 只能假定先返回成功。
    return TRUE;
}

DWORD
WINAPI
GetFinalPathNameByHandleWXP(
    HANDLE hFile,
    LPWSTR lpszFilePath,
    DWORD cchFilePath,
    DWORD dwFlags
    )
{
    //参数检查
    if (INVALID_HANDLE_VALUE == hFile)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }


    switch (dwFlags & (VOLUME_NAME_DOS | VOLUME_NAME_GUID | VOLUME_NAME_NONE | VOLUME_NAME_NT))
    {
    case VOLUME_NAME_DOS:
        break;
    case VOLUME_NAME_GUID:
        break;
    case VOLUME_NAME_NT:
        break;
    case VOLUME_NAME_NONE:
        break;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
        break;
    }

    UNICODE_STRING VolumeNtName = { 0 };

    wchar_t szVolumeRoot[MAX_PATH];
    szVolumeRoot[0] = L'\0';

    wchar_t* szLongPathNameBuffer = NULL;

    //目标所需的分区名称，不包含最后的 '\\'
    UNICODE_STRING TargetVolumeName = { 0 };
    //目标所需的文件名，开始包含 '\\'
    UNICODE_STRING TargetFileName = { 0 };

    HANDLE ProcessHeap = ((struct TEB_*)NtTeb())->ProcessEnvironmentBlock->ProcessHeap;
    LSTATUS lStatus = ERROR_SUCCESS;
    DWORD   cchReturn = 0;

    OBJECT_NAME_INFORMATION* pObjectName = NULL;
    ULONG cbObjectName = 528;

    FILE_NAME_INFORMATION* pFileNameInfo = NULL;
    ULONG cbFileNameInfo = 528;

    for (;;)
    {
        if (pObjectName)
        {
            OBJECT_NAME_INFORMATION* pNewBuffer = (OBJECT_NAME_INFORMATION*)(void *)HeapReAlloc(ProcessHeap, 0, pObjectName, cbObjectName);

            if (!pNewBuffer)
            {
                lStatus = ERROR_NOT_ENOUGH_MEMORY;
                goto __Exit;
            }

            pObjectName = pNewBuffer;
        }
        else
        {
            pObjectName = (OBJECT_NAME_INFORMATION*)HeapAlloc(ProcessHeap, 0, cbObjectName);

            if (!pObjectName)
            {
                //内存不足？
                lStatus = ERROR_NOT_ENOUGH_MEMORY;
                goto __Exit;
            }
        }

        NTSTATUS Status = NtQueryObject(hFile, ObjectNameInformation, pObjectName, cbObjectName, &cbObjectName);

        if (STATUS_BUFFER_OVERFLOW == Status)
        {
            continue;
        }
        else if (Status < 0)
        {
            lStatus = NtStatusToDosError(Status);

            goto __Exit;
        }
        else
        {
            break;
        }
    }

    for (;;)
    {
        if (pFileNameInfo)
        {
            FILE_NAME_INFORMATION* pNewBuffer = (FILE_NAME_INFORMATION*)HeapReAlloc(ProcessHeap, 0, pFileNameInfo, cbFileNameInfo);
            if (!pNewBuffer)
            {
                lStatus = ERROR_NOT_ENOUGH_MEMORY;
                goto __Exit;
            }

            pFileNameInfo = pNewBuffer;
        }
        else
        {
            pFileNameInfo = (FILE_NAME_INFORMATION*)HeapAlloc(ProcessHeap, 0, cbFileNameInfo);

            if (!pFileNameInfo)
            {
                //内存不足？
                lStatus = ERROR_NOT_ENOUGH_MEMORY;
                goto __Exit;
            }
        }

        IO_STATUS_BLOCK IoStatusBlock;

        NTSTATUS Status = NtQueryInformationFile(hFile, &IoStatusBlock, pFileNameInfo, cbFileNameInfo, FileNameInformation);

        if (STATUS_BUFFER_OVERFLOW == Status)
        {
            cbFileNameInfo = pFileNameInfo->FileNameLength + sizeof(FILE_NAME_INFORMATION);
            continue;
        }
        else if (Status < 0)
        {
            lStatus = NtStatusToDosError(Status);

            goto __Exit;
        }
        else
        {
            break;
        }
    }

    if (pFileNameInfo->FileName[0] != '\\')
    {
        lStatus = ERROR_ACCESS_DENIED;
        goto __Exit;
    }



    if (pFileNameInfo->FileNameLength >= pObjectName->Name.Length)
    {
        lStatus = ERROR_BAD_PATHNAME;
        goto __Exit;
    }

    VolumeNtName.Buffer = pObjectName->Name.Buffer;
    VolumeNtName.Length = VolumeNtName.MaximumLength = pObjectName->Name.Length - pFileNameInfo->FileNameLength + sizeof(wchar_t);


    if (VOLUME_NAME_NT & dwFlags)
    {
        //返回NT路径
        TargetVolumeName.Buffer = VolumeNtName.Buffer;
        TargetVolumeName.Length = TargetVolumeName.MaximumLength = VolumeNtName.Length - sizeof(wchar_t);
    }
    else if (VOLUME_NAME_NONE & dwFlags)
    {
        //仅返回文件名
    }
    else
    {
        if (VOLUME_NAME_GUID & dwFlags)
        {
            //返回分区GUID名称
            if (!BasepGetVolumeGUIDFromNTName(&VolumeNtName, szVolumeRoot))
            {
                lStatus = GetLastError();
                goto __Exit;
            }
        }
        else
        {
            //返回Dos路径
            if (!BasepGetVolumeDosLetterNameFromNTName(&VolumeNtName, szVolumeRoot))
            {
                lStatus = GetLastError();
                goto __Exit;
            }
        }

        TargetVolumeName.Buffer = szVolumeRoot;
        TargetVolumeName.Length = TargetVolumeName.MaximumLength = (wcslen(szVolumeRoot) - 1) * sizeof(szVolumeRoot[0]);
    }

    //将路径进行规范化
    if ((FILE_NAME_OPENED & dwFlags) == 0)
    {
        //由于 Windows XP不支持 FileNormalizedNameInformation，所以我们直接调用 GetLongPathNameW 获取完整路径。

        DWORD cbszVolumeRoot = TargetVolumeName.Length;

        if (szVolumeRoot[0] == L'\0')
        {
            //转换分区信息

            if (!BasepGetVolumeDosLetterNameFromNTName(&VolumeNtName, szVolumeRoot))
            {
                lStatus = GetLastError();

                if(lStatus == ERROR_NOT_ENOUGH_MEMORY)
                    goto __Exit;

                if (!BasepGetVolumeGUIDFromNTName(&VolumeNtName, szVolumeRoot))
                {
                    lStatus = GetLastError();
                    goto __Exit;
                }
            }

            cbszVolumeRoot = (wcslen(szVolumeRoot) - 1) * sizeof(szVolumeRoot[0]);
        }



        DWORD cbLongPathNameBufferSize = cbszVolumeRoot + pFileNameInfo->FileNameLength + 1024;

        szLongPathNameBuffer = (wchar_t*)HeapAlloc(ProcessHeap, 0, cbLongPathNameBufferSize);
        if (!szLongPathNameBuffer)
        {
            lStatus = ERROR_NOT_ENOUGH_MEMORY;
            goto __Exit;
        }

        DWORD cchLongPathNameBufferSize = cbLongPathNameBufferSize / sizeof(szLongPathNameBuffer[0]);

        memcpy(szLongPathNameBuffer, szVolumeRoot, cbszVolumeRoot);
        memcpy((char*)szLongPathNameBuffer + cbszVolumeRoot, pFileNameInfo->FileName, pFileNameInfo->FileNameLength);
        szLongPathNameBuffer[(cbszVolumeRoot + pFileNameInfo->FileNameLength) / sizeof(wchar_t)] = L'\0';

        for (;;)
        {
            DWORD result = GetLongPathNameW(szLongPathNameBuffer, szLongPathNameBuffer, cchLongPathNameBufferSize);

            if (result == 0)
            {
                //失败
                lStatus = GetLastError();
                goto __Exit;
            }
            else if (result >= cchLongPathNameBufferSize)
            {
                cchLongPathNameBufferSize = result + 1;

                wchar_t* pNewLongPathName = (wchar_t*)HeapReAlloc(ProcessHeap, 0, szLongPathNameBuffer, cchLongPathNameBufferSize * sizeof(wchar_t));
                if (!pNewLongPathName)
                {
                    lStatus = ERROR_NOT_ENOUGH_MEMORY;
                    goto __Exit;
                }

                szLongPathNameBuffer = pNewLongPathName;
        
            }
            else
            {
                //转换成功
                TargetFileName.Buffer = (wchar_t*)((char*)szLongPathNameBuffer + cbszVolumeRoot);
                TargetFileName.Length = TargetFileName.MaximumLength = result * sizeof(wchar_t) - cbszVolumeRoot;
                break;
            }
        }
    }
    else
    {
        //直接返回原始路径
        TargetFileName.Buffer = pFileNameInfo->FileName;
        TargetFileName.Length = TargetFileName.MaximumLength = pFileNameInfo->FileNameLength;
    }


    //返回结果，根目录 + 文件名 的长度
    cchReturn = (TargetVolumeName.Length + TargetFileName.Length) / sizeof(wchar_t);

    if (cchFilePath <= cchReturn)
    {
        //长度不足……

        cchReturn += 1;
    }
    else
    {
        //复制根目录
        memcpy(lpszFilePath, TargetVolumeName.Buffer, TargetVolumeName.Length);
        //复制文件名
        memcpy((char*)lpszFilePath + TargetVolumeName.Length, TargetFileName.Buffer, TargetFileName.Length);
        //保证字符串 '\0' 截断
        lpszFilePath[cchReturn] = L'\0';
    }

__Exit:
    if (pFileNameInfo)
        HeapFree(ProcessHeap, 0, pFileNameInfo);
    if (pObjectName)
        HeapFree(ProcessHeap, 0, pObjectName);
    if (szLongPathNameBuffer)
        HeapFree(ProcessHeap, 0, szLongPathNameBuffer);

    if (lStatus != ERROR_SUCCESS)
    {
        SetLastError(lStatus);
        return 0;
    }
    else
    {
        return cchReturn;
    }
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
            RtlNtStatusToDosError = (ULONG (NTAPI*)(IN NTSTATUS status))GetProcAddress(ntdll, "RtlNtStatusToDosError");
            NtQueryObject = (pNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
            NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(ntdll, "NtQueryInformationFile");
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