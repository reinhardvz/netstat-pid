#include <windows.h>
#include <tchar.h>

#include <Iptypes.h>
#include <Iphlpapi.h>


typedef struct _MIB_TCPROW_EX {
	DWORD dwState; // MIB_TCP_STATE_*
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwRemoteAddr;
	DWORD dwRemotePort;
	DWORD dwProcessId;
} MIB_TCPROW_EX, *PMIB_TCPROW_EX;

typedef struct _MIB_TCPTABLE_EX{
	DWORD dwNumEntries;
	MIB_TCPROW_EX table[ANY_SIZE];
} MIB_TCPTABLE_EX, *PMIB_TCPTABLE_EX;

typedef struct _MIB_UDPROW_EX{
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwProcessId;
} MIB_UDPROW_EX, *PMIB_UDPROW_EX;

typedef struct _MIB_UDPTABLE_EX{
	DWORD dwNumEntries;
	MIB_UDPROW_EX table[ANY_SIZE];
} MIB_UDPTABLE_EX, *PMIB_UDPTABLE_EX;

#ifndef TCP_TABLE_CLASS

typedef enum  {
  TCP_TABLE_BASIC_LISTENER,
  TCP_TABLE_BASIC_CONNECTIONS,
  TCP_TABLE_BASIC_ALL,
  TCP_TABLE_OWNER_PID_LISTENER,
  TCP_TABLE_OWNER_PID_CONNECTIONS,
  TCP_TABLE_OWNER_PID_ALL,
  TCP_TABLE_OWNER_MODULE_LISTENER,
  TCP_TABLE_OWNER_MODULE_CONNECTIONS,
  TCP_TABLE_OWNER_MODULE_ALL 
} TCP_TABLE_CLASS, *PTCP_TABLE_CLASS;

#endif

#ifndef ANY_SIZE
#define ANY_SIZE 1
#endif

#ifndef TCPIP_OWNING_MODULE_SIZE
#define TCPIP_OWNING_MODULE_SIZE 16
#endif

static char TcpState[][32] = {   
    "???",   
    "CLOSED",   
	"LISTENING",   
	"SYN_SENT",   
	"SYN_RCVD",   
	"ESTABLISHED",   
	"FIN_WAIT1",   
	"FIN_WAIT2",   
	"CLOSE_WAIT",   
	"CLOSING",   
	"LAST_ACK",   
	"TIME_WAIT",   
	"DELETE_TCB"  
};   

#ifndef UDP_TABLE_CLASS
typedef enum  {
  UDP_TABLE_BASIC,
  UDP_TABLE_OWNER_PID,
  UDP_TABLE_OWNER_MODULE 
} UDP_TABLE_CLASS, *PUDP_TABLE_CLASS;
#endif

#define NT_SUCCESS(Status)            ((NTSTATUS)(Status) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH        ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define SystemHandleInformation 16

typedef LONG  NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
	NTSTATUS    Status;
	ULONG        Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
	USHORT        Length;
	USHORT        MaximumLength;
	PWSTR        Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
}ANSI_STRING,*PANSI_STRING;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING          ObjectName;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;


typedef struct _OBJECT_ATTRIBUTES {

	ULONG        Length;
	HANDLE        RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG        Attributes;
	PVOID        SecurityDescriptor;
	PVOID        SecurityQualityOfService;

} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;  

typedef struct _TDI_CONNECTION_INFO { 

	ULONG          State; 
	ULONG          Event; 
	ULONG          TransmittedTsdus; 
	ULONG          ReceivedTsdus; 
	ULONG          TransmissionErrors; 
	ULONG          ReceiveErrors; 
	LARGE_INTEGER  Throughput; 
	LARGE_INTEGER  Delay; 
	ULONG          SendBufferSize; 
	ULONG          ReceiveBufferSize; 
	BOOLEAN        Unreliable; 

} TDI_CONNECTION_INFO, *PTDI_CONNECTION_INFO; 

typedef struct _TDI_CONNECTION_INFORMATION { 

	LONG   UserDataLength; 
	PVOID  UserData; 
	LONG   OptionsLength; 
	PVOID  Options; 
	LONG   RemoteAddressLength; 
	PVOID  RemoteAddress; 

} TDI_CONNECTION_INFORMATION, *PTDI_CONNECTION_INFORMATION; 


//* Structure of an entity ID.
typedef struct TDIEntityID {
	
	ULONG		tei_entity;
	ULONG		tei_instance;

} TDIEntityID;

//* Structure of an object ID.
typedef struct TDIObjectID {
	
	TDIEntityID	toi_entity;
	ULONG		toi_class;
	ULONG		toi_type;
	ULONG		toi_id;

} TDIObjectID;


#define EXTRACT_SHORT(p)\
	((USHORT)\
	((USHORT)*((UCHAR *)p+0)<<8|\
	(USHORT)*((UCHAR *)p+1)<<0))


#define EXTRACT_LONG(p)\
	((UINT)*((UCHAR *)p+0)<<24|\
	(UINT)*((UCHAR *)p+1)<<16|\
	(UINT)*((UCHAR *)p+2)<<8|\
	(UINT)*((UCHAR *)p+3)<<0)


#define	MAX_TDI_ENTITIES			4096

#define	CONTEXT_SIZE				16

#define	CO_TL_ENTITY				0x400
#define	INFO_CLASS_PROTOCOL			0x200
#define	INFO_TYPE_PROVIDER			0x100

#define TCP_MIB_ADDRTABLE_ENTRY_ID    0x101
#define	INFO_TYPE_CONNECTION		0x300

#define	CO_TL_TCP					0x404

#define  UDP L"\\Device\\Udp"
#define  TCP L"\\Device\\Tcp" //11*2

//
// QueryInformationEx IOCTL. The return buffer is passed as the OutputBuffer
// in the DeviceIoControl request. This structure is passed as the
// ITKutBuffer.
//
struct tcp_request_query_information_ex {
	TDIObjectID   ID;                     // object ID to query.
	ULONG *     Context[CONTEXT_SIZE/sizeof(ULONG *)];  // multi-request context. Zeroed
	// for the first request.
};
typedef struct tcp_request_query_information_ex TCP_REQUEST_QUERY_INFORMATION_EX, *PTCP_REQUEST_QUERY_INFORMATION_EX;


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;


typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG                   Unknown1;
	ACCESS_MASK             DesiredAccess;
	ULONG                   HandleCount;
	ULONG                   ReferenceCount;
	ULONG                   PagedPoolQuota;
	ULONG                   NonPagedPoolQuota;
	BYTE                    Unknown2[32];
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,			// Result is OBJECT_BASIC_INFORMATION structure
	ObjectNameInformation,			// Result is OBJECT_NAME_INFORMATION structure
	ObjectTypeInformation,			// Result is OBJECT_TYPE_INFORMATION structure
	ObjectAllInformation,			// Result is OBJECT_ALL_INFORMATION structure
	ObjectDataInformation			// Result is OBJECT_DATA_INFORMATION structure
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;



typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING          TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE               PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_TYPES_INFORMATION {
	ULONG NumberOfTypes;
	OBJECT_TYPE_INFORMATION TypeInformation[1];
} OBJECT_ALL_TYPES_INFORMATION, *POBJECT_ALL_TYPES_INFORMATION;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _PROCESS_PARAMETERS {
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING		  Unknown3;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
} PROCESS_PARAMETRS, *PPROCESS_PARAMETRS;


typedef struct _PROCESS_ENVIRONMENT_BLOCK
{
	//BOOL				InheritedAddressSpace;
	//BOOL				ReadImageFileExecOptions;
	WORD					unknown0;
	//BOOL				BeingDebugged;
	//BOOL				Spare;
	WORD					unknown1;
	//HANDLE				Mutant;
	DWORD					unknown2;

	PVOID					ImageBaseAddress;
	//PVOID				LoaderData;
	PHANDLE				handles;
	PPROCESS_PARAMETRS    ProcessParameters;

	HANDLE                ProcessHeap;                 
	DWORD                 FastPebLock;

	PVOID					FastPebLockRoutine;
	PVOID					FastPebUnlockRoutine;
	PVOID					*FastPebLockCount;
	PVOID                 Environment;
	PHANDLE				heaps;
	PVOID			        CriticalSection;
	DWORD                 ver;
} PROCESS_ENVIRONMENT_BLOCK, *PPROCESS_ENVIRONMENT_BLOCK;

typedef PROCESS_ENVIRONMENT_BLOCK PEB, *PPEB;


typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS	ExitStatus;
	PPEB		PebBaseAddress;
	ULONG		AffinityMask;
	ULONG		BasePriority; 
	ULONG		UniqueProcessId;
	ULONG		InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
						  IN PVOID ApcContext,
						  IN PIO_STATUS_BLOCK IoStatusBlock,
						  IN ULONG Reserved
						  );

//#define NTAPI _stdcall

typedef NTSTATUS (NTAPI * PFNNTQUERYSYSTEMINFORMATION)(
						 IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
						 OUT PVOID SystemInformation,
						 IN ULONG SystemInformationLength,
						 OUT PULONG ReturnLength OPTIONAL
						 );

typedef NTSTATUS(NTAPI * PFNNTQUERYOBJECT)(
					IN HANDLE               ObjectHandle OPTIONAL,
					IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
					OUT PVOID               ObjectInformation,
					IN ULONG                Length,
					OUT PULONG              ResultLength
					);

typedef NTSTATUS (NTAPI *PFNNTDEVICEIOCONTROLFILE)(
					  IN HANDLE               FileHandle,
					  IN HANDLE               Event OPTIONAL,
					  IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
					  IN PVOID                ApcContext OPTIONAL,
					  OUT PIO_STATUS_BLOCK    IoStatusBlock,
					  IN ULONG                IoControlCode,
					  IN PVOID                InputBuffer OPTIONAL,
					  IN ULONG                InputBufferLength,
					  OUT PVOID               OutputBuffer OPTIONAL,
					  IN ULONG                OutputBufferLength );


typedef NTSTATUS(NTAPI *PFNNTQUERYINFORMATIONPROCESS)(
								HANDLE ProcessHandle,
								PROCESSINFOCLASS ProcessInformationClass,
								PVOID ProcessInformation,
								ULONG ProcessInformationLength,
								PULONG ReturnLength
								);

typedef DWORD (WINAPI *PROCALLOCATEANDGETTCPEXTABLEFROMSTACK)(PMIB_TCPTABLE_EX*,BOOL,HANDLE,DWORD,DWORD);


typedef DWORD (WINAPI *PROCALLOCATEANDGETUDPEXTABLEFROMSTACK)(PMIB_UDPTABLE_EX*,BOOL,HANDLE,DWORD,DWORD);


typedef DWORD (WINAPI *PROCGETEXTENDEDTCPTABLE)(PVOID,PDWORD,BOOL,ULONG,TCP_TABLE_CLASS,ULONG);


typedef DWORD (WINAPI *PROCGETEXTENDEDUDPTABLE)(PVOID,PDWORD,BOOL,ULONG,UDP_TABLE_CLASS,ULONG);


typedef struct _OBJECT_NAME_PRIVATE {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
	WCHAR  ObjName[sizeof(TCP)/sizeof(WCHAR)];
} OBJECT_NAME_PRIVATE, *POBJECT_NAME_PRIVATE;


typedef struct _TResult {
	DWORD pid;
} TResult;

DWORD QueryDevice(HANDLE hPort);

BOOL LoadPrivilege(const TCHAR* Privilege);

BOOL GetPortFromTcpHandle(DWORD ProcessId,HANDLE hCurrent);

DWORD OpenPort();

PWSTR GetProcessPathByPID(DWORD PID);

char* TcpConvert2State(DWORD dwState);

BOOL LoadExIpHelperPortTableProcedures(void);

#ifndef GETPROC
#define GETPROC(dll, type, name)	(type) GetProcAddress(dll, name)
#endif


typedef BOOL (WINAPI *fnVerifyVersionInfo)(LPOSVERSIONINFOEX, DWORD, DWORDLONG);
typedef ULONGLONG (WINAPI *fnVerSetConditionMask)(ULONGLONG, DWORD, BYTE);

BOOL yjVerifyVersionInfo(LPOSVERSIONINFOEX lpVersionInfo, DWORD dwTypeMask, DWORDLONG dwConditionMask, BOOL *bVerified);
BOOL IsWin2K();
BOOL IsWinXP();
BOOL IsWinVistaOrHigher();


























