// netstat_pid.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"
#include "netstat_pid.h"
#include <Ws2tcpip.h>
#include <Mstcpip.h>

PFNNTQUERYSYSTEMINFORMATION pfnNtQuerySystemInformation = NULL;
PFNNTQUERYOBJECT pfnNtQueryObject = NULL;
//PFNRTLCOMPAREUNICODESTRING pfnRtlCompareUnicodeString = NULL;
//PFNRTLINITUNICODESTRING pfnRtlInitUnicodeString = NULL;
//PFNZWOPENFILE pfnZwOpenFile = NULL;
//PFNNTDUPLICATEOBJECT pfnNtDuplicateObject = NULL;
PFNNTDEVICEIOCONTROLFILE pfnNtDeviceIoControlFile = NULL;
//PFNRTLNTSTATUSTODOSERROR pfnRtlNtStatusToDosError = NULL;
PFNNTQUERYINFORMATIONPROCESS pfnNtQueryInformationProcess = NULL;

PROCALLOCATEANDGETTCPEXTABLEFROMSTACK lpfnAllocateAndGetTcpExTableFromStack = NULL;
PROCALLOCATEANDGETUDPEXTABLEFROMSTACK lpfnAllocateAndGetUdpExTableFromStack = NULL;
PROCGETEXTENDEDTCPTABLE lpfnGetExtendedTcpTable = NULL;
PROCGETEXTENDEDUDPTABLE lpfnGetExtendedUdpTable = NULL;

TResult ResultPorts[2][65535];

typedef LPTSTR (__stdcall *fnRtlIpv6AddressToString)(UCHAR*,LPTSTR);
fnRtlIpv6AddressToString TK_Ipv6AddressToStringA = NULL; 


DWORD QueryDevice(HANDLE hPort)
{

	TDI_CONNECTION_INFO TdiConnInfo = {0};
	TDI_CONNECTION_INFORMATION TdiConnInformation = {0};

	IO_STATUS_BLOCK IoStatusBlock = {0};

	NTSTATUS Status;

	HANDLE hEven = NULL;

	hEven = CreateEvent(0,1,0,0);

	TdiConnInformation.RemoteAddressLength= 3; 

	//Tdi
	Status  = pfnNtDeviceIoControlFile(
		hPort,
		hEven,
		NULL,
		NULL,
		&IoStatusBlock,
		0x210012, 
		&TdiConnInformation,
		sizeof(TdiConnInformation),
		&TdiConnInfo,
		sizeof(TdiConnInfo)
		);

	if(hEven != NULL) {
		CloseHandle(hEven);
		hEven = NULL;
	}

	if(!NT_SUCCESS(Status)) {
		//printf("%08X ",hPort);
		//SetLastError(RtlNtStatusToDosError(Status));
		//fprintf(stderr, "GetTdi, Erreur: %s", get_error());
		return 0;
	}

	//return (ntohs((WORD)TdiConnInfo.ReceivedTsdus));
	return EXTRACT_SHORT(&(TdiConnInfo.ReceivedTsdus));

}


BOOL LoadPrivilege(const TCHAR* Privilege)
{
	HANDLE hToken;
	LUID SEDebugNameValue;
	TOKEN_PRIVILEGES tkp;


	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		//fprintf(stderr, "OpenProcessToken, Erreur: %s", get_error());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, Privilege, &SEDebugNameValue)) {
		//fprintf(stderr, "LookupPrivilegeValue, Erreur: %s", get_error());
		CloseHandle(hToken);
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = SEDebugNameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		//fprintf(stderr, "LookupPrivilegeValue, Erreur: %s", get_error());
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}

BOOL GetPortFromTcpHandle(DWORD ProcessId,HANDLE hCurrent)
{
	POBJECT_NAME_INFORMATION pObjName;
	HANDLE hPort=NULL;
	DWORD Port;
	DWORD RequiredLength;
	NTSTATUS Status;
	HANDLE hProc=NULL;

	hProc = OpenProcess(PROCESS_DUP_HANDLE,	FALSE, ProcessId);

	if(hProc == INVALID_HANDLE_VALUE) {
		return 0;
	}
/*
1.	Status=NtDuplicateObject(hProc,hCurrent,(HANDLE)-1,
2.	&hPort, STANDARD_RIGHTS_ALL | GENERIC_ALL, FALSE, 0);
3.	CloseHandle(hProc);
4.
5.	if(NT_SUCCESS(Status))
6.*/
	if(DuplicateHandle(hProc, hCurrent,	(HANDLE)-1, &hPort, STANDARD_RIGHTS_ALL | GENERIC_ALL, FALSE,0)) {
		
		RequiredLength=sizeof(OBJECT_NAME_PRIVATE);
		pObjName = (POBJECT_NAME_INFORMATION) VirtualAlloc (NULL,RequiredLength,MEM_COMMIT,PAGE_READWRITE);

		Status = pfnNtQueryObject(hPort,ObjectNameInformation,pObjName, RequiredLength, &RequiredLength);

		if(NT_SUCCESS(Status)) {
			
			if(pObjName->ObjectName.Length == 11*2) { //len \device\tcp = 11
			
				Port = 0;
				pObjName->ObjectName.Buffer[pObjName->ObjectName.Length]='\0';

				if(wcscmp(pObjName->ObjectName.Buffer, TCP) == 0) {
					
					Port=QueryDevice(hPort);

					if(Port != 0) {
						ResultPorts[0][Port].pid=ProcessId;
					}
				}

				if(wcscmp(pObjName->ObjectName.Buffer,UDP ) == 0) {
					
					Port = QueryDevice(hPort);
					
					if(Port != 0) {
						ResultPorts[1][Port].pid=ProcessId;
					}
				}

			}
		}

		VirtualFree(pObjName,0, MEM_RELEASE);
		CloseHandle(hPort);
	}

	CloseHandle(hProc);

	return 1;			
}

DWORD OpenPort()
{
	DWORD i;
	NTSTATUS Status;

	PSYSTEM_HANDLE_INFORMATION HandleInfo;
	DWORD RequiredLength;
	HANDLE hPort=NULL,hProc=NULL;

	RequiredLength = 1000 * sizeof(SYSTEM_HANDLE_INFORMATION);
	HandleInfo = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL,RequiredLength,MEM_COMMIT,PAGE_READWRITE);

	if (HandleInfo == NULL)
		return 0;

	do {

		Status = pfnNtQuerySystemInformation( (SYSTEM_INFORMATION_CLASS)SystemHandleInformation, HandleInfo, RequiredLength, NULL);
		if(NT_SUCCESS(Status)) {
			break;
		}

		RequiredLength += 1000*sizeof(SYSTEM_HANDLE_INFORMATION);
		VirtualFree(HandleInfo,0,MEM_RELEASE);

		HandleInfo = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc (NULL,RequiredLength,MEM_COMMIT,PAGE_READWRITE);
		if(HandleInfo == NULL) {
			return 0;
		}


	} while (Status == STATUS_INFO_LENGTH_MISMATCH);

	for( i = 0; i< HandleInfo->NumberOfHandles; i++) {
		GetPortFromTcpHandle((DWORD)HandleInfo->Handles[i].UniqueProcessId,	(HANDLE)HandleInfo->Handles[i].HandleValue);
	}

	VirtualFree(HandleInfo,0,MEM_RELEASE);

	return 1;
}

// 내부 메모리 할당 함수 
// 외부에서 해제 필요.

PWSTR GetProcessPathByPID(DWORD PID)
{
	HANDLE hMyProc;
	SIZE_T dwRealReaded;

	PROCESS_BASIC_INFORMATION ProcessInfo;
	PEB peb;
	//PPEB ppeb;
	PROCESS_PARAMETRS	ProcessParm;
	PWSTR PathBuf;

	PathBuf = (PWSTR)LocalAlloc(LMEM_FIXED|LMEM_ZEROINIT,MAX_PATH*sizeof(WCHAR*));

	hMyProc=OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,FALSE,PID);

	if(hMyProc == INVALID_HANDLE_VALUE) {
		return 0;
	}

	if(pfnNtQueryInformationProcess(hMyProc , ProcessBasicInformation, &ProcessInfo, sizeof(ProcessInfo), 0) == 0) {
		
		ReadProcessMemory(hMyProc,ProcessInfo.PebBaseAddress, &peb, sizeof(PEB), &dwRealReaded);

		/*__asm
		1.    {
		2.        mov     eax, fs:[0x30]
		3.		mov     ppeb, eax //parm
		4.
		5.    }
		6.	peb = *ppeb;
		7.*/
		if(dwRealReaded == sizeof(PEB)) {
			ReadProcessMemory(hMyProc,peb.ProcessParameters,&ProcessParm,sizeof(PROCESS_PARAMETRS) , &dwRealReaded);
		}

		if(dwRealReaded == sizeof(PROCESS_PARAMETRS)) {
			ReadProcessMemory(hMyProc, ProcessParm.ImagePathName.Buffer, PathBuf, ProcessParm.ImagePathName.Length, &dwRealReaded);
		}

	}

	CloseHandle(hMyProc);

	return PathBuf;
}


char* TcpConvert2State(DWORD dwState)
{
	switch(dwState) {
		case MIB_TCP_STATE_CLOSED:
			return "CLOSED";
		case MIB_TCP_STATE_LISTEN:
			return "LISTENING";
		case MIB_TCP_STATE_SYN_SENT:
			return "SYN_SENT";
		case MIB_TCP_STATE_SYN_RCVD:
			return "SYN_RECEIVED";
		case MIB_TCP_STATE_ESTAB:
			return "ESTABLISHED";
		case MIB_TCP_STATE_FIN_WAIT1:
			return "FIN_WAIT1";
		case MIB_TCP_STATE_FIN_WAIT2:
			return "FIN_WAIT2";
		case MIB_TCP_STATE_CLOSE_WAIT:
			return "CLOSE_WAIT";
		case MIB_TCP_STATE_CLOSING:
			return "CLOSING";
		case MIB_TCP_STATE_LAST_ACK:
			return "LAST_ACK";
		case MIB_TCP_STATE_TIME_WAIT:
			return "TIME_WAIT";
		case MIB_TCP_STATE_DELETE_TCB:
			return "DELETE_TCB";
		default:
			return "UNKNOWN";
	}
}

BOOL LoadExIpHelperPortTableProcedures(void)
{
	HMODULE hModule, hModule0;
	
	hModule = LoadLibrary(_T("iphlpapi.dll"));
	if (hModule == NULL)
		return FALSE;
	
	if(TRUE == IsWin2K()) {
		hModule0 = LoadLibrary(_T("ntdll.dll"));
		if(hModule0 == NULL) {
			OutputDebugString(_T("ntdll.dll LoadLibrary Fail\n"));	
			return FALSE;
		} else {
			pfnNtQuerySystemInformation = (PFNNTQUERYSYSTEMINFORMATION)GetProcAddress(hModule0, "NtQuerySystemInformation");
			if(pfnNtQuerySystemInformation == NULL) {
				OutputDebugString(_T("pfnNtQuerySystemInformation Get Fail\n"));
				return FALSE;
			}
			pfnNtQueryObject = (PFNNTQUERYOBJECT)GetProcAddress(hModule0, "NtQueryObject");
			if(pfnNtQueryObject == NULL) {
				OutputDebugString(_T("NtQueryObject Get Fail\n"));
				return FALSE;
			}
			pfnNtDeviceIoControlFile = (PFNNTDEVICEIOCONTROLFILE)GetProcAddress(hModule0, "NtDeviceIoControlFile");
			if(pfnNtDeviceIoControlFile == NULL) {
				OutputDebugString(_T("NtDeviceIoControlFile Get Fail\n"));
				return FALSE;
			}
			pfnNtQueryInformationProcess = (PFNNTQUERYINFORMATIONPROCESS)GetProcAddress(hModule0, "NtQueryInformationProcess");
			if(pfnNtQueryInformationProcess == NULL) {
				OutputDebugString(_T("NtQueryInformationProcess Get Fail\n"));
				return FALSE;
			}
		}
		//OutputDebugString(_T("get success\n"));
		return TRUE;
	} else if(TRUE == IsWinXP()) {
		// XP and later
		lpfnAllocateAndGetTcpExTableFromStack = (PROCALLOCATEANDGETTCPEXTABLEFROMSTACK)GetProcAddress(hModule,"AllocateAndGetTcpExTableFromStack");
		if (lpfnAllocateAndGetTcpExTableFromStack == NULL)
			return FALSE;

		// XP and later
		lpfnAllocateAndGetUdpExTableFromStack = (PROCALLOCATEANDGETUDPEXTABLEFROMSTACK)GetProcAddress(hModule,"AllocateAndGetUdpExTableFromStack");
		if (lpfnAllocateAndGetUdpExTableFromStack == NULL)
			return FALSE;

	} else {
		// Vista
		//GetExtendedTcpTable 
		lpfnGetExtendedTcpTable = (PROCGETEXTENDEDTCPTABLE)GetProcAddress(hModule, "GetExtendedTcpTable");
		if(lpfnGetExtendedTcpTable == NULL)
			return FALSE;

		//GetExtendedUdpTable 
		lpfnGetExtendedUdpTable = (PROCGETEXTENDEDUDPTABLE)GetProcAddress(hModule, "GetExtendedUdpTable");
		if(lpfnGetExtendedUdpTable == NULL) 
			return FALSE;

		HINSTANCE hinstLib;

		hinstLib = LoadLibraryA("ntdll.dll"); 
		if (hinstLib != NULL) { 
			TK_Ipv6AddressToStringA = (fnRtlIpv6AddressToString) GetProcAddress(hinstLib, "RtlIpv6AddressToStringA"); 
		}
	}
	
	return TRUE;
}

BOOL yjVerifyVersionInfo(LPOSVERSIONINFOEX lpVersionInfo, DWORD dwTypeMask, DWORDLONG dwConditionMask, BOOL *bVerified)
{
	BOOL					bRet = FALSE;
	HINSTANCE				hDll = NULL;
	fnVerifyVersionInfo		FVerifyVersionInfo;
	fnVerSetConditionMask	FVerSetConditionMask;

	hDll = LoadLibrary(_T("kernel32.dll"));
	if(hDll != NULL)
	{
		FVerifyVersionInfo = GETPROC(hDll, fnVerifyVersionInfo, "VerifyVersionInfoA");
		FVerSetConditionMask = GETPROC(hDll, fnVerSetConditionMask, "VerSetConditionMask");

		if(FVerifyVersionInfo != NULL && FVerSetConditionMask != NULL)
		{
			dwConditionMask = 0;
			if(dwTypeMask & VER_MAJORVERSION)
				dwConditionMask = FVerSetConditionMask(dwConditionMask, VER_MAJORVERSION, VER_EQUAL);

			if(dwTypeMask & VER_MINORVERSION)
				dwConditionMask = FVerSetConditionMask(dwConditionMask, VER_MINORVERSION, VER_EQUAL);

			if(dwTypeMask & VER_PLATFORMID)
				dwConditionMask = FVerSetConditionMask(dwConditionMask, VER_PLATFORMID, VER_EQUAL);

			if(dwTypeMask & VER_PRODUCT_TYPE)
				dwConditionMask = FVerSetConditionMask(dwConditionMask, VER_PRODUCT_TYPE, VER_EQUAL);


			*bVerified = FVerifyVersionInfo(lpVersionInfo, dwTypeMask, dwConditionMask);
			bRet = TRUE;
		}
		FreeLibrary(hDll);
	}

	return bRet;
}

BOOL IsWin2K()
{
	OSVERSIONINFOEX	osi;
	DWORDLONG		dwlConditionMask = 0;
	BOOL			bRet = FALSE;
	BOOL			bVerified = FALSE;
	
	ZeroMemory(&osi, sizeof(OSVERSIONINFOEX));
	osi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	osi.dwMajorVersion = 5;
	osi.dwMinorVersion = 0;
	osi.dwPlatformId = VER_PLATFORM_WIN32_NT;
	
	bRet = yjVerifyVersionInfo(&osi, VER_MAJORVERSION | VER_MINORVERSION | VER_PLATFORMID, dwlConditionMask, &bVerified);
	if(bRet == TRUE)
		return bVerified;
	
	osi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if(GetVersionEx((OSVERSIONINFO *) &osi) == 0)
	{
		osi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		if(GetVersionEx((OSVERSIONINFO *) &osi) == 0)
			return 0;
	}	return	(osi.dwMajorVersion == 5) && (osi.dwMinorVersion == 0) &&
		(osi.dwPlatformId == VER_PLATFORM_WIN32_NT);
}

BOOL IsWinXP()
{
	OSVERSIONINFOEX	osi;
	DWORDLONG		dwlConditionMask = 0;
	BOOL			bRet = FALSE;
	BOOL			bVerified = FALSE;
	
	ZeroMemory(&osi, sizeof(OSVERSIONINFOEX));
	osi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	osi.dwMajorVersion = 5;
	osi.dwMinorVersion = 1;
	osi.dwPlatformId = VER_PLATFORM_WIN32_NT;
	
	bRet = yjVerifyVersionInfo(&osi, VER_MAJORVERSION | VER_MINORVERSION | VER_PLATFORMID, dwlConditionMask, &bVerified);
	if(bRet == TRUE)
		return bVerified;
	
	osi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if(GetVersionEx((OSVERSIONINFO *) &osi) == 0)
	{
		osi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		if(GetVersionEx((OSVERSIONINFO *) &osi) == 0)
			return 0;
	}	return	(osi.dwMajorVersion == 5) && (osi.dwMinorVersion == 1) &&
		(osi.dwPlatformId == VER_PLATFORM_WIN32_NT) && (osi.wProductType == VER_NT_WORKSTATION);
}

BOOL IsWinVistaOrHigher()
{

	OSVERSIONINFO osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	
	GetVersionEx(&osvi);
	
	return	((osvi.dwMajorVersion >= 6)) ? TRUE : FALSE ;

}


int _tmain(int argc, _TCHAR* argv[])
{
	BOOLEAN bRet = TRUE;
	PMIB_TCPTABLE_EX lpBuffer = NULL;
	PMIB_UDPTABLE_EX lpBuffer1 = NULL;
	
	PMIB_TCPTABLE_OWNER_MODULE tcpTable = NULL; 
	PMIB_UDPTABLE_OWNER_MODULE udpTable = NULL; 
	PMIB_TCP6TABLE_OWNER_MODULE tcp6Table = NULL;
	PMIB_UDP6TABLE_OWNER_MODULE udp6Table = NULL; 

	DWORD tcpsize = 0, udpsize = 0, i=0, tcp6size =0, udp6size =0;
	DWORD dwLastError=0,dwSize=0;

	if (!LoadExIpHelperPortTableProcedures()) {
		OutputDebugString(_T("InsertAllSuspiciousProcess fail... LoadExIpHelperPortTableProcedures error\n"));
		return FALSE;
	} else {

		if(TRUE == IsWin2K()) {
			
			if(!LoadPrivilege(SE_DEBUG_NAME)) {
				OutputDebugString(_T("InsertAllSuspiciousProcess fail... LoadPrivilege error\n"));
				return FALSE;
			} else {
				
				if(OpenPort())	{
					
					//printf("Pid    Port   Proto  Path\n\n");
					int i;
					for( i = 0 ; i < 65534 ; i++) {
						//disable idle process
						if(ResultPorts[0][i].pid != 0) {
							
						}
					}

					for(i=0; i < 65534; i++) {
					
						if(ResultPorts[1][i].pid != 0) {
														
						}
					}
					
				}
			
			}

					
		} else if(TRUE == IsWinXP()) {

			dwLastError = lpfnAllocateAndGetTcpExTableFromStack(&lpBuffer,TRUE,GetProcessHeap(),0,2);
			if (dwLastError == NO_ERROR) {
				
				for (dwSize = 0; dwSize < lpBuffer->dwNumEntries; dwSize++) {
					
					//if( (lpBuffer->table[dwSize].dwState == MIB_TCP_STATE_LISTEN) 
					//	|| (lpBuffer->table[dwSize].dwState == MIB_TCP_STATE_ESTAB) ) {
					
					//}
				}
			}

			dwLastError = lpfnAllocateAndGetUdpExTableFromStack(&lpBuffer1,TRUE,GetProcessHeap(),0,2);
			
			if (dwLastError == NO_ERROR) {
				for (dwSize = 0; dwSize < lpBuffer1->dwNumEntries; dwSize++) {
			
				}
			}

			if (lpBuffer) HeapFree(GetProcessHeap(),0,lpBuffer);
			if (lpBuffer1) HeapFree(GetProcessHeap(),0,lpBuffer1);

		} else { // Vista
			
			if (lpfnGetExtendedTcpTable (NULL, &tcpsize, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) == ERROR_INSUFFICIENT_BUFFER)  {
				
				tcpTable = (PMIB_TCPTABLE_OWNER_MODULE) malloc(tcpsize); 
				
				if (!lpfnGetExtendedTcpTable (tcpTable, &tcpsize, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0)) {

					printf("pid \t Proto\t Local \t Remote \t State\n");

					for( i = 0; i < tcpTable->dwNumEntries; i++ ) {   
						
						//if( (tcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN) || (tcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) ) {
							
													
							struct in_addr LocalIpAddr, RemoteIpAddr; 
							
							LocalIpAddr.S_un.S_addr = (u_long) tcpTable->table[i].dwLocalAddr;
							RemoteIpAddr.S_un.S_addr = (u_long) tcpTable->table[i].dwRemoteAddr;

							printf(" %d \t TCP  \t %s:%d \t %s:%d  \t %s\n",
									tcpTable->table[i].dwOwningPid, 
									inet_ntoa(LocalIpAddr),	
									htons( tcpTable->table[i].dwLocalPort),
									inet_ntoa(RemoteIpAddr),
									htons( tcpTable->table[i].dwRemotePort),
									TcpConvert2State(tcpTable->table[i].dwState)
									);

						//}
					}   
				}
				free(tcpTable);
			}
			
			/*
			if (lpfnGetExtendedTcpTable (NULL, &tcp6size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0) == ERROR_INSUFFICIENT_BUFFER)  {
				
				tcp6Table = (PMIB_TCP6TABLE_OWNER_MODULE) malloc(tcp6size); 
				
				if (!lpfnGetExtendedTcpTable (tcp6Table, &tcp6size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0)) {

					//printf("pid \t Proto\t Local \t Remote \t State\n");

					for( i = 0; i < tcp6Table->dwNumEntries; i++ ) {   
						
						//if( (tcp6Table->table[i].dwState == MIB_TCP_STATE_LISTEN) || (tcp6Table->table[i].dwState == MIB_TCP_STATE_ESTAB) ) {
							
							//if(0x0100007f != tcp6Table->table[i].dwLocalAddr) { // 127.0.0.1 이 아니면. // 127.0.0.1 (0x0100007f)
								
								struct in6_addr LocalIpv6Addr, RemoteIpv6Addr; 
								TCHAR	LocalIpv6Str[40] = {0,}, RemoteIpv6Str[40] ={0,};
								
								//LocalIpv6Addr.S_un.S_addr = (u_long) tcpTable->table[i].dwLocalAddr;
								//RemoteIpAddr.S_un.S_addr = (u_long) tcpTable->table[i].dwRemoteAddr;
								TK_Ipv6AddressToStringA(tcp6Table->table[i].ucLocalAddr, LocalIpv6Str);
								TK_Ipv6AddressToStringA(tcp6Table->table[i].ucRemoteAddr, RemoteIpv6Str);
								//reinhard
								printf(" %d \t TCP  \t [%s]:%d \t [%s]:%d  \t %s\n",
										tcp6Table->table[i].dwOwningPid, 
										LocalIpv6Str,//tcp6Table->table[i].ucLocalAddr
										htons( tcp6Table->table[i].dwLocalPort),
										RemoteIpv6Str,
										htons( tcp6Table->table[i].dwRemotePort),
										TcpConvert2State(tcp6Table->table[i].dwState)
										);
								
							//}

						//}
					}   
				}
				free(tcp6Table);
			}
			*/

			if (lpfnGetExtendedUdpTable (NULL, &udpsize, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) == ERROR_INSUFFICIENT_BUFFER)  {
				
				udpTable = (PMIB_UDPTABLE_OWNER_MODULE) malloc(udpsize); 
				
				if (!lpfnGetExtendedUdpTable (udpTable, &udpsize, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0)) {
					for( i = 0; i < udpTable->dwNumEntries; i++ ) {
						
					}   
				}

				free(udpTable);
			}
		}
	}

	return 0;
}