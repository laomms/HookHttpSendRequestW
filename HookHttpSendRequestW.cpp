#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <string>
#include <comdef.h>

#pragma warning(disable: 4996) 
// Function Protos:
int Privileges();
DWORD GetPid(char* ProcName);
int CheckOSVersion();
BOOL InjWithCRT(char* Process, char* DLLPath);
BOOL InjWithNtCTEx(char* Process, char* DLLPath);

// NtCreateThreadEx stuff:
HANDLE NtCreateThreadEx(HANDLE process, LPTHREAD_START_ROUTINE Start, LPVOID lpParameter);

typedef NTSTATUS(WINAPI* LPFUN_NtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN DWORD StackZeroBits,
	IN DWORD SizeOfStackCommit,
	IN DWORD SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

struct NtCreateThreadExBuffer
{
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
};

HANDLE NtCreateThreadEx(HANDLE process, LPTHREAD_START_ROUTINE Start, LPVOID lpParameter)
{

	HMODULE modNtDll = LoadLibrary(_T("ntdll.dll"));

	if (!modNtDll) {
		return 0;
	}

	LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx)GetProcAddress(modNtDll, "NtCreateThreadEx");

	if (!funNtCreateThreadEx) {
		return 0;
	}
	NtCreateThreadExBuffer ntbuffer;

	memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));
	DWORD temp1 = 0;
	DWORD temp2 = 0;

	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = 0x8;
	ntbuffer.Unknown3 = &temp2;
	ntbuffer.Unknown4 = 0;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = 4;
	ntbuffer.Unknown7 = &temp1;
	// ntbuffer.Unknown8 = 0;

	HANDLE hThread;
	NTSTATUS status = funNtCreateThreadEx(
		&hThread,
		0x1FFFFF,
		NULL,
		process,
		(LPTHREAD_START_ROUTINE)Start,
		lpParameter,
		FALSE,
		0,
		0,
		0,
		&ntbuffer
		);


	return hThread;

}

int main()
{

	char Process[20];
	char DLLPath[MAX_PATH];

	printf("/-------------------------------------------------------------------------------");
	printf("DLL Injector - GYX. 2013 \n");
	printf("Works on Windows XP, Vista, 7, and 8. Uses Simple VirtualAllocEx, WriteProcessMemory, CreateRemoteThread/NtCreateThreadEx technique.");
	printf(" To use, first enter the name of the process you would like to load the DLL into. Then enter the full path to the DLL you would like to");
	printf(" inject. Any Errors will be reported in this window. If you see no messages starting with ERROR, then injection was successful.");
	printf("--------------------------------------------------------------------------------/\n");
	printf("Process name: ");
	scanf("%s", Process);

	if (!strstr(Process, ".exe")) {
		printf("Be sure to enter .exe in the process name, try again. \n");
		printf("Process name: ");
		scanf("%s", Process);
	}
	else {
	}

	printf("DLL path: ");
	scanf("%s", DLLPath);

	if (!strstr(DLLPath, ".dll")) {
		printf("Be sure to enter .dll in DLL path, try again. \n");
		printf("DLL path: ");
		scanf("%s", DLLPath);
	}
	else {
	}

	if (FILE* file = fopen(DLLPath, "r"))
		fclose(file);
	else {
		printf("Specified DLL does not exist. Make sure to check you have the exact path, try again. \n");
		printf("DLL path: ");
		scanf("%s", DLLPath);
	}

	if (Privileges() != 0) {
		printf("ERROR: Failed to acquire sufficient privileges. Press any key to exit...");
		getchar();
		return 0;
	}
	else {
	}

	if (CheckOSVersion() == 2 || CheckOSVersion() == 3)
		InjWithNtCTEx(Process, DLLPath);

	else if (CheckOSVersion() == 1 || CheckOSVersion() == 4)
		InjWithCRT(Process, DLLPath);

	else {
		printf("ERROR: Failed to acquire OS version. Supported OS's are Windows XP, Vista, 7, and 8. Press any key to exit...");
		getchar();
		return 0;
	}

	return 0;
}

int Privileges()
{
	HANDLE Token;
	TOKEN_PRIVILEGES tp;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
	{
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (AdjustTokenPrivileges(Token, 0, &tp, sizeof(tp), NULL, NULL) == 0) {
			return 1;
		}
		else {
			return 0;
		}
	}
	return 1;
}

DWORD GetPid(char* ProcName)
{
	std::wstring w;
	std::copy(ProcName, ProcName + strlen(ProcName), back_inserter(w));
	const WCHAR* pwcsName = w.c_str();

	HANDLE hsnap;
	PROCESSENTRY32 pt;
	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	do {

		if (!wcscmp(pt.szExeFile, pwcsName)) {
			DWORD pid = pt.th32ProcessID;
			CloseHandle(hsnap);
			return pid;
		}
	} while (Process32Next(hsnap, &pt));
	CloseHandle(hsnap);
	return 0;
}

int CheckOSVersion()
{
	/*
	Failure = 0
	Windows XP = 1 (NT 5.0)
	Windows Vista = 2 (NT 6.0)
	Windows 7 = 3 (NT 6.1)
	Windows 8 = 4 (NT 6.2)
	*/

	OSVERSIONINFO OSVersion;
	OSVersion.dwOSVersionInfoSize = sizeof(OSVersion);

	if (!GetVersionEx(&OSVersion))
		return 0;

	if (!(OSVersion.dwPlatformId == VER_PLATFORM_WIN32_NT))
		return 0;
	if (OSVersion.dwMajorVersion == 5)
		return 1;
	if (OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion == 0)
		return 2;
	if (OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion == 1)
		return 3;
	if (OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion == 2)
		return 4;

	return 0;
}

BOOL InjWithCRT(char* Process, char* DLLPath)
{

	DWORD Pid = GetPid(Process);
	if (Pid == 0) {
		printf("ERROR: Failed to find the PID of the specified process. Press any key to exit...");
		getchar();
		return FALSE;
	}

	HANDLE ProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
	if (ProcHandle == NULL) {
		printf("ERROR: Failed to open target process. Press any key to exit...");
		getchar();
		return FALSE;
	}

	LPVOID LoadLibraryAddr = GetProcAddress(LoadLibrary(_T("kernel32.dll")), "LoadLibraryA");
	LPVOID OurMemoryAddr = VirtualAllocEx(ProcHandle, 0, strlen(DLLPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (OurMemoryAddr == NULL) {
		printf("ERROR: Failed to allocate space in target process. Press any key to exit...");
		getchar();
		return FALSE;
	}

	if (!WriteProcessMemory(ProcHandle, OurMemoryAddr, DLLPath, strlen(DLLPath) + 1, 0)) {
		printf("ERROR: Failed to write our DLL to the target process' memory. Press any key to exit...");
		getchar();
		return FALSE;
	}

	HANDLE RemoteThread = CreateRemoteThread(ProcHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddr, OurMemoryAddr, 0, 0);
	if (RemoteThread == NULL) {
		printf("ERROR: Failed to create our remote thread in the target process...");
		getchar();
		return FALSE;
	}

	WaitForSingleObject(RemoteThread, INFINITE);
	VirtualFree(OurMemoryAddr, 0, MEM_RELEASE);
	CloseHandle(ProcHandle);
	CloseHandle(RemoteThread);

	printf("SUCESS: DLL has been successfully injected. Press any key to exit...");
	getchar();
	return TRUE;
}

BOOL InjWithNtCTEx(char* Process, char* DLLPath)
{

	DWORD Pid = GetPid(Process);
	if (Pid == 0) {
		printf("ERROR: Failed to find PID of specified process. Press any key to exit...");
		getchar();
		return FALSE;
	}

	HANDLE ProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
	if (ProcHandle == NULL) {
		printf("ERROR: Failed to open target process. Press any key to exit...");
		getchar();
		return FALSE;
	}

	LPVOID LoadLibraryAddr = GetProcAddress(LoadLibrary(_T("kernel32.dll")), "LoadLibraryA");
	LPVOID OurMemoryAddr = VirtualAllocEx(ProcHandle, 0, strlen(DLLPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (OurMemoryAddr == NULL) {
		printf("ERROR: Failed to allocate space in target process. Press any key to exit...");
		getchar();
		return FALSE;
	}

	if (!WriteProcessMemory(ProcHandle, OurMemoryAddr, DLLPath, strlen(DLLPath) + 1, 0)) {
		printf("ERROR: Failed to write our DLL to the target process' memory. Press any key to exit...");
		getchar();
		return FALSE;
	}

	HANDLE RemoteThread = NtCreateThreadEx(ProcHandle, (LPTHREAD_START_ROUTINE)LoadLibraryAddr, OurMemoryAddr);
	if (RemoteThread == NULL) {
		printf("ERROR: Failed to create our remote thread in the target process...");
		getchar();
		return FALSE;
	}

	WaitForSingleObject(RemoteThread, INFINITE);
	VirtualFree(OurMemoryAddr, 0, MEM_RELEASE);
	CloseHandle(ProcHandle);
	CloseHandle(RemoteThread);

	printf("SUCESS: DLL has been successfully injected. Press any key to exit...");
	getchar();
	return TRUE;
}
