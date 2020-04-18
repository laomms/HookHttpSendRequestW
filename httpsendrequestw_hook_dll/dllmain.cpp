// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>
//#include "stdafx.h"

// Globals:
DWORD Pid;
char OrigBytes[5];
char PatchBytes[5];
BOOL RetValue;

// Function protos:
typedef BOOL(WINAPI* OldHttpSendRequestW) (HINTERNET, LPCTSTR, DWORD, LPVOID, DWORD);
FARPROC HttpSendRequestWPtr;
OldHttpSendRequestW HSRW = NULL;
BOOL SwapBytes(DWORD Pid, DWORD NewFuncAddr, FARPROC OldFuncAddr, char* OriginalBytes, char* PatchedBytes);
BOOL PatchAPI(DWORD Pid, FARPROC OldFuncAddr, char NewBytes[5]);

// Hook function:
BOOL WINAPI HookedHttpSendRequestW(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{

	MessageBoxA(NULL, "Hooked", "MsgBox", MB_OK);

	PatchAPI(Pid, HttpSendRequestWPtr, OrigBytes);
	RetValue = HSRW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
	PatchAPI(Pid, HttpSendRequestWPtr, PatchBytes);

	return RetValue;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  reason, LPVOID lpReserved)
{

	switch (reason)
	{

	case DLL_PROCESS_ATTACH:

		Pid = GetCurrentProcessId();
		HttpSendRequestWPtr = GetProcAddress(GetModuleHandleA("wininet.dll"), "HttpSendRequestW");
		HSRW = (OldHttpSendRequestW)HttpSendRequestWPtr;

		SwapBytes(Pid, (DWORD)HookedHttpSendRequestW, HttpSendRequestWPtr, OrigBytes, PatchBytes);
		PatchAPI(Pid, HttpSendRequestWPtr, PatchBytes);
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

BOOL SwapBytes(DWORD Pid, DWORD NewFuncAddr, FARPROC OldFuncAddr, char* OriginalBytes, char* PatchedBytes)
{

	// Get old bytes, store in OriginalBytes
	HANDLE ProcHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, Pid);
	if (ProcHandle == NULL)
		return FALSE;

	if (!ReadProcessMemory(ProcHandle, OldFuncAddr, OriginalBytes, 5, NULL)) {
		CloseHandle(ProcHandle);
		return FALSE;
	}

	// Get the new bytes that we will use in PatchAPI
	DWORD JMPAddr = ((DWORD)NewFuncAddr - (DWORD)OldFuncAddr - 5);
	PatchedBytes[0] = 0xE9;

	if (!WriteProcessMemory(ProcHandle, PatchedBytes + 1, &JMPAddr, 4, NULL)) {
		CloseHandle(ProcHandle);
		return FALSE;
	}

	return TRUE;
}

BOOL PatchAPI(DWORD Pid, FARPROC OldFuncAddr, char NewBytes[5])
{

	HANDLE ProcHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, Pid);
	if (ProcHandle == NULL)
		return FALSE;

	if (!WriteProcessMemory(ProcHandle, OldFuncAddr, NewBytes, 5, NULL)) {
		CloseHandle(ProcHandle);
		return FALSE;
	}

	return TRUE;
}