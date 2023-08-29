#include <windows.h>
#include <stdio.h>
#include "stdafx.h"
#include "easyhook.h"
#include <list>
#include <string>
#include <thread>
#include <iostream>
#include <algorithm>

typedef BOOL(WINAPI* MoveFile_t)(
	LPCTSTR lpExistingFileName,
	LPCTSTR lpNewFileName
	);

typedef BOOL(WINAPI* MoveFileEx_t)(
	LPCTSTR lpExistingFileName,
	LPCTSTR lpNewFileName,
	DWORD   dwFlags
	);


MoveFile_t original_MoveFile = (MoveFile_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFile");
MoveFileEx_t original_MoveFileEx = (MoveFileEx_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileEx");


BOOL WINAPI My_MoveFile(
	LPCTSTR lpExistingFileName,
	LPCTSTR lpNewFileName
)
{
	std::cout << "(MoveFile)HOOKED: Movido de " << lpExistingFileName << " para " << lpNewFileName << "\n";
	return original_MoveFile(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI My_MoveFileEx(
	LPCTSTR lpExistingFileName,
	LPCTSTR lpNewFileName,
	DWORD   dwFlags
)
{
	std::cout << "(MoveFileEx)HOOKED: Movido de " << lpExistingFileName << " para " << lpNewFileName << " com flags: " << dwFlags << "\n";
	return original_MoveFileEx(lpExistingFileName, lpNewFileName, dwFlags);
}

void hookMoveFile(FARPROC addr) {
	HOOK_TRACE_INFO hHook = { NULL };

	NTSTATUS result = LhInstallHook(
		addr,
		My_MoveFile,
		NULL,
		&hHook);


	if (FAILED(result))
	{
		std::cout << "\nFalha ao instalar o hook - MoveFile\n";
	}
	else
	{
		std::cout << "Hook instalado com sucesso - MoveFile.\n";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookMoveFileEx(FARPROC addr) {
	HOOK_TRACE_INFO hHook = { NULL };

	NTSTATUS result = LhInstallHook(
		addr,
		My_MoveFileEx,
		NULL,
		&hHook);

	if (FAILED(result))
	{
		std::cout << "\nFalha ao instalar o hook - MoveFileEx\n";
	}
	else
	{
		std::cout << "Hook instalado com sucesso - MoveFileEx.\n";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookMoving()
{
	std::cout << "Aqui pegou";

	FARPROC procAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFile");
	if (procAddress != 0 && procAddress != NULL)
		hookMoveFile(procAddress);

	procAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileEx");
	if (procAddress != 0 && procAddress != NULL)
		hookMoveFileEx(procAddress);
}