#include <windows.h>
#include <stdio.h>
#include "stdafx.h"
#include "easyhook.h"
#include <list>
#include <string>
#include <thread>
#include <iostream>
#include <algorithm>

std::string LPCTSTR_to_string(LPCTSTR lpctstr)
{
	if (lpctstr == NULL) return std::string();
	int len = WideCharToMultiByte(CP_ACP, 0, lpctstr, -1, NULL, 0, NULL, NULL);
	char* buffer = new char[len];
	WideCharToMultiByte(CP_ACP, 0, lpctstr, -1, buffer, len, NULL, NULL);
	std::string str(buffer);
	delete[] buffer;
	return str;
}


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

std::list<std::string> windowsExtensions = { ".exe", ".dll", ".sys", ".drv", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".txt", ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip" };

BOOL WINAPI My_MoveFile(
	LPCTSTR lpExistingFileName,
	LPCTSTR lpNewFileName
)
{
	std::string newFileName = LPCTSTR_to_string(lpNewFileName);
	std::string extension = newFileName.substr(newFileName.find_last_of("."));
	if (std::find(windowsExtensions.begin(), windowsExtensions.end(), extension) != windowsExtensions.end()) {
		TerminateProcess(GetCurrentProcess(), 0);
		return 0;
	}
	return original_MoveFile(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI My_MoveFileEx(
	LPCTSTR lpExistingFileName,
	LPCTSTR lpNewFileName,
	DWORD   dwFlags
)
{
	std::string newFileName = LPCTSTR_to_string(lpNewFileName);
	std::string extension = newFileName.substr(newFileName.find_last_of("."));
	if (std::find(windowsExtensions.begin(), windowsExtensions.end(), extension) != windowsExtensions.end()) {
		TerminateProcess(GetCurrentProcess(), 0);
		return 0;
	}
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
		TerminateProcess(GetCurrentProcess(), 0);
	}
	else
	{
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
		TerminateProcess(GetCurrentProcess(), 0);
	}
	else
	{
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookMoving()
{
	FARPROC procAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFile");
	if (procAddress != 0 && procAddress != NULL)
		hookMoveFile(procAddress);

	procAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "MoveFileEx");
	if (procAddress != 0 && procAddress != NULL)
		hookMoveFileEx(procAddress);
}