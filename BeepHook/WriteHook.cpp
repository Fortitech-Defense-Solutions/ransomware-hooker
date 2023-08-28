#include <windows.h>
#include <stdio.h>
#include "stdafx.h"
#include "easyhook.h"
#include <ntstatus.h>

#include <list>
#include <string>
#include <thread>
#include <iostream>
#include <algorithm>
#include <vector>
#include <cmath>

using namespace std;

// A function that calculates the entropy of a byte sequence
double entropy(const vector<unsigned char>& bytes) {
	// Count the frequency of each byte value
	vector<int> freq(256, 0);
	for (auto b : bytes) {
		freq[b]++;
	}
	// Calculate the entropy using the formula
	// H = -sum(p_i * log2(p_i))
	double h = 0.0;
	for (auto f : freq) {
		if (f > 0) {
			double p = (double)f / bytes.size();
			h -= p * log2(p);
		}
	}
	return h;
}

// A function that checks if a byte sequence is likely encrypted
bool is_encrypted(const vector<unsigned char>& bytes) {
	// A threshold for the entropy value
	const double threshold = 4.;
	// Calculate the entropy of the byte sequence
	double h = entropy(bytes);
	// Compare the entropy with the threshold
	// If the entropy is high, it is likely encrypted
	return h > threshold;
}

// Define the function types
typedef BOOL(WINAPI* WriteFile_t)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);

typedef BOOL(WINAPI* WriteFileEx_t)(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPOVERLAPPED lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);

typedef BOOL(WINAPI* WriteFileGather_t)(
	HANDLE hFile,
	FILE_SEGMENT_ELEMENT aSegmentArray[],
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpReserved,
	LPOVERLAPPED lpOverlapped
	);

typedef NTSTATUS(NTAPI* NtWriteFile_t)(
	HANDLE hFile,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key
	);

// Get the original functions
WriteFile_t original_WriteFile = (WriteFile_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile");
WriteFileEx_t original_WriteFileEx = (WriteFileEx_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFileEx");
WriteFileGather_t original_WriteFileGather = (WriteFileGather_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFileGather");
NtWriteFile_t original_NtWriteFile = (NtWriteFile_t)GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtWriteFile");

// Define the hooked functions
BOOL WINAPI My_WriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	std::cout << "(WriteFile)HOOKED: ";

	vector<unsigned char> bytes;
	for (DWORD i = 0; i < nNumberOfBytesToWrite; ++i)
	{
		BYTE b = (((BYTE*)lpBuffer)[i]);
		bytes.push_back(b);
	}
	std::cout << "\n";

	if (is_encrypted(bytes)) {
		TerminateProcess(GetCurrentProcess, 0);
		return 0;
	}

	return original_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI My_WriteFileEx(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPOVERLAPPED lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	std::cout << "(WriteFileEx)HOOKED: ";

	vector<unsigned char> bytes;
	for (DWORD i = 0; i < nNumberOfBytesToWrite; ++i)
	{
		BYTE b = (((BYTE*)lpBuffer)[i]);
		bytes.push_back(b);
	}
	std::cout << "\n";

	if (is_encrypted(bytes)) {
		TerminateProcess(GetCurrentProcess, 0);
		return 0;
	}

	return original_WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
}

BOOL WINAPI My_WriteFileGather(
	HANDLE hFile,
	FILE_SEGMENT_ELEMENT aSegmentArray[],
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpReserved,
	LPOVERLAPPED lpOverlapped
)
{
	std::cout << "(WriteFileGather)HOOKED: ";
	DWORD totalBytes = 0;

	vector<unsigned char> bytes;

	while (totalBytes < nNumberOfBytesToWrite) {
		for (DWORD i = 0; i < nNumberOfBytesToWrite; ++i) {
			BYTE b = ((BYTE*)aSegmentArray[totalBytes / 4096].Buffer)[totalBytes % 4096];
			totalBytes++;
			if (totalBytes >= nNumberOfBytesToWrite) {
				break;
			}
			bytes.push_back(b);
		}
		std::cout << "\n";
	}

	if (is_encrypted(bytes)) {
		TerminateProcess(GetCurrentProcess, 0);
		return 0;
	}

	return original_WriteFileGather(hFile, aSegmentArray, nNumberOfBytesToWrite, lpReserved, lpOverlapped);
}

NTSTATUS NTAPI My_NtWriteFile(
	HANDLE hFile,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key
)
{
	std::cout << "(NtWriteFile)HOOKED: ";
	std::string output;
	for (ULONG i = 0; i < Length; ++i)
	{
		output += (((BYTE*)Buffer)[i]);
	}
	std::cout << output << "\n";

	vector<unsigned char> bytes(static_cast<const unsigned char*>(Buffer), static_cast<const unsigned char*>(Buffer) + Length);

	if (is_encrypted(bytes)) {
		TerminateProcess(GetCurrentProcess, 0);
		return 0;
	}
	
	return original_NtWriteFile(hFile, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);	

}

void hookWriteFile(FARPROC addr) {
	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook

	// Install the hook for WriteFile
	NTSTATUS result = LhInstallHook(
		addr,
		My_WriteFile,
		NULL,
		&hHook);

	// Check result and set ACL...
	if (FAILED(result))
	{
		std::cout << "\nFailed to install hook - WriteFile\n";
	}
	else
	{
		std::cout << "Hook installed successfully- WriteFile.\n";

		// If the threadId in the ACL is set to 0,
		// then internally EasyHook uses GetCurrentThreadId()
		ULONG ACLEntries[1] = { 0 };

		// Disable the hook for the provided threadIds, enable for all others
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookWriteFileEx(FARPROC addr) {

	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook
	// Install the hook for WriteFileEx
	NTSTATUS result = LhInstallHook(
		addr,
		My_WriteFileEx,
		NULL,
		&hHook);

	// Check result and set ACL...
	if (FAILED(result))
	{
		std::cout << "\nFailed to install hook - WriteFileEx\n";
	}
	else
	{
		std::cout << "Hook installed successfully - WriteFileEx\n";

		// If the threadId in the ACL is set to 0,
		// then internally EasyHook uses GetCurrentThreadId()
		ULONG ACLEntries[1] = { 0 };

		// Disable the hook for the provided threadIds, enable for all others
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookWriteFileGather(FARPROC addr) {

	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook

	// Install the hook for WriteFileGather
	NTSTATUS result = LhInstallHook(
		addr,
		My_WriteFileGather,
		NULL,
		&hHook);

	// Check result and set ACL...
	if (FAILED(result))
	{
		std::cout << "\nFailed to install hook - WriteFileGather\n";
	}
	else
	{
		std::cout << "Hook installed successfully - WriteFileGather.\n";

		// If the threadId in the ACL is set to 0,
		// then internally EasyHook uses GetCurrentThreadId()
		ULONG ACLEntries[1] = { 0 };

		// Disable the hook for the provided threadIds, enable for all others
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookNtWriteFile(FARPROC addr) {

	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook

	// Install the hook for NtWriteFile
	NTSTATUS result = LhInstallHook(
		addr,
		My_NtWriteFile,
		NULL,
		&hHook);

	// Check result and set ACL...
	if (FAILED(result))
	{
		std::cout << "\nFailed to install hook - NtWriteFile\n";
	}
	else
	{
		std::cout << "Hook installed successfully - NtWriteFile\n";

		// If the threadId in the ACL is set to 0,
		// then internally EasyHook uses GetCurrentThreadId()
		ULONG ACLEntries[1] = { 0 };

		// Disable the hook for the provided threadIds, enable for all others
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}


void hookWriting()
{
	std::cout << "Aqui pegou";

	// NtWriteFile
	FARPROC procAddress = GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtWriteFile");
	if (procAddress != 0 && procAddress != NULL)
		hookNtWriteFile(procAddress);

	// WriteFileGather
	procAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFileGather");
	if (procAddress != 0 && procAddress != NULL)
		hookWriteFileGather(procAddress);

	// WriteFileEx
	procAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFileEx");
	if (procAddress != 0 && procAddress != NULL)
		hookWriteFileEx(procAddress);

	// NtWriteFile
	procAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile");
	if (procAddress != 0 && procAddress != NULL)
		hookWriteFile(procAddress);

}

