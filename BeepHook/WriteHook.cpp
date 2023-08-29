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

double entropy(const vector<unsigned char>& bytes) {
	// Conta a frequ�ncia de cada valor de byte
	vector<int> freq(256, 0);
	for (auto b : bytes) {
		freq[b]++;
	}
	// Calcula a entropia usando a f�rmula
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

// Uma fun��o que verifica se uma sequ�ncia de bytes est� provavelmente criptografada
bool is_encrypted(const vector<unsigned char>& bytes) {
	const double threshold = 0.;
	double h = entropy(bytes);
	return h > threshold;
}

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

WriteFile_t original_WriteFile = (WriteFile_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile");
WriteFileEx_t original_WriteFileEx = (WriteFileEx_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFileEx");
WriteFileGather_t original_WriteFileGather = (WriteFileGather_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFileGather");
NtWriteFile_t original_NtWriteFile = (NtWriteFile_t)GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtWriteFile");

BOOL WINAPI My_WriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	vector<unsigned char> bytes;
	for (DWORD i = 0; i < nNumberOfBytesToWrite; ++i)
	{
		BYTE b = (((BYTE*)lpBuffer)[i]);
		bytes.push_back(b);
	}

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
	vector<unsigned char> bytes;
	for (DWORD i = 0; i < nNumberOfBytesToWrite; ++i)
	{
		BYTE b = (((BYTE*)lpBuffer)[i]);
		bytes.push_back(b);
	}

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
	DWORD totalBytes = 0;

	vector<unsigned char> bytes;

	while (totalBytes < nNumberOfBytesToWrite) {
		for (DWORD i = 0; i < nNumberOfBytesToWrite; ++i) {
			BYTE b = ((BYTE*)aSegmentArray[totalBytes / 4096].Buffer)[totalBytes % 4096];
			bytes.push_back(b);
			totalBytes++;
			if (totalBytes >= nNumberOfBytesToWrite) {
				break;
			}
		}
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
	vector<unsigned char> bytes(static_cast<const unsigned char*>(Buffer), static_cast<const unsigned char*>(Buffer) + Length);

	if (is_encrypted(bytes)) {
		TerminateProcess(GetCurrentProcess(), 0);
		return 0;
	}
	
	return original_NtWriteFile(hFile, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);	

}

void hookWriteFile(FARPROC addr) {
	HOOK_TRACE_INFO hHook = { NULL }; 

	NTSTATUS result = LhInstallHook(
		addr,
		My_WriteFile,
		NULL,
		&hHook);

	if (FAILED(result))
	{
		//std::cout << "\nFalha ao instalar hook - WriteFile\n";
		TerminateProcess(GetCurrentProcess(), 0);
	}
	else
	{
		//std::cout << "Hook instalado com sucesso - WriteFile.\n";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookWriteFileEx(FARPROC addr) {

	HOOK_TRACE_INFO hHook = { NULL };
	NTSTATUS result = LhInstallHook(
		addr,
		My_WriteFileEx,
		NULL,
		&hHook);

	if (FAILED(result))
	{
		//std::cout << "\nFalha ao instalar o hook - WriteFileEx\n";
		TerminateProcess(GetCurrentProcess(), 0);
	}
	else
	{
		//std::cout << "Hook instalado com sucesso - WriteFileEx\n";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookWriteFileGather(FARPROC addr) {

	HOOK_TRACE_INFO hHook = { NULL }; 

	NTSTATUS result = LhInstallHook(
		addr,
		My_WriteFileGather,
		NULL,
		&hHook);

	if (FAILED(result))
	{
		//std::cout << "\nFalha ao instalar o hook - WriteFileGather\n";
		TerminateProcess(GetCurrentProcess(), 0);
	}
	else
	{
		//std::cout << "Hook instalado com sucesso - WriteFileGather.\n";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}

void hookNtWriteFile(FARPROC addr) {

	HOOK_TRACE_INFO hHook = { NULL }; 

	NTSTATUS result = LhInstallHook(
		addr,
		My_NtWriteFile,
		NULL,
		&hHook);

	if (FAILED(result))
	{
		//std::cout << "\nFalha ao instalar o hook - NtWriteFile\n";
		TerminateProcess(GetCurrentProcess(), 0);
	}
	else
	{
		//std::cout << "Hook instalado com sucesso - NtWriteFile\n";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}
}


void hookWriting()
{
	FARPROC procAddress = GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtWriteFile");
	if (procAddress != 0 && procAddress != NULL)
		hookNtWriteFile(procAddress);

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