#include <windows.h>
#include <stdio.h>
#include "stdafx.h"
#include "easyhook.h"

#include <list>
#include <string>
#include <thread>
#include <iostream>
#include <algorithm>

#include <bcrypt.h> // Include headers for BCrypt functions
#include <wincrypt.h> // Include headers for Crypto functions

// Include any additional headers required for CryptoAPI functions

typedef BOOL(WINAPI* CryptEncrypt_t)(
    HCRYPTKEY   hKey,
    HCRYPTHASH  hHash,
    BOOL        Final,
    DWORD       dwFlags,
    BYTE* pbData,
    DWORD* pdwDataLen,
    DWORD       dwBufLen
    );

CryptEncrypt_t original_CryptEncrypt = (CryptEncrypt_t)GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptEncrypt");

BOOL WINAPI My_CryptEncrypt(
    HCRYPTKEY   hKey,
    HCRYPTHASH  hHash,
    BOOL        Final,
    DWORD       dwFlags,
    BYTE* pbData,
    DWORD* pdwDataLen,
    DWORD       dwBufLen
)
{
    std::cout << "Process " << GetCurrentProcessId() << " called CryptEncrypt" << std::endl;
    TerminateProcess(GetCurrentProcess(), 0);

    return original_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

typedef NTSTATUS(NTAPI* BCryptEncrypt_t)(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR            pbInput,
    ULONG             cbInput,
    VOID* pPaddingInfo,
    PUCHAR            pbIV,
    ULONG             cbIV,
    PUCHAR            pbOutput,
    ULONG             cbOutput,
    ULONG* pcbResult,
    ULONG             dwFlags
    );

BCryptEncrypt_t original_BCryptEncrypt = (BCryptEncrypt_t)GetProcAddress(GetModuleHandle(TEXT("bcrypt")), "BCryptEncrypt");

NTSTATUS NTAPI My_BCryptEncrypt(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR            pbInput,
    ULONG             cbInput,
    VOID* pPaddingInfo,
    PUCHAR            pbIV,
    ULONG             cbIV,
    PUCHAR            pbOutput,
    ULONG             cbOutput,
    ULONG* pcbResult,
    ULONG             dwFlags
)
{
    std::cout << "Hooked: BCryptEncrypt\n";
    // Your custom code to log or manipulate encrypted data
    // ...

    return original_BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}

typedef BOOL(WINAPI* CryptUnprotectData_t)(
    DATA_BLOB* pDataIn,
    LPCWSTR         pszDataDescr,
    DATA_BLOB* pOptionalEntropy,
    PVOID           pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
    DWORD           dwFlags,
    DATA_BLOB* pDataOut
    );

CryptUnprotectData_t original_CryptUnprotectData = (CryptUnprotectData_t)GetProcAddress(GetModuleHandle(TEXT("crypt32")), "CryptUnprotectData");

BOOL WINAPI My_CryptUnprotectData(
    DATA_BLOB* pDataIn,
    LPCWSTR         pszDataDescr,
    DATA_BLOB* pOptionalEntropy,
    PVOID           pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
    DWORD           dwFlags,
    DATA_BLOB* pDataOut
)
{
    std::cout << "Hooked: CryptUnprotectData\n";
    // Your custom code to log or manipulate decrypted data
    // ...

    return original_CryptUnprotectData(pDataIn, pszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);
}

typedef BOOL(WINAPI* CryptGenKey_t)(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    DWORD dwFlags,
    HCRYPTKEY* phKey
    );

CryptGenKey_t original_CryptGenKey = (CryptGenKey_t)GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptGenKey");

BOOL WINAPI My_CryptGenKey(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    DWORD dwFlags,
    HCRYPTKEY* phKey
)
{
    std::cout << "Hooked: CryptGenKey\n";
    // Your custom code to log or manipulate key generation
    // ...

    return original_CryptGenKey(hProv, Algid, dwFlags, phKey);
}

typedef BOOL(WINAPI* CryptExportKey_t)(
    HCRYPTKEY hKey,
    HCRYPTKEY hExpKey,
    DWORD dwBlobType,
    DWORD dwFlags,
    BYTE* pbData,
    DWORD* pdwDataLen
    );

CryptExportKey_t original_CryptExportKey = (CryptExportKey_t)GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptExportKey");

BOOL WINAPI My_CryptExportKey(
    HCRYPTKEY hKey,
    HCRYPTKEY hExpKey,
    DWORD dwBlobType,
    DWORD dwFlags,
    BYTE* pbData,
    DWORD* pdwDataLen
)
{
    std::cout << "Hooked: CryptExportKey\n";
    // Your custom code to log or manipulate key export
    // ...

    return original_CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
}

void hookCryptEncrypt(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    // Install the hook for CryptEncrypt
    NTSTATUS result = LhInstallHook(
        addr,
        My_CryptEncrypt,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFailed to install hook - CryptEncrypt\n";
    }
    else {
        std::cout << "Hook installed successfully - CryptEncrypt\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookBCryptEncrypt(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    // Install the hook for BCryptEncrypt
    NTSTATUS result = LhInstallHook(
        addr,
        My_BCryptEncrypt,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFailed to install hook - BCryptEncrypt\n";
    }
    else {
        std::cout << "Hook installed successfully - BCryptEncrypt\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookCryptUnprotectData(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    // Install the hook for CryptUnprotectData
    NTSTATUS result = LhInstallHook(
        addr,
        My_CryptUnprotectData,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFailed to install hook - CryptUnprotectData\n";
    }
    else {
        std::cout << "Hook installed successfully - CryptUnprotectData\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookCryptGenKey(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    // Install the hook for CryptGenKey
    NTSTATUS result = LhInstallHook(
        addr,
        My_CryptGenKey,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFailed to install hook - CryptGenKey\n";
    }
    else {
        std::cout << "Hook installed successfully - CryptGenKey\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookCryptExportKey(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    // Install the hook for CryptExportKey
    NTSTATUS result = LhInstallHook(
        addr,
        My_CryptExportKey,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFailed to install hook - CryptExportKey\n";
    }
    else {
        std::cout << "Hook installed successfully - CryptExportKey\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookCrypto()
{
    // CryptUnprotectData
    FARPROC procAddress = GetProcAddress(GetModuleHandle(TEXT("crypt32")), "CryptUnprotectData");
    hookCryptUnprotectData(procAddress);

    // BCryptEncrypt
    procAddress = GetProcAddress(GetModuleHandle(TEXT("bcrypt")), "BCryptEncrypt");
    hookBCryptEncrypt(procAddress);

    // CryptEncrypt
    procAddress = GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptEncrypt");
    hookCryptEncrypt(procAddress);

    // CryptGenKey
    procAddress = GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptGenKey");
    hookCryptGenKey(procAddress);

    // CryptExportKey
    procAddress = GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptExportKey");
    hookCryptExportKey(procAddress);
}




