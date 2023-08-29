#include <windows.h>
#include <stdio.h>
#include "stdafx.h"
#include "easyhook.h"

#include <list>
#include <string>
#include <thread>
#include <iostream>
#include <algorithm>
#include <vector> // Inclui os cabecalhos para a whitelist
#include <tlhelp32.h> // Inclui os cabecalhos para a whitelist
#include <psapi.h> // Inclui os cabecalhos para a whitelist
#pragma comment(lib, "psapi.lib") // Inclui os cabecalhos para a whitelist

#include <bcrypt.h> // Inclui os cabecalhos para as funcoes BCryptAPI
#include <wincrypt.h> // Inclui os cabecalhos para as funcoes da CryptoAPI

bool isOnWhitelist(DWORD processId) {
    
    std::vector<std::string> whitelist = {
        "System",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "explorer.exe",
        "winlogon.exe",
    };

    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    WCHAR processName[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, processName, sizeof(processName)) == 0) {
        CloseHandle(hProcess);
        return false;
    }
    CloseHandle(hProcess);

    int bufferSize = WideCharToMultiByte(CP_ACP, 0, processName, -1, NULL, 0, NULL, NULL);
    char* narrowString = new char[bufferSize];
    WideCharToMultiByte(CP_ACP, 0, processName, -1, narrowString, bufferSize, NULL, NULL);
    std::string processNameStr(narrowString);
    delete[] narrowString;

    return std::find(whitelist.begin(), whitelist.end(), processNameStr) != whitelist.end();
}

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
    if (!isOnWhitelist(GetCurrentProcessId())) 
    {
        std::cout << "O processo n�o confi�vel " << GetCurrentProcessId() << " tentou chamar CryptEncrypt!" << std::endl;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    std::cout << "O processo confi�vel " << GetCurrentProcessId() << " chamou CryptEncrypt!" << std::endl;
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
    if (!isOnWhitelist(GetCurrentProcessId()))
    {
        std::cout << "O processo n�o confi�vel " << GetCurrentProcessId() << " tentou chamar BCryptEncrypt!" << std::endl;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    std::cout << "O processo confi�vel " << GetCurrentProcessId() << " chamou BCryptEncrypt!" << std::endl;
    
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
    if (!isOnWhitelist(GetCurrentProcessId()))
    {
        std::cout << "O processo n�o confi�vel " << GetCurrentProcessId() << " tentou chamar CryptUnprotectData!" << std::endl;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    std::cout << "O processo confi�vel " << GetCurrentProcessId() << " chamou CryptUnprotectData!" << std::endl;

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
    if (!isOnWhitelist(GetCurrentProcessId()))
    {
        std::cout << "O processo n�o confi�vel " << GetCurrentProcessId() << " tentou chamar CryptGenKey!" << std::endl;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    std::cout << "O processo confi�vel " << GetCurrentProcessId() << " chamou CryptGenKey!" << std::endl;

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
    if (!isOnWhitelist(GetCurrentProcessId()))
    {
        std::cout << "O processo n�o confi�vel " << GetCurrentProcessId() << " tentou chamar CryptExportKey!" << std::endl;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    std::cout << "O processo confi�vel " << GetCurrentProcessId() << " chamou CryptExportKey!" << std::endl;

    return original_CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
}

void hookCryptEncrypt(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    NTSTATUS result = LhInstallHook(
        addr,
        My_CryptEncrypt,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFalha ao instalar o hook - CryptEncrypt\n";
    }
    else {
        std::cout << "Hook instalado com sucesso - CryptEncrypt\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookBCryptEncrypt(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    NTSTATUS result = LhInstallHook(
        addr,
        My_BCryptEncrypt,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFalha ao instalar o hook - BCryptEncrypt\n";
    }
    else {
        std::cout << "Hook instalado com sucesso - BCryptEncrypt\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookCryptUnprotectData(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    NTSTATUS result = LhInstallHook(
        addr,
        My_CryptUnprotectData,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFalha ao instalar o hook - CryptUnprotectData\n";
    }
    else {
        std::cout << "Hook instalado com sucesso - CryptUnprotectData\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookCryptGenKey(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    NTSTATUS result = LhInstallHook(
        addr,
        My_CryptGenKey,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFalha ao instalar o hook - CryptGenKey\n";
    }
    else {
        std::cout << "Hook instalado com sucesso - CryptGenKey\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookCryptExportKey(FARPROC addr) {
    HOOK_TRACE_INFO hHook = { NULL };

    NTSTATUS result = LhInstallHook(
        addr,
        My_CryptExportKey,
        NULL,
        &hHook);

    if (FAILED(result)) {
        std::cout << "\nFalha ao instalar o hook - CryptExportKey\n";
    }
    else {
        std::cout << "Hook instalado com sucesso - CryptExportKey\n";
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hHook);
    }
}

void hookCrypto()
{
    std::cout << "Aqui pegou";

    FARPROC procAddress = GetProcAddress(GetModuleHandle(TEXT("crypt32")), "CryptUnprotectData");
    hookCryptUnprotectData(procAddress);
    procAddress = GetProcAddress(GetModuleHandle(TEXT("bcrypt")), "BCryptEncrypt");
    hookBCryptEncrypt(procAddress);
    procAddress = GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptEncrypt");
    hookCryptEncrypt(procAddress);
    procAddress = GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptGenKey");
    hookCryptGenKey(procAddress);
    procAddress = GetProcAddress(GetModuleHandle(TEXT("advapi32")), "CryptExportKey");
    hookCryptExportKey(procAddress);
}