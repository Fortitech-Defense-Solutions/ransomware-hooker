#include "stdafx.h"
#include <list>
#include <iostream>
#include <string>
#include <cstring>
#include <windows.h>
#include <tlhelp32.h>
#include <easyhook.h>

std::list<int> processosVistos;

int innithook()
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Pega um snapshot de todos os processos em execução
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot falhou, código de erro: " << GetLastError() << std::endl;
        return 1;
    }

    // Configura o tamanho da estrutura antes de usá-la
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Recupera informações sobre o primeiro processo e sai se falhar
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Process32First falhou, código de erro: " << GetLastError() << std::endl;
        CloseHandle(hProcessSnap);
        return 1;
    }

    // Agora, percorre a lista de processos em execução e exibe as informações
    do {
        if (std::find(processosVistos.begin(), processosVistos.end(), pe32.th32ProcessID) == processosVistos.end()) {
            std::cout << "Novo processo encontrado: " << pe32.th32ProcessID << "\n";
            processosVistos.push_back(pe32.th32ProcessID);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return 0;
}
