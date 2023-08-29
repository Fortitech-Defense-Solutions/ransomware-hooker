#include "stdafx.h"
#include "innithook.h"

#include <list>
#include <string>
#include <thread>
#include <iostream>
#include <algorithm>

#include <windows.h>
#include <tlhelp32.h>

int _tmain(int argc, _TCHAR* argv[]){
    std::list<DWORD> currentProcesses;
    std::list<DWORD> newProcesses;

    
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        
        return -1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        
        CloseHandle(hProcessSnap);
        return -1;
    }

    do {
        currentProcesses.push_back(pe32.th32ProcessID);
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    while (true) {
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
           
            return -1;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcessSnap, &pe32)) {
            
            CloseHandle(hProcessSnap);
            return -1;
        }

        do {
            if (std::find(currentProcesses.begin(), currentProcesses.end(), pe32.th32ProcessID) == currentProcesses.end()) {
                newProcesses.push_back(pe32.th32ProcessID);
            }
        } while (Process32Next(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);

        
        for (DWORD pid : newProcesses) {
            makehook(pid);
        }

        currentProcesses.splice(currentProcesses.end(), newProcesses);

        Sleep(1000);
    }

	return 0;
}