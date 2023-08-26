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

    // Get the list of current processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        // Failed to create snapshot of processes
        return -1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        // Failed to get first process
        CloseHandle(hProcessSnap);
        return -1;
    }

    do {
        currentProcesses.push_back(pe32.th32ProcessID);
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    // Continuously update the list of new processes
    while (true) {
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            // Failed to create snapshot of processes
            return -1;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcessSnap, &pe32)) {
            // Failed to get first process
            CloseHandle(hProcessSnap);
            return -1;
        }

        do {
            if (std::find(currentProcesses.begin(), currentProcesses.end(), pe32.th32ProcessID) == currentProcesses.end()) {
                newProcesses.push_back(pe32.th32ProcessID);
            }
        } while (Process32Next(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);

        // Print the new processes
        for (DWORD pid : newProcesses) {
            makehook(pid);
        }

        // Update the current processes list
        currentProcesses.splice(currentProcesses.end(), newProcesses);

        // Wait for 1 second before checking again
        Sleep(1000);
    }

	return 0;
}