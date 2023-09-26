#include "stdafx.h"
#include "innithook.h"

#include <windows.h>
#include <tlhelp32.h>

#include <list>
#include <vector>
#include <string>
#include <thread>
#include <iostream>
#include <algorithm>

int _tmain(int argc, _TCHAR* argv[]){
    std::list<DWORD> currentProcesses;
    std::list<DWORD> newProcesses;

    std::vector<std::wstring> paths = { L"C:\\Windows\\System32", L"C:\\Program Files"};

    
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
            if (pid != GetCurrentProcessId()) {
                TCHAR szEXEPath[MAX_PATH] = { 0 };

                HANDLE hPid = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

                if (hPid == NULL)
                    continue;

                if (hPid != NULL) {
                    DWORD dwSize = MAX_PATH;
                    if (!QueryFullProcessImageName(hPid, 0, szEXEPath, &dwSize)) {
                        std::cerr << "QueryFullProcessImageName failed." << std::endl;
                    }
                    else {
                        std::wstring exePath(szEXEPath);
                        boolean permitido = 0;

                        for (const auto& path : paths) {
                            if (exePath.substr(0, path.length()) == path) {
                                permitido = 1;
                                break;
                            }
                        }

                        if (!permitido) {
                            std::cout << "PID: " << pid << std::endl;
                            std::wcout << L"Executable Path: " << szEXEPath << std::endl;

                            HANDLE tPid = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

                            if (makehook(pid) != 1) {

                                BOOL result = TerminateProcess(tPid, 0);

                                if (!result) {
                                    TerminateProcess(tPid, 0);
                                }

                            }
                            CloseHandle(tPid);
                        }
                    }
                }

                
                CloseHandle(hPid);
            }
        }

        currentProcesses.splice(currentProcesses.end(), newProcesses);

        Sleep(1000);
    }

	return 0;
}