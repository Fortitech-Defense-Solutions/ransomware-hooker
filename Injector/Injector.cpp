#include "stdafx.h"
#include <iostream>
#include <string>
#include <cstring>
#include <easyhook.h>
#include "innithook.h"
#include <thread>

void MonitorarProcessos() {
	while (true) {
		innithook(); // Chama a função innithook para atualizar a lista global de processos

		// Aguarde um pouco antes de verificar novamente
		std::this_thread::sleep_for(std::chrono::seconds(1));
		//deletepid () 
	}
}

int _tmain(int argc, _TCHAR* argv[])

{
	MonitorarProcessos();
	DWORD processId;
	std::wcout << "Enter the target process Id: ";
	std::cin >> processId;

	DWORD freqOffset = 0;
	std::cout << "Enter a frequency offset in hertz (e.g. 800): ";
	std::cin >> freqOffset;

	WCHAR* dllToInject = L"..\\Debug\\Hooker.dll";
	wprintf(L"Attempting to inject: %s\n\n", dllToInject);
	
	// injeta a dllToInject no processid alvo 

	NTSTATUS nt = RhInjectLibrary(
		processId,   
		0,           
		EASYHOOK_INJECT_DEFAULT,
		dllToInject,
		NULL,	
		&freqOffset,
		sizeof(DWORD)
	);

	if (nt != 0)
	{
		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";
	}
	else 
	{
		std::wcout << L"Library injected successfully.\n";
	}

	std::wcout << "Press Enter to exit";
	std::wstring input;
	std::getline(std::wcin, input);
	std::getline(std::wcin, input);
	return 0;
}