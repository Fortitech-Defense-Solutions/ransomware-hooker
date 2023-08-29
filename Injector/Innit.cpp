#include "stdafx.h"
#include <iostream>
#include <windows.h>
#include <easyhook.h>
#include <string>

int makehook(DWORD processId) {

	WCHAR* dllToInject = L".\\Hooker.dll";
	wprintf(L"Tentando injetar: %s\n\n", dllToInject);

	// Injeta a dllToInject no processo alvo 
	NTSTATUS nt = RhInjectLibrary(
		processId,
		0,
		EASYHOOK_INJECT_DEFAULT,
		NULL,
		dllToInject,
		NULL,
		0
	);

	if (nt != 0)
	{
		printf("RhInjectLibrary falhou com o código de erro = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";
	}
	else
	{
		std::wcout << L"Biblioteca injetada com sucesso.\n";
	}

	return 0;
}
