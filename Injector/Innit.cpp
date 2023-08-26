#include "stdafx.h"
#include <iostream>
#include <windows.h>
#include <easyhook.h>
#include <string>

int makehook(DWORD processId) {

	WCHAR* dllToInject = L".\\Hooker.dll";
	wprintf(L"Attempting to inject: %s\n\n", dllToInject);

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
		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";
	}
	else
	{
		std::wcout << L"Library injected successfully.\n";
	}

	return 0;
}
