// BeepHook.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#include <easyhook.h>
#include <Windows.h>
#include "hookfunctions.h"

#include <string>
#include <iostream>

// EasyHook will be looking for this export to support DLL injection. If not found then 
// DLL injection will fail.
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{	
	hookWriting();

	hookMoving();

	hookCrypto();

	return;
}