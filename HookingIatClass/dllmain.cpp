#include <Windows.h>
#include "IATHook.h"

void TestHook()
{
	HookIAT Hook1;
	uintptr_t GetModuleHandleAAddr = (uintptr_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "GetModuleHandleA");
	Hook1.Hook("MessageBoxA", GetModuleHandleAAddr);
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD  reasonCall, LPVOID lpReserved)
{
	if (reasonCall == DLL_PROCESS_ATTACH)
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)TestHook, nullptr, 0, 0);

    return TRUE;
}

