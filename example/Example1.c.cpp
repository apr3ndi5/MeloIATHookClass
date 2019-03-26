#include "pch.h"
#include <iostream>
#include <Windows.h>
#include "IATHook.h"

void CheckAddr()
{
	for (;;)
	{
		DWORD Addr = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetModuleHandleW");
		printf("0x%x\n", Addr);
	}
}

void printinscreen()
{
	printf("Hooked lmao\n");
}


int main()
{
	
	HANDLE A = GetModuleHandle(nullptr);
	LoadCursorA(nullptr, "A");
	MessageBox(nullptr, L"AAAAAAA", L"AAAAAAA", 1);
	HookIAT IATHook;
	CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)CheckAddr, 0, 0, 0);
	IATHook.Hook("MessageBoxW", (DWORD)&printinscreen);
	MessageBox(nullptr, L"AAAAAAA", L"AAAAAAA", 1);
	//This stopped an exception
	__asm
	{
		pop ebx
	}
}
