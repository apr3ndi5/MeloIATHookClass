#pragma once
#define  ReCa reinterpret_cast
#include <Windows.h>
#include <string>

class HookIAT {


private:
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS NTHeaders;
	PIMAGE_OPTIONAL_HEADER OPHeader;
	PIMAGE_DATA_DIRECTORY DataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;


public:
	HookIAT()
	{
		this->DOSHeader = ReCa<PIMAGE_DOS_HEADER>(GetModuleHandle(nullptr));
		this->NTHeaders = ReCa<PIMAGE_NT_HEADERS>((BYTE*)DOSHeader + DOSHeader->e_lfanew);
		this->OPHeader = &NTHeaders->OptionalHeader;
		this->DataDirectory = this->OPHeader->DataDirectory;
		this->ImportDescriptor = ReCa<PIMAGE_IMPORT_DESCRIPTOR>((BYTE*)DOSHeader + DataDirectory[1].VirtualAddress);
	}

	BOOL Hook(std::string FunctionName, uintptr_t Addr)
	{

		PIMAGE_THUNK_DATA ImportLookUpTable = nullptr;
		PIMAGE_IMPORT_BY_NAME FunctionGetName = nullptr;
		PIMAGE_THUNK_DATA IAT = nullptr;

		for (int i = 0; ; ++i)
		{

			if (ImportDescriptor[i].OriginalFirstThunk == NULL)
				break;

			ImportLookUpTable = ReCa<PIMAGE_THUNK_DATA>(ImportDescriptor[i].OriginalFirstThunk + (BYTE*)DOSHeader);

			if (ImportLookUpTable == NULL)
				break;

			if (!(ImportLookUpTable->u1.AddressOfData & IMAGE_ORDINAL_FLAG))
				FunctionGetName = ReCa<PIMAGE_IMPORT_BY_NAME>(ImportLookUpTable->u1.AddressOfData + (BYTE*)DOSHeader);

			if (FunctionGetName->Name != FunctionName)
				continue;
			else
			{
				IAT = ReCa<PIMAGE_THUNK_DATA>(ImportDescriptor[i].FirstThunk + (BYTE*)DOSHeader);
				*ReCa<uintptr_t*>(IAT) = Addr;
				return true;
			}
		}
		return false;
	}


};