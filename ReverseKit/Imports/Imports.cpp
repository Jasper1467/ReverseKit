#include "Imports.h"

#include <Windows.h>

void GetImportsFromIAT()
{
	const auto hModule = GetModuleHandle(nullptr);

	const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	const auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hModule) + pDosHeader->e_lfanew);
	auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<BYTE*>(hModule) + pNtHeaders->OptionalHeader.DataDirectory[
		IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name)
    {
	    const auto dllName = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hModule) + pImportDesc->Name);
	    auto pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<BYTE*>(hModule) + pImportDesc->FirstThunk);
	    auto pThunkOrig = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<BYTE*>(hModule) + pImportDesc->OriginalFirstThunk);
        while (pThunkOrig->u1.AddressOfData)
        {
            ImportInfo info;
            info.dllName = dllName;
            if (pThunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                info.functionName = std::to_string(IMAGE_ORDINAL(pThunkOrig->u1.Ordinal));
                info.functionAddress = reinterpret_cast<void*>(pThunk->u1.Function);
            }
            else
            {
	            const auto pImportByName
            	= reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<BYTE*>(hModule) + pThunkOrig->u1.AddressOfData);

                info.functionName = pImportByName->Name;
                info.functionAddress = reinterpret_cast<void*>(pThunk->u1.Function);
            }

            bool alreadyExists = false;
            for (const auto& [dllName, functionName, functionAddress] : imports) {
                if (dllName == info.dllName && functionName == info.functionName) {
                    alreadyExists = true;
                    break;
                }
            }

            if (!alreadyExists) {
                imports.push_back(info);
            }

            pThunk++;
            pThunkOrig++;
        }

        pImportDesc++;
    }
}