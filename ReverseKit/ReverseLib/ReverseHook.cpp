#include "ReverseHook.h"

#include <Windows.h>
#include <cstdint>

void ReverseHook::hook(void* original_function, void* hooked_function, unsigned char* original_bytes)
{
	DWORD oldProtect;

	VirtualProtect(original_function, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(original_bytes, original_function, 14);

	/*
		   mov rax, hooked_function
		   jmp rax
	*/

	*static_cast<unsigned char*>(original_function) = 0x48;
	*(static_cast<unsigned char*>(original_function) + 1) = 0xB8;
	*reinterpret_cast<int64_t*>(static_cast<unsigned char*>(original_function) + 2) = reinterpret_cast<int64_t>(hooked_function);
	*(static_cast<unsigned char*>(original_function) + 10) = 0xFF;
	*(static_cast<unsigned char*>(original_function) + 11) = 0xE0;

	VirtualProtect(original_function, 14, oldProtect, &oldProtect);
}

void ReverseHook::unhook(void* original_function, const unsigned char* original_bytes)
{
	DWORD oldProtect;

	VirtualProtect(original_function, 14, PAGE_EXECUTE_READWRITE, &oldProtect);

	memcpy(original_function, original_bytes, 14);

	VirtualProtect(original_function, 14, oldProtect, &oldProtect);
}

void* ReverseHook::Trampoline::createTrampoline(void* original_function)
{
	void* trampoline = VirtualAlloc(nullptr, 14 + sizeof(void*), MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (trampoline == nullptr)
		return nullptr;

	/*
		mov rax, original_function
		jmp rax
	*/
	*static_cast<unsigned char*>(trampoline) = 0x48;
	*(static_cast<unsigned char*>(trampoline) + 1) = 0xB8;
	*reinterpret_cast<void**>(static_cast<unsigned char*>(trampoline) + 2) = original_function;
	*(static_cast<unsigned char*>(trampoline) + 10) = 0xFF;
	*(static_cast<unsigned char*>(trampoline) + 11) = 0xE0;

	return trampoline;
}

void ReverseHook::Trampoline::hook(void* original_function, void* hooked_function,
	unsigned char* original_bytes)
{

	DWORD oldProtect = 0;

	void* trampoline = createTrampoline(original_function);

	if (trampoline == nullptr)
		return;

	memcpy(original_bytes, original_function, 14);

	/*
		mov rax, hooked_function
		jmp rax
	*/

	*static_cast<unsigned char*>(original_function) = 0x48;
	*(static_cast<unsigned char*>(original_function) + 1) = 0xB8;
	*reinterpret_cast<void**>(static_cast<unsigned char*>(original_function) + 2) = hooked_function;
	*(static_cast<unsigned char*>(original_function) + 10) = 0xFF;
	*(static_cast<unsigned char*>(original_function) + 11) = 0xE0;

	*(static_cast<unsigned char*>(trampoline) + 14) = 0xE9;

	*reinterpret_cast<int*>(static_cast<unsigned char*>(trampoline) + 15)
		= static_cast<int>(static_cast<unsigned char*>(original_function) + 14 - (static_cast<unsigned char*>(trampoline) + 14));

	VirtualProtect(original_function, 14, oldProtect, &oldProtect);
}

void ReverseHook::Trampoline::unhook(void* original_function, const unsigned char* original_bytes)
{
	DWORD oldProtect = 0;

	VirtualProtect(original_function, 14, PAGE_EXECUTE_READWRITE, &oldProtect);

	memcpy(original_function, original_bytes, 14);

	VirtualProtect(original_function, 14, oldProtect, &oldProtect);
}