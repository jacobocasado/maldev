#include <stdio.h>
#include "helpers.h"

int main() {

	printf("Kernel32.dll memaddress GetModuleHandle: %lp\n", GetModuleHandleW(L"kernel32.dll"));
	printf("Address of AddAtomA inside Kernel32.dll: %lp\n", GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "AcquireSRWLockExclusive"));

	printf("Kernel32.dll memaddress GetModuleHandle: %lp\n", customGetModuleHandle(L"kernel32.dll"));
	printf("Address of AddAtomA inside Kernel32.dll: %lp\n", customGetProcAddress(customGetModuleHandle(L"kernel32.dll"), "AcquireSRWLockExclusive"));
}