# Processes
Instance of an executable. Container that has everything needed for a program to run (code, data, memory...). BUT, single thread. Each thread has its own process.

If an application has one thread, it has one process. Therefore, an application can have more than one process attached to it, one per each thread; e.g., chrome spawn a new process for each tab that we create. 

Also, an application can have a single process and this process can spawn MULTIPLE processes; these processes are called "child processes".

Typically, the process **does not know how to communicate with other process**. Each process has its own **virtual address space**, VA space. Remember that processes think they are alone in the computer.

Application processes, background processes, window processes.
- Application processes: Basically, if the process has a window attached to it, they are application processes.
- Background: They do not require user interaction; they usually execute automatically but it is not neccesary as some process that start as application process spawn background processes or turn as background process. They are usually important for system management.
- Windows processes: System level processes that are **vital** for OS function. Perform critical tasks.

![](attachments/processes,%20threads%20and%20handles.png)

Processes have a priority level assigned to them -> CPU time assigned relatively to each process. REALTIME is the most demanding CPU but it is dangerous to use; not recommended.
![](attachments/processes,%20threads%20and%20handles-1.png)

Each process has its PID, the image path (the EXE that generates this process), and more info.

# Threads
Each process start with a single thread. But a process can have more threads (as an application can have more processes). The difference is that threads share the same process, so they know between each others as they are in the same memory zone.

Note that threads are much more light, take less time to spawn and kill, and they work together to get the same objective.

Threads have IDs and handles, like processes. We can create threads and processes in our own scripts,  like we will do in some malwares.

# Handles
We will deal with handles so much during maldev, so we have to know them.
A handle is a **pointer to an object. It allows our programs to interact with the handles, to know where to point**. We will have handles to processes, handles to modules, handles to windows. 

For example, a Windows API function called getProcessInfo:
![](attachments/processes,%20threads%20and%20handles-2.png)
This accepts a handle to a process to retrieve the process information!
We will know more about handles when we program our malware and interact with them. Sometimes handles are the only way to manipulate the resources.

Handles are system wide, that means that if process A knows its process handle, process B can interact with process A. Before that, they did not know each others.

# Windows API
AKA. Win32 API. Application Programming Interface to interact with the OS. Offers a lot of functionalities.
Win32 API is well documented, but a low level API like NTAPI is not documented but reversed by other people.

To include the Windows API in our programs, we can add the windows.h library:
![](attachments/processes,%20threads%20and%20handles-3.png)
In the last example, I managed to create a message box using the Windows API. Note that, this is documented and easy to use.

In most of the Windows API functions, we will have different variants. For example, MessageBox has MessageBoxW (UNICODE) and MessageBoxA )(ANSI). Note that the strings need to be added differently in both functions, as the rendering of the strings differ.
Nevertheless, ANSI is dated, so use Unicode (ending in W). But remember to add an L before each string, to use Unicode:
![](attachments/processes,%20threads%20and%20handles-4.png)

There are other type of extensions, like the "Ex", that have more parameters or more debugging options. E.g., createRemoteThread vs CreateRemoteThreadEx. The things that each function does differ slightly.

Now, we will create a process with the CreateProcessW function from the Windows API.
Recommended to copy the syntax of the code from the documentation on top, as a comment, to learn a bit more at first:
![](attachments/processes,%20threads%20and%20handles-5.png)
Reading what are the parameters that the CreateProcessW function needs, we managed to create the following code, which spawns the notepad.exe application as a main process:
```c
#include <windows.h>
#include <stdio.h>

int main(void) {

	STARTUPINFOW si = {0}; // All the values on 0
	PROCESS_INFORMATION pi = {0}; //All the values on 0

	ZeroMemory(&si, sizeof(si)); // Other way to initialize struct to 0, official Windows way.
	ZeroMemory(&pi, sizeof(pi)); // Other way to initialize struct to 0, official Windows way.

	if (!CreateProcessW(
		L"C:\\Windows\\System32\\notepad.exe",
		NULL, // No CLI
		NULL,
		NULL,
		FALSE,
		BELOW_NORMAL_PRIORITY_CLASS,
		NULL,
		NULL,
		&si,
		&pi
	)) {
		// GetLastError will get the last error code from the thread.
		printf("[!] Failed to create process. Error: %ld", GetLastError());
		return EXIT_FAILURE;
	}

	printf("Process started with PID %ld", pi.dwProcessId);
	return EXIT_SUCCESS;
}
```

We can even see that the PID that we printed getting pi.dwProcessId is the same value as the returned in Process Hacker:
![](attachments/processes,%20threads%20and%20handles-6.png)
We managed also to specify the CPU cycle priority below normal, which gets reflected in task manager: 
![](attachments/processes,%20threads%20and%20handles-7.png)
