# What is a PE file
**Portable Executable** files (commonly known as PEs) are a way to organize an executable code in a file on disk so that windows OS loader can read from the disk **and load in into memory as a process.**

In a nutshell, consider PE as a book. Contains the text, has an index, information about the book, etc. 

PE file have **headers and sections**. That is the first separation when we look a PE file internally.
![](attachments/Pasted%20image%2020240210094511.png)
Let's analyze the image. We can see the headers (information about the executable, metadata) and then sections. The sections are the real contents of the executable (the code, the imports from Windows libraries and the data used by the code, like strings).

# Analyzing PEs practically
Let's use PEbear to analyze the calc.exe program in Windows/System32/calc.exe.

We can see the sections, which is what really interests us, and see that there are several of them:
![](attachments/Pasted%20image%2020240210095559.png)

I will describe briefly each of the sections:
- .text: The code that will be executed. This will be, from what I know, read and executed.
- .rdata: Read only data.
- .data: Data like global variables, etc. 
- .pdata: For exception handling
- .rsrc: A section that contain resources, like images, DLLs, manifests, etc. 
- .reloc: A section so that the loader can load the process in memory with random addresses.

## Analyzing the resources in a PE.
We can use PEbear to look for the .rsrc section, which is pretty interesting for us:
![](attachments/Pasted%20image%2020240210095820.png)
We can see that literaly, there are images, manifests, in the .rsrc section and we can see the content.

# EXEs vs DLL
EXEs need to have a function called main, which will be the one detected by the Windows loader one it has initialized the process in memory. This means that, the way windows knows which part of the program is the starting one, is by searching from the main function in the executable file.

DLLs work in a way that they are called by other programs (they are dinamically linked libraries). How DLLs work is simple and the main difference is that the OS **does not create a new process**: when a program needs a DLL function, the OS makes some space in memory **within the process** to load the DLL, loads the DLL, and once the DLL is loaded into memory, the loader handles the DLL control to the process that asked for that specific library so that the process can call the functions from the DLL. This way, when we make malware, we need the DLLMain section so the DLL is initialized and also external function(s) that will be executed by the malware.

## About DLLs

Every process that loads the DLL maps it into its virtual address space. After the process loads the DLL into its virtual address, it can call the exported DLL functions.

The system maintains a per-process reference count for each DLL. When a thread loads the DLL, the reference count is incremented by one. When the process terminates, or when the reference count becomes zero (run-time dynamic linking only), the DLL is unloaded from the virtual address space of the process.

Like any other function, an exported DLL function runs in the context of the thread that calls it. Therefore, the following conditions apply:

- The threads of the process that called the DLL can use handles opened by a DLL function. Similarly, handles opened by any thread of the calling process can be used in the DLL function.
- The DLL uses the stack of the calling thread and the virtual address space of the calling process.
- The DLL allocates memory from the virtual address space of the calling process.
