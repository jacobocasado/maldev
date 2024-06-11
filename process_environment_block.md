In Windows, there are a couple of structures in **runtime that contain information about threads and processes.**
PEB and TEB are the most important.  

We will talk about the process-related one, the PEB (Process Environment Block).
Its structure is defined in `winternl.h`:
```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

We can see a lot of **reserved fields**.
Indeed, this is added as a commentary in the field, Microsoft does not want developers from using these structures as they change from time to time:
![[attachments/process_environment_block.png]]

The structures change depending on the architecture, so that is why it is not recommended to use these structures.

We can use Windows Debugger to get more information about the structures.
For example, here is the PEB of notepad.exe:
![[attachments/process_environment_block-1.png]]
We can see that we have a table containing the base address of all loaded DLLs in the process memory, and this table includes the process too.
We can "walk over" the PEB structure of a process in order to obtain a handle to the base address of the DLL in that process memory... That would be enough to not use `GetModuleHandle` as that is what the function does.
Once we have the memory of the DLL, we could walk over the export table of the DLL and get the address of any exported function by "walking over" its Export Directory Table, again, enough to not use `GetProcAddress`.
![[attachments/process_environment_block-2.png]]
We are interested in a structure inside the Ldr zone, at offset 0x020, which is the InMemoryOrderModuleList:
![[attachments/process_environment_block-3.png]]
This is a chain of addresses following a loop, you can parse it backwards or forwards.
How do we parse it? Well, on each of the address of `_LIST_ENTRY`, there is a structure called `_LDR_DATA_TABLE_ENTRY`, which has the following structure:
![[attachments/process_environment_block-4.png]]
We can see that at offset 0x048 of `_LDR_DATA_TABLE_ENTRY` base address there is the unicode of the DLL name.
We can just do the following:
- Irnos del TEB al PEB
- En el Peb, irnos a LDR 0x018 en este caso. Obtener la memaddress de Ldr y visitar esa memaddress
- Ir al offset 0x020 de esa memaddres que sabvemos que es el list entry. Lista de punteros.
- Para cada puntero de la lista, ir al offset 0x048, ver el nombre, SI es el DLL que queremos retornar esa address.
- Si no, vamos a la lista de punteros y tomamos el flink o el blink para ir recorriendo la lista y visitar el offset 0x48.
- Si ninguno es, entonces el dll no esta cargado en la memoria del proceso xD

Ahora, como obtenemos el PEB del proceso? XD
We reach the PEB of a process via the TEB of a thread. Each of the threads has a TEB (Thread Environment Block).


