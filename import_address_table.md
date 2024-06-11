http://sandsprite.com/CodeStuff/Understanding_imports.html
https://medium.com/@s12deff/bypass-iat-detection-import-address-table-971c77b73b75
https://devblogs.microsoft.com/oldnewthing/20221006-07/?p=107257
https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking
https://www.bordergate.co.uk/import-address-tables/
https://unprotect.it/technique/iat-hooking/
https://alice.climent-pommeret.red/posts/how-and-why-to-unhook-the-import-address-table/
https://github.com/m0n0ph1/IAT-Hooking-Revisited
https://www.blackhat.com/presentations/bh-dc-09/Krumheuer_Raber/BlackHat-DC-09-Krumheuer-Raber-QuietRIATT-WhitePaper.pdf
https://0xrick.github.io/win-internals/pe6/
https://ntcore.com/files/inject2it.htm

# What is the Import Address Table (IAT)
IAT is a "table" that all portable executables have (EXEs and DLLs). 
When a program needs to use a function from a DLL, it must first locate the address of that function.
But when the program is loaded, the DLL is not still in memory, so it is not possible to know which address does the function have.
When all the DLLs needed by a program are loaded into the program's memory (and therefore the memory addresses are known), the PE loader fulfills the address of these needed functions so that the program can call them.
The place where the loader places these memory addresses is the Import Address Table.
To know more about the IAT, we need to learn about the Import Directory Table, or IDT.

# Import Directory table (IDT)
The Import Directory Table is a Data Directory located at the beginning of the `.idata` section.

It consists of an array of `IMAGE_IMPORT_DESCRIPTOR` structures, one per imported DLL.
It doesn’t have a fixed size, so the last `IMAGE_IMPORT_DESCRIPTOR` of the array is zeroed-out (NULL-Padded) to indicate the end of the Import Directory Table.
`IMAGE_IMPORT_DESCRIPTOR` is defined as follows:

```C
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME; // Union means that the variable can be called either X or Y.
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name; // Name of the imported DLL
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```
The size of each `IMAGE_IMPORT_DESCRIPTOR` is 20 bytes long.
Of this structure, we must know that:
- `OriginalFirstThunk` is a pointer to the Import Lookup Table (ILT) which contains the names and "hints" (like ordinals) of the needed imported functions.
- `FirstThunk` is a pointer to the **Import Address Table (IAT)** which contains the memory addresses of the imported functions. At start, **the IAT has the same content as the ILT. Once it gets fulfilled by the OS loader, the value differs as the IAT gets fulfilled with memory addresses. The ILT does not get overwritten.**
- `Name` is a pointer to the name of the imported DLL.

Note that there is one IAT per imported DLL also, and that the 
Here we can see the `IMAGE_IMPORT_DESCRIPTOR` for `kernel32.dll`, which is needed by `notepad.exe`.
![[attachments/import_address_table.png]]
In the following image we can see that the IAT and ILT have the same starting values:
![[attachments/import_address_table-1.png]]
![[attachments/import_address_table-2.png]]
The PE loader basically uses the ILT to know what functions to search its memory address to fulfill the IAT.
And to get the functions' memory address, it uses the Export Address Table (EAT) of the exported DLL.

