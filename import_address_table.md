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

# What is the Import Address Table (IAT)
IAT is a table that all portable executables have (EXEs and DLLs). 

When a program needs to use a function from a DLL, it must first locate the function’s address in memory. The IAT is used to store the addresses of the functions in the DLL that the program is using. The IAT is a table of pointers that is filled at runtime when the program loads, with the addresses of the functions it needs from the DLLs it depends on.

The IAT is a table that contains a list of each of the functions from other DLLs that our executable needs, next to the memory address to that function in the external DLL. Our problem is solved, as now we can replace all of the calls to an external function to a place in the IAT.

The OS is in charge of "fulfilling" the entries of each of the functions in the IAT, adding the memory address for each one (remember that we do not know it before executing, as the DLL is loaded into the memory of the process).

## Technical info about the IAT and related things
The Import Directory Table is a Data Directory located at the beginning of the `.idata` section of the executable.

### Import directory table (IDT)
The Import Directory Table is a Data Directory located at the beginning of the `.idata` section.

It consists of an array of `IMAGE_IMPORT_DESCRIPTOR` structures, each one of them is for a DLL.  
It doesn’t have a fixed size, so the last `IMAGE_IMPORT_DESCRIPTOR` of the array is zeroed-out (NULL-Padded) to indicate the end of the Import Directory Table.

`IMAGE_IMPORT_DESCRIPTOR` is defined as follows:

```
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

- **`OriginalFirstThunk`:** RVA of the ILT.
- **`TimeDateStamp`:** A time date stamp, that’s initially set to `0` if not bound and set to `-1` if bound.  
    In case of an unbound import the time date stamp gets updated to the time date stamp of the DLL after the image is bound.  
    In case of a bound import it stays set to `-1` and the real time date stamp of the DLL can be found in the Bound Import Directory Table in the corresponding `IMAGE_BOUND_IMPORT_DESCRIPTOR` .  
    We’ll discuss bound imports in the next section.
- **`ForwarderChain`:** The index of the first forwarder chain reference.  
    This is something responsible for DLL forwarding. (DLL forwarding is when a DLL forwards some of its exported functions to another DLL.)
- **`Name`:** An RVA of an ASCII string that contains the name of the imported DLL.
- **`FirstThunk`:** RVA of the IAT.

---
### Bound Imports

A bound import essentially means that the import table contains fixed addresses for the imported functions.  
These addresses are calculated and written during compile time by the linker.

Using bound imports is a speed optimization, it reduces the time needed by the loader to resolve function addresses and fill the IAT, however if at run-time the bound addresses do not match the real ones then the loader will have to resolve these addresses again and fix the IAT.

When discussing `IMAGE_IMPORT_DESCRIPTOR.TimeDateStamp`, I mentioned that in case of a bound import, the time date stamp is set to `-1` and the real time date stamp of the DLL can be found in the corresponding `IMAGE_BOUND_IMPORT_DESCRIPTOR` in the Bound Import Data Directory.
#### Bound Import Data Directory

The Bound Import Data Directory is similar to the Import Directory Table, however as the name suggests, it holds information about the bound imports.

It consists of an array of `IMAGE_BOUND_IMPORT_DESCRIPTOR` structures, and ends with a zeroed-out `IMAGE_BOUND_IMPORT_DESCRIPTOR`.

`IMAGE_BOUND_IMPORT_DESCRIPTOR` is defined as follows:

```
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;
```

- **`TimeDateStamp`:** The time date stamp of the imported DLL.
- **`OffsetModuleName`:** An offset to a string with the name of the imported DLL.  
    It’s an offset from the first `IMAGE_BOUND_IMPORT_DESCRIPTOR`
- **`NumberOfModuleForwarderRefs`:** The number of the `IMAGE_BOUND_FORWARDER_REF` structures that immediately follow this structure.  
    `IMAGE_BOUND_FORWARDER_REF` is a structure that’s identical to `IMAGE_BOUND_IMPORT_DESCRIPTOR`, the only difference is that the last member is reserved.

That’s all we need to know about bound imports.

---

### Import Lookup Table (ILT)[Permalink](https://0xrick.github.io/win-internals/pe6/#import-lookup-table-ilt "Permalink")

Sometimes people refer to it as the Import Name Table (INT).

Every imported DLL has an Import Lookup Table.  
`IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk` holds the RVA of the ILT of the corresponding DLL.

The ILT is essentially a table of names or references, it tells the loader which functions are needed from the imported DLL.

The ILT consists of an array of 32-bit numbers (for PE32) or 64-bit numbers for (PE32+), the last one is zeroed-out to indicate the end of the ILT.

Each entry of these entries encodes information as follows:

- **Bit 31/63 (most significant bit)**: This is called the Ordinal/Name flag, it specifies whether to import the function by name or by ordinal.
- **Bits 15-0:** If the Ordinal/Name flag is set to `1` these bits are used to hold the 16-bit ordinal number that will be used to import the function, bits 30-15/62-15 for PE32/PE32+ must be set to `0`.
- **Bits 30-0:** If the Ordinal/Name flag is set to `0` these bits are used to hold an RVA of a Hint/Name table.

#### Hint/Name Table[Permalink](https://0xrick.github.io/win-internals/pe6/#hintname-table "Permalink")

A Hint/Name table is a structure defined in `winnt.h` as `IMAGE_IMPORT_BY_NAME`:

```
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

- **`Hint`:** A word that contains a number, this number is used to look-up the function, that number is first used as an index into the export name pointer table, if that initial check fails a binary search is performed on the DLL’s export name pointer table.
- **`Name`:** A null-terminated string that contains the name of the function to import.

---
### Import Address Table (IAT)[Permalink](https://0xrick.github.io/win-internals/pe6/#import-address-table-iat "Permalink")

On disk, the IAT is identical to the ILT, however during bounding when the binary is being loaded into memory, the entries of the IAT get overwritten with the addresses of the functions that are being imported.