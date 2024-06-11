EXES, DLLs, kernel modules and even UEFI modules have the same structure: they are PE files.
This type of format has a defined structure. 
We will see the most important sections of the PE here:
- DOS header (`_IMAGE_DOS_HEADER`).
- DOS Stub.
- NT header**s** (`_IMAGE_NT_HEADERS`), headers as it is composed by:
	- File header (`_IMAGE_FILE_HEADER`).
	- Optional header **(don't take into account the "optional" term as this header is SO important)** (`_IMAGE_OPTIONAL_HEADER`).
- Section headers (`_IMAGE_SECTION_HEADER`).

# DOS Header 
Also called MS-DOS header. Internally called `_IMAGE_DOS_HEADER`.
Every PE file starts with this 64-bytes-long structure called the **DOS header**, it’s what makes the PE file an MS-DOS executable.
This header is not so important for the functionality of PE files on modern Windows systems. It is a header that is still present for backwards compatibility reasons.
This header makes the file a MS-DOS executable, so when it is loaded on MS-DOS the DOS stub gets executed instead of the program. We will see what the DOS stub is later.
## Structure
This structure is important to the PE loader on MS-DOS.
Only a few parameters of the structure are important to the PE loader on Windows Systems, so we are not going to take a deep look on all of them.
2 important members:
- `e_magic`: WORD. 2 bytes. Magic number; fixed value of `0x5A4D` or `MZ` in ASCII. Used to mark the file as an MS-DOS executable.
- `e_lfanew`: Last member of the DOS header. Located at offset `0x3C` into this header and **holds the offset to the start of NT headers**. This member is important to the PE Loader **as it tells the loader where to look for the NT header.**

Let's open a PE file with PEBear and see the DOS header, checking for these numbers:
![[attachments/pe_headers.png]]

We can see that the first value is called "Magic number" with the aforementioned value and that the last value is called "File address of the new exe header" and it is on 3C and points to the address 100.
If we go to this address, we can see the PE header first value:
![[attachments/pe_headers-1.png]]
## DOS Stub
The DOS Stub is what gets executed when the program is loaded in MS-DOS as the MS-DOS PE Loader will load this section of code instead of the real "entry point" of the executable.
Nowadays, the common DOS Stub is "This program cannot be run in DOS mode" and exiting, as our newest programs do not implement a DOS code.
![[attachments/pe_headers-2.png]]

Once we know what the DOS header and DOS stub is, here is a graphical description of the difference between a Windows PE loader and a MS-DOS PE loader:
![[attachments/pe_headers-3.png]]


# NT Headers
This is the main PE Header structure, the biggest one. Contains two headers, the file header and the optional headers.
## Relative Virtual Address (RVA)
Before we get into this section, we need to talk about the concept of **Relative Virtual Address, or RVA.**
The RVA of a binary is just **the offset from where the image was loaded in memory (the Image Base).** 
To translate an RVA to a absolute virtual address, it is needed to add the RVA to the Image Base.
The PE files use a lot the RVA value, so it is important to know what is it beforehand.

## Definition of NT Header
We can see the structure here, defined in [Windows Docs](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32):
```c
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```
It is important to mention that the structure is divided in **two versions, one for 32-bit PEs or PE32 executables and other for 64-bit executables, or PE32+ executables.**
The main difference between the two versions is the used version of `IMAGE_OPTIONAL_HEADER` structure which has two versions, `IMAGE_OPTIONAL_HEADER32` for 32-bit executables and `IMAGE_OPTIONAL_HEADER64` for 64-bit executables.

The NT Headers part contains three main parts:
## **PE signature** 
A 4-byte signature that **identifies the file as a PE file.** Its value is always I `0x50450000` which translates to `PE\0\0` in ASCII. (`45 50` is PE in HEX, inserted in Little Endian).
![[attachments/pe_headers-4.png]]
## **File Header** 
20 bytes structure. A standard `COFF` File Header. It holds **some information about the PE file, as the target architecture of the PE, number of sections (like .data, .text, etc.), the timestamp of its creation, pointer to the symbols table, size of the optional header, and some characteristics.** We will use this structure to pars the File Header. Here are the members of this structure:
	- **`Machine`:** Number that indicates the type of machine (**CPU Architecture**) the executable is targeting. Amongst all the values, the importants are `0x8864` for `AMD64` and `0x14c` for `i386`. For the whole list, just check the [official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).
	- **`NumberOfSections`:** This field holds the **number of sections** (or the number of section headers aka. the size of the section table.).
	- **`TimeDateStamp`:** A `unix` timestamp that indicates when the file was created.
	- **`PointerToSymbolTable` and `NumberOfSymbols`:** These two fields hold the file offset to the `COFF` symbol table and the number of entries in that symbol table. If they get set to `0` that means that no COFF symbol table is present. These values are usually set to 0 because the COFF debugging information is deprecated and is not used anymore.
	- **`SizeOfOptionalHeader`:** The size of the **Optional Header.**
	- **`Characteristics`:** A flag that indicates the attributes of the file, these attributes can be things like the file being executable, the file being a system file and not a user program, and a lot of other things. again, to check all the flags check the [official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).
	![[attachments/pe_headers-5.png]]

**Optional Header:** 
**The most important header of the NT Headers**, its name is the Optional Header because some files like object files don’t have it, but the PE loader looks for a lot of information in this header for files like executable files. This header provides important information to the OS loader and provides the most critical fields. This header doesn’t have a fixed size, that’s why the `IMAGE_FILE_HEADER.SizeOfOptionalHeader` member exists.
The first 8 elements of the Optional header are standard for every implementation of the COFF file format. The rest of the elements are an extension added by Microsoft used for the Microsoft PE Loader.
As mentioned earlier, there are two versions of the Optional Header, one for 32-bit executables and one for 64-bit executables.  
The two versions are different in two aspects:

- **The size of the structure itself (or the number of members defined within the structure):** `IMAGE_OPTIONAL_HEADER32` has 31 members while `IMAGE_OPTIONAL_HEADER64` only has 30 members, that additional member in the 32-bit version is a DWORD named `BaseOfData` which holds an RVA of the beginning of the data section.
- **The data type of some of the members:** The following 5 members of the Optional Header structure are defined as `DWORD` in the 32-bit version and as `ULONGLONG` in the 64-bit version:
    - **`ImageBase`**
    - **`SizeOfStackReserve`**
    - **`SizeOfStackCommit`**
    - **`SizeOfHeapReserve`**
    - **`SizeOfHeapCommit`**

Here is the structure of the Optional Header for 32 bits:
```c
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

And here it is for 64 bits:
```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

Let's see the most important elements of the Optional Header:
- **`Magic`:** Microsoft documentation describes this field as an integer that identifies the state of the image, the documentation mentions three common values:
	- **`0x10B`:** Identifies the image as a `PE32` executable.
	- **`0x20B`:** Identifies the image as a `PE32+` executable.
	- **`0x107`:** Identifies the image as a ROM image.
	- We saw that in the File header there was already a flag containing the architecture of the file (`IMAGE_FILE_HEADER.Machine`). However, the value is ignored by the Windows PE loader and this value is the one used instead.
- **`SizeOfCode`:** The size of the code (`.text`) section, or the sum of all code sections if there are multiple.
- **`SizeOfInitializedData`:** The size of the initialized data (`.data`) section, or the sum of all initialized data sections if there are multiple.
- **`SizeOfUninitializedData`:** The size of the uninitialized data (`.bss`) section, or the sum of all uninitialized data sections if there are multiple.
- **`AddressOfEntryPoint`:** An RVA of the entry point when the file is loaded into memory. The documentation states that for program images this relative address points to the starting address and for device drivers it points to initialization function. For DLLs the entry point is optional, and in that case, if there is no entry point, the `AddressOfEntryPoint` field is set to `0`.
- **`BaseOfCode`:** An RVA of the start of the code (`.text`) section when the file is loaded into memory.
- **`ImageBase`:** This value holds the **preferred address** of the first byte of the image when loaded into memory (the preferred base address). This value **must be multiple of 64K**. Due to protections like ASLR, this value is almost never used, and in that case the PE loader chooses an unused memory range to load the image into and **relocates** the image, which consists on **fix the constant addresses within the image to work with the new Image base that is set.** There is a specific section called `.reloc`  that is uses in cases of relocation and this section indicates the places that need fixing when relocating the base address.
- **`SectionAlignment`:** This field holds a value that gets used for section alignment in memory (in bytes), sections are aligned in memory boundaries that are multiples of this value. The documentation states that this value defaults to the page size for the architecture and it can’t be less than the value of `FileAlignment`.
- **`MajorOperatingSystemVersion`, `MinorOperatingSystemVersion`, `MajorImageVersion`, `MinorImageVersion`, `MajorSubsystemVersion` and `MinorSubsystemVersion`:** These members of the structure specify the major version number of the required operating system, the minor version number of the required operating system, the major version number of the image, the minor version number of the image, the major version number of the subsystem and the minor version number of the subsystem respectively.
- **`Win32VersionValue`:** A reserved field that the documentation says should be set to `0`.
- **`SizeOfImage:`** The size of the image file (in bytes), including all headers. It gets rounded up to a multiple of `SectionAlignment` because this value is used when loading the image into memory.
- **`SizeOfHeaders`:** The combined size of the DOS stub, PE header (NT Headers), and section headers rounded up to a multiple of `FileAlignment`.
- **`DLLCharacteristics`:** This field defines some characteristics of the image file, like if it’s `NX` compatible and if it can be relocated at run time. It has no sense to be called `DLLCharacteristics`, it exists within normal executable image files and it defines characteristics that can apply to normal executable files. A complete list of the possible flags for `DLLCharacteristics` can be found on the [official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).
- **`SizeOfStackReserve`, `SizeOfStackCommit`, `SizeOfHeapReserve` and `SizeOfHeapCommit`:** These fields specify the size of the stack to reserve, the size of the stack to commit, the size of the local heap space to reserve and the size of the local heap space to commit respectively.
- **`NumberOfRvaAndSizes` :** Size of the `DataDirectory` array. 
- **`DataDirectory`:** An array of `IMAGE_DATA_DIRECTORY` structures. We will talk about the DataDirectory structure and all of the possible `IMAGE_DATA_DIRECTORY` options. As a TL;DR, thios table where each of the directory is inside the PE. For example, the Import Directory (IAT) is at X RVA inside the PE.

Let's see the Optional Header of `notepad.exe` in W64:
![[attachments/pe_headers-6.png]]
![[attachments/pe_headers-7.png]]
The **Data Directory** is holding a lot of address regarding different directories that are relevant. I will talk about some of these directories, as the Import and Export directory, in other posts.
# Section Table
After the NT header, there is a Section Table. The section table follows the Optional Header immediately, it is an array of Image Section Headers, there’s a section header for every section in the PE file.  
Each header contains information about the section it refers to.

A section (like `.text`, `.data`, `.rsrc`) is where the actual contents of the file are stored, these include things like data and resources that the program uses, and also the actual code of the program, there are several sections each one with its own purpose. 