## What is the Export Address Table
When a program uses a exported function of a DLL, the loader goes to the DLL to execute the code of the function.
But how does the loader know **what is the memory address of that function?** Well, that is what the EAT (Export Address Table) is for.
The EAT is a table inside the DLL that indicate **the RVA (Relative Virtual Address)** of each of the exported functions of the DLL.
The loader obtains the memory address and therefore the execution routine of the function by visiting this table inside the DLL.

Here is the EAT inside the PE structure:
![[attachments/Export Address Table.png]]

The loader searches for the `_IMAGE_EXPORT_DIRECTORY` header of the PE in order to find the EAT. 
Here is the `_IMAGE_EXPORT_DIRECTORY` header structure:
![[attachments/Export Address Table-1.png]]

These are the interesting fields of the IET:
- **Name**: Name of the DLL.
- **Base**: The number used to subtract from the ordinal number to get the index into the AddressOfFunctions array. We will see what is the ordinal in a moment.
- **NumberOfFunctions**: Integer containing the total number of exported functions, either by name or ordinal.
- **NumberOfNames**: Number of the exported names, which does not have to be the NumberOfFunctions name as the functions can be exported by ordinal and not by name. Therefore, if this value is 0, then all of the functions in this module are exported by ordinal and none of them is exported by name.
- **AddressOfFunctions**: A **pointer** to the **Export Address Table**. The pointer points to the first exported function address of the EAT. The EAT is basically the array AddressOfFunctions, as it contains the RVA of the exported functions.
- **AddressOfNames**: A **pointer** to the array of **NAMES** of the functions that are exported. 
- **AddressOfNameOrdinals**: A **pointer** to the array of **ORDINALS** of the exported functions. The ordinals from this array need to add the "Base" number that we talked about before.

So let’s suppose PE loader wants to load the **name3** function in a particular DLL. First step is to parse the DLL headers and get access to the IMAGE_EXPORT_DIRECTORY. Then, the lookup will start as follows:
![[attachments/Export Address Table-2.png]]

The PE loader will obtain the **position of the "name3" function in the `AddressOfNames` comparing the names of the function with "name3".** In this case, it will obtain the number 3 (starting from 0).
After that, it will check the value of `AddressOfNameOrdinals[3]` to obtain the position of the address of "name3" in the AddressOfFunctions array, which is the array that contain the addresses.
In this case, the value of `AddressOfNameOrdinals[3]` is 4, so it will check `AddressOfFunctions[4]` to finally obtain the RVA of the "name3" function.

Obviously, if the loader tries to find "name3" in the `AddressOfNames` array and it is not found, that means that the DLL does not export such function and the loader retrieves an error.
What happens if the loader does not know the function name but knows **the ordinal of the function?** It is simple: it takes the Base number, substracts the ordinal minus the base number and visits the value of `AddressOfFunctions` with such resulting number.
This means that it is possible to use an exported function knowing its ordinal and not its name.

## Practical use case
Let's open `kernel32.dll` with PEstudio and see what we have seen in a practical way.
First, let's get the `_IMAGE_EXPORT_DIRECTORY` header:
![[attachments/Export Address Table-3.png]]

We can see that this is at high level and we want to understand a bit more what is happening behind. Let's open the DLL with PEBear:
![[attachments/Export Address Table-4.png]]

Let's visit this header which is the `_IMAGE_EXPORT_DIRECTORY` header:
![[attachments/Export Address Table-5.png]]

We can see that in the "Exports" section we get a parsed view from this header.
The interesting thing of this header is the EAT, `AddressOfFunctions`.
In the "Exported Functions" section of PEBear, we have the AddressOfFunctions memory address, and the corresponding memory address of each function is "Function RVA":
![[attachments/Export Address Table-6.png]]
The other columns, like Ordinal and Name RVA are in the table because PEBear correlates them for a better overview.

Here we can see that the column corresponding to the memory address of the exported function is "Function RVA":
![[attachments/Export Address Table-7.png]]
## Forwarded functions
Why there are exported functions that include a "Forwarder" value?
![[attachments/Export Address Table-8.png]]

And why do these functions have a **high Function RVA** value (starting on 9....) and the other functions without a forwarder have a different value?
Well, the functions with a Forwarder are in the .rdata section, and in reality, they do not include the **memory address of the function, but they include the name of the DLL that really imports the function (the forwarded DLL) and how this function is called in the forwarded DLL**.
For example, the function in the first ordinal forwards us to NTDLL.RtlAcquireSRWLockExclusive:
![[attachments/Export Address Table-9.png]]
The value is not a pointer but a string indicating the forwarded DLL and the function name. **We can recognize this, but for the loader, this is all hexadecimal values. How does the loader recognize that this is a forwarded function?**
With a simple check: If the RVA of the function is in the range of the Export Directory section (it is in .rdata), it is a forwarded function. If not, it is an explicit implementation and not a forwarder.
For example, the RVA of this forwarded function is 9D0A1.
This memory address is between the Export Directory section (99080 to 99080-DF58)
![[attachments/Export Address Table-10.png]]
Therefore, it is a forwarded function and interprets the value as (DLLNAME.FunctionName) and repeats this whole process of obtaining the memory value of the function in the RVA of the forwarded DLL.


