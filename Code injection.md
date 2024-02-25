Method of transfering our payload to another process.
E.g., malware running (from phishing or trojan), code running.
We want to run this payload, to migrate it, to a different process.

Reasons:
- Shrot lived process (backdoored program that will be closed, we want to go to a process that will have a larger life)
- changing working context -> word.exe payload starting downloading in internet? strange. go to a browser,. Also firewall blocking connections
- TOON rule -> have two connections to your c2, one co nnection can be lost and xD. injection is your backup.

Classic methods:
- Shellcode/payload injection
- DLL injection

But phases usually are the same:
- Make the shellcode avaialble for the other process
- Make the other process execute that shellcode

Popular combination of code injection using WinAPI:
VirtualAllocEx (extended version, allows allocating in another process) + WriteProcessMemory (RtlMoveMemory but for other processes) + CreateRemoteThread (remote process)