# UsingWinSyscall

UsingWinSyscall is a simple example of how to use Windows syscalls. Instead of calling GetProcAddress, UsingWinSyscall define the assembly of x86/x64 syscall to call ntapi. Therefore, we cannot find out what syscall it calls by looking it up in the import address table and setting breakpoints at GetProcAddress or the address of the syscall in ntdll. Since Windows OS frequently update SSDT table, UsingWinSyscall read ntdll file to find SSDT index.
