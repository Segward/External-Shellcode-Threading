#pragma once

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

class Memory {
public:

    Memory(const char processName[]);
    ~Memory();

    uintptr_t getModuleBase(const char moduleName[]);
    DWORD getPid() { return pid; }
    HANDLE getHandle() { return hProcess; }
    LPVOID allocateEx(size_t size);
    HANDLE threadEx(uintptr_t address, LPVOID buffer);
    BOOL writeEx(uintptr_t address, LPVOID buffer, size_t size);
    BOOL tempPatchEx(uintptr_t address, LPVOID buffer, size_t size, int sleepTime);

private:

    const char* processName;
    DWORD pid = 0;
    HANDLE hProcess = NULL;
    void setProcessId();
    void setHandle();

};

Memory::Memory(const char processName[]) {
    this->processName = processName;
    try {
        setProcessId();
        setHandle();

    } catch (const char* error) {
        std::cout << error << std::endl;
        CloseHandle(hProcess);
    }
}

Memory::~Memory() {
    CloseHandle(hProcess);
}

void Memory::setProcessId() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        throw "Error: CreateToolhelp32Snapshot failed";

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    if (!Process32First(hSnap, &pe32))
        throw "Error: Process32First failed";

    do {
        this->pid = strcmp(reinterpret_cast<const char *>(pe32.szExeFile),processName) == 0 ? 
            pe32.th32ProcessID : 0;
    } while (Process32Next(hSnap, &pe32) && this->pid == 0);

    if (this->pid == 0)
        throw "Error: Process not found";

    CloseHandle(hSnap);
}

void Memory::setHandle() {
    this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == INVALID_HANDLE_VALUE)
        throw "Error: OpenProcess failed";
}

uintptr_t Memory::getModuleBase(const char moduleName[]) {
    try {
        if (hProcess == NULL)
            throw "Error: Process handle is NULL";

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->pid);
        if (hSnap == INVALID_HANDLE_VALUE)
            throw "Error: CreateToolhelp32Snapshot failed";

        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        uintptr_t baseAddress = 0;

        if (!Module32First(hSnap, &modEntry))
            throw "Error: Module32First failed";

        do {
            baseAddress = strcmp(reinterpret_cast<const char *>(modEntry.szModule), moduleName) == 0 ? 
                reinterpret_cast<uintptr_t>(modEntry.modBaseAddr) : 0;
        } while (Module32Next(hSnap, &modEntry) && baseAddress == 0);

        if (baseAddress == 0)
            throw "Error: Module not found";

        CloseHandle(hSnap);
        return baseAddress;

    } catch (const char* error) {
        std::cout << error << std::endl;
    }

    return 0;
}

LPVOID Memory::allocateEx(size_t size) {
    try {
        if (hProcess == NULL)
            throw "Error: Process handle is NULL";

        LPVOID pMemory = VirtualAllocEx(hProcess, 0, size, 
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (pMemory == NULL)
            throw "Error: VirtualAllocEx failed";

        return pMemory;

    } catch (const char* error) {
        std::cout << error << std::endl;
    }

    return NULL;
}

HANDLE Memory::threadEx(uintptr_t address, LPVOID buffer) {
    try {
        if (hProcess == NULL)
            throw "Error: Process handle is NULL";

        HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, 
            (LPTHREAD_START_ROUTINE)address, buffer, 0, 0);
        if (hThread == NULL)
            throw "Error: CreateRemoteThread failed";

        return hThread;

    } catch (const char* error) {
        std::cout << error << std::endl;
    }

    return NULL;
}

BOOL Memory::writeEx(uintptr_t address, LPVOID buffer, size_t size) {
    try {
        if (hProcess == NULL)
            throw "Error: Process handle is NULL";

        if (!WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, 0))
            throw "Error: WriteProcessMemory failed";

        return TRUE;

    } catch (const char* error) {
        std::cout << error << std::endl;
    }

    return FALSE;
}

BOOL Memory::tempPatchEx(uintptr_t address, LPVOID buffer, size_t size, int sleepTime) {
    try {
        if (hProcess == NULL)
            throw "Error: Process handle is NULL";

        unsigned char* originalData = new unsigned char[size];
        if (!ReadProcessMemory(hProcess, (LPVOID)address, originalData, size, 0))
            throw "Error: ReadProcessMemory failed";
        
        if (!WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, 0))
            throw "Error: WriteProcessMemory failed";

        Sleep(sleepTime);

        if (!WriteProcessMemory(hProcess, (LPVOID)address, originalData, size, 0))
            throw "Error: WriteProcessMemory failed";

        return TRUE;

    } catch (const char* error) {
        std::cout << error << std::endl;
    }

    return FALSE;
}