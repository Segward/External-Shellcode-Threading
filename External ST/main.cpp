#include "memory.hpp"

int main() {

    Memory memory("Target.exe");
    uintptr_t baseAddress = memory.getModuleBase("Target.exe");

    uintptr_t rebase =          0x140000000;                        // rebase
    uintptr_t function1 =       0x140001450;                        // function1
    uintptr_t function2 =       0x14000148B;                        // function2
    uintptr_t function3 =       0x1400014C3;                        // function3

    uintptr_t addrFunction1 = baseAddress + function1 - rebase;     // function1
    uintptr_t addrFunction2 = baseAddress + function2 - rebase;     // function2
    uintptr_t addrFunction3 = baseAddress + function3 - rebase;     // function3

    unsigned char shellcodeData[86] = {
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0 ; index 2
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0 ; index 12
        0x48, 0x83, 0xEC, 0x32,                                     // sub rsp, 32
        0xFF, 0xD0,                                                 // call rax
        0x48, 0x83, 0xC4, 0x32,                                     // add rsp, 32

        0xB9, 0x05, 0x00, 0x00, 0x00,                               // mov ecx, 5
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0 ; index 37
        0x48, 0x83, 0xEC, 0x32,                                     // sub rsp, 32
        0xFF, 0xD0,                                                 // call rax
        0x48, 0x83, 0xC4, 0x32,                                     // add rsp, 32

        0xB9, 0x05, 0x00, 0x00, 0x00,                               // mov ecx, 5
        0xBA, 0x0A, 0x00, 0x00, 0x00,                               // mov edx, 10
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0 ; index 67
        0x48, 0x83, 0xEC, 0x32,                                     // sub rsp, 32
        0xFF, 0xD0,                                                 // call rax
        0x48, 0x83, 0xC4, 0x32,                                     // add rsp, 32

        0xC3                                                        // ret                                                                
    };

    const char* str = "Goodbye, World!";
    LPVOID addrStr = memory.allocateEx(strlen(str));
    LPVOID addrShellcode = memory.allocateEx(sizeof(shellcodeData));

    *(uintptr_t *)&shellcodeData[2] = (uintptr_t) addrStr;
    *(uintptr_t *)&shellcodeData[12] = (uintptr_t) addrFunction1;
    *(uintptr_t *)&shellcodeData[37] = (uintptr_t) addrFunction2;
    *(uintptr_t *)&shellcodeData[67] = (uintptr_t) addrFunction3;

    BOOL writeStr = memory.writeEx(reinterpret_cast<uintptr_t>(addrStr), 
    (LPVOID)str, strlen(str));

    BOOL writeShellcode = memory.writeEx(reinterpret_cast<uintptr_t>(addrShellcode), 
    shellcodeData, sizeof(shellcodeData));

    HANDLE hThread = memory.threadEx(reinterpret_cast<uintptr_t>(addrShellcode), NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    std::cout << "Shellcode executed at: " << std::hex << addrShellcode << std::endl;

    return 0;
}