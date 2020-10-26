#define WIN32_LEAN_AND_MEAN  
#define VC_EXTRALEAN
#include <Windows.h>
#include <vector>
#include <Psapi.h>
#include <TlHelp32.h>
#include <chrono>
#include <fmt/os.h>
#include <filesystem>

#define ZYDIS_STATIC_DEFINE
#include <Zydis/Zydis.h>

#pragma comment(lib, "Zydis.lib")

using namespace std;

DWORD GetProcessIdByName(const wchar_t* const name) {
    PVOID snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry = { sizeof(entry) };
    DWORD pid = 0;
    while (Process32NextW(snapshot, &entry)) { if (wcscmp(entry.szExeFile, name) == 0) { pid = entry.th32ProcessID; break; } }
    CloseHandle(snapshot);
    return pid;
}

bool GetProcessModules(const DWORD pid, vector<MODULEENTRY32W>& modules) {
    PVOID snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry = { sizeof(entry) };
    while (Module32NextW(snapshot, &entry)) { modules.push_back(entry); }
    CloseHandle(snapshot);
    return modules.size() != 0;
}

DWORD GetSections(BYTE* const pe, vector<PIMAGE_SECTION_HEADER>& sections) {
    if (!pe) return 0;
    const PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(pe);
    const PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(pe + dos->e_lfanew);
    uint32_t numSec = nt->FileHeader.NumberOfSections;
    DWORD count = 0u;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (auto i = 0u; i < numSec; i++, section++) { if (section->Characteristics & IMAGE_SCN_CNT_CODE) { sections.push_back(section); count++; } }
    return count;
}

DWORD LoadMem(const HANDLE& proc, const MODULEENTRY32W& modEntry, BYTE*& data) {
    if (!proc || data || !modEntry.modBaseSize) return 0;
    data = new BYTE[modEntry.modBaseSize];
    SIZE_T size = 0;
    bool status = false;
    goto code;
cleanup:
    if (!status) { delete[] data; data = nullptr; }
    return size;
code:
    if (!ReadProcessMemory(proc, modEntry.modBaseAddr, data, modEntry.modBaseSize, &size)) { 
        if (GetLastError() == ERROR_PARTIAL_COPY) {
            delete[] data;
            data = new BYTE[size];
            if (ReadProcessMemory(proc, modEntry.modBaseAddr, data, size, &size)) { status = true; };
        } 
        goto cleanup;
    };
    status = true;
    goto cleanup;
}

// todo: reformat code 
int wmain(const int argc, const wchar_t* const argv[])
{
    if (argc != 2) { printf("HooksFinder.exe \"process.exe\".\n"); return 1; }
    auto procName = argv[1];
    auto pid = GetProcessIdByName(procName);
    if (!pid) { printf("Process \"%ls\" not found.\n", procName); return 1; }
    auto proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (proc == INVALID_HANDLE_VALUE) { printf("Can't open handle to \"%ls\". Error %d\n", procName, GetLastError()); return 1; }
    vector<MODULEENTRY32W> mods;
    if (!GetProcessModules(pid, mods)) { printf("Can't get \"%ls\"'s modules.\n", procName); return 1; };
    const auto begin = std::chrono::system_clock::now();
    mods.erase(mods.begin());
    ZydisDecoder decoder;
    BOOL bWow64 = FALSE;
    IsWow64Process(proc, &bWow64);
#ifdef _WIN64
    if (bWow64) { printf("Process is under wow64\n"); return 1; }
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64))) { printf("ZydisDecoderInit failed\n"); return 1; };
#else 
    if (!bWow64) { printf("Process is noy under wow64\n"); return 1; }
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#endif
    ZydisFormatter formatter;
    if (ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) { printf("ZydisFormatterInit failed\n"); return 1; };
    for (const auto& mod : mods) {
        void* file = nullptr;
        void* mapping = nullptr;
        BYTE* cold = nullptr;
        BYTE* hot = nullptr;
        goto code;
    cleanup:
        if (mapping) CloseHandle(mapping);
        if (file) CloseHandle(file);
        if (cold) UnmapViewOfFile(cold);
        if (hot) { delete[] hot; }
        continue;
    code:
        file = CreateFileW(mod.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) goto cleanup;
        mapping = CreateFileMappingW(file, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
        if (mapping == INVALID_HANDLE_VALUE) goto cleanup;
        cold = reinterpret_cast<BYTE*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
        if (!cold) goto cleanup;
        vector<PIMAGE_SECTION_HEADER> coldSections;
        if (!GetSections(cold, coldSections)) goto cleanup;
        if (!LoadMem(proc, mod, hot)) goto cleanup;
        vector<PIMAGE_SECTION_HEADER> hotSections;
        if (!GetSections(hot, hotSections)) goto cleanup;
        if (hotSections.size() != coldSections.size()) goto cleanup;
        
        printf("%p\t%ls\n", mod.modBaseAddr, mod.szModule);
        for (auto i = 0u; i < coldSections.size(); i++) {
            auto& coldSect = coldSections[i];
            auto& hotSect = hotSections[i];
            const ZyanUSize length = coldSect->Misc.VirtualSize;
            for (ZyanUSize offset = coldSect->VirtualAddress; offset < length; ) {
                BYTE* runtime_address = mod.modBaseAddr + offset;
                bool result = false;
                if (cold[offset] != hot[offset]) {
                    printf("%p\t", runtime_address);
                    ZydisDecodedInstruction instruction;
                    if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, hot + offset, length - offset, &instruction))) {
                        char buffer[256];
                        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), ZYDIS_RUNTIME_ADDRESS_NONE);
                        printf(buffer);

                        if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP)
                        {
                            switch (instruction.opcode) {
                            case 0xFF:
                            {
                                int rel = *reinterpret_cast<int*>(hot + offset + 2);
                                if (rel == 0) {
                                    printf(" (jump to %llx)\n", *reinterpret_cast<uint64_t*>(hot + offset + 6));
                                    offset += 13;
                                    continue;
                                }
                                break;
                            }
                            case 0xE9:
                            {
                                int rel = *reinterpret_cast<int*>(hot + offset + 1);
                                printf(" (jump to %p)\n", runtime_address + 5 + rel);
                                offset += 5;
                                continue;
                            }
                            }
                        }

                        printf("\n");
                        offset += instruction.length;
                        continue;
                    }
                    else {
                        printf("0x%x\n", hot[offset]);
                    }
                  
                }
                offset++;
            }
        }
        printf("-----------------------------------------------------------------------\n");
        goto cleanup;
    }
    printf("Finished, took %lld ms.", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - begin).count());
    return 0;
}