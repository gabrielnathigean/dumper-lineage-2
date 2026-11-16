// inject.cpp - carrega l2hook.dll no L2.exe (32-bit). Uso: inject.exe <pid> <caminho\l2hook.dll>
// Compile como 32-bit (o L2.exe e 32-bit).
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <cstdlib>

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) { wprintf(L"uso: inject <pid> <dll>\n"); return 2; }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    wchar_t full[MAX_PATH];
    if (!GetFullPathNameW(argv[2], MAX_PATH, full, nullptr)) return 3;
    HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                           PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!p) { wprintf(L"OpenProcess falhou: %lu\n", GetLastError()); return 4; }
    SIZE_T n = (wcslen(full) + 1) * sizeof(wchar_t);
    void* mem = VirtualAllocEx(p, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem || !WriteProcessMemory(p, mem, full, n, nullptr)) { wprintf(L"alloc/write falhou\n"); return 5; }
    auto load = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE t = CreateRemoteThread(p, nullptr, 0, load, mem, 0, nullptr);
    if (!t) { wprintf(L"CreateRemoteThread falhou: %lu\n", GetLastError()); return 6; }
    WaitForSingleObject(t, 10000);
    DWORD rc = 0; GetExitCodeThread(t, &rc);
    wprintf(rc ? L"ok (modulo carregado)\n" : L"LoadLibrary retornou 0\n");
    VirtualFreeEx(p, mem, 0, MEM_RELEASE);
    CloseHandle(t); CloseHandle(p);
    return rc ? 0 : 7;
}
