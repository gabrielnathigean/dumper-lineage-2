// l2hook.cpp - DLL propria (32-bit) para o cliente L2 Interlude.
// Hook por IAT de send/recv (ws2_32) importados por engine.dll; publica os bytes
// em \\.\pipe\l2hook. Frame: u8 dir (0=recv,1=send) | u32 len | bytes.
// Fase 1: SOMENTE captura (passivo). SEM CRT/STL: so API Win32 (o cliente e antigo e
// a primeira versao com CRT/std::mutex derrubou o L2.exe em ucrtbase.dll).
// Build: i686-w64-mingw32-g++ -shared -O2 -nostdlib -fno-exceptions -fno-rtti \
//        -Wl,-e,_DllMain@12 -o l2hook.dll l2hook.cpp -lkernel32 -lws2_32
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>

static void* mcopy(void* d, const void* s, DWORD n) {
    volatile BYTE* dd = (volatile BYTE*)d; const BYTE* ss = (const BYTE*)s;
    while (n--) *dd++ = *ss++;
    return d;
}
static int seq(const char* a, const char* b, bool ci) {
    for (;; ++a, ++b) {
        char x = *a, y = *b;
        if (ci) { if (x >= 'A' && x <= 'Z') x += 32; if (y >= 'A' && y <= 'Z') y += 32; }
        if (x != y) return 1;
        if (!x) return 0;
    }
}

typedef int (WSAAPI* send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI* recv_t)(SOCKET, char*, int, int);

static send_t g_send = nullptr;
static recv_t g_recv = nullptr;
static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_cs;
static volatile LONG g_run = 1;
static HMODULE g_self = nullptr;
static HMODULE g_self_mod() { return g_self; }

// ---- objetos de chave L2 (vivos) ----
// Os enderecos vem de %TEMP%\l2hook_addrs.txt ("<addr_send_obj_hex> <addr_recv_obj_hex>", cada um aponta
// para o 1o byte da chave de 16 bytes; o contador fica em +8). Quem acha os enderecos e o l2live\livefind.py.
// Nenhuma varredura de memoria acontece dentro da DLL (a v4/v5 travaram/enganaram-se com tabelas falsas).
static BYTE* volatile g_ks = nullptr;   // objeto de chave do ENVIO
static BYTE* volatile g_kr = nullptr;   // objeto de chave do RECEBIMENTO
static BYTE g_cs16[16], g_cr16[16];
static BYTE* g_ks_sent = nullptr;
static BYTE* g_kr_sent = nullptr;
static HANDLE g_lastPipe = INVALID_HANDLE_VALUE;

static DWORD parse_hex(const char*& p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    DWORD v = 0;
    for (;; ++p) {
        char c = *p; int d;
        if (c >= '0' && c <= '9') d = c - '0'; else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10; else break;
        v = (v << 4) | d;
    }
    return v;
}

static DWORD WINAPI scan_thread(LPVOID) {   // le o arquivo de enderecos a cada 1 s
    char path[MAX_PATH + 32];
    DWORD n = GetTempPathA(MAX_PATH, path);
    const char* nm = "l2hook_addrs.txt";
    for (int i = 0; nm[i]; ++i) path[n++] = nm[i];
    path[n] = 0;
    while (g_run) {
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[64]; DWORD r = 0;
            if (ReadFile(h, buf, 63, &r, nullptr)) {
                buf[r] = 0; const char* p = buf;
                BYTE* s = (BYTE*)(ULONG_PTR)parse_hex(p); BYTE* rr = (BYTE*)(ULONG_PTR)parse_hex(p);
                if (s && rr && !IsBadReadPtr(s, 16) && !IsBadReadPtr(rr, 16)) { g_ks = s; g_kr = rr; }
            }
            CloseHandle(h);
        }
        Sleep(1000);
    }
    return 0;
}

// Frame: u8 dir | u32 len | u32 cS | u32 cR | payload.  dir 0=recv 1=send 2=chaves (payload = keySend16||keyRecv16)
// ATENCAO: nesta versao cA = contador do ENVIO, cB = contador do RECEBIMENTO (papeis fixos).
static void write_frame(BYTE dir, const char* p, int n, DWORD cA, DWORD cB) {
    BYTE hdr[13]; hdr[0] = dir; DWORD len = (DWORD)n;
    mcopy(hdr + 1, &len, 4); mcopy(hdr + 5, &cA, 4); mcopy(hdr + 9, &cB, 4);
    DWORD w = 0;
    BOOL ok = WriteFile(g_pipe, hdr, 13, &w, nullptr) && (n == 0 || WriteFile(g_pipe, p, (DWORD)n, &w, nullptr));
    if (!ok) { DisconnectNamedPipe(g_pipe); CloseHandle(g_pipe); g_pipe = INVALID_HANDLE_VALUE; }
}

static void emit(BYTE dir, const char* p, int n) {
    if (n <= 0 || n > (1 << 20)) return;
    EnterCriticalSection(&g_cs);
    if (g_pipe != INVALID_HANDLE_VALUE) {
        DWORD cS = 0, cR = 0;
        BYTE* ks = g_ks; BYTE* kr = g_kr;
        if (ks && kr && !IsBadReadPtr(ks, 16) && !IsBadReadPtr(kr, 16)) {
            bool changed = (ks != g_ks_sent) || (kr != g_kr_sent) || g_pipe != g_lastPipe;
            for (int i = 0; i < 16 && !changed; ++i) if (ks[i] != g_cs16[i] || kr[i] != g_cr16[i]) changed = true;
            // chave fixa muda so em nova conexao; o contador (bytes 8..11) muda sempre e nao conta
            bool fixedChanged = false;
            for (int i = 0; i < 16; ++i) { if (i >= 8 && i < 12) continue; if (ks[i] != g_cs16[i] || kr[i] != g_cr16[i]) fixedChanged = true; }
            if ((ks != g_ks_sent) || (kr != g_kr_sent) || g_pipe != g_lastPipe || fixedChanged) {
                mcopy(g_cs16, ks, 16); mcopy(g_cr16, kr, 16);
                char kb[32]; mcopy(kb, ks, 16); mcopy(kb + 16, kr, 16);
                write_frame(2, kb, 32, 0, 0);
                g_ks_sent = ks; g_kr_sent = kr; g_lastPipe = g_pipe;
            }
            if (g_pipe != INVALID_HANDLE_VALUE) { mcopy(&cS, ks + 8, 4); mcopy(&cR, kr + 8, 4); }
        }
        if (g_pipe != INVALID_HANDLE_VALUE) write_frame(dir, p, n, cS, cR);
    }
    LeaveCriticalSection(&g_cs);
}

static int WSAAPI hk_send(SOCKET s, const char* b, int n, int fl) {
    int r = g_send(s, b, n, fl);
    if (r > 0) emit(1, b, r);
    return r;
}
static int WSAAPI hk_recv(SOCKET s, char* b, int n, int fl) {
    int r = g_recv(s, b, n, fl);
    if (r > 0) emit(0, b, r);
    return r;
}

typedef int (WSAAPI* wsasend_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
static wsasend_t g_wsasend = nullptr;
static sendto_t g_sendto = nullptr;

static int WSAAPI hk_wsasend(SOCKET s, LPWSABUF b, DWORD c, LPDWORD sent, DWORD fl, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = g_wsasend(s, b, c, sent, fl, o, cr);
    if (r == 0 && !o && sent) {  // so envio sincrono (buffers validos); overlapped fica para depois
        DWORD left = *sent;
        for (DWORD i = 0; i < c && left; ++i) {
            DWORD n = b[i].len < left ? b[i].len : left;
            emit(1, b[i].buf, (int)n); left -= n;
        }
    }
    return r;
}
static int WSAAPI hk_sendto(SOCKET s, const char* b, int n, int fl, const struct sockaddr* to, int tl) {
    int r = g_sendto(s, b, n, fl, to, tl);
    if (r > 0) emit(1, b, r);
    return r;
}

// Casa a entrada de IAT pelo ENDERECO resolvido da funcao (nao depende dos nomes/OFT,
// que podem estar zerados). Devolve o ponteiro original ou nullptr.
static void* iat_hook(HMODULE mod, const char* dllName, const char* funcName, void* hook) {
    HMODULE dm = GetModuleHandleA(dllName);
    if (!dm) return nullptr;
    DWORD target = (DWORD)(ULONG_PTR)GetProcAddress(dm, funcName);
    if (!target) return nullptr;
    BYTE* base = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return nullptr;
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    for (; imp->Name && imp->FirstThunk; ++imp) {
        DWORD* slot = (DWORD*)(base + imp->FirstThunk);
        for (; *slot; ++slot) {
            if (*slot != target) continue;
            DWORD old;
            VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &old);
            InterlockedExchange((volatile LONG*)slot, (LONG)(ULONG_PTR)hook);
            VirtualProtect(slot, sizeof(DWORD), old, &old);
            return (void*)(ULONG_PTR)target;
        }
    }
    return nullptr;
}

static DWORD WINAPI pipe_thread(LPVOID) {
    while (g_run) {
        HANDLE h = CreateNamedPipeW(L"\\\\.\\pipe\\l2hook", PIPE_ACCESS_OUTBOUND,
                                    PIPE_TYPE_BYTE | PIPE_WAIT, 1, 1 << 20, 0, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        if (ConnectNamedPipe(h, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            EnterCriticalSection(&g_cs); g_pipe = h; LeaveCriticalSection(&g_cs);
            for (;;) {
                Sleep(250);
                EnterCriticalSection(&g_cs);
                bool gone = (g_pipe == INVALID_HANDLE_VALUE);
                LeaveCriticalSection(&g_cs);
                if (gone || !g_run) break;
            }
        } else {
            CloseHandle(h);
        }
    }
    return 0;
}

static void hook_all(HMODULE self) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me)) {
        HMODULE m = me.hModule;
        if (m == self) continue;
        iat_hook(m, "ws2_32.dll", "send", (void*)hk_send);
        iat_hook(m, "ws2_32.dll", "recv", (void*)hk_recv);
        iat_hook(m, "ws2_32.dll", "WSASend", (void*)hk_wsasend);
        iat_hook(m, "ws2_32.dll", "sendto", (void*)hk_sendto);
    }
    CloseHandle(snap);
}

static DWORD WINAPI init_thread(LPVOID) {
    HMODULE eng = nullptr;
    for (int i = 0; i < 600 && !(eng = GetModuleHandleW(L"engine.dll")); ++i) Sleep(100);
    if (!eng) return 1;
    CreateThread(nullptr, 0, pipe_thread, nullptr, 0, nullptr);
    HMODULE ws = GetModuleHandleW(L"ws2_32.dll");
    if (!ws) return 2;
    g_send = (send_t)GetProcAddress(ws, "send");
    g_recv = (recv_t)GetProcAddress(ws, "recv");
    g_wsasend = (wsasend_t)GetProcAddress(ws, "WSASend");
    g_sendto = (sendto_t)GetProcAddress(ws, "sendto");
    CreateThread(nullptr, 0, scan_thread, nullptr, 0, nullptr);
    hook_all(g_self);
    return 0;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = (HMODULE)h;
        DisableThreadLibraryCalls(h);
        InitializeCriticalSection(&g_cs);
        CreateThread(nullptr, 0, init_thread, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_run = 0;
    }
    return TRUE;
}
