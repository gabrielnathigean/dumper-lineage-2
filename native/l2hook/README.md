# l2hook (fase 1: captura passiva)

DLL 32-bit propria para o `L2.exe` (Interlude). Faz hook por IAT de `send`/`recv` (`ws2_32`) importados por
`engine.dll` (confirmado pelos imports do cliente em `Downloads\client\system`) e publica os bytes no pipe
`\\.\pipe\l2hook`. Nao altera nem injeta pacotes.

## Build (toolchain **x86 / 32-bit**; testado com llvm-mingw i686)
A DLL NAO usa CRT/STL (so Win32): versoes com CRT derrubaram o L2.exe. Flags obrigatorias:
- `i686-w64-mingw32-g++ -shared -O2 -nostdlib -fno-exceptions -fno-rtti -Wl,-e,_DllMain@12 -o l2hook.dll l2hook.cpp -lkernel32 -lws2_32`
- `i686-w64-mingw32-g++ -O2 -municode -static -o inject.exe inject.cpp`
Binarios compilados nao sao versionados (.gitignore).

## Uso
1. Abra o cliente e faca login.  2. `inject.exe <pid do L2.exe> l2hook.dll`
3. `py -3 l2live\livefind.py` (acha os objetos de chave vivos; refazer a cada login) e depois `py -3 l2live\livedecode.py --mem`
   (ou `hookclient.py --hex` so para captura bruta). Notas de protocolo: `l2live/PROTOCOL_NOTES.md`.

## Limites conhecidos
- Nao testado (sem compilador aqui). O hook so pega `send`/`recv` do `engine.dll`; `nwindow.dll` usa `WSASend` (nao hookado).
- Corpo dos pacotes cifrado (XOR por conexao apos o primeiro pacote); decifrar e a proxima etapa.
- Se o servidor usa protecao anti-cheat/GameGuard (ha `npkcrypt.dll`/`npkpdb.dll` no cliente), a injecao pode ser bloqueada.
