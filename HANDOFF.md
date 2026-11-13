# Handoff - continuing on another machine

## Where we are
- `l2ud/` : offline static PE analyzer (0.5.0). `l2live/` : runtime, read-only offset finder for the L2 Interlude client (32-bit `L2.exe`, Windows).
- Confirmed on 2 client runs: player HP/MP/CP gauges, layout `8, 12, MAX, 0, CUR`, MP = HP-0x380, CP = HP+0x380,
  47 stable pointer chains (`[Core.dll+0x22eed0] +0x8 +0x2f0` etc., `l2live/chains_hp_stable.json`). Details: `l2live/OFFSETS_INTERLUDE.md`.
- `py -3 l2live/monitor.py` opens a live HP/MP/CP window (needs the client running and logged in).

## NOT found yet: HP of the target (monster), monster list
Tried and failed (see OFFSETS_INTERLUDE.md): gauge pattern, int32/float32 "went down" tracking, name-string pointers.

## Best lead
The client's `system\engine.dll` is unpacked and exports named symbols (10083). Useful ones:
`UNetworkHandler::GetUser / GetNearestNPC / GetNextNPC / GetNearestCreature`, `AddNetworkQueue`, `DispatchNetworkQueue`,
`OnSetupGaugePacket`, `ClearObjectMap`, `FObjectMap`, `struct User`. The target's HP is most likely a field of `User`.
Plan: decompile `GetUser`/`GetNextNPC`/`AddNetworkQueue` in engine.dll (Ghidra), learn the `User` struct layout and where
`UNetworkHandler` keeps its object map, then read it with l2live (read-only). Packet hook is plan B (needs a 32-bit toolchain; none installed here).
Note: Ghidra auto-analysis of the 30 MB engine.dll exceeded the 330 s startup limit; raise `REA_GHIDRA_STARTUP_TIMEOUT_MS`.

## Setup on the new machine
`pip install numpy` (pointer search), Python 3.10+, Windows. Client folder was `...\Downloads\client\system` (L2.exe, engine.dll, Core.dll, Window.dll, clmods.dll).
Run state files (`session.json`, `*_snap.json`, `*.npz`) are git-ignored; regenerate them.
