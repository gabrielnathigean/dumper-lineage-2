# Interlude (L2.exe 32-bit) - HUD gauges, found with l2live

Verified on 2 client runs (restart in between) + 2 level-ups. Not verified against other client builds.

## Gauge layout (int32, 20 bytes)
`+0x00 = 8, +0x04 = 12, +0x08 = MAX, +0x0C = 0, +0x10 = CURRENT`
Pattern to find it without values: `08 00 00 00 0C 00 00 00 <max> 00 00 00 00 <cur>` (max > 0, 0 < cur <= max).

| Stat | Address relative to HP gauge |
|------|------------------------------|
| HP   | +0x000 (max), +0x008 (current from the max field) |
| MP   | -0x380 |
| CP   | +0x380 |

(current = max field address + 8 bytes: the MAX is at `addr`, CURRENT at `addr + 8`.)

## Stable pointer chains to the HP max field
`addr = *(module+RVA)`, then `addr = *(addr + o1)`, ..., final `addr + oN` = HP max field. 47 chains survived both runs, all ending in `+0x2f0`.
Shortest:
- `[Core.dll + 0x22eed0] +0x8 +0x2f0`
- `[Core.dll + 0x22eecc] +0x78 +0x2f0`
- `[Core.dll + 0x22eec8] +0xe8 +0x2f0`
- `[Core.dll + 0x22eeac] +0x3f8 +0x2f0`
Full list: `chains_hp_stable.json`.

## Update: player gauges confirmed with live play
`monitor.py` showed HP/MP/CP following the game (damage, regen, level-ups).

## Target HP: tried, NOT found
- Gauge pattern (8,12,max,0,cur): the target bar is not one of these.
- int32 2..2000 that decreases after each hit (3 rounds): 130 cells, none plausible.
- float32 0.001..5000 that decreases (3 rounds incl. kill): 1353 cells, none in HUD heap.
- Name text ("Wolf") copies are identical with/without target; pointer cells into them are noisy.
Next ideas: hook/log the client's network queue (engine.dll `UNetworkHandler::AddNetworkQueue`), or static analysis of Window.dll's target window.

## Not established
- These are HUD widget fields, not proven to be the character model.
- Current vs max was seen on HP only (current dropped, max stayed); MP/CP current untested under damage.
- No target HP, no monster list, no other builds yet.
- Core.dll RVAs depend on this exact Core.dll build; re-run `ptr` + `intersect` if it changes.
