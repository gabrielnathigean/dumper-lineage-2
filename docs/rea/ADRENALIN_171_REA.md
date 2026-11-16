# Adrenalin 1.71 (TESTE 1) - achados REA (analise estatica + dump de memoria)

Fonte: C:\Users\Gabriel Araujo\Downloads\TESTE 1. Nada do bot/crack foi copiado para o repo; so notas.
Lista completa de identificadores Delphi do Boot.exe: mantida so localmente (nao versionada).

## Arquivos
| Arquivo | Papel | Evidencia |
|---|---|---|
| Boot.exe (5.8MB) | Bot Delphi (UI + logica). Empacotador custom (secoes .UPX0/.UPX1 falsas, sem header UPX). Dump em memoria = 17MB | observado |
| Start.exe | Updater Delphi (UPX) - atualiza Adrenalin.exe, A.dll, Loader.exe, L2DB.dat, L2ICO.dat, mapas | inferido de Settings.ini |
| A.dll | Criptografada em disco (sem MZ). Carregada de memoria (AVEncryptedFastDllStream no Boot) - provavel DLL injetada no l2.exe | inferido |
| Tunel.exe | Loader/patcher do crack (CreateProcess suspenso + WriteProcessMemory). Fora de escopo | observado |
| L2DB.dat | Banco de skills/itens/npcs (binario, strings tipo "Sit/Stand") | observado |
| Settings/global.gmap | XML de zonas (poligonos x,y) | observado |

## Arquitetura inferida (nomes Delphi no dump)
- Camada L2 (units): L2Base, L2Types, L2Const, L2Classes, L2Object, L2Skill, L2Item, L2Clan, L2Spawn, L2Control, L2Tools, **L2Packets** (TL2Parser, DoPacket), **L2Live**.
- Classes: TL2User, TL2Npc, TL2Pet, TL2Skill, TL2Item, TL2Buff, TL2Effect, TL2Cast, TL2Shop, TL2Status, TL2Actions, TL2EventType, TL2ChatType, TL2Race, TL2Class.
- **BotEngine / iBotEngine / RegisterEngine / PaxEngine**: motor do bot; PaxEngine = scripting (PaxCompiler).
- **PipeServer / fPipeServer**: comunicacao UI <-> DLL injetada via named pipe (modelo: DLL no cliente captura pacotes/eventos e manda ao bot).
- Eventos vindos do cliente (prefixo `la`): laCast, laMyCast, laCastFailed, laCancelCast, laTarget, laMyTarget, laUnTarget, laMyUnTarget, laStartAttack, laStopAttack, laBuffs, laSkills, laPartyBuffs, laNpcTrade, laLeaveParty.
- Acoes para o cliente: UseSkill/DUseSkill, DLearnSkill, SetTarget/SetTargetID, CancelTarget, MoveToTarget, BypassToServer, InviteParty/JoinParty/LeaveParty/DismissParty/SetPartyLeader, NpcExchange, PickUp, LoadSkillList/UpdateSkillList, GetInventory/GetNpcList/GetParty/GetSkillList, CharByOID/NpcByOID, ServerTime/fGetServerTime.
- Estado do bot: fTarget, fLastTargetOID, fLastTargetHP, fUserTargetOID, fNpcList, fParty, fSkills, fInventory, fSpoiled, fSweepable, fCastSpd, fLootType.
- Modulos de funcao: AutoAttack, AutoBuff, AutoHeal, AutoTarget, PartyAssist/Follow/Protect/Relax, Spoil/Sweep (fSpoilAtk, Sweepable), Looter (ldLooter, ldRandomSpoil), NpcFilter*, EventNpcAgro, EventPlayerFilter (PK/PVP), etDetectPlayer.
- Cripto/protecao: CryptMode, uEncrypt/uCodeEncrypt, TfEncrypt, synacrypt, VarXor, AsmXorREG_REG.
- Hooks (Delphi/VCL, nao do jogo): AVHookManager, AVIVirtualAllocationManager, AdvapiHook, HookMainWindow, JvWndProcHook.
- Rede: Indy (IdStack, IdSocks, TransparentProxy), ws2_32.send importado, LoadLibraryA/W, WriteProcessMemory, SuspendThread.

## Imports relevantes no dump
kernel32: LoadLibraryA/W, WriteProcessMemory, SuspendThread; ws2_32: send.

## O que NAO foi obtido
- Offsets/enderecos do cliente L2 e layout dos pacotes: estao em A.dll (criptografada); nao decifrada.
- Disassembly de Boot.exe pelo Ghidra: timeout de 330s (binario 17MB, partes ofuscadas). Precisa REA_GHIDRA_STARTUP_TIMEOUT_MS maior.
- Versao do protocolo (Interlude vs HF): "Maps(HF)" no updater sugere High Five; nao confirmado.

## Uteis para o l2live
1. Modelo de arquitetura (DLL no cliente + named pipe + engine de eventos `la*`) e um bom molde.
2. Vocabulario de eventos/acoes acima como checklist de funcoes a expor.
3. L2DB.dat pode ser parseado para tabela de skills/itens (formato a reverter).
