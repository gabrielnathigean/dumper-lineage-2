# Protocolo (Interlude) - achados via l2hook (captura propria, sessao do proprio cliente)

## Cifra (observada, confirmada por decriptacao coerente)
XOR em cadeia padrao do L2, chave de 16 bytes, uma por direcao, mesmos 12 bytes fixos nas duas:
- decrypt: `p[i] = c[i] ^ key[i & 15] ^ c[i-1]` (c[-1]=0); encrypt: `c[i] = p[i] ^ key[i&15] ^ c[i-1]`.
- key[8..11] = contador LE de 32 bits; apos cada pacote soma o tamanho do corpo (sem os 2 bytes de tamanho).
- Implementacao: `l2live/l2cipher.py`. A chave e **por conexao** (nao versionar).
- Chave localizada na memoria do L2.exe (2 copias, 0x11 bytes de distancia, uma por direcao) com `l2live/keyscan.py`
  (somente leitura; padrao parcial deduzido de pacotes ValidatePosition: K0 = 0x78 etc.).

## Opcodes cliente->servidor confirmados (corpo decifrado)
| op | tam corpo | significado | campos |
|----|-----------|-------------|--------|
| 0x48 | 21 | ValidatePosition | x,y,z,heading (i32) + 0 |
| 0x01 | 29 | MoveBackwardToLocation | alvo xyz, origem xyz, tipo |
| 0x0a | 18 | Attack | objectId, x,y,z, shift |
Coordenadas decodificadas ~ (83700, 148000, -2900) = Giran (coerente).

## Limite conhecido
K9 (2o byte do contador) ficou ambiguo no teste offline (63 valores plausiveis), pois so afeta o byte idx 9
(z low) e nao ha plaintext conhecido. Em tempo real isso se resolve lendo o contador da memoria, ou fazendo a
DLL sincronizar o contador. Direcao servidor->cliente: nao decifrada ainda.

## Servidor->cliente (mesma cifra, chave fixa igual; contador proprio)
Opcodes ja legiveis sem contador (op = byte0 ^ 0x78): 0x01 (29 B, mov. com objectId+destino+origem), 0x0e, 0x05, 0x48, 0x76, 0x2e...
**StatusUpdate (0x0e)**: `op | objectId u32 | count u32 | (attr u32, valor u32) * count`.
Amostra com o objectId do monstro atacado: pares (?, 3861) e (9=CUR_HP, 3861) => **HP do alvo chega por aqui**.
Bytes 8..11 de cada pacote dependem do contador (K8 pode ser lido do byte idx8 do count, que e 0).
Pendente: sincronizar o contador por pacote (ideia: a DLL le o contador na memoria no instante do 1o frame; para recv o contador
ainda e o de antes do pacote, para send ja foi somado).

## VALIDADO em combate real (livedecode.py --mem, sessao de 50 s)
- HP do alvo desce em tempo real via StatusUpdate (0x0e). Ex.: monstro 0x109308d8: MAX 62 -> CUR 62, 49, 36, 22, 9, 0 (morreu);
  mais dois monstros com a mesma serie (62->...->0). Atributos observados: 9=CUR_HP, 10=MAX_HP, 11=CUR_MP, 33=CUR_CP, 34=MAX_CP,
  13=SP (sobe a cada kill: 278, 280, 282). Proprio personagem = objectId 0x10811112 (HP~292-299, MP 100, CP 88/88).
- Como sincroniza sem a DLL v6: `livefind.py` acha os objetos vivos (contador += soma dos corpos) e grava %TEMP%/l2hook_addrs.txt;
  `livedecode.py --mem` le o contador na memoria logo apos cada frame: inicio_do_chunk = contador_lido - soma_corpos (send e recv).
- Limite: esse metodo assume que o engine processa o chunk antes de o Python ler (ms); `--raw` imprime 'resync' se falhar.
