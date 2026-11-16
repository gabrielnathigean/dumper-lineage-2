r"""Parser de L2DB.dat (banco do bot) -> CSVs de itens, skills e NPCs.

Uso: python l2db_parse.py <L2DB.dat> [pasta_saida]
Formato inferido (engenharia reversa estatica, nao oficial):
  registro = [campos fixos][id u32][nome\0][cauda]; tipo identificado pela
  distancia (gap) entre o fim do nome e o inicio do proximo nome.
  item : gap 35, id = u32 em (inicio_nome - 4)
  skill: gap 31, id = u32 em (-8), nivel = u32 em (-4)
  npc  : [id u32][nome\0][titulo\0][u16 a][u16 b] encadeados sem folga
         (a,b = dimensoes provaveis, significado nao confirmado);
         so cadeias com >=20 registros apos o offset 0x100000.
"""
import re, sys, struct, csv, os, collections


def strings(d):
    return [(m.start(), m.end(), m.group(0).decode('latin1'))
            for m in re.finditer(rb'[\x20-\x7e]{2,}(?=\x00)', d)]


def runs(S, minlen=15):
    out = []; i = 0
    while i < len(S) - 1:
        g = S[i+1][0] - S[i][1]; j = i
        while j < len(S) - 1 and S[j+1][0] - S[j][1] == g: j += 1
        if j - i >= minlen: out.append((i, j, g))
        i = max(j, i + 1)
    return out


_PR = re.compile(rb'^[\x20-\x7e]*$')


def _npc_at(d, s):
    if s < 0 or s + 8 > len(d): return None
    nid = struct.unpack_from('<I', d, s)[0]
    if not 1000 < nid < 2000000: return None
    e = d.find(b'\x00', s + 4)
    if e < 0 or not 2 <= e - s - 4 <= 60 or not _PR.match(d[s+4:e]): return None
    e2 = d.find(b'\x00', e + 1)
    if e2 < 0 or e2 - e - 1 > 60 or not _PR.match(d[e+1:e2]): return None
    if e2 + 5 > len(d): return None
    a, b = struct.unpack_from('<HH', d, e2 + 1)
    return nid, d[s+4:e].decode('latin1'), d[e+1:e2].decode('latin1'), a, b, e2 + 5


def parse_npcs(d, min_chain=20, min_off=0x100000):
    cand = re.compile(rb'..[\x00-\x1e]\x00[\x20-\x7e]{2,60}\x00[\x20-\x7e]{0,60}\x00', re.S)
    seen, npcs = set(), {}
    for m in cand.finditer(d):
        s = m.start()
        if s in seen or s < min_off: continue
        cur, ch = s, []
        while True:
            r = _npc_at(d, cur)
            if not r: break
            ch.append(r); seen.add(cur); cur = r[-1]
        if len(ch) >= min_chain:
            for nid, name, title, a, b, _ in ch: npcs[nid] = (name, title, a, b)
    return npcs


def main(path, outdir='data'):
    d = open(path, 'rb').read(); os.makedirs(outdir, exist_ok=True)
    S = strings(d); R = runs(S)
    items, skills = {}, {}
    for i, j, g in R:
        for k in range(i, j + 1):
            o = S[k][0]; name = S[k][2]
            if g == 35 and o >= 4:
                items[struct.unpack_from('<I', d, o-4)[0]] = name
            elif g == 31 and o >= 8:
                sid, lvl = struct.unpack_from('<II', d, o-8)
                skills[(sid, lvl)] = name
    with open(os.path.join(outdir, 'items.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['id', 'name'])
        for k in sorted(items): w.writerow([k, items[k]])
    with open(os.path.join(outdir, 'skills.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['id', 'level', 'name'])
        for (a, b) in sorted(skills): w.writerow([a, b, skills[(a, b)]])
    npcs = parse_npcs(d)
    with open(os.path.join(outdir, 'npcs.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['id', 'name', 'title', 'dim_a', 'dim_b'])
        for k in sorted(npcs): w.writerow([k, *npcs[k]])
    print('npcs', len(npcs), 'itens', len(items), 'skills', len(skills),
          'gaps:', collections.Counter(g for _, _, g in R).most_common(6))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'data')
