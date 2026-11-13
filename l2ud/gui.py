"""GUI tkinter 0.4.0.

Abas: Resultados · Hex · Disassembly · CFG · Referências · Estruturas · Relatório · Builds/DB.
Trabalho pesado roda em thread (a UI não trava). Recursos que exigem Capstone mostram a instrução de
instalação em vez de falhar; nenhum botão é decorativo.
"""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from collections import deque
from tkinter import filedialog, messagebox, ttk

from . import aob, disasm
from .analysis import Context, analyze_function, hexdump, hexdump_file, xrefs_to
from .pe import PeImage
from .sigs import load_sigs, run_all
from .storage import Database, diff, export_structs, write_export

MONO = ("Consolas", 10)
NEED_CS = "Capstone não instalado.\n\n  pip install capstone\n\nEste recurso precisa dele (o modo Lite não decodifica instruções)."
EDGE_COLOR = {"fall": "#888888", "jmp": "#2a7f3f", "jcc": "#2060c0", "table": "#a040a0"}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("L2 Universal Dumper 0.4.0")
        self.geometry("1180x740")
        self.q: queue.Queue = queue.Queue()
        self.img: PeImage | None = None
        self.ctx: Context | None = None
        self.results: list = []
        self.sigs_list: list[dict] = []
        self.cands: list = []
        self.cur_cfg = None
        self.exe, self.sigs, self.dbpath = tk.StringVar(), tk.StringVar(), tk.StringVar(value="l2ud.db")
        self.engine = tk.StringVar(value="auto")
        self.inc_probable, self.inc_all = tk.BooleanVar(value=False), tk.BooleanVar(value=False)

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        for r, (lbl, var, kinds) in enumerate((("PE:", self.exe, [("PE", "*.exe *.dll *.bin"), ("Todos", "*.*")]),
                                               ("Assinaturas:", self.sigs, [("JSON", "*.json")]))):
            ttk.Label(top, text=lbl, width=12).grid(row=r, column=0, sticky="w")
            ttk.Entry(top, textvariable=var).grid(row=r, column=1, sticky="ew")
            ttk.Button(top, text="…", width=3,
                       command=lambda v=var, k=kinds: v.set(filedialog.askopenfilename(filetypes=k) or v.get())
                       ).grid(row=r, column=2)
        ttk.Label(top, text="Motor:").grid(row=0, column=3, padx=(10, 2))
        ttk.Combobox(top, textvariable=self.engine, values=["auto", "lite", "capstone"], width=9,
                     state="readonly").grid(row=0, column=4)
        ttk.Label(top, text="Capstone: " + ("sim" if disasm.available() else "não (modo Lite)")).grid(
            row=1, column=3, columnspan=2, padx=10)
        top.columnconfigure(1, weight=1)

        bar = ttk.Frame(self, padding=(8, 0))
        bar.pack(fill="x")
        ttk.Button(bar, text="Carregar PE", command=self.load_pe).pack(side="left")
        self.run_btn = ttk.Button(bar, text="Analisar assinaturas", command=self.run_sigs)
        self.run_btn.pack(side="left", padx=6)
        ttk.Button(bar, text="Exportar resultados…", command=self.export).pack(side="left")
        ttk.Checkbutton(bar, text="incluir PROBABLE", variable=self.inc_probable).pack(side="left", padx=6)
        ttk.Checkbutton(bar, text="incluir tudo", variable=self.inc_all).pack(side="left")
        self.status = ttk.Label(bar, text="pronto")
        self.status.pack(side="right")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)
        self._tab_results()
        self._tab_hex()
        self._tab_disasm()
        self._tab_cfg()
        self._tab_xrefs()
        self._tab_structs()
        self._tab_catalog()
        self._tab_report()
        self._tab_db()
        self.after(100, self.poll)

    # ================================================================ infra
    def bg(self, fn, done, busy: str = "trabalhando…") -> None:
        self.status.config(text=busy)

        def work():
            try:
                self.q.put((done, fn(), None))
            except Exception as e:  # noqa: BLE001 - qualquer erro vai para a UI
                self.q.put((done, None, e))
        threading.Thread(target=work, daemon=True).start()

    def poll(self) -> None:
        try:
            while True:
                done, res, err = self.q.get_nowait()
                self.run_btn.state(["!disabled"])
                if err:
                    self.status.config(text="erro")
                    messagebox.showerror("Erro", f"{type(err).__name__}: {err}")
                else:
                    self.status.config(text="pronto")
                    done(res)
        except queue.Empty:
            pass
        self.after(100, self.poll)

    @staticmethod
    def _text(parent, wrap: str = "none", height: int | None = None) -> tk.Text:
        f = ttk.Frame(parent)
        f.pack(fill="both", expand=True)
        t = tk.Text(f, font=MONO, wrap=wrap, **({"height": height} if height else {}))
        sb = ttk.Scrollbar(f, command=t.yview)
        t.configure(yscrollcommand=sb.set, state="disabled")
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        return t

    @staticmethod
    def _set(t: tk.Text, s: str) -> None:
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("1.0", s)
        t.configure(state="disabled")

    def _need_img(self) -> bool:
        if self.img is None:
            messagebox.showwarning("Sem PE", "Carregue um PE primeiro (botão 'Carregar PE').")
            return False
        return True

    def _need_cs(self, widget: tk.Text | None = None) -> bool:
        if not disasm.available():
            if widget is not None:
                self._set(widget, NEED_CS)
            else:
                messagebox.showinfo("Capstone", NEED_CS)
            return False
        return True

    @staticmethod
    def _num(s: str, what: str = "valor") -> int | None:
        try:
            return int(s.strip(), 0)
        except ValueError:
            messagebox.showwarning("Número inválido", f"{what}: use decimal ou 0x…")
            return None

    def _ensure_ctx(self) -> Context:
        if self.ctx is None or self.ctx.engine_req != self.engine.get():
            self.ctx = Context(self.img, self.engine.get())
        return self.ctx

    def _addr_bar(self, parent, default: str, cmd, label: str, second: str | None = None):
        bar = ttk.Frame(parent, padding=4)
        bar.pack(fill="x")
        ttk.Label(bar, text="RVA:").pack(side="left")
        rva = tk.StringVar(value=default)
        ttk.Entry(bar, textvariable=rva, width=14).pack(side="left", padx=4)
        n = None
        if second is not None:
            ttk.Label(bar, text=second).pack(side="left")
            n = tk.StringVar(value="40")
            ttk.Entry(bar, textvariable=n, width=6).pack(side="left", padx=4)
        ttk.Button(bar, text=label, command=cmd).pack(side="left", padx=4)
        return bar, rva, n

    # ================================================================ carga
    def load_pe(self) -> None:
        path = self.exe.get()
        if not path:
            messagebox.showwarning("Faltando", "Escolha o PE.")
            return
        eng = self.engine.get()

        def work():
            img = PeImage.load(path)
            ctx = Context(img, eng)
            _ = ctx.fmap                      # constrói mapa de funções (com CFG se Capstone)
            return img, ctx

        def done(r):
            self.img, self.ctx = r
            self.status.config(text=f"{self.img.arch} | {len(self.img.sections)} seções | {len(self.ctx.fmap)} funções "
                                    f"({self.ctx.fmap.funcs[0].label if self.ctx.fmap.funcs else '-'})")
        self.bg(work, done, "carregando…")

    # ================================================================ Resultados
    def _tab_results(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Resultados")
        cols = ("status", "name", "kind", "value", "va", "notes")
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=9)
        for c, w in zip(cols, (160, 200, 100, 100, 130, 380)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="x")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        self.detail = self._text(f)

    def run_sigs(self) -> None:
        if not self.exe.get() or not self.sigs.get():
            messagebox.showwarning("Faltando", "Escolha o PE e o arquivo de assinaturas.")
            return
        self.run_btn.state(["disabled"])
        eng, exe, sigs_path = self.engine.get(), self.exe.get(), self.sigs.get()   # Tk vars só na thread principal

        def work():
            img = PeImage.load(exe)
            ctx = Context(img, eng)
            sigs = load_sigs(sigs_path)
            return img, ctx, sigs, run_all(img, sigs, ctx=ctx)

        def done(r):
            self.img, self.ctx, self.sigs_list, self.results = r
            self.tree.delete(*self.tree.get_children())
            for i, x in enumerate(self.results):
                self.tree.insert("", "end", iid=str(i), values=(
                    x.status.value, x.name, x.value_kind, "-" if x.value is None else f"{x.value:#x}",
                    "" if x.va is None else f"{x.va:#x}", x.notes))
            self.status.config(text=f"{len(self.results)} resultado(s) · motor {self.ctx.engine_label}")
        self.bg(work, done, "analisando…")

    def show_detail(self, _e=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        r = self.results[int(sel[0])]
        lines = [f"{r.name}  [{r.status.value}]", f"padrão : {r.pattern}", f"tipo   : {r.kind} / {r.value_kind}",
                 f"valor  : {'-' if r.value is None else hex(r.value)}"]
        if r.value_kind == "RVA" and r.value is not None:
            lines.append(f"VA (base preferida) : {r.va:#x}" if r.va is not None else "")
            lines.append(f"file offset         : {r.file_offset:#x}" if r.file_offset is not None
                         else "file offset         : (só em memória)")
        if r.hits:
            lines.append("matches (RVA)       : " + ", ".join(f"{h:#x}" for h in r.hits[:8]))
        if len(r.candidates) > 1:
            lines.append("candidatos: " + ", ".join(hex(c) for c in r.candidates))
        v = r.meta.get("validation")
        if v:
            lines += ["", f"validação Capstone: {'OK' if v['ok'] else 'FALHOU'} em {v['checked']}/{v['total']} match(es)"
                          f"{' — PARCIAL' if v.get('partial') else ''}  {v.get('instruction', '')}"]
            if v.get("invalid"):
                lines.append("   matches inválidos: " + ", ".join(v["invalid"][:8]))
            lines += [f"   problema: {i}" for i in v["issues"]]
            if v["suggestion"] and not v["ok"]:
                lines.append(f"   sugestão: {v['suggestion']}")
        lines += ["", "evidências:"] + [f"  · {e}" for e in r.evidence]
        if r.notes:
            lines += ["", f"notas: {r.notes}"]
        self._set(self.detail, "\n".join(lines))

    def export(self) -> None:
        if not self.results or not self.img:
            messagebox.showinfo("Sem resultados", "Rode 'Analisar assinaturas' primeiro.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json",
                                         filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("C++ header", "*.hpp")])
        if p:
            write_export(self.results, p, self.inc_probable.get(), self.inc_all.get(),
                         self.img.image_base, self.img.sha256[:16])
            self.status.config(text=f"exportado: {p}")

    # ================================================================ Hex
    def _tab_hex(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Hex")
        bar = ttk.Frame(f, padding=4)
        bar.pack(fill="x")
        self.hex_mode = tk.StringVar(value="rva")
        ttk.Radiobutton(bar, text="RVA", variable=self.hex_mode, value="rva").pack(side="left")
        ttk.Radiobutton(bar, text="File offset", variable=self.hex_mode, value="file").pack(side="left", padx=(0, 6))
        self.hex_pos, self.hex_len, self.hex_pat = tk.StringVar(value="0x1000"), tk.StringVar(value="256"), tk.StringVar()
        ttk.Entry(bar, textvariable=self.hex_pos, width=14).pack(side="left")
        ttk.Label(bar, text=" bytes:").pack(side="left")
        ttk.Entry(bar, textvariable=self.hex_len, width=6).pack(side="left", padx=4)
        ttk.Button(bar, text="Ir", command=self.do_hex).pack(side="left")
        ttk.Button(bar, text="◀", width=3, command=lambda: self.hex_page(-1)).pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="▶", width=3, command=lambda: self.hex_page(1)).pack(side="left")
        ttk.Label(bar, text="  AOB:").pack(side="left")
        ttk.Entry(bar, textvariable=self.hex_pat, width=28).pack(side="left", padx=4)
        ttk.Button(bar, text="Buscar próximo", command=self.hex_find).pack(side="left")
        self.hex_t = self._text(f)

    def _hex_cur(self) -> tuple[int, int] | None:
        pos, n = self._num(self.hex_pos.get(), "posição"), self._num(self.hex_len.get(), "bytes")
        return (pos, max(16, n)) if pos is not None and n is not None else None

    def do_hex(self) -> None:
        if not self._need_img() or (pn := self._hex_cur()) is None:
            return
        pos, n = pn
        self._set(self.hex_t, hexdump(self.img, pos, n) if self.hex_mode.get() == "rva" else hexdump_file(self.img, pos, n))

    def hex_page(self, d: int) -> None:
        if (pn := self._hex_cur()) is None:
            return
        self.hex_pos.set(hex(max(0, pn[0] + d * pn[1])))
        self.do_hex()

    def hex_find(self) -> None:
        if not self._need_img() or (pn := self._hex_cur()) is None:
            return
        try:
            hits = aob.scan(self.img, self.hex_pat.get())
        except aob.AobError as e:
            messagebox.showwarning("Padrão inválido", str(e))
            return
        pos = pn[0]
        cur_file = pos if self.hex_mode.get() == "file" else (self.img.rva_to_file(pos) or 0)
        nxt = next((h for h in sorted(hits, key=lambda h: h.file_offset) if h.file_offset > cur_file), None)
        if nxt is None:
            self.status.config(text=f"sem mais matches ({len(hits)} no total)")
            return
        self.hex_pos.set(hex(nxt.file_offset if self.hex_mode.get() == "file" else nxt.rva))
        self.do_hex()
        self.status.config(text=f"match em RVA {nxt.rva:#x} / file {nxt.file_offset:#x} ({len(hits)} no total)")

    # ================================================================ Disassembly
    def _tab_disasm(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Disassembly")
        _, self.dis_rva, self.dis_n = self._addr_bar(f, "0x1000", self.do_disasm, "Desmontar", "instruções:")
        ttk.Button(f, text="Próxima página ▶", command=lambda: self.do_disasm(True)).pack(anchor="w", padx=4)
        self.dis_t = self._text(f)
        self.dis_next: int | None = None

    def do_disasm(self, cont: bool = False) -> None:
        if not self._need_img() or not self._need_cs(self.dis_t):
            return
        rva = self.dis_next if (cont is True and self.dis_next) else self._num(self.dis_rva.get(), "RVA")
        n = self._num(self.dis_n.get(), "instruções")
        if rva is None or n is None:
            return
        ctx = self._ensure_ctx()
        img = self.img

        def work():
            fn = ctx.fmap.containing(rva)
            return fn, ctx.disassembler.decode(rva, n)

        def done(r):
            fn, ins = r
            head = (f"; função {fn.start:#x}-{fn.end:#x} — {fn.label}\n" if fn else "; (fora de função conhecida)\n")
            self._set(self.dis_t, head + ("\n".join(i.text() for i in ins) or "RVA sem bytes em disco / não executável"))
            self.dis_next = ins[-1].end if ins else None
            self.dis_rva.set(hex(rva))
        self.bg(work, done, "desmontando…")

    # ================================================================ CFG
    def _tab_cfg(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="CFG")
        bar, self.cfg_rva, _ = self._addr_bar(f, "0x1000", self.do_cfg, "Gerar CFG")
        ttk.Button(bar, text="Exportar DOT…", command=self.cfg_dot).pack(side="left", padx=4)
        ttk.Label(bar, text="verde=jmp  azul=jcc  cinza=fall  roxo=tabela  vermelho=aresta de retorno (loop)").pack(side="left", padx=8)
        pw = ttk.PanedWindow(f, orient="vertical")
        pw.pack(fill="both", expand=True)
        cf = ttk.Frame(pw)
        self.canvas = tk.Canvas(cf, background="white", height=360)
        hs, vs = ttk.Scrollbar(cf, orient="horizontal", command=self.canvas.xview), ttk.Scrollbar(cf, command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=hs.set, yscrollcommand=vs.set)
        hs.pack(side="bottom", fill="x")
        vs.pack(side="right", fill="y")
        self.canvas.pack(fill="both", expand=True)
        tf = ttk.Frame(pw)
        self.cfg_t = self._text(tf, height=8)
        pw.add(cf, weight=3)
        pw.add(tf, weight=1)

    def do_cfg(self) -> None:
        if not self._need_img() or not self._need_cs(self.cfg_t):
            return
        rva = self._num(self.cfg_rva.get(), "RVA")
        if rva is None:
            return
        ctx = self._ensure_ctx()

        def work():
            return ctx.fmap.containing(rva), ctx.cfg(rva)

        def done(r):
            fn, cfg = r
            self.cur_cfg = cfg
            if cfg is None:
                self._set(self.cfg_t, "Nenhuma função conhecida contém esse RVA.")
                self.canvas.delete("all")
                return
            lines = [f"função {fn.start:#x}-{fn.end:#x} — {fn.label}", f"resumo: {cfg.summary()}", ""]
            for b in sorted(cfg.blocks.values(), key=lambda x: x.start):
                succ = ", ".join(f"{t:#x}({k})" for t, k in b.succs) or "-"
                lines.append(f"bloco {b.start:#x}-{b.end:#x} {len(b.insns)} insn term={b.terminator}"
                             f"{' [INDIRETO NÃO RESOLVIDO]' if b.indirect_unresolved else ''} -> {succ}")
            lines += [f"região {t}: {a:#x}-{e:#x}" for a, e, t in cfg.ambiguous]
            lines += [f"desvio EXTERNO {x.kind} {x.src:#x} -> {x.dst:#x}: {x.cls}" for x in cfg.external]
            lines += [f"aresta INVÁLIDA {s_:#x} -> {d_:#x}: {w}" for s_, d_, w in cfg.invalid_edges]
            lines += [f"jump table @{j.table_rva:#x}: {'RESOLVIDA' if j.resolved else 'NÃO resolvida'} limite={j.bound} "
                      f"aceitas={len(j.entries)} rejeitadas={len(j.rejected)}" for j in cfg.jump_tables]
            self._set(self.cfg_t, "\n".join(lines))
            self.draw_cfg(cfg)
        self.bg(work, done, "construindo CFG…")

    def draw_cfg(self, cfg) -> None:
        c = self.canvas
        c.delete("all")
        if len(cfg.blocks) > 80:
            c.create_text(20, 20, anchor="nw", text=f"CFG com {len(cfg.blocks)} blocos: grande demais para desenhar "
                                                   "(veja a lista abaixo ou exporte o DOT).")
            return
        depth = {cfg.entry: 0}
        dq = deque([cfg.entry])
        while dq:
            a = dq.popleft()
            for t, _ in cfg.blocks[a].succs:
                if t not in depth:
                    depth[t] = depth[a] + 1
                    dq.append(t)
        mx = max(depth.values(), default=0)
        for a in cfg.blocks:
            depth.setdefault(a, mx + 1)
        layers: dict[int, list[int]] = {}
        for a, d in depth.items():
            layers.setdefault(d, []).append(a)
        BW, GX, GY, LH = 270, 40, 46, 14
        pos: dict[int, tuple[int, int, int]] = {}
        y = 20
        for d in sorted(layers):
            hmax = 0
            for j, a in enumerate(sorted(layers[d])):
                b = cfg.blocks[a]
                n = min(len(b.insns), 6) + 1 + (1 if len(b.insns) > 6 else 0)
                h = LH * n + 8
                hmax = max(hmax, h)
                pos[a] = (20 + j * (BW + GX), y, h)
            y += hmax + GY
        for a, (x, yy, h) in pos.items():
            b = cfg.blocks[a]
            fill = "#fff4d6" if a == cfg.entry else "#f3f3f3"
            c.create_rectangle(x, yy, x + BW, yy + h, fill=fill, outline="#444")
            txt = [f"{b.start:#x}  ({b.terminator})"] + [f"{i.mnemonic} {i.op_str}"[:38] for i in b.insns[:6]]
            if len(b.insns) > 6:
                txt.append(f"… +{len(b.insns) - 6} insn")
            c.create_text(x + 6, yy + 4, anchor="nw", text="\n".join(txt), font=("Consolas", 9))
        for a, b in cfg.blocks.items():
            x1, y1, h1 = pos[a]
            for t, k in b.succs:
                if t not in pos:
                    continue
                x2, y2, _ = pos[t]
                if depth[t] > depth[a]:
                    c.create_line(x1 + BW / 2, y1 + h1, x2 + BW / 2, y2, arrow=tk.LAST, fill=EDGE_COLOR.get(k, "#888"), smooth=True)
                else:   # aresta de retorno / mesmo nível: contorna pelo lado direito
                    xr = max(x1, x2) + BW + 14
                    c.create_line(x1 + BW, y1 + h1 / 2, xr, y1 + h1 / 2, xr, y2 + 8, x2 + BW, y2 + 8, arrow=tk.LAST,
                                  fill="#c03030", smooth=False)
        c.configure(scrollregion=c.bbox("all"))

    def cfg_dot(self) -> None:
        if self.cur_cfg is None:
            messagebox.showinfo("Sem CFG", "Gere um CFG primeiro.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".dot", filetypes=[("Graphviz DOT", "*.dot")])
        if p:
            from .cfg import to_dot
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(to_dot(self.cur_cfg))
            self.status.config(text=f"DOT gravado: {p}")

    # ================================================================ Referências
    def _tab_xrefs(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Referências")
        _bar, self.xr_rva, _n = self._addr_bar(f, "0x2000", self.do_xrefs, "Buscar xrefs + função")
        cols = ("kind", "from", "fn", "engine", "rw")
        self.xr = ttk.Treeview(f, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (70, 110, 420, 160, 60)):
            self.xr.heading(c, text=c)
            self.xr.column(c, width=w)
        self.xr.pack(fill="x")
        self.fn_t = self._text(f)

    def do_xrefs(self) -> None:
        if not self._need_img() or (rva := self._num(self.xr_rva.get(), "RVA")) is None:
            return
        ctx, img = self._ensure_ctx(), self.img

        def work():
            return xrefs_to(img, rva, ctx.xrefs), analyze_function(img, ctx, rva), ctx.engine_used

        def done(r):
            xs, fa, eng = r
            self.xr.delete(*self.xr.get_children())
            for x in xs:
                fn = x.function
                self.xr.insert("", "end", values=(x.kind, f"{x.from_rva:#x}", f"{fn.start:#x}-{fn.end:#x} [{fn.label}]" if fn else "-",
                                                  f"{x.engine}/{x.via}", x.rw))
            if not fa:
                self._set(self.fn_t, f"(motor {eng}) Nenhuma função conhecida contém esse RVA.")
                return
            f = fa["function"]
            out = [f"Função {f.start:#x}-{f.end:#x} — {fa['bounds_label'].upper()}  motor={eng}",
                   "chamadores: " + (", ".join(f"{c:#x}" for c in fa["callers"][:20]) or "-"),
                   "chamados  : " + (", ".join(f"{c:#x}" for c in fa["callees"][:20]) or "-"),
                   "imports   : " + (", ".join(fa["imports"]) or "-")]
            if "cfg" in fa:
                c = fa["cfg"]
                out.append(f"CFG: {c['blocks']} blocos, {c['edges']} arestas, {c['instructions']} insn, "
                           f"{c['indirect_unresolved']} indireto(s) não resolvido(s)")
                out += [f"região {t}: {a:#x}-{e:#x}" for a, e, t in fa["ambiguous"][:8]]
            out += [f"string {a:#x}: {s!r}" for a, s in list(fa["strings"].items())[:30]]
            self._set(self.fn_t, "\n".join(out))
        self.bg(work, done, "calculando xrefs…")

    # ================================================================ Estruturas
    def _tab_structs(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Estruturas")
        bar = ttk.Frame(f, padding=4)
        bar.pack(fill="x")
        self.max_fn, self.min_fields, self.hints_path = tk.StringVar(value="2000"), tk.StringVar(value="4"), tk.StringVar()
        ttk.Label(bar, text="máx. funções:").pack(side="left")
        ttk.Entry(bar, textvariable=self.max_fn, width=7).pack(side="left", padx=3)
        ttk.Label(bar, text="min. campos:").pack(side="left")
        ttk.Entry(bar, textvariable=self.min_fields, width=4).pack(side="left", padx=3)
        ttk.Button(bar, text="Hints…", command=lambda: self.hints_path.set(
            filedialog.askopenfilename(filetypes=[("JSON", "*.json")]) or self.hints_path.get())).pack(side="left", padx=3)
        self.x86_regs = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="x86: assumir ecx/edx", variable=self.x86_regs).pack(side="left", padx=3)
        ttk.Button(bar, text="Descobrir", command=self.do_structs).pack(side="left", padx=3)
        ttk.Button(bar, text="Salvar no DB", command=self.structs_save).pack(side="left", padx=3)
        ttk.Button(bar, text="Carregar do DB", command=self.structs_load).pack(side="left", padx=3)
        ttk.Button(bar, text="Exportar…", command=self.structs_export).pack(side="left", padx=3)
        ttk.Label(bar, text="inferência estática — sempre CANDIDATE").pack(side="left", padx=8)
        pw = ttk.PanedWindow(f, orient="vertical")
        pw.pack(fill="both", expand=True)
        self.st_tree = ttk.Treeview(pw, columns=("info",), show="tree headings", height=12)
        self.st_tree.heading("#0", text="estrutura / campo / relação")
        self.st_tree.heading("info", text="detalhe")
        self.st_tree.column("#0", width=420)
        self.st_tree.column("info", width=520)
        self.st_tree.bind("<<TreeviewSelect>>", self.show_struct)
        tf = ttk.Frame(pw)
        self.st_t = self._text(tf, wrap="word", height=9)
        pw.add(self.st_tree, weight=3)
        pw.add(tf, weight=1)

    def do_structs(self) -> None:
        if not self._need_img() or not self._need_cs():
            return
        from .structs import discover
        mx, mf = self._num(self.max_fn.get() or "0", "máx. funções"), self._num(self.min_fields.get(), "min. campos")
        if mx is None or mf is None:
            return
        hints = None
        if self.hints_path.get():
            import json
            with open(self.hints_path.get(), encoding="utf-8") as fh:
                hints = json.load(fh)
        ctx = self._ensure_ctx()
        img, assume = self.img, self.x86_regs.get()          # Tk vars só na thread principal
        self.bg(lambda: discover(img, ctx, hints, mf, mx or None, assume_x86_reg_args=assume), self._fill_structs,
                "descobrindo estruturas…")

    def _fill_structs(self, cands) -> None:
        from .intel import explain_struct
        self.cands = cands
        self.st_expl = {}
        t = self.st_tree
        t.delete(*t.get_children())
        for i, s in enumerate(cands):
            top = t.insert("", "end", iid=f"s{i}", text=f"#{s.id}  CANDIDATE  conf={s.confidence}  interesse={s.interest}",
                           values=(f"tamanho ≥ {s.size_estimate:#x} · {len(s.fields)} campos · {len(s.functions)} função(ões)",), open=(i < 2))
            g = t.insert(top, "end", text="origem", values=("",))
            for r in s.roots:
                t.insert(g, "end", text=r, values=("",))
            g = t.insert(top, "end", text=f"campos ({len(s.fields)})", values=("",), open=True)
            for f in s.fields:
                t.insert(g, "end", text=f"{f['offset']:>8}  {f['type_guess']}",
                         values=(f"r={f['reads']} w={f['writes']} fn={f['functions']} {f.get('notes', '')}",))
            if s.relations:
                g = t.insert(top, "end", text=f"relações ({len(s.relations)})", values=("",))
                for r in s.relations:
                    t.insert(g, "end", text=r["kind"], values=(r.get("detail", ""),))
            if s.hints:
                g = t.insert(top, "end", text="hints (NÃO verificados)", values=("",))
                for h in s.hints:
                    t.insert(g, "end", text=h, values=("",))
            ev = s.evidence
            g = t.insert(top, "end", text="evidência", values=("",))
            for k in ("accesses", "reads", "writes", "functions"):
                t.insert(g, "end", text=f"{k}: {ev.get(k, 0)}", values=("",))
            for m in ev.get("merge_reasons", [])[:6]:
                t.insert(g, "end", text="fusão", values=(m,))
            for m in ev.get("refused_merges", [])[:4]:
                t.insert(g, "end", text="fusão recusada", values=(m,))
            for m in ev.get("conflicts", []):
                t.insert(g, "end", text="ressalva", values=(m,))
            for m in ev.get("assumptions", []):
                t.insert(g, "end", text="HIPÓTESE", values=(m,))
            if ev.get("dataflow_incomplete"):
                t.insert(g, "end", text="DATAFLOW INCOMPLETO", values=(", ".join(ev["dataflow_incomplete"]),))
            self.st_expl[f"s{i}"] = explain_struct(s) + "\n\n" + s.render_text(60)
        self.status.config(text=f"{len(cands)} candidato(s)")

    def show_struct(self, _e=None) -> None:
        sel = self.st_tree.selection()
        if not sel:
            return
        node = sel[0]
        while self.st_tree.parent(node):
            node = self.st_tree.parent(node)
        self._set(self.st_t, getattr(self, "st_expl", {}).get(node, ""))

    def _db(self) -> Database | None:
        """Conexão única (thread principal). A anterior é fechada ao abrir outra."""
        try:
            old = getattr(self, "_dbc", None)
            if old is not None:
                old.close()
            self._dbc = Database(self.dbpath.get() or "l2ud.db")
            return self._dbc
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Banco", str(e))
            return None

    def destroy(self) -> None:
        if getattr(self, "_dbc", None) is not None:
            self._dbc.close()
        super().destroy()

    def structs_save(self) -> None:
        if not self.cands or not self.img:
            messagebox.showinfo("Sem estruturas", "Descubra estruturas primeiro.")
            return
        if (db := self._db()) is None:
            return
        bid = db.register_build(self.img)
        rid = db.save_structs(bid, self.cands)
        self.status.config(text=f"estruturas salvas: build #{bid}, run #{rid}")

    def structs_load(self) -> None:
        if (db := self._db()) is None:
            return
        ref = self._ask("Build/run a carregar (ex.: 1, 1@3, @3 ou sha256):")
        if not ref:
            return
        try:
            c = db.load_structs(ref)
        except KeyError as e:
            messagebox.showwarning("Não encontrado", str(e))
            return
        if not c:
            messagebox.showinfo("Vazio", "Sem estruturas gravadas para essa referência.")
            return
        self._fill_structs(c)

    def structs_export(self) -> None:
        if not self.cands:
            messagebox.showinfo("Sem estruturas", "Descubra ou carregue estruturas primeiro.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json"), ("Markdown", "*.md")])
        if p:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(export_structs(self.cands, "md" if p.lower().endswith(".md") else "json"))
            self.status.config(text=f"exportado: {p}")

    def _ask(self, prompt: str) -> str:
        win = tk.Toplevel(self)
        win.title("Informe")
        win.transient(self)
        ttk.Label(win, text=prompt, padding=8).pack()
        v = tk.StringVar()
        e = ttk.Entry(win, textvariable=v, width=40)
        e.pack(padx=8)
        e.focus_set()
        out = {"v": ""}

        def ok(_e=None):
            out["v"] = v.get().strip()
            win.destroy()
        e.bind("<Return>", ok)
        ttk.Button(win, text="OK", command=ok).pack(pady=8)
        self.wait_window(win)
        return out["v"]

    # ================================================================ Catálogo de Descoberta Automática
    def _tab_catalog(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Catálogo")
        bar = ttk.Frame(f, padding=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="Descobrir Offsets (Pipeline)", command=self.do_discover_offsets).pack(side="left")
        ttk.Button(bar, text="Abrir Catálogo JSON…", command=self.load_catalog_json).pack(side="left", padx=4)
        ttk.Button(bar, text="Exportar Catálogo…", command=self.export_catalog).pack(side="left", padx=4)

        ttk.Label(bar, text="Categoria:").pack(side="left", padx=(8, 2))
        self.cat_filter_var = tk.StringVar(value="Todas")
        from .catalog import CATEGORIES
        cat_choices = ["Todas"] + list(CATEGORIES)
        cat_cb = ttk.Combobox(bar, textvariable=self.cat_filter_var, values=cat_choices, state="readonly", width=18)
        cat_cb.pack(side="left")
        cat_cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_catalog_tree())

        ttk.Label(bar, text="Status:").pack(side="left", padx=(8, 2))
        self.cat_status_var = tk.StringVar(value="Todos")
        st_choices = ["Todos", "STATIC_CANDIDATE", "STATIC_CORROBORATED", "KNOWN_REFERENCE_VALIDATED", "RUNTIME_VALIDATED"]
        st_cb = ttk.Combobox(bar, textvariable=self.cat_status_var, values=st_choices, state="readonly", width=16)
        st_cb.pack(side="left")
        st_cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_catalog_tree())

        cols = ("category", "name", "kind", "value", "status", "obs")
        self.cat_tree = ttk.Treeview(f, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (180, 180, 80, 100, 150, 60)):
            self.cat_tree.heading(c, text=c)
            self.cat_tree.column(c, width=w, anchor="w")
        self.cat_tree.pack(fill="x")
        self.cat_tree.bind("<<TreeviewSelect>>", self.show_catalog_detail)
        self.cat_detail = self._text(f)
        self.current_catalog = None

    def do_discover_offsets(self) -> None:
        if not self._need_img() or not self._need_cs(self.cat_detail):
            return
        from .pipeline import AutoDiscoverPipeline
        pipe = AutoDiscoverPipeline()

        def work():
            return pipe.run(self.pe_path)

        def done(res):
            cat, graph, rep = res
            self.current_catalog = cat
            self.refresh_catalog_tree()
            self._set(self.cat_detail, f"Descoberta concluída!\nBundle: {cat.bundle_id}\nTotal de itens: {len(cat.items)}\nResumo:\n" + cat.to_markdown())

        self.bg(work, done, "executando descoberta automática…")

    def load_catalog_json(self) -> None:
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not p:
            return
        from .catalog import Catalog
        import json
        try:
            self.current_catalog = Catalog.from_dict(json.loads(Path(p).read_text(encoding="utf-8")))
            self.refresh_catalog_tree()
            self._set(self.cat_detail, f"Catálogo carregado de {p}\nBundle: {self.current_catalog.bundle_id}\nTotal: {len(self.current_catalog.items)} itens")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar catálogo: {e}")

    def export_catalog(self) -> None:
        if not self.current_catalog:
            messagebox.showinfo("Catálogo", "Nenhum catálogo ativo para exportar.")
            return
        p = filedialog.asksaveasfilename(filetypes=[("C++ Header", "*.hpp"), ("JSON", "*.json"), ("CSV", "*.csv"), ("Markdown", "*.md")])
        if not p:
            return
        try:
            self.current_catalog.export(p, include_candidates=True)
            messagebox.showinfo("Exportado", f"Catálogo exportado com sucesso para:\n{p}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar catálogo: {e}")

    def refresh_catalog_tree(self) -> None:
        self.cat_tree.delete(*self.cat_tree.get_children())
        if not self.current_catalog:
            return
        sel_cat = self.cat_filter_var.get()
        sel_st = self.cat_status_var.get()
        for it in sorted(self.current_catalog.items.values(), key=lambda x: (x.category, x.name)):
            if sel_cat != "Todas" and it.category != sel_cat:
                continue
            if sel_st != "Todos" and it.status != sel_st:
                continue
            v_str = f"{it.value:#x}" if it.value is not None else "-"
            obs = it.independence.get("observations", 0)
            self.cat_tree.insert("", "end", iid=it.id, values=(it.category, it.name, it.value_kind, v_str, it.status, obs))

    def show_catalog_detail(self, _evt=None) -> None:
        sel = self.cat_tree.selection()
        if not sel or not self.current_catalog:
            return
        it = self.current_catalog.get(sel[0])
        if not it:
            return
        lines = [
            f"ID: {it.id}",
            f"Nome: {it.name}",
            f"Categoria: {it.category}",
            f"Tipo de valor: {it.value_kind}",
            f"Valor: {f'{it.value:#x}' if it.value is not None else '-'}",
            f"VA Preferido: {f'{it.va_preferred:#x}' if it.va_preferred is not None else '-'}",
            f"File Offset: {f'{it.file_offset:#x}' if it.file_offset is not None else '-'}",
            f"Status: {it.status}",
            f"Motivo do status: {it.status_reason}",
            f"Observações independentes: {it.independence.get('observations', 0)} ({', '.join(it.independence.get('types', []))})",
            f"Resumo: {it.summary}",
            "",
            "Limitações:",
        ] + [f"  - {lim}" for lim in it.limitations]
        if it.signature:
            lines += ["", f"Assinatura AOB: {it.signature.get('pattern', '')}"]
        if it.attrs:
            lines += ["", f"Atributos: {json.dumps(it.attrs, indent=2, ensure_ascii=False)}"]
        self._set(self.cat_detail, "\n".join(lines))

    # ================================================================ Relatório
    def _tab_report(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Relatório")
        bar = ttk.Frame(f, padding=4)
        bar.pack(fill="x")
        self.rep_db = tk.BooleanVar(value=False)
        ttk.Button(bar, text="Gerar relatório (Offset Intelligence)", command=self.do_report).pack(side="left")
        ttk.Checkbutton(bar, text="incluir histórico do DB", variable=self.rep_db).pack(side="left", padx=8)
        ttk.Button(bar, text="Salvar…", command=self.report_save).pack(side="left")
        ttk.Label(bar, text="usa os resultados de 'Analisar assinaturas' e as estruturas da aba Estruturas").pack(side="left", padx=8)
        self.rep_t = self._text(f, wrap="word")
        self.rep_md = ""

    def do_report(self) -> None:
        if not self._need_img():
            return
        if not self.results:
            messagebox.showinfo("Sem resultados", "Rode 'Analisar assinaturas' primeiro.")
            return
        from .intel import build_report, to_markdown
        ctx, img, results, structs = self._ensure_ctx(), self.img, list(self.results), list(self.cands)
        hist = None
        if self.rep_db.get() and (db := self._db()) is not None:       # SQLite só na thread principal
            hist = {r.name: db.history(r.name) for r in results}

        def work():
            return to_markdown(build_report(img, ctx, results, structs, (lambda n: hist.get(n, [])) if hist is not None else None))

        def done(md):
            self.rep_md = md
            self._set(self.rep_t, md)
        self.bg(work, done, "consolidando evidências…")

    def report_save(self) -> None:
        if not self.rep_md:
            messagebox.showinfo("Sem relatório", "Gere o relatório primeiro.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown", "*.md")])
        if p:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(self.rep_md)
            self.status.config(text=f"relatório salvo: {p}")

    # ================================================================ Builds / DB
    def _tab_db(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Builds / DB")
        bar = ttk.Frame(f, padding=4)
        bar.pack(fill="x")
        ttk.Label(bar, text="banco:").pack(side="left")
        ttk.Entry(bar, textvariable=self.dbpath, width=30).pack(side="left", padx=4)
        ttk.Button(bar, text="…", width=3, command=lambda: self.dbpath.set(
            filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("SQLite", "*.db")]) or self.dbpath.get())).pack(side="left")
        for txt, cmd in (("Atualizar", self.db_refresh), ("Salvar execução atual", self.db_save_run),
                         ("Comparar 2 runs", self.db_compare), ("Eventos da build", self.db_events), ("Similaridade", self.db_similar)):
            ttk.Button(bar, text=txt, command=cmd).pack(side="left", padx=3)
        pw = ttk.PanedWindow(f, orient="vertical")
        pw.pack(fill="both", expand=True)
        self.b_tree = ttk.Treeview(pw, columns=("id", "module", "arch", "runs", "created", "sha"), show="headings", height=5)
        for c, w in zip(("id", "module", "arch", "runs", "created", "sha"), (40, 200, 50, 50, 150, 520)):
            self.b_tree.heading(c, text=c)
            self.b_tree.column(c, width=w)
        self.b_tree.bind("<<TreeviewSelect>>", self.db_pick_build)
        self.r_tree = ttk.Treeview(pw, columns=("run", "started", "ver", "engine", "n", "digest", "note"), show="headings",
                                   height=5, selectmode="extended")
        for c, w in zip(("run", "started", "ver", "engine", "n", "digest", "note"), (50, 150, 70, 80, 40, 100, 400)):
            self.r_tree.heading(c, text=c)
            self.r_tree.column(c, width=w)
        tf = ttk.Frame(pw)
        self.db_t = self._text(tf, height=10)
        pw.add(self.b_tree, weight=1)
        pw.add(self.r_tree, weight=1)
        pw.add(tf, weight=2)

    def db_refresh(self) -> None:
        if (db := self._db()) is None:
            return
        self.b_tree.delete(*self.b_tree.get_children())
        self.r_tree.delete(*self.r_tree.get_children())
        for b in db.builds_info():
            self.b_tree.insert("", "end", iid=str(b["id"]), values=(b["id"], b["module"] or "-", b["arch"], b["runs"],
                                                                      b["created"], b["sha256"]))
        self.status.config(text=f"{len(self.b_tree.get_children())} build(s) em {self.dbpath.get()}")

    def db_pick_build(self, _e=None) -> None:
        sel = self.b_tree.selection()
        if not sel or (db := self._db()) is None:
            return
        self.r_tree.delete(*self.r_tree.get_children())
        for r in db.runs(int(sel[0])):
            self.r_tree.insert("", "end", iid=str(r["run"]), values=(r["run"], r["started"], r["tool_version"], r["engine"] or "-",
                                                                       r["results"], (r["sigs_digest"] or "-")[:10], r["note"] or ""))

    def db_save_run(self) -> None:
        if not self.results or not self.img:
            messagebox.showinfo("Sem resultados", "Rode 'Analisar assinaturas' primeiro.")
            return
        if (db := self._db()) is None:
            return
        note = self._ask("Nota desta execução (opcional):")
        bid, rid = db.save_run(self.img, self.results, self.sigs_list, self.ctx.engine_label if self.ctx else "", note)
        self.db_refresh()
        self.status.config(text=f"salvo: build #{bid}, run #{rid}")

    def db_compare(self) -> None:
        sel = self.r_tree.selection()
        if len(sel) != 2:
            messagebox.showinfo("Comparar", "Selecione EXATAMENTE 2 runs na lista do meio (Ctrl+clique).")
            return
        if (db := self._db()) is None:
            return
        a, b = sorted(int(x) for x in sel)
        d = diff(db.results(f"@{a}"), db.results(f"@{b}"))
        h = lambda v: "-" if v is None else hex(v)  # noqa: E731
        out = [f"run #{a}  →  run #{b}", ""]
        out += [f"CHANGED  {n}: {h(o)} -> {h(v)}" + ("" if dl is None else f" (Δ {'+' if dl >= 0 else '-'}{abs(dl):#x})") for n, o, v, dl in d["changed"]]
        out += [f"ADDED    {n}: {h(v)}" for n, v in d["added"]] + [f"REMOVED  {n}: {h(v)}" for n, v in d["removed"]]
        out += [f"DEGRADED {n}: {o} -> {v}" for n, o, v in d["degraded"]] + [f"IMPROVED {n}: {o} -> {v}" for n, o, v in d["improved"]]
        out += [f"PATTERN  {n}: padrão diferente" for n in d["pattern_changed"]] + [f"{len(d['unchanged'])} inalterado(s)"]
        self._set(self.db_t, "\n".join(out))

    def db_events(self) -> None:
        sel = self.b_tree.selection()
        if not sel or (db := self._db()) is None:
            messagebox.showinfo("Eventos", "Selecione uma build na lista de cima.")
            return
        self._set(self.db_t, "\n".join(f"{ts}  {k:<13} {d}" for ts, k, d in db.build_events(int(sel[0]))) or "sem eventos")

    def db_similar(self) -> None:
        if (db := self._db()) is None:
            return
        from .buildid import families, similarity
        profs = {f"#{b['id']} {b['module']}": p for b in db.builds_info() if (p := db.profile(b["id"]))}
        if len(profs) < 2:
            messagebox.showinfo("Similaridade", "Precisa de ≥2 builds com perfil gravado.")
            return
        names, out = list(profs), []
        for i, x in enumerate(names):
            for y in names[i + 1:]:
                s = similarity(profs[x], profs[y])
                out.append(f"{x} ~ {y}: {s['score']:.3f}  " + ", ".join(f"{k}={v}" for k, v in s["parts"].items() if v is not None))
        out += ["", *[f"família (≥0.8): {', '.join(g)}" for g in families(profs, 0.8)],
                "", "similaridade ≠ compatibilidade de assinaturas: valide por build"]
        self._set(self.db_t, "\n".join(out))


def main() -> None:
    App().mainloop()
