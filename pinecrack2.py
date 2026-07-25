#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PineCrack 2.0 - a modern dashboard front-end for the PineCrack engine.
=====================================================================
Same tested backend as pinecrack.py (imported), brand-new "cool" GUI:
sidebar navigation, live dashboard with stat cards + speed sparkline,
auto-crack pipeline, pre-run time estimate, notifications and restore.

    AUTHORIZED USE ONLY - only test networks / files you own or are
    explicitly permitted to assess.

Run:  py -3.11 pinecrack2.py
"""

import os
import json
import queue
import threading
import subprocess
import time
import collections

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import pinecrack as pc
from pinecrack import (
    Config, locate_all, HASH_MODES, MASK_PRESETS, MASK_HELP_TEXT, EXTRACTORS, BENCH_MODES,
    build_hashcat_cmd, build_hashcat_stdin_cmd, build_aircrack_cmd, build_convert_cmd,
    build_prince_cmd, build_kwp_cmd, build_pcfg_cmd, build_benchmark_cmd,
    build_extractor_cmd, find_extractor, clean_john_hash, guess_hc_mode,
    JobRunner, parse_crack_line, parse_hc22000, mask_keyspace,
    human_count, human_time, fmt_duration, estimate_candidates, parse_bench_speed,
    notify, build_profile_wordlist, wordlist_stats, merge_dedupe_files, gen_pattern_list,
    POTFILE_PATH, OUTFILE_PATH,
)

APP_NAME = "PineCrack"
APP_VERSION = "2.3"

# --- self-update ------------------------------------------------------------
# Community edition checks the public GitHub releases. To point at your own
# server instead, set PINECRACK_UPDATE_URL to a JSON manifest:
#   {"version": "2.3", "url": "<installer .exe URL>", "notes": "..."}
UPDATE_GITHUB_REPO = "Lovkar-Squid/PineCrack-Community"
UPDATE_MANIFEST_URL = os.environ.get("PINECRACK_UPDATE_URL", "")


def _pc_ver_tuple(s):
    out = []
    for part in str(s).lstrip("vV").split("."):
        digits = "".join(c for c in part if c.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out) if out else (0,)


def pc_fetch_latest():
    """Return (version, download_url, notes); raises on network error."""
    import urllib.request

    def _get(url):
        req = urllib.request.Request(url, headers={"User-Agent": "PineCrack-Updater"})
        with urllib.request.urlopen(req, timeout=12) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    if UPDATE_MANIFEST_URL:
        j = _get(UPDATE_MANIFEST_URL)
        return str(j.get("version", "")).lstrip("vV"), j.get("url", ""), j.get("notes", "")
    j = _get("https://api.github.com/repos/%s/releases/latest" % UPDATE_GITHUB_REPO)
    ver = str(j.get("tag_name", "")).lstrip("vV")
    url = ""
    for a in j.get("assets", []):
        if str(a.get("name", "")).lower().endswith(".exe"):
            url = a.get("browser_download_url", "")
            break
    return ver, url, j.get("body", "")

# ---- palette -------------------------------------------------------------
BG      = "#0b0f17"
SIDEBAR = "#0e1420"
PANEL   = "#131b28"
CARD    = "#1a2434"
CARD2   = "#202c40"
ACCENT  = "#22d3ee"   # cyan
ACCENT2 = "#a78bfa"   # violet
OK      = "#34d399"   # green
WARN    = "#f59e0b"
BAD     = "#f87171"
MUTE    = "#64748b"
TEXT    = "#e2e8f0"

ATTACKS = ["Dictionary", "Dictionary + Rules", "Mask / brute-force",
           "Combinator", "Hybrid: word + mask", "Hybrid: mask + word",
           "PRINCE", "Keyboard-walk", "PCFG"]
ATTACK_KEY = {"Dictionary": "dict", "Dictionary + Rules": "rules",
              "Mask / brute-force": "mask", "Combinator": "combinator",
              "Hybrid: word + mask": "hybrid_wm", "Hybrid: mask + word": "hybrid_mw",
              "PRINCE": "prince", "Keyboard-walk": "kwp", "PCFG": "pcfg"}


def cwd_for(cmd):
    """hashcat must run from its own dir (needs ./OpenCL, ./modules)."""
    try:
        exe = cmd[0]
        if os.path.basename(exe).lower().startswith("hashcat") and os.path.dirname(exe):
            return os.path.dirname(exe)
    except Exception:
        pass
    return str(pc.APP_DIR)


HISTORY_PATH = pc.APP_DIR / "pinecrack_history.jsonl"


def append_history(rows):
    try:
        with open(HISTORY_PATH, "a", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    except Exception:
        pass


def load_history():
    out = []
    try:
        if HISTORY_PATH.exists():
            for ln in HISTORY_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if ln:
                    try:
                        out.append(json.loads(ln))
                    except Exception:
                        pass
    except Exception:
        pass
    return out


def list_restore_sessions(hashcat_path):
    """Find hashcat <session>.restore files next to the hashcat binary."""
    d = os.path.dirname(hashcat_path) if hashcat_path else ""
    res = []
    try:
        if d and os.path.isdir(d):
            for fn in os.listdir(d):
                if fn.lower().endswith(".restore"):
                    full = os.path.join(d, fn)
                    st = os.stat(full)
                    res.append((fn[:-8], full, st.st_mtime, st.st_size))
    except Exception:
        pass
    return sorted(res, key=lambda x: -x[2])


# ordered longest/most-specific first
IDENTIFY_SIGS = [
    ("$zip2$", "13600  (WinZip AES)"), ("$pkzip2$", "17200 / 17210  (PKZIP)"),
    ("$rar5$", "13000  (RAR5)"), ("$RAR3$", "12500  (RAR3-hp)"), ("$7z$", "11600  (7-Zip)"),
    ("$office$*2013", "9600  (MS Office 2013)"), ("$office$*2010", "9500  (MS Office 2010)"),
    ("$office$*2007", "9400  (MS Office 2007)"), ("$office$", "9600  (MS Office)"),
    ("$oldoffice$0", "9700  (Office <=2003, MD5+RC4)"), ("$oldoffice$1", "9710"),
    ("$oldoffice$3", "9800  (Office <=2003, SHA1+RC4)"),
    ("$pdf$1", "10400  (PDF 1.1-1.3)"), ("$pdf$2", "10500  (PDF 1.4-1.6)"), ("$pdf$4", "10500  (PDF 1.4-1.6)"),
    ("$pdf$5*5", "10600  (PDF 1.7 L3)"), ("$pdf$5*6", "10700  (PDF 1.7 L8)"), ("$pdf$", "10500  (PDF)"),
    ("$keepass$", "13400  (KeePass)"), ("$bitlocker$", "22100  (BitLocker)"),
    ("$krb5tgs$23", "13100  (Kerberoast TGS-REP, RC4)"), ("$krb5tgs$17", "19600  (Kerberoast, AES128)"),
    ("$krb5tgs$18", "19700  (Kerberoast, AES256)"), ("$krb5tgs$", "13100  (Kerberoast TGS-REP)"),
    ("$krb5asrep$", "18200  (Kerberos AS-REP roast)"), ("$krb5pa$", "7500  (Kerberos pre-auth)"),
    ("$sshng$", "22911  (SSH private key)"), ("$bitcoin$", "11300  (Bitcoin/Litecoin wallet)"),
    ("$ethereum$p", "15600  (Ethereum, PBKDF2)"), ("$ethereum$s", "15700  (Ethereum, scrypt)"),
    ("$electrum$", "16600  (Electrum wallet)"),
    ("$apr1$", "1600  (Apache apr1-md5)"), ("$1$", "500  (md5crypt / Cisco-IOS $1$)"),
    ("$5$", "7400  (sha256crypt, Linux $5$)"), ("$6$", "1800  (sha512crypt, Linux $6$)"),
    ("$2a$", "3200  (bcrypt)"), ("$2b$", "3200  (bcrypt)"), ("$2y$", "3200  (bcrypt)"), ("$2x$", "3200  (bcrypt)"),
    ("$P$", "400  (phpass - WordPress)"), ("$H$", "400  (phpass - phpBB3)"), ("$S$", "7900  (Drupal7)"),
    ("$ml$", "7100  (macOS 10.8+ PBKDF2)"), ("$DCC2$", "2100  (Domain Cached Creds 2)"),
    ("{SSHA512}", "1711  (LDAP SSHA-512)"), ("{SSHA256}", "1411  (LDAP SSHA-256)"),
    ("{SSHA}", "111  (LDAP salted SHA1)"), ("{SHA}", "101  (LDAP SHA1)"), ("{SMD5}", "1610  (LDAP salted MD5)"),
    ("pbkdf2_sha256$", "10000  (Django PBKDF2-SHA256)"), ("sha1$", "124  (Django SHA1)"),
    ("$gost$", "6900  (GOST R 34.11-94)"), ("$WPA", "22000  (WPA)"), ("$NT$", "1000  (NTLM)"),
]


def identify_hash(line):
    """Best-effort hash-mode identification from one hash line. Signature table
    first, then NetNTLM / pwdump structure, then hex length + charset."""
    line = (line or "").strip()
    if not line:
        return "empty line"
    for sig, desc in IDENTIFY_SIGS:
        if line.startswith(sig):
            return desc
    # NetNTLMv1/v2:  user::domain:...:...:...
    if "::" in line and line.count(":") >= 4:
        return "5600  (NetNTLMv2)" if len(line.rsplit(":", 1)[-1]) > 48 else "5500  (NetNTLMv1)"
    # pwdump line:  user:rid:LM:NT:::
    if line.count(":") >= 6 and ":::" in line:
        return "1000  (NTLM — the 4th field of this pwdump line)  /  3000 (LM = 3rd)"
    h = line.split(":")[0].strip()
    if h and all(c in "0123456789abcdefABCDEF" for c in h):
        by_len = {16: "3000  (LM, half)  /  12 (PostgreSQL)",
                  32: "0 (MD5)  or  1000 (NTLM)  or  900 (MD4)",
                  40: "100  (SHA1)", 56: "1300  (SHA-224)",
                  64: "1400 (SHA-256)  or  17400 (SHA3-256)", 96: "10800  (SHA-384)",
                  128: "1700 (SHA-512)  or  17600 (SHA3-512)"}
        return by_len.get(len(h), "%d-hex digest (uncommon length — check hashcat --example-hashes)" % len(h))
    return "unrecognised — pick the Hash type manually on the Attack tab"


class PineCrack2(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.title("%s %s" % (APP_NAME, APP_VERSION))
        self.geometry("1180x760")
        self.minsize(1040, 660)
        self.configure(fg_color=BG)

        self.cfg = Config()
        self.tools = locate_all(self.cfg)
        self.ev = queue.Queue()
        self.runner = JobRunner(self.ev)

        self.hashfile = ""
        self.capfile = ""
        self.captures = []
        self.wordlists = []
        self.run_before = set()            # passwords already cracked before this run
        self.job_started = 0.0
        self.auto = {"active": False, "queue": [], "idx": 0}
        self.queue = []                    # list of {label, hashfile, profile}
        self.queue_active = False
        self.queue_idx = 0
        self.bench_speed = {}
        self.spark = collections.deque(maxlen=90)

        # tk variables
        self.v_engine = ctk.StringVar(value="hashcat (GPU)")
        self.v_attack = ctk.StringVar(value=ATTACKS[0])
        self.v_workload = ctk.StringVar(value=self.cfg.get("workload", "3") or "3")
        self.v_rules = ctk.StringVar(value="")
        self.v_mask = ctk.StringVar(value=MASK_PRESETS[0][1])
        self.v_preset = ctk.StringVar(value=MASK_PRESETS[0][0])
        self.v_opt = ctk.BooleanVar(value=False)
        self.v_inc = ctk.BooleanVar(value=False)
        self.v_incmin = ctk.StringVar(value="")
        self.v_incmax = ctk.StringVar(value="")
        self.v_hashmode = ctk.StringVar(value=HASH_MODES[0][0])
        self.v_custmode = ctk.StringVar(value="")
        self.v_profile = ctk.StringVar(value="")
        self.v_profname = ctk.StringVar(value="")
        self.v_device = ctk.StringVar(value="")
        self.v_session = ctk.StringVar(value="")
        self.v_cs1 = ctk.StringVar(value="")
        self.v_cs2 = ctk.StringVar(value="")
        self.v_markov = ctk.StringVar(value="")
        self.v_rules2 = ctk.StringVar(value="")
        self.watch = {"active": False}

        self._build()
        self.after(200, self._pump)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------------------------------------------------------- layout
    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self.content = ctk.CTkFrame(self, fg_color=BG)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        self.views = {}
        for name, builder in (("Dashboard", self._view_dashboard),
                              ("Target", self._view_target),
                              ("Attack", self._view_attack),
                              ("Queue", self._view_queue),
                              ("Results", self._view_results),
                              ("History", self._view_history),
                              ("Tools", self._view_tools),
                              ("Settings", self._view_settings)):
            f = ctk.CTkFrame(self.content, fg_color=BG)
            f.grid(row=0, column=0, sticky="nsew")
            self.views[name] = f
            builder(f)
        self._show("Dashboard")

    def _build_sidebar(self):
        bar = ctk.CTkFrame(self, fg_color=SIDEBAR, width=210, corner_radius=0)
        bar.grid(row=0, column=0, sticky="nsew")
        bar.grid_propagate(False)
        ctk.CTkLabel(bar, text="⚡ PineCrack", font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=ACCENT).pack(anchor="w", padx=20, pady=(22, 0))
        ctk.CTkLabel(bar, text="v%s  ·  community edition" % APP_VERSION, font=ctk.CTkFont(size=11),
                     text_color=MUTE).pack(anchor="w", padx=20, pady=(0, 18))
        self.nav_btns = {}
        for name, icon in (("Dashboard", "◆"), ("Target", "⌘"), ("Attack", "⚔"),
                           ("Queue", "≡"), ("Results", "🔓"), ("History", "🕘"),
                           ("Tools", "🛠"), ("Settings", "⚙")):
            b = ctk.CTkButton(bar, text="  %s   %s" % (icon, name), anchor="w",
                              font=ctk.CTkFont(size=14), height=42, corner_radius=10,
                              fg_color="transparent", hover_color=CARD2, text_color=TEXT,
                              command=lambda n=name: self._show(n))
            b.pack(fill="x", padx=12, pady=3)
            self.nav_btns[name] = b
        gpu = "no GPU"
        try:
            g = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                               capture_output=True, text=True, timeout=6)
            if g.stdout.strip():
                gpu = g.stdout.strip().splitlines()[0]
        except Exception:
            pass
        self.gpu_name = gpu
        badge = ctk.CTkFrame(bar, fg_color=CARD, corner_radius=12)
        badge.pack(side="bottom", fill="x", padx=12, pady=16)
        ctk.CTkLabel(badge, text="GPU", font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=MUTE).pack(anchor="w", padx=12, pady=(8, 0))
        ctk.CTkLabel(badge, text=gpu, font=ctk.CTkFont(size=12), text_color=OK,
                     wraplength=160, justify="left").pack(anchor="w", padx=12, pady=(0, 8))
        upd = ctk.CTkButton(bar, text="⟳  Check for updates", anchor="w",
                            font=ctk.CTkFont(size=12), height=34, corner_radius=10,
                            fg_color="transparent", hover_color=CARD2, text_color=MUTE,
                            command=self._check_updates)
        upd.pack(side="bottom", fill="x", padx=12, pady=(0, 2))
        self.after(2500, lambda: self._check_updates(silent=True))  # quiet check on launch

    def _check_updates(self, silent=False):
        def work():
            try:
                ver, url, notes = pc_fetch_latest()
            except Exception as e:
                if not silent:
                    self.after(0, lambda: messagebox.showerror(
                        "Check for updates", "Could not check for updates:\n%s" % e))
                return
            if not ver or _pc_ver_tuple(ver) <= _pc_ver_tuple(APP_VERSION):
                if not silent:
                    self.after(0, lambda: messagebox.showinfo(
                        "Check for updates", "You're on the latest version (v%s)." % APP_VERSION))
                return
            self.after(0, lambda: self._offer_update(ver, url, notes))
        threading.Thread(target=work, daemon=True).start()

    def _offer_update(self, ver, url, notes):
        msg = "PineCrack v%s is available (you have v%s)." % (ver, APP_VERSION)
        if notes:
            msg += "\n\nWhat's new:\n%s" % str(notes)[:400]
        if not url:
            messagebox.showinfo("Update available", msg + "\n\n(No installer link found in the release.)")
            return
        if not messagebox.askyesno("Update available", msg + "\n\nDownload and install now?"):
            return

        def dl():
            try:
                import urllib.request, tempfile
                dst = os.path.join(tempfile.gettempdir(), "PineCrack-Setup-%s.exe" % ver)
                urllib.request.urlretrieve(url, dst)
                self.after(0, lambda: (os.startfile(dst), self.destroy()))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Update", "Download failed:\n%s" % e))
        threading.Thread(target=dl, daemon=True).start()
        messagebox.showinfo("Downloading",
                            "Downloading v%s in the background…\nThe installer will open when it's ready." % ver)

    def _show(self, name):
        self.views[name].tkraise()
        for n, b in self.nav_btns.items():
            b.configure(fg_color=(CARD2 if n == name else "transparent"),
                        text_color=(ACCENT if n == name else TEXT))

    # ------------------------------------------------------------- dashboard
    def _card(self, parent, title, col):
        c = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14)
        c.grid(row=0, column=col, padx=8, pady=4, sticky="nsew")
        parent.grid_columnconfigure(col, weight=1)
        ctk.CTkLabel(c, text=title, font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=MUTE).pack(anchor="w", padx=16, pady=(12, 0))
        val = ctk.CTkLabel(c, text="—", font=ctk.CTkFont(size=26, weight="bold"), text_color=TEXT)
        val.pack(anchor="w", padx=16, pady=(0, 12))
        return val

    def _view_dashboard(self, f):
        head = ctk.CTkFrame(f, fg_color="transparent"); head.pack(fill="x", padx=22, pady=(20, 4))
        ctk.CTkLabel(head, text="Dashboard", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=TEXT).pack(anchor="w")
        self.tgt_lbl = ctk.CTkLabel(head, text="No target loaded — go to Target",
                                    font=ctk.CTkFont(size=12), text_color=MUTE)
        self.tgt_lbl.pack(anchor="w")

        cards = ctk.CTkFrame(f, fg_color="transparent"); cards.pack(fill="x", padx=14, pady=6)
        self.c_speed = self._card(cards, "SPEED", 0)
        self.c_prog = self._card(cards, "PROGRESS", 1)
        self.c_eta = self._card(cards, "ETA (time left)", 2)
        self.c_rec = self._card(cards, "RECOVERED", 3)
        self.c_temp = self._card(cards, "GPU TEMP", 4)

        spark_wrap = ctk.CTkFrame(f, fg_color=CARD, corner_radius=14)
        spark_wrap.pack(fill="x", padx=22, pady=8)
        ctk.CTkLabel(spark_wrap, text="SPEED  (live)", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=MUTE).pack(anchor="w", padx=16, pady=(10, 0))
        self.canvas = tk.Canvas(spark_wrap, height=90, bg=CARD, highlightthickness=0)
        self.canvas.pack(fill="x", padx=12, pady=(2, 12))
        self.progress = ctk.CTkProgressBar(f, progress_color=ACCENT, height=10)
        self.progress.set(0); self.progress.pack(fill="x", padx=22, pady=(0, 8))

        btns = ctk.CTkFrame(f, fg_color="transparent"); btns.pack(fill="x", padx=20, pady=4)
        ctk.CTkButton(btns, text="▶  Start", width=120, height=42, corner_radius=12,
                      fg_color=OK, hover_color="#059669", text_color="#04140c",
                      font=ctk.CTkFont(size=15, weight="bold"), command=self.start_attack).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="⚡  Auto-crack", width=140, height=42, corner_radius=12,
                      fg_color=ACCENT2, hover_color="#8b5cf6", text_color="#0b0f17",
                      font=ctk.CTkFont(size=15, weight="bold"), command=self.start_auto).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="⏱ Estimate", width=110, height=42, corner_radius=12,
                      fg_color=CARD2, hover_color="#2a3852", command=self.do_estimate).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="♻ Restore", width=104, height=42, corner_radius=12,
                      fg_color=CARD2, hover_color="#2a3852", command=self.do_restore).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="⏸ Pause", width=90, height=42, corner_radius=12,
                      fg_color=CARD2, hover_color="#2a3852", command=self.pause_job).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="⏹ Stop", width=86, height=42, corner_radius=12,
                      fg_color=BAD, hover_color="#dc2626", text_color="#1a0606",
                      font=ctk.CTkFont(weight="bold"), command=self.stop_all).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="🗂 Sessions", width=112, height=42, corner_radius=12,
                      fg_color=CARD2, hover_color="#2a3852", command=self.sessions_manager).pack(side="left", padx=6)

        self.log_box = ctk.CTkTextbox(f, fg_color="#0a0e15", text_color="#9fb3c8",
                                      font=ctk.CTkFont(family="Consolas", size=11), wrap="none")
        self.log_box.pack(fill="both", expand=True, padx=22, pady=(6, 14))

    def _draw_spark(self):
        c = self.canvas
        c.delete("all")
        w = c.winfo_width() or 800
        h = c.winfo_height() or 90
        if len(self.spark) < 2:
            return
        mx = max(self.spark) or 1
        n = len(self.spark)
        step = w / max(1, (self.spark.maxlen - 1))
        pts = []
        for i, v in enumerate(self.spark):
            x = i * step
            y = h - 6 - (v / mx) * (h - 14)
            pts += [x, y]
        # area
        c.create_line(*pts, fill=ACCENT, width=2, smooth=True)
        c.create_oval(pts[-2] - 3, pts[-1] - 3, pts[-2] + 3, pts[-1] + 3, fill=ACCENT, outline="")

    # ---------------------------------------------------------------- target
    def _view_target(self, f):
        ctk.CTkLabel(f, text="Target", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=22, pady=(20, 2))
        ctk.CTkLabel(f, text="Import a handshake (.pcap/.cap/.hc22000) or any hash file, then set it as target.",
                     text_color=MUTE, font=ctk.CTkFont(size=12)).pack(anchor="w", padx=22)
        row = ctk.CTkFrame(f, fg_color="transparent"); row.pack(fill="x", padx=20, pady=10)
        ctk.CTkButton(row, text="＋ Import capture…", command=self.import_files, width=150,
                      fg_color=CARD2, hover_color="#2a3852").pack(side="left", padx=6)
        ctk.CTkButton(row, text="📁 Pull from loot", command=self.pull_loot, width=140,
                      fg_color=CARD2, hover_color="#2a3852").pack(side="left", padx=6)
        ctk.CTkButton(row, text="🔁 Convert .pcap", command=self.convert_server, width=160,
                      fg_color=ACCENT, hover_color="#0891b2", text_color="#04121a").pack(side="left", padx=6)
        ctk.CTkButton(row, text="✔ Use selected", command=self.use_selected, width=130,
                      fg_color=OK, hover_color="#059669", text_color="#04140c").pack(side="left", padx=6)
        row2 = ctk.CTkFrame(f, fg_color="transparent"); row2.pack(fill="x", padx=20, pady=(0, 4))
        self.v_autoconv = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(row2, text="Auto-convert .pcap on use", variable=self.v_autoconv).pack(side="left", padx=6)
        self.watch_btn = ctk.CTkButton(row2, text="👁 Watch loot", command=self.toggle_watch, width=132,
                                       fg_color=ACCENT2, hover_color="#8b5cf6", text_color="#0b0f17")
        self.watch_btn.pack(side="left", padx=6)
        ctk.CTkButton(row2, text="🩺 Handshake check", command=self.do_hs_check, width=160,
                      fg_color=CARD2, hover_color="#2a3852").pack(side="left", padx=6)
        self.cap_list = tk.Listbox(f, height=11, bg="#0a0e15", fg="#cbd5e1",
                                   selectbackground=ACCENT, selectforeground="#04121a",
                                   highlightthickness=0, borderwidth=0, font=("Consolas", 10))
        self.cap_list.pack(fill="both", expand=True, padx=22, pady=8)
        self.tgt_lbl2 = ctk.CTkLabel(f, text="Target: —", text_color=ACCENT,
                                     font=ctk.CTkFont(size=13, weight="bold"))
        self.tgt_lbl2.pack(anchor="w", padx=22, pady=(0, 14))

    # ---------------------------------------------------------------- attack
    def _view_attack(self, f):
        ctk.CTkLabel(f, text="Attack", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=22, pady=(20, 6))
        grid = ctk.CTkFrame(f, fg_color=PANEL, corner_radius=14); grid.pack(fill="x", padx=20, pady=6)

        def label(r, t):
            ctk.CTkLabel(grid, text=t, text_color=MUTE, font=ctk.CTkFont(size=12),
                         width=120, anchor="w").grid(row=r, column=0, padx=(16, 6), pady=7, sticky="w")

        label(0, "Engine")
        ctk.CTkOptionMenu(grid, variable=self.v_engine, values=["hashcat (GPU)", "aircrack-ng (CPU)"],
                          width=200, fg_color=CARD2, button_color=ACCENT2).grid(row=0, column=1, sticky="w", pady=7)
        label(1, "Hash type")
        ctk.CTkOptionMenu(grid, variable=self.v_hashmode, values=[m[0] for m in HASH_MODES],
                          width=300, fg_color=CARD2, button_color=ACCENT2).grid(row=1, column=1, sticky="w", pady=7)
        label(2, "Attack mode")
        ctk.CTkOptionMenu(grid, variable=self.v_attack, values=ATTACKS, width=240,
                          fg_color=CARD2, button_color=ACCENT2,
                          command=lambda *_: self._preview()).grid(row=2, column=1, sticky="w", pady=7)
        label(3, "Wordlists")
        wf = ctk.CTkFrame(grid, fg_color="transparent"); wf.grid(row=3, column=1, sticky="w", pady=7)
        ctk.CTkButton(wf, text="＋ Add", width=70, command=self.add_wordlist,
                      fg_color=CARD2, hover_color="#2a3852").pack(side="left")
        for lbl, fn in (("rockyou", "rockyou.txt"),):
            ctk.CTkButton(wf, text=lbl, width=90, fg_color="#182234", hover_color="#2a3852",
                          command=lambda p=fn: self.quick_wl(p)).pack(side="left", padx=4)
        ctk.CTkButton(wf, text="clear", width=54, fg_color="#3a1620", hover_color="#5a1d2a",
                      command=lambda: (self.wordlists.clear(), self._refresh_wl())).pack(side="left", padx=4)
        self.wl_lbl = ctk.CTkLabel(grid, text="(none)", text_color=MUTE, font=ctk.CTkFont(size=11),
                                   wraplength=560, justify="left")
        self.wl_lbl.grid(row=4, column=1, sticky="w")
        label(5, "Rules file")
        rf = ctk.CTkFrame(grid, fg_color="transparent"); rf.grid(row=5, column=1, sticky="w", pady=7)
        ctk.CTkEntry(rf, textvariable=self.v_rules, width=280).pack(side="left")
        ctk.CTkButton(rf, text="…", width=32, command=self.pick_rules,
                      fg_color=CARD2).pack(side="left", padx=4)
        ctk.CTkButton(rf, text="best66", width=70, fg_color="#182234",
                      command=lambda: self.v_rules.set(os.path.join(self.cfg.get("rules_dir", r"C:\hashcat\rules"), "best66.rule"))).pack(side="left", padx=4)
        ctk.CTkLabel(rf, text="+2").pack(side="left", padx=(8, 2))
        ctk.CTkEntry(rf, textvariable=self.v_rules2, width=120, placeholder_text="stack 2nd rule").pack(side="left")
        ctk.CTkButton(rf, text="…", width=28, fg_color=CARD2, command=self.pick_rules2).pack(side="left", padx=2)
        label(6, "Mask")
        mf = ctk.CTkFrame(grid, fg_color="transparent"); mf.grid(row=6, column=1, sticky="w", pady=7)
        ctk.CTkOptionMenu(mf, variable=self.v_preset, values=[p[0] for p in MASK_PRESETS], width=210,
                          fg_color=CARD2, button_color=ACCENT2,
                          command=lambda *_: self._apply_preset()).pack(side="left")
        ctk.CTkEntry(mf, textvariable=self.v_mask, width=180).pack(side="left", padx=6)
        ctk.CTkButton(mf, text="❓", width=32, fg_color=CARD2, command=self._mask_help).pack(side="left")
        adv = ctk.CTkFrame(grid, fg_color="transparent"); adv.grid(row=7, column=1, sticky="w", pady=7)
        ctk.CTkLabel(adv, text="Workload").pack(side="left", padx=(0, 2))
        ctk.CTkOptionMenu(adv, variable=self.v_workload, values=["1", "2", "3", "4"], width=56,
                          fg_color=CARD2, button_color=ACCENT2).pack(side="left", padx=(0, 10))
        ctk.CTkCheckBox(adv, text="-O optimized", variable=self.v_opt).pack(side="left", padx=(0, 8))
        ctk.CTkCheckBox(adv, text="Increment", variable=self.v_inc).pack(side="left", padx=6)
        ctk.CTkLabel(adv, text="min").pack(side="left", padx=(8, 2))
        ctk.CTkEntry(adv, textvariable=self.v_incmin, width=40, placeholder_text="8").pack(side="left")
        ctk.CTkLabel(adv, text="max").pack(side="left", padx=(6, 2))
        ctk.CTkEntry(adv, textvariable=self.v_incmax, width=40, placeholder_text="10").pack(side="left")
        ctk.CTkLabel(adv, text="Markov").pack(side="left", padx=(8, 2))
        ctk.CTkEntry(adv, textvariable=self.v_markov, width=48, placeholder_text="256").pack(side="left")
        adv2 = ctk.CTkFrame(grid, fg_color="transparent"); adv2.grid(row=8, column=1, sticky="w", pady=7)
        ctk.CTkLabel(adv2, text="GPU").pack(side="left", padx=(0, 2))
        self.gpu_menu = ctk.CTkOptionMenu(adv2, values=self._gpu_options(), width=150,
                                          fg_color=CARD2, button_color=ACCENT2, command=self._pick_gpu)
        self.gpu_menu.pack(side="left")
        ctk.CTkLabel(adv2, text="-d").pack(side="left", padx=(8, 2))
        ctk.CTkEntry(adv2, textvariable=self.v_device, width=40, placeholder_text="all").pack(side="left")
        ctk.CTkLabel(adv2, text="Session").pack(side="left", padx=(8, 2))
        ctk.CTkEntry(adv2, textvariable=self.v_session, width=88, placeholder_text="name").pack(side="left")
        ctk.CTkLabel(adv2, text="charset -1").pack(side="left", padx=(8, 2))
        ctk.CTkEntry(adv2, textvariable=self.v_cs1, width=84, placeholder_text="?l?d").pack(side="left")
        ctk.CTkLabel(adv2, text="-2").pack(side="left", padx=(6, 2))
        ctk.CTkEntry(adv2, textvariable=self.v_cs2, width=84, placeholder_text="?u?l").pack(side="left")
        ctk.CTkLabel(grid, text="Mask keys:  ?l a-z  ?u A-Z  ?d 0-9  ?s sym  ?a all  |  ?1/?2 custom  |  each ? = 1 char",
                     text_color=MUTE, font=ctk.CTkFont(size=11)).grid(row=9, column=1, sticky="w", pady=(0, 8))

        prof = ctk.CTkFrame(f, fg_color="transparent"); prof.pack(fill="x", padx=22, pady=6)
        ctk.CTkLabel(prof, text="Profile:", text_color=MUTE).pack(side="left")
        self.prof_menu = ctk.CTkOptionMenu(prof, variable=self.v_profile, width=200,
                                           values=(list(self.cfg.get("profiles", {}).keys()) or ["—"]),
                                           fg_color=CARD2, button_color=ACCENT2)
        self.prof_menu.pack(side="left", padx=6)
        ctk.CTkButton(prof, text="Load", width=64, command=self.load_profile,
                      fg_color=CARD2).pack(side="left", padx=4)
        ctk.CTkEntry(prof, textvariable=self.v_profname, width=150,
                     placeholder_text="new profile name").pack(side="left", padx=(16, 4))
        ctk.CTkButton(prof, text="💾 Save", width=74, command=self.save_profile,
                      fg_color=CARD2).pack(side="left", padx=4)
        ctk.CTkButton(prof, text="＋ Queue", width=84, command=self.queue_add,
                      fg_color=CARD2).pack(side="left", padx=4)

        ctk.CTkLabel(f, text="Command preview", text_color=MUTE,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=22, pady=(8, 0))
        self.preview = ctk.CTkTextbox(f, height=70, fg_color="#0a0e15", text_color=ACCENT,
                                      font=ctk.CTkFont(family="Consolas", size=11), wrap="word")
        self.preview.pack(fill="x", padx=22, pady=(2, 12))
        for v in (self.v_mask, self.v_rules, self.v_rules2, self.v_hashmode, self.v_incmin,
                  self.v_incmax, self.v_device, self.v_session, self.v_cs1, self.v_cs2,
                  self.v_markov, self.v_workload):
            v.trace_add("write", lambda *_: self._preview())
        self._preview()

    # --------------------------------------------------------------- results
    def _view_results(self, f):
        ctk.CTkLabel(f, text="🔓 Cracked passwords", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=22, pady=(20, 2))
        self.res_count = ctk.CTkLabel(f, text="No results yet", text_color=MUTE)
        self.res_count.pack(anchor="w", padx=22, pady=(0, 8))
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("PC2.Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=TEXT, rowheight=30, borderwidth=0, font=("Segoe UI", 10))
        style.configure("PC2.Treeview.Heading", background=CARD2, foreground=ACCENT,
                        relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("PC2.Treeview", background=[("selected", ACCENT2)], foreground=[("selected", "#0b0f17")])
        wrap = ctk.CTkFrame(f, fg_color=PANEL, corner_radius=12); wrap.pack(fill="both", expand=True, padx=22, pady=4)
        cols = ("essid", "pw", "bssid", "src")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", style="PC2.Treeview",
                                 selectmode="extended", height=13)
        for c, t, w in (("essid", "ESSID / Target", 230), ("pw", "Password", 240),
                        ("bssid", "BSSID / MAC", 150), ("src", "Source", 80)):
            self.tree.heading(c, text=t); self.tree.column(c, width=w, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
        self.tree.tag_configure("odd", background=PANEL)
        self.tree.tag_configure("even", background="#182234")
        self.tree.bind("<Double-1>", lambda e: self.copy_pw())
        row = ctk.CTkFrame(f, fg_color="transparent"); row.pack(fill="x", padx=22, pady=8)
        ctk.CTkButton(row, text="↻ Refresh", width=96, command=self.refresh_results,
                      fg_color=CARD2).pack(side="left")
        ctk.CTkButton(row, text="📋 Copy password", width=150, command=self.copy_pw,
                      fg_color=ACCENT, text_color="#04121a").pack(side="left", padx=8)
        ctk.CTkButton(row, text="📋 Copy all", width=100, command=self.copy_all,
                      fg_color=CARD2).pack(side="left")
        ctk.CTkButton(row, text="⬇ Export CSV", width=118, command=self.export_csv,
                      fg_color=CARD2).pack(side="left", padx=8)
        ctk.CTkButton(row, text="🗑 Clear", width=88, command=self.clear_results,
                      fg_color="#7f1d1d", hover_color="#991b1b").pack(side="right")
        ctk.CTkLabel(f, text="Double-click a row to copy its password.", text_color=MUTE,
                     font=ctk.CTkFont(size=11)).pack(anchor="w", padx=22, pady=(0, 8))

    # ----------------------------------------------------------------- queue
    def _view_queue(self, f):
        ctk.CTkLabel(f, text="Job queue", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=22, pady=(20, 2))
        ctk.CTkLabel(f, text="Queue several attacks — they run one after another (great overnight). "
                             "Use ＋ Queue on the Attack tab (or ＋ Add here) to capture the current target + settings.",
                     text_color=MUTE, font=ctk.CTkFont(size=12), wraplength=830, justify="left").pack(anchor="w", padx=22)
        row = ctk.CTkFrame(f, fg_color="transparent"); row.pack(fill="x", padx=20, pady=8)
        ctk.CTkButton(row, text="＋ Add current", width=128, command=self.queue_add,
                      fg_color=CARD2, hover_color="#2a3852").pack(side="left", padx=4)
        ctk.CTkButton(row, text="▶ Run queue", width=118, command=self.run_queue,
                      fg_color=OK, text_color="#04140c").pack(side="left", padx=4)
        ctk.CTkButton(row, text="⏹ Stop", width=78, command=self.stop_all,
                      fg_color=BAD, text_color="#1a0606").pack(side="left", padx=4)
        ctk.CTkButton(row, text="↑", width=38, command=lambda: self.queue_move(-1), fg_color=CARD2).pack(side="left", padx=(12, 2))
        ctk.CTkButton(row, text="↓", width=38, command=lambda: self.queue_move(1), fg_color=CARD2).pack(side="left", padx=2)
        ctk.CTkButton(row, text="✖ Remove", width=94, command=self.queue_remove, fg_color=CARD2).pack(side="left", padx=8)
        ctk.CTkButton(row, text="🗑 Clear", width=84, command=self.queue_clear, fg_color="#7f1d1d").pack(side="right", padx=6)
        self.queue_count = ctk.CTkLabel(f, text="Queue empty", text_color=MUTE, font=ctk.CTkFont(size=12))
        self.queue_count.pack(anchor="w", padx=22, pady=(2, 0))
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("PC2.Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=28, borderwidth=0, font=("Segoe UI", 10))
        style.configure("PC2.Treeview.Heading", background=CARD2, foreground=ACCENT,
                        relief="flat", font=("Segoe UI", 10, "bold"))
        wrap = ctk.CTkFrame(f, fg_color=PANEL, corner_radius=12); wrap.pack(fill="both", expand=True, padx=22, pady=6)
        cols = ("n", "status", "attack", "detail", "target")
        self.queue_tree = ttk.Treeview(wrap, columns=cols, show="headings", style="PC2.Treeview", height=12)
        for c, t, w in (("n", "#", 40), ("status", "Status", 118), ("attack", "Attack", 150),
                        ("detail", "Wordlist / mask", 250), ("target", "Target", 170)):
            self.queue_tree.heading(c, text=t); self.queue_tree.column(c, width=w, anchor="w")
        self.queue_tree.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.queue_tree.yview)
        self.queue_tree.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
        self.queue_tree.tag_configure("running", foreground=WARN)
        self.queue_tree.tag_configure("done", foreground=MUTE)
        self.queue_tree.tag_configure("cracked", foreground=OK)
        self.queue_tree.tag_configure("pending", foreground=TEXT)
        self.refresh_queue()

    # --------------------------------------------------------------- history
    def _view_history(self, f):
        ctk.CTkLabel(f, text="🕘 Crack history", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=22, pady=(20, 2))
        self.hist_stats = ctk.CTkLabel(f, text="", text_color=OK, font=ctk.CTkFont(size=12, weight="bold"))
        self.hist_stats.pack(anchor="w", padx=22, pady=(0, 4))
        self.hist_canvas = tk.Canvas(f, height=72, bg=BG, highlightthickness=0)
        self.hist_canvas.pack(fill="x", padx=22, pady=(0, 4))
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("PC2.Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=28, borderwidth=0, font=("Segoe UI", 10))
        style.configure("PC2.Treeview.Heading", background=CARD2, foreground=ACCENT,
                        relief="flat", font=("Segoe UI", 10, "bold"))
        wrap = ctk.CTkFrame(f, fg_color=PANEL, corner_radius=12); wrap.pack(fill="both", expand=True, padx=22, pady=4)
        cols = ("when", "essid", "pw", "secs")
        self.hist_tree = ttk.Treeview(wrap, columns=cols, show="headings", style="PC2.Treeview",
                                      selectmode="extended", height=13)
        for c, t, w in (("when", "When", 150), ("essid", "ESSID / Target", 220),
                        ("pw", "Password", 220), ("secs", "Time to crack", 120)):
            self.hist_tree.heading(c, text=t); self.hist_tree.column(c, width=w, anchor="w")
        self.hist_tree.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
        self.hist_tree.tag_configure("odd", background=PANEL)
        self.hist_tree.tag_configure("even", background="#182234")
        row = ctk.CTkFrame(f, fg_color="transparent"); row.pack(fill="x", padx=22, pady=8)
        ctk.CTkButton(row, text="↻ Refresh", width=100, command=self.refresh_history, fg_color=CARD2).pack(side="left")
        ctk.CTkButton(row, text="⬇ Export CSV", width=120, command=self.export_history, fg_color=CARD2).pack(side="left", padx=8)
        ctk.CTkButton(row, text="🗑 Clear history", width=132, command=self.clear_history,
                      fg_color="#7f1d1d", hover_color="#991b1b").pack(side="right")
        self.refresh_history()

    # ----------------------------------------------------------------- tools
    def _view_tools(self, f):
        ctk.CTkLabel(f, text="Tools", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=22, pady=(20, 8))
        wrap = ctk.CTkScrollableFrame(f, fg_color=BG); wrap.pack(fill="both", expand=True, padx=14, pady=4)

        def tool(title, desc, btn, cmd):
            c = ctk.CTkFrame(wrap, fg_color=CARD, corner_radius=12); c.pack(fill="x", padx=6, pady=6)
            left = ctk.CTkFrame(c, fg_color="transparent"); left.pack(side="left", fill="x", expand=True, padx=14, pady=10)
            ctk.CTkLabel(left, text=title, font=ctk.CTkFont(size=14, weight="bold"),
                         text_color=TEXT, anchor="w").pack(anchor="w")
            ctk.CTkLabel(left, text=desc, font=ctk.CTkFont(size=11), text_color=MUTE,
                         anchor="w", justify="left").pack(anchor="w")
            ctk.CTkButton(c, text=btn, width=140, command=cmd, fg_color=ACCENT2,
                          hover_color="#8b5cf6", text_color="#0b0f17").pack(side="right", padx=14)

        tool("Benchmark GPU (WPA)", "Measure hashes/sec for -m 22000.", "Run benchmark",
             lambda: (self._show("Dashboard"), self._run(build_benchmark_cmd(self.tools.get("hashcat") or "hashcat"))))
        tool("Targeted wordlist creator", "CUPP-style list from a name/surname/year, with leet.",
             "Create…", self.wordlist_gen)
        tool("Extract hash from file", "zip/rar/office/pdf/keepass → crackable hash (sets target).",
             "Extract…", self.extract_hash)
        tool("Time estimate", "Estimate the current attack's runtime from measured speed.",
             "Estimate", self.do_estimate)
        tool("Identify hash mode", "hashcat --identify on the loaded target → matching -m modes.",
             "Identify", self.do_identify_hash)
        tool("Benchmark all Wi-Fi modes", "22000 / 22001 / 16800 in one sequential run.",
             "Run full benchmark", self.do_benchmark_all)
        tool("List targets in .hc22000", "Parse the loaded target → ESSID / type / AP-MAC.",
             "Show targets", self.do_targets)
        tool("List networks in capture", "Show handshakes/ESSIDs in the selected .pcap (hcxpcapngtool).",
             "Analyze capture", self.do_identify_cap)
        tool("Wordlist stats", "Count lines, usable (≥8), min/avg/max length.", "Analyze…", self.do_stats)
        tool("Merge + dedupe wordlists", "Combine several wordlists into one unique list.", "Merge…", self.do_merge)
        tool("Mutate wordlist (+digits/years)", "Append 1/123/!/1970-2030 to each word, keep ≥8.",
             "Mutate…", self.do_mutate)
        tool("Generate pattern / phone list", "prefix + N digits (e.g. 040 + 6) → wordlist.",
             "Generate…", self.do_genpattern)
        tool("Precomputed PMK (WPA 'rainbow')", "Why rainbow tables don't apply to WPA + the alternative.",
             "Explain", self.do_pmk_info)
        tool("Environment / tool check", "Show detected tool paths and GPU info.", "Show info", self.show_tools_info)

    # -------------------------------------------------------------- settings
    def _view_settings(self, f):
        ctk.CTkLabel(f, text="Settings", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=22, pady=(20, 8))
        wrap = ctk.CTkScrollableFrame(f, fg_color=BG); wrap.pack(fill="both", expand=True, padx=14, pady=4)
        self.setting_vars = {}

        def row(label, key, browse="file"):
            fr = ctk.CTkFrame(wrap, fg_color="transparent"); fr.pack(fill="x", padx=6, pady=4)
            ctk.CTkLabel(fr, text=label, width=180, anchor="w", text_color=MUTE).pack(side="left", padx=6)
            var = ctk.StringVar(value=self.cfg.get(key, "")); self.setting_vars[key] = var
            ctk.CTkEntry(fr, textvariable=var, width=460).pack(side="left", padx=6)
            if browse:
                ctk.CTkButton(fr, text="…", width=34, fg_color=CARD2,
                              command=lambda: var.set((filedialog.askopenfilename() if browse == "file"
                                                       else filedialog.askdirectory()) or var.get())).pack(side="left")
        for lbl, key, br in (("hashcat.exe", "hashcat_path", "file"),
                             ("hcxpcapngtool.exe", "hcxpcapngtool_path", "file"),
                             ("aircrack-ng.exe", "aircrack_path", "file"),
                             ("Wordlist folder", "wordlist_dir", "dir"),
                             ("Loot folder (SMB)", "loot_dir", "dir"),
                             ("Rules folder", "rules_dir", "dir"),
                             ("Extra hashcat flags", "extra_flags", None),
                             ("princeprocessor (pp64)", "prince_path", "file"),
                             ("kwprocessor (kwp)", "kwp_path", "file"),
                             ("kwp base file", "kwp_base", "file"),
                             ("kwp keymap file", "kwp_keymap", "file"),
                             ("kwp route file", "kwp_route", "file"),
                             ("PCFG guesser (.py)", "pcfg_path", "file"),
                             ("PCFG ruleset dir", "pcfg_ruleset", "dir"),
                             ("John run/ folder", "john_dir", "dir"),
                             ("Strawberry Perl (perl.exe)", "perl_path", "file"),
                             ("GPU temp-abort °C (blank = off)", "temp_abort", None),
                             ("Phone push — ntfy topic", "ntfy_topic", None)):
            row(lbl, key, br)
        self.v_notify = ctk.BooleanVar(value=bool(self.cfg.get("notify_sound", True)))
        nf = ctk.CTkFrame(wrap, fg_color="transparent"); nf.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(nf, text="Notify on finish", width=180, anchor="w", text_color=MUTE).pack(side="left", padx=6)
        ctk.CTkCheckBox(nf, text="sound + alert when a job finishes / cracks", variable=self.v_notify).pack(side="left")
        tf = ctk.CTkFrame(wrap, fg_color="transparent"); tf.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(tf, text="Theme", width=180, anchor="w", text_color=MUTE).pack(side="left", padx=6)
        self.v_theme = ctk.StringVar(value=self.cfg.get("theme", "dark"))
        ctk.CTkOptionMenu(tf, variable=self.v_theme, values=["dark", "light", "system"], fg_color=CARD2,
                          button_color=ACCENT2, command=lambda v: ctk.set_appearance_mode(v)).pack(side="left", padx=6)
        brow = ctk.CTkFrame(wrap, fg_color="transparent"); brow.pack(fill="x", padx=6, pady=12)
        ctk.CTkButton(brow, text="💾 Save settings", command=self.save_settings, width=160,
                      fg_color=OK, text_color="#04140c").pack(side="left", padx=4)
        ctk.CTkButton(brow, text="🔎 Auto-detect tools", width=160, fg_color=CARD2,
                      command=lambda: (self.tools.update(locate_all(self.cfg)), self.show_tools_info())).pack(side="left", padx=8)

    # ============================================================== behaviour
    def attack_key(self):
        return ATTACK_KEY.get(self.v_attack.get(), "dict")

    def hash_mode(self):
        for label, m in HASH_MODES:
            if label == self.v_hashmode.get():
                return (self.v_custmode.get().strip() or "22000") if m == "custom" else m
        return "22000"

    def _resolve_wl(self, w):
        # a bare filename (e.g. "rockyou.txt") -> your Wordlist folder, else the bundled wordlists
        if w and not os.path.isabs(w) and (os.sep not in w) and ("/" not in w):
            base = self.cfg.get("wordlist_dir") or ""
            if base and os.path.exists(os.path.join(base, w)):
                return os.path.join(base, w)
            bundled = os.path.join(str(pc.WORDLISTS_DIR), w)
            if os.path.exists(bundled):
                return bundled
            if base:
                return os.path.join(base, w)
        return w

    def current_plan(self):
        atk = self.attack_key()
        hc = self.tools.get("hashcat") or "hashcat"
        if self.v_engine.get().startswith("aircrack"):
            wl = self._resolve_wl(self.wordlists[0]) if self.wordlists else "<wordlist>"
            return ("single", build_aircrack_cmd(self.tools.get("aircrack") or "aircrack-ng",
                                                  self.capfile or "<capture.cap>", wl))
        if atk in ("prince", "kwp", "pcfg"):
            cons = build_hashcat_stdin_cmd(hc, self.hashfile or "<target.hc22000>",
                                           workload=self.v_workload.get(), extra=self.cfg.get("extra_flags", ""),
                                           optimized=self.v_opt.get(), device=self.v_device.get(),
                                           session=self.v_session.get(), mode=self.hash_mode())
            wl0 = self._resolve_wl(self.wordlists[0]) if self.wordlists else "<wordlist>"
            if atk == "prince":
                gen = build_prince_cmd(self.cfg.get("prince_path") or "pp64", wl0)
            elif atk == "kwp":
                gen = build_kwp_cmd(self.cfg.get("kwp_path") or "kwp", self.cfg.get("kwp_base") or "<base>",
                                    self.cfg.get("kwp_keymap") or "<keymap>", self.cfg.get("kwp_route") or "<route>")
            else:
                gen = build_pcfg_cmd(self.cfg.get("pcfg_path") or "<pcfg.py>", self.cfg.get("pcfg_ruleset", ""))
            return ("pipe", gen, self._augment(cons))
        cmd = build_hashcat_cmd(
            hc, self.hashfile or "<target.hc22000>", atk,
            [self._resolve_wl(w) for w in self.wordlists] or ["<wordlist>"],
            self.v_rules.get(), self.v_mask.get(), workload=self.v_workload.get(),
            extra=self.cfg.get("extra_flags", ""), optimized=self.v_opt.get(), increment=self.v_inc.get(),
            device=self.v_device.get(), session=self.v_session.get(),
            charsets=[self.v_cs1.get(), self.v_cs2.get()],
            inc_min=self.v_incmin.get(), inc_max=self.v_incmax.get(),
            markov_threshold=self.v_markov.get(), mode=self.hash_mode())
        return ("single", self._augment(cmd))

    def _augment(self, cmd):
        """Append optional flags: GPU temp-abort guard, a 2nd stacked rules file."""
        try:
            temp = str(self.cfg.get("temp_abort", "") or "").strip()
            if temp and "--hwmon-temp-abort" not in " ".join(cmd):
                cmd = cmd + ["--hwmon-temp-abort", temp]
            r2 = (self.v_rules2.get().strip() if hasattr(self, "v_rules2") else "")
            if r2 and self.attack_key() == "rules":
                cmd = cmd + ["-r", r2]
        except Exception:
            pass
        return cmd

    def _perl_env(self):
        """PATH so Strawberry Perl's XS DLLs (in c\\bin) load — 7z2john.pl etc. need it."""
        env = os.environ.copy()
        perl = self.tools.get("perl") or ""
        try:
            d = os.path.dirname(perl)                       # ...\perl\bin
            root = os.path.dirname(os.path.dirname(d))      # ...\ (strawberry root)
            cbin = os.path.join(root, "c", "bin")
            sbin = os.path.join(root, "perl", "site", "bin")
            if os.path.isdir(cbin):
                env["PATH"] = os.pathsep.join([sbin, d, cbin]) + os.pathsep + env.get("PATH", "")
        except Exception:
            pass
        return env

    def _preview(self):
        try:
            plan = self.current_plan()
            self.preview.delete("1.0", "end")
            if plan[0] == "single":
                self.preview.insert("1.0", " ".join(pc._quote(c) for c in plan[1]))
            else:
                self.preview.insert("1.0", " ".join(pc._quote(c) for c in plan[1]) + "  |  " +
                                    " ".join(pc._quote(c) for c in plan[2]))
        except Exception as e:
            self.preview.delete("1.0", "end"); self.preview.insert("1.0", "(%s)" % e)

    def _apply_preset(self):
        for name, m in MASK_PRESETS:
            if name == self.v_preset.get():
                self.v_mask.set(m); break

    def _mask_help(self):
        w = ctk.CTkToplevel(self); w.title("Mask legend"); w.geometry("580x540")
        w.configure(fg_color=PANEL)
        box = ctk.CTkTextbox(w, wrap="word", font=ctk.CTkFont(family="Consolas", size=12))
        box.pack(fill="both", expand=True, padx=10, pady=10)
        box.insert("1.0", MASK_HELP_TEXT); box.configure(state="disabled")

    def _refresh_wl(self):
        self.wl_lbl.configure(text=("\n".join(os.path.basename(w) for w in self.wordlists) or "(none)"))
        self._preview()

    def add_wordlist(self):
        p = filedialog.askopenfilename(title="Wordlist", initialdir=self.cfg.get("wordlist_dir") or "/")
        if p and p not in self.wordlists:
            self.wordlists.append(p); self._refresh_wl()

    def quick_wl(self, fname):
        base = self.cfg.get("wordlist_dir") or ""
        cand = os.path.join(base, fname) if base else ""
        if not (cand and os.path.exists(cand)):
            b = os.path.join(str(pc.WORDLISTS_DIR), fname)
            cand = b if os.path.exists(b) else cand
        if not cand:
            messagebox.showinfo(APP_NAME, "Set your Wordlist folder in Settings first (or use ＋ Add)."); return
        if cand not in self.wordlists:
            self.wordlists.append(cand); self._refresh_wl()

    def pick_rules(self):
        p = filedialog.askopenfilename(title="Rule file", initialdir=self.cfg.get("rules_dir") or "/",
                                       filetypes=[("Rules", "*.rule"), ("All", "*.*")])
        if p:
            self.v_rules.set(p)

    def pick_rules2(self):
        p = filedialog.askopenfilename(title="2nd rule file (stacked)", initialdir=self.cfg.get("rules_dir") or "/",
                                       filetypes=[("Rules", "*.rule"), ("All", "*.*")])
        if p:
            self.v_rules2.set(p)

    def _detect_gpus(self):
        gpus = []
        try:
            r = subprocess.run(["nvidia-smi", "--query-gpu=index,name", "--format=csv,noheader"],
                               capture_output=True, text=True, timeout=6)
            for ln in (r.stdout or "").strip().splitlines():
                parts = ln.split(",", 1)
                if len(parts) == 2:
                    gpus.append((parts[0].strip(), parts[1].strip()))
        except Exception:
            pass
        return gpus

    def _gpu_options(self):
        opts = ["all devices"] + ["%s: %s" % (i, n) for i, n in self._detect_gpus()]
        return opts if opts else ["all devices"]

    def _pick_gpu(self, choice):
        if choice.startswith("all"):
            self.v_device.set("")
        else:
            self.v_device.set(choice.split(":", 1)[0].strip())

    # ---- target actions
    def _add_caps(self, paths):
        for p in paths:
            if p and p not in self.captures:
                self.captures.append(p)
        self.cap_list.delete(0, "end")
        for p in self.captures:
            self.cap_list.insert("end", os.path.basename(p))

    def import_files(self):
        paths = filedialog.askopenfilenames(title="Select capture(s)", initialdir=self.cfg.get("loot_dir") or "/",
                filetypes=[("Captures", "*.pcap *.pcapng *.cap *.hccapx *.hc22000 *.22000"), ("All", "*.*")])
        if paths:
            self._add_caps(list(paths))

    def pull_loot(self):
        base = self.cfg.get("loot_dir") or ""
        if not base or not os.path.isdir(base):
            base = filedialog.askdirectory(title="Loot folder", initialdir=base or "/")
            if not base:
                return
        found = []
        for ext in ("*.pcap", "*.pcapng", "*.cap", "*.hccapx", "*.hc22000", "*.22000"):
            try:
                for x in pc.Path(base).rglob(ext):
                    if x.is_file() and x.stat().st_size > 0:
                        found.append(str(x))
            except Exception:
                pass
        if found:
            self._add_caps(sorted(set(found)))
            self._set_status("Pulled %d capture(s) from loot." % len(set(found)))
        else:
            messagebox.showinfo(APP_NAME, "No capture files found in:\n%s" % base)

    def use_selected(self):
        sel = self.cap_list.curselection()
        if not sel:
            return
        p = self.captures[sel[0]]
        if p.lower().endswith((".hc22000", ".22000", ".hccapx")):
            self.hashfile = p
            self._update_target()
        else:
            self.capfile = p
            self._update_target()
            if getattr(self, "v_autoconv", None) and self.v_autoconv.get():
                self.convert_server()

    def _update_target(self):
        t = os.path.basename(self.hashfile) or "— (convert a .pcap first)"
        cap = os.path.basename(self.capfile) or "—"
        self.tgt_lbl2.configure(text="Target hash: %s     Capture: %s" % (t, cap))
        self.tgt_lbl.configure(text="Target: %s" % (os.path.basename(self.hashfile) or os.path.basename(self.capfile) or "none"))
        self._preview()

    def convert_server(self):
        src = self.capfile or (self.captures[self.cap_list.curselection()[0]] if self.cap_list.curselection() else "")
        if not src:
            messagebox.showinfo(APP_NAME, "Select a .pcap/.cap capture first."); return
        # Community edition: LOCAL conversion only (no server).
        # 1) local hcxpcapngtool.exe (part of hcxtools), if its path is set
        hcx = self.tools.get("hcxpcapngtool") or self.cfg.get("hcxpcapngtool_path")
        if hcx and os.path.exists(hcx):
            self._set_status("Converting locally (hcxpcapngtool)…")
            threading.Thread(target=self._convert_local, args=(src, hcx), daemon=True).start()
            return
        # 2) WSL: run the Linux hcxpcapngtool via Windows Subsystem for Linux
        if self._wsl_hcx_available():
            self._set_status("Converting via WSL (hcxpcapngtool)…")
            threading.Thread(target=self._convert_wsl, args=(src,), daemon=True).start()
            return
        messagebox.showwarning(APP_NAME,
            "No local converter found.\n\n"
            "Set up local .pcap → .hc22000 conversion one of these ways:\n"
            "  •  run “PineCrack – Set up WSL” from the Start Menu (installs WSL + hcxtools), or\n"
            "  •  re-run the installer and tick “Set up WSL + hcxtools”, or\n"
            "  •  set a Windows hcxpcapngtool.exe path in Settings.")

    def _wsl_hcx_available(self):
        if getattr(self, "_wsl_ok", None) is not None:
            return self._wsl_ok
        self._wsl_ok = False
        try:
            r = subprocess.run(["wsl", "-e", "sh", "-c", "command -v hcxpcapngtool"],
                               capture_output=True, text=True, timeout=15,
                               creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            self._wsl_ok = bool((r.stdout or "").strip())
        except Exception:
            self._wsl_ok = False
        return self._wsl_ok

    def _convert_wsl(self, src):
        # Compute the /mnt/<drive>/... path in Python. (Calling `wsl wslpath` returns
        # UTF-16 text that gets garbled when captured, which corrupts the path.)
        def towsl(p):
            p = os.path.abspath(p)
            drive, rest = os.path.splitdrive(p)
            if not drive:  # UNC path (\\server\share) — WSL can't reach it
                return None
            return "/mnt/" + drive[0].lower() + rest.replace("\\", "/")
        import tempfile, shutil
        tmpdir = None
        try:
            work = src
            # WSL can't read \\server\share paths — copy the capture to a local temp first.
            if towsl(src) is None or str(src).startswith("\\\\"):
                tmpdir = tempfile.mkdtemp(prefix="pinecrack_")
                work = os.path.join(tmpdir, os.path.basename(src) or "capture.pcap")
                shutil.copy2(src, work)
            out_win = os.path.splitext(work)[0] + ".hc22000"
            r = subprocess.run(["wsl", "hcxpcapngtool", "-o", towsl(out_win), towsl(work)],
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180,
                               creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            report = (r.stdout or "") + (r.stderr or "")
            for ln in report.splitlines():
                if any(k in ln for k in ("PMKID", "EAPOL", "handshake", "written", "read", "frames", "networks")):
                    self.ev.put(("log", "[hcx] " + ln.strip()))
            if os.path.exists(out_win) and os.path.getsize(out_win) > 0:
                final = out_win
                if tmpdir:  # capture came from a network share — save the result somewhere local
                    dest = os.path.dirname(os.path.abspath(src))
                    if str(src).startswith("\\\\") or not os.path.isdir(dest):
                        dest = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "PineCrack", "converted")
                    os.makedirs(dest, exist_ok=True)
                    final = os.path.join(dest, os.path.basename(out_win))
                    shutil.copy2(out_win, final)
                self.ev.put(("converted", final))
            else:
                tail = "\n".join([l for l in report.splitlines() if l.strip()][-8:])
                self.ev.put(("convert_fail",
                    "hcxpcapngtool ran but produced no hash — this capture has no complete WPA "
                    "handshake (EAPOL 4-way) or PMKID.\n\nhcxpcapngtool report:\n" + (tail or "(no output)")))
        except Exception as ex:
            self.ev.put(("convert_fail", "WSL convert failed: %s" % ex))
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)

    def _convert_local(self, src, hcx):
        try:
            out = os.path.splitext(src)[0] + ".hc22000"
            r = subprocess.run(build_convert_cmd(hcx, src, out), capture_output=True, text=True, timeout=120,
                               creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            report = (r.stdout or "") + (r.stderr or "")
            for ln in report.splitlines():
                if any(k in ln for k in ("PMKID", "EAPOL", "handshake", "written", "read", "frames", "networks")):
                    self.ev.put(("log", "[hcx] " + ln.strip()))
            if os.path.exists(out) and os.path.getsize(out) > 0:
                self.ev.put(("converted", out))
            else:
                tail = "\n".join([l for l in report.splitlines() if l.strip()][-8:])
                self.ev.put(("convert_fail", "hcxpcapngtool produced no hash — no complete WPA handshake (EAPOL) "
                                             "or PMKID in this capture.\n\nhcxpcapngtool report:\n" + (tail or "(no output)")))
        except Exception as ex:
            self.ev.put(("convert_fail", "Local convert failed: %s\n\nCheck the hcxpcapngtool.exe path in Settings." % ex))

    def _convert_worker(self, src, host, user, key):
        try:
            import paramiko
            c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(host, 22, user, key_filename=key, timeout=20)
            sftp = c.open_sftp()
            rin = "/tmp/pc_%s" % os.path.basename(src)
            rout = rin + ".hc22000"
            try:
                c.exec_command("rm -f '%s'" % rout)
            except Exception:
                pass
            sftp.put(src, rin)
            hcx = self.cfg.get("server_hcx") or "hcxpcapngtool"
            _, o, e = c.exec_command("%s -o '%s' '%s' 2>&1" % (hcx, rout, rin), timeout=90)
            report = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
            for ln in report.splitlines():
                if any(k in ln for k in ("PMKID", "EAPOL", "handshake", "written", "read", "frames", "networks")):
                    self.ev.put(("log", "[hcx] " + ln.strip()))
            size = 0
            try:
                size = sftp.stat(rout).st_size
            except Exception:
                size = 0
            if not size:
                sftp.close(); c.close()
                self.ev.put(("convert_fail",
                             "No usable handshake in this capture.\n\n"
                             "The .pcap must contain a full WPA handshake (EAPOL, ideally all "
                             "4 messages) or a PMKID. This file has neither.\n\n"
                             "Fix: capture again while a client (re)connects to the AP "
                             "(deauth → reconnect), then convert."))
                return
            local = os.path.splitext(src)[0] + ".hc22000"
            sftp.get(rout, local)
            sftp.close(); c.close()
            self.ev.put(("converted", local))
        except Exception as ex:
            self.ev.put(("convert_fail",
                         "Convert failed: %s\n\nCheck: SSH server reachable? key authorized? "
                         "hcxpcapngtool on the server? Valid .pcap/.pcapng/.cap file?" % ex))

    # ---- watch-folder auto-crack + handshake quality
    def _scan_loot(self, base):
        found = []
        for ext in ("*.hc22000", "*.22000", "*.cap", "*.pcap", "*.pcapng"):
            try:
                for x in pc.Path(base).rglob(ext):
                    if x.is_file() and x.stat().st_size > 0:
                        found.append(str(x))
            except Exception:
                pass
        return found

    def toggle_watch(self):
        if self.watch.get("active"):
            self.watch["active"] = False
            self.watch_btn.configure(text="👁 Watch loot")
            self._set_status("Watch stopped.")
            return
        base = self.cfg.get("loot_dir") or ""
        if not base or not os.path.isdir(base):
            messagebox.showwarning(APP_NAME, "Set a valid Loot folder in Settings first."); return
        self.watch["active"] = True
        self.watch["seen"] = set(self._scan_loot(base))
        self.watch_btn.configure(text="👁 Watching…")
        self._set_status("👁 Watching loot — new captures auto-convert + auto-crack.")
        threading.Thread(target=self._watch_loop, args=(base,), daemon=True).start()

    def _watch_loop(self, base):
        while self.watch.get("active"):
            try:
                cur = set(self._scan_loot(base))
                new = cur - self.watch.get("seen", set())
                if new:
                    self.watch["seen"] = cur
                    for f in sorted(new):
                        self.ev.put(("watch_new", f))
            except Exception:
                pass
            time.sleep(5)

    def _handle_watch_new(self, path):
        self._add_caps([path])
        self.log_box.insert("end", "[watch] new capture: %s\n" % os.path.basename(path)); self.log_box.see("end")
        if path.lower().endswith((".hc22000", ".22000")):
            self.hashfile = path; self._update_target()
            if not self.runner.is_running() and not self.queue_active:
                self.start_auto()
        elif path.lower().endswith((".cap", ".pcap", ".pcapng")):
            host = self.cfg.get("server_host"); user = self.cfg.get("server_user"); key = self.cfg.get("server_key")
            if host and user and key:
                self.watch["autocrack"] = True
                self._set_status("👁 Converting new capture on server…")
                threading.Thread(target=self._convert_worker, args=(path, host, user, key), daemon=True).start()
            else:
                self.log_box.insert("end", "[watch] .pcap needs server convert — set server in Settings.\n")

    def do_hs_check(self):
        src = self.hashfile or self.capfile
        if not src:
            messagebox.showinfo(APP_NAME, "Load a target/capture first (Use selected)."); return
        if src.lower().endswith((".hc22000", ".22000")):
            tg = parse_hc22000(src)
            if not tg:
                messagebox.showwarning(APP_NAME, "⚠ No handshakes parsed — file looks empty/invalid.\nRe-capture or re-convert."); return
            types = {}
            for e, t, m in tg:
                types[t] = types.get(t, 0) + 1
            tail = "\n".join("%-22s  %-6s  %s" % (e, t, m) for e, t, m in tg[:30])
            messagebox.showinfo(APP_NAME + " · handshake quality",
                                "✅ %d crackable handshake(s):  %s\n\nESSID / type / AP-MAC\n%s"
                                % (len(tg), ", ".join("%d× %s" % (v, k) for k, v in types.items()), tail))
        else:
            messagebox.showinfo(APP_NAME, "This is a raw .pcap — convert it first (Convert .pcap); "
                                          "conversion verifies EAPOL/PMKID presence. Then re-check the .hc22000.")

    # ---- profiles
    def load_profile(self):
        p = (self.cfg.get("profiles", {}) or {}).get(self.v_profile.get())
        if not p:
            return
        self.v_engine.set(p.get("engine", "hashcat (GPU)")); self.v_attack.set(p.get("attack", "Dictionary"))
        self.v_workload.set(p.get("workload", "3")); self.wordlists = list(p.get("wordlists", []))
        self.v_rules.set(p.get("rules", "")); self.v_mask.set(p.get("mask", ""))
        self.v_opt.set(p.get("opt", False)); self.v_inc.set(p.get("inc", False))
        self.v_incmin.set(p.get("inc_min", "")); self.v_incmax.set(p.get("inc_max", ""))
        self.v_device.set(p.get("device", "")); self.v_session.set(p.get("session", ""))
        self.v_cs1.set(p.get("cs1", "")); self.v_cs2.set(p.get("cs2", ""))
        self.v_markov.set(p.get("markov", "")); self.v_custmode.set(p.get("custmode", ""))
        self.v_hashmode.set(p.get("hashmode", HASH_MODES[0][0]))
        self._refresh_wl(); self._set_status("Profile loaded: %s" % self.v_profile.get())

    def collect_profile(self):
        return {"engine": self.v_engine.get(), "attack": self.v_attack.get(),
                "workload": self.v_workload.get(), "wordlists": list(self.wordlists),
                "rules": self.v_rules.get(), "mask": self.v_mask.get(),
                "opt": self.v_opt.get(), "inc": self.v_inc.get(), "device": self.v_device.get(),
                "session": self.v_session.get(), "cs1": self.v_cs1.get(), "cs2": self.v_cs2.get(),
                "inc_min": self.v_incmin.get(), "inc_max": self.v_incmax.get(),
                "markov": self.v_markov.get(), "hashmode": self.v_hashmode.get(),
                "custmode": self.v_custmode.get()}

    def save_profile(self):
        name = (self.v_profname.get().strip() or self.v_profile.get().strip())
        if not name:
            messagebox.showinfo(APP_NAME, "Enter a profile name."); return
        profs = self.cfg.get("profiles", {}) or {}
        profs[name] = self.collect_profile()
        self.cfg.set("profiles", profs); self.cfg.save()
        self.prof_menu.configure(values=list(profs.keys())); self.v_profile.set(name)
        self._set_status("Profile saved: %s" % name)

    # ---- run control
    def _run(self, cmd):
        self.log_box.delete("1.0", "end"); self.progress.set(0)
        for c in (self.c_speed, self.c_prog, self.c_eta, self.c_rec, self.c_temp):
            c.configure(text="—")
        self.spark.clear()
        self.run_before = {r[1] for r in self._cracked_rows()}; self.job_started = time.time()
        if not self.runner.start(cmd, cwd=cwd_for(cmd)):
            messagebox.showinfo(APP_NAME, "A job is already running.")

    def start_attack(self):
        if self.v_engine.get().startswith("aircrack"):
            if not self.capfile or not self.wordlists:
                messagebox.showwarning(APP_NAME, "aircrack needs a .cap and a wordlist."); return
        else:
            if not self.tools.get("hashcat"):
                messagebox.showwarning(APP_NAME, "hashcat not found (Settings)."); return
            if not self.hashfile:
                messagebox.showwarning(APP_NAME, "No target. Load one in Target."); return
            if self.attack_key() in ("dict", "rules", "combinator", "hybrid_wm", "hybrid_mw", "prince") and not self.wordlists:
                messagebox.showwarning(APP_NAME, "Add at least one wordlist (Attack)."); return
        self._show("Dashboard"); self._set_status("Running…")
        if not self.v_engine.get().startswith("aircrack") and not self.v_session.get().strip():
            self.v_session.set("pinecrack")   # ensures ♻ Restore can find the session
        plan = self.current_plan()
        self.log_box.delete("1.0", "end"); self.progress.set(0); self.spark.clear()
        self.run_before = {r[1] for r in self._cracked_rows()}; self.job_started = time.time()
        if plan[0] == "single":
            if not self.runner.start(plan[1], cwd=cwd_for(plan[1])):
                messagebox.showinfo(APP_NAME, "A job is already running.")
        else:
            if not self.runner.start_pipe(plan[1], plan[2], cwd=cwd_for(plan[2])):
                messagebox.showinfo(APP_NAME, "A job is already running.")

    def do_restore(self):
        hc = self.tools.get("hashcat")
        if not hc:
            messagebox.showwarning(APP_NAME, "hashcat not found."); return
        if self.runner.is_running():
            messagebox.showinfo(APP_NAME, "A job is already running."); return
        sess = self.v_session.get().strip() or "pinecrack"
        self._show("Dashboard"); self._set_status("Resuming session '%s'…" % sess)
        self._run([hc, "--session", sess, "--restore"])

    def start_auto(self):
        if self.runner.is_running():
            messagebox.showinfo(APP_NAME, "A job is already running."); return
        if not self.hashfile:
            messagebox.showwarning(APP_NAME, "Load a target first (Target)."); return
        names = sorted((self.cfg.get("profiles", {}) or {}).keys())
        if not names:
            messagebox.showwarning(APP_NAME, "No profiles saved."); return
        self.auto.update({"active": True, "queue": names, "idx": 0})
        self._show("Dashboard")
        self._set_status("⚡ Auto-crack 1/%d — %s" % (len(names), names[0]))
        self.v_profile.set(names[0]); self.load_profile()
        self.after(350, self.start_attack)

    def _auto_advance(self, cracked):
        if not self.auto["active"]:
            return
        if cracked:
            self.auto["active"] = False
            self._set_status("⚡ Auto-crack: PASSWORD FOUND ✅")
            notify(self.cfg, APP_NAME, "Auto-crack found the password!", cracked=True); self._flash()
            return
        self.auto["idx"] += 1
        if self.auto["idx"] >= len(self.auto["queue"]):
            self.auto["active"] = False
            self._set_status("⚡ Auto-crack: all profiles done — not found.")
            notify(self.cfg, APP_NAME, "Auto-crack finished — not found.", cracked=False)
            return
        name = self.auto["queue"][self.auto["idx"]]
        self._set_status("⚡ Auto-crack %d/%d — %s" % (self.auto["idx"] + 1, len(self.auto["queue"]), name))
        self.v_profile.set(name); self.load_profile()
        self.after(600, self.start_attack)

    # ---- pause / stop / sessions manager
    def pause_job(self):
        if not self.runner.is_running():
            self._set_status("Nothing running to pause."); return
        self.auto["active"] = False; self.queue_active = False
        self.runner.stop()
        self._set_status("⏸ Paused — click ♻ Restore (or Sessions) to continue.")

    def stop_all(self):
        self.auto["active"] = False; self.queue_active = False
        self.runner.stop()
        self._set_status("Stopped.")

    def sessions_manager(self):
        hc = self.tools.get("hashcat")
        sess = list_restore_sessions(hc)
        dlg = ctk.CTkToplevel(self); dlg.title("Resumable sessions"); dlg.geometry("560x360")
        dlg.configure(fg_color=PANEL)
        ctk.CTkLabel(dlg, text="Saved hashcat sessions (.restore)", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=14, pady=(12, 2))
        lb = tk.Listbox(dlg, bg="#0a0e15", fg="#cbd5e1", selectbackground=ACCENT, selectforeground="#04121a",
                        highlightthickness=0, borderwidth=0, font=("Consolas", 10))
        lb.pack(fill="both", expand=True, padx=12, pady=8)
        for name, full, mtime, size in sess:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
            lb.insert("end", "%-16s  %s  %d B" % (name, when, size))
        if not sess:
            lb.insert("end", "(no saved sessions — Stop a running job to create one)")

        def resume_sel():
            i = lb.curselection()
            if not i or not sess:
                return
            name = sess[i[0]][0]; dlg.destroy()
            if not hc:
                messagebox.showwarning(APP_NAME, "hashcat not found."); return
            if self.runner.is_running():
                messagebox.showinfo(APP_NAME, "A job is already running."); return
            self.v_session.set(name)
            self._show("Dashboard"); self._set_status("Resuming '%s'…" % name)
            self.run_before = {r[1] for r in self._cracked_rows()}; self.job_started = time.time()
            self._run([hc, "--session", name, "--restore"])

        def delete_sel():
            i = lb.curselection()
            if not i or not sess:
                return
            full = sess[i[0]][1]
            if messagebox.askyesno(APP_NAME, "Delete this restore point? (cannot resume after)"):
                try:
                    os.remove(full)
                except Exception as e:
                    messagebox.showerror(APP_NAME, str(e)); return
                dlg.destroy(); self.sessions_manager()
        r = ctk.CTkFrame(dlg, fg_color="transparent"); r.pack(fill="x", padx=12, pady=(0, 12))
        ctk.CTkButton(r, text="▶ Resume selected", command=resume_sel, fg_color=OK, text_color="#04140c").pack(side="left")
        ctk.CTkButton(r, text="🗑 Delete", command=delete_sel, fg_color="#7f1d1d").pack(side="left", padx=8)

    # ---- job queue
    def _profile_label(self, p):
        wl = ", ".join(os.path.basename(w) for w in p.get("wordlists", [])) or p.get("mask", "") or "?"
        return "%s | %s | %s" % (p.get("attack", "?"), wl, os.path.basename(self.hashfile) or "?")

    def queue_add(self):
        if not self.hashfile:
            messagebox.showwarning(APP_NAME, "Load a target first (Target)."); return
        prof = self.collect_profile()
        self.queue.append({"label": self._profile_label(prof), "hashfile": self.hashfile,
                           "profile": prof, "status": "pending"})
        self.refresh_queue(); self._set_status("Added to queue (%d job(s))." % len(self.queue))

    _QICON = {"pending": "• pending", "running": "▶ running", "done": "✓ done", "cracked": "🔓 CRACKED"}

    def refresh_queue(self):
        if not hasattr(self, "queue_tree"):
            return
        for i in self.queue_tree.get_children():
            self.queue_tree.delete(i)
        for i, j in enumerate(self.queue):
            st = j.get("status", "pending")
            p = j["profile"]
            detail = ", ".join(os.path.basename(w) for w in p.get("wordlists", [])) or p.get("mask", "") or "—"
            self.queue_tree.insert("", "end", tags=(st,),
                                   values=(i + 1, self._QICON.get(st, st), p.get("attack", "?"),
                                           detail, os.path.basename(j.get("hashfile", "")) or "?"))
        n = len(self.queue)
        done = sum(1 for j in self.queue if j.get("status") in ("done", "cracked"))
        run = sum(1 for j in self.queue if j.get("status") == "running")
        self.queue_count.configure(text=("%d job(s) — %d done, %d running, %d pending"
                                         % (n, done, run, n - done - run)) if n else "Queue empty")

    def _queue_sel_index(self):
        sel = self.queue_tree.selection()
        return self.queue_tree.index(sel[0]) if sel else -1

    def queue_remove(self):
        i = self._queue_sel_index()
        if 0 <= i < len(self.queue):
            del self.queue[i]; self.refresh_queue()

    def queue_move(self, delta):
        i = self._queue_sel_index()
        j = i + delta
        if 0 <= i < len(self.queue) and 0 <= j < len(self.queue):
            self.queue[i], self.queue[j] = self.queue[j], self.queue[i]
            self.refresh_queue()
            kids = self.queue_tree.get_children()
            if j < len(kids):
                self.queue_tree.selection_set(kids[j])

    def queue_clear(self):
        self.queue.clear(); self.refresh_queue()

    def run_queue(self):
        if self.runner.is_running():
            messagebox.showinfo(APP_NAME, "A job is already running."); return
        if not self.queue:
            messagebox.showinfo(APP_NAME, "Queue is empty. Add attacks first."); return
        for j in self.queue:
            j["status"] = "pending"
        self.queue_active = True; self.queue_idx = 0
        self._show("Dashboard"); self._start_queue_item()

    def _start_queue_item(self):
        j = self.queue[self.queue_idx]
        j["status"] = "running"; self.refresh_queue()
        self.hashfile = j["hashfile"]
        self._apply_profile_dict(j["profile"]); self._update_target()
        self._set_status("≡ Queue %d/%d — %s" % (self.queue_idx + 1, len(self.queue), j["label"]))
        self.after(350, self.start_attack)

    def _apply_profile_dict(self, p):
        self.v_engine.set(p.get("engine", "hashcat (GPU)")); self.v_attack.set(p.get("attack", "Dictionary"))
        self.v_workload.set(p.get("workload", "3")); self.wordlists = list(p.get("wordlists", []))
        self.v_rules.set(p.get("rules", "")); self.v_mask.set(p.get("mask", ""))
        self.v_opt.set(p.get("opt", False)); self.v_inc.set(p.get("inc", False))
        self.v_incmin.set(p.get("inc_min", "")); self.v_incmax.set(p.get("inc_max", ""))
        self.v_device.set(p.get("device", "")); self.v_session.set(p.get("session", ""))
        self.v_cs1.set(p.get("cs1", "")); self.v_cs2.set(p.get("cs2", ""))
        self.v_markov.set(p.get("markov", "")); self.v_hashmode.set(p.get("hashmode", HASH_MODES[0][0]))
        self.v_custmode.set(p.get("custmode", "")); self._refresh_wl()

    def _queue_advance(self, cracked):
        if not self.queue_active:
            return
        if 0 <= self.queue_idx < len(self.queue):
            self.queue[self.queue_idx]["status"] = "cracked" if cracked else "done"
        self.refresh_queue()
        self.queue_idx += 1
        if self.queue_idx >= len(self.queue):
            self.queue_active = False
            self._set_status("≡ Queue finished (%d job(s))." % len(self.queue))
            notify(self.cfg, APP_NAME, "Job queue finished.", cracked=False)
            return
        self._start_queue_item()

    # ---- crack history
    def _cracked_rows(self):
        best, order = {}, []
        for src, fpath in (("potfile", POTFILE_PATH), ("outfile", OUTFILE_PATH)):
            try:
                if not fpath.exists():
                    continue
                for ln in fpath.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not ln.strip():
                        continue
                    tgt, pw, bssid = parse_crack_line(ln)
                    if not pw:
                        continue
                    if pw not in best:
                        best[pw] = (tgt, pw, bssid, src); order.append(pw)
                    elif not best[pw][0] and tgt:
                        best[pw] = (tgt, pw, bssid, src)
            except Exception:
                pass
        return [best[pw] for pw in order]

    def _log_new_cracks(self):
        rows = self._cracked_rows()
        new = [r for r in rows if r[1] not in self.run_before]
        if new:
            dt = int(time.time() - self.job_started) if self.job_started else 0
            append_history([{"ts": time.time(), "essid": r[0], "pw": r[1], "bssid": r[2], "secs": dt} for r in new])
        return len(new)

    def refresh_history(self):
        if not hasattr(self, "hist_tree"):
            return
        for i in self.hist_tree.get_children():
            self.hist_tree.delete(i)
        hist = load_history()
        for idx, h in enumerate(reversed(hist)):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(h.get("ts", 0)))
            secs = h.get("secs", 0)
            self.hist_tree.insert("", "end", values=(when, h.get("essid", ""), h.get("pw", ""),
                                                     fmt_duration(secs) if secs else "—"),
                                  tags=(("even" if idx % 2 else "odd"),))
        self.hist_stats.configure(text="Total cracked (all time): %d" % len(hist))
        self._draw_hist_chart(hist)

    def _draw_hist_chart(self, hist):
        c = getattr(self, "hist_canvas", None)
        if not c:
            return
        c.delete("all")
        w = c.winfo_width() or 800; h = c.winfo_height() or 72
        import collections as _co
        days = _co.Counter(time.strftime("%m-%d", time.localtime(e.get("ts", 0))) for e in hist)
        items = sorted(days.items())[-14:]
        if not items:
            c.create_text(10, h / 2, anchor="w", fill=MUTE, text="No cracks yet", font=("Segoe UI", 10)); return
        mx = max(v for _, v in items) or 1
        bw = w / max(1, len(items))
        for i, (d, v) in enumerate(items):
            x = i * bw; bh = (v / mx) * (h - 22)
            c.create_rectangle(x + 5, h - 16 - bh, x + bw - 5, h - 16, fill=ACCENT, outline="")
            c.create_text(x + bw / 2, h - 16 - bh - 6, fill=TEXT, text=str(v), font=("Segoe UI", 8))
            c.create_text(x + bw / 2, h - 6, fill=MUTE, text=d, font=("Segoe UI", 7))

    def clear_history(self):
        if not messagebox.askyesno(APP_NAME, "Delete ALL crack history?\n(backed up to *.jsonl.bak)"):
            return
        try:
            if HISTORY_PATH.exists():
                HISTORY_PATH.replace(HISTORY_PATH.with_suffix(HISTORY_PATH.suffix + ".bak"))
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e)); return
        self.refresh_history(); self._set_status("History cleared (.bak kept).")

    def export_history(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="crack_history.csv")
        if not p:
            return
        import csv
        with open(p, "w", newline="", encoding="utf-8") as fo:
            w = csv.writer(fo); w.writerow(["when", "essid", "password", "bssid", "seconds"])
            for h in load_history():
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h.get("ts", 0))),
                            h.get("essid", ""), h.get("pw", ""), h.get("bssid", ""), h.get("secs", 0)])
        self._set_status("Exported history → %s" % p)

    def do_estimate(self):
        if self.v_engine.get().startswith("aircrack"):
            messagebox.showinfo(APP_NAME, "Estimate is for hashcat attacks."); return
        atk = self.attack_key()
        n = estimate_candidates(atk, self.wordlists, self.v_rules.get(), self.v_mask.get())
        if not n:
            messagebox.showinfo(APP_NAME, "Can't estimate this attack (need wordlist/mask)."); return
        mode = self.hash_mode()
        self._set_status("Estimating… measuring GPU speed (-m %s)…" % mode)

        def worker():
            speed = self.bench_speed.get(mode) or self._measure_speed(mode)
            if speed:
                self.bench_speed[mode] = speed
                msg = ("Attack: %s\nCandidates: %s\nGPU speed: %s H/s (-m %s)\n\n➤  ~%s"
                       % (atk, human_count(n), human_count(speed), mode, fmt_duration(n / speed)))
            else:
                msg = "Candidates: %s\nCould not measure GPU speed." % human_count(n)
            self.ev.put(("estimate", msg))
        threading.Thread(target=worker, daemon=True).start()

    def _measure_speed(self, mode):
        hc = self.tools.get("hashcat")
        if not hc:
            return 0.0
        try:
            r = subprocess.run([hc, "-b", "-m", str(mode)], cwd=cwd_for([hc]),
                               capture_output=True, text=True, timeout=180,
                               creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            return parse_bench_speed(r.stdout or "")
        except Exception:
            return 0.0

    # ---- results
    def _count_cracked(self):
        seen = set()
        for fpath in (OUTFILE_PATH, POTFILE_PATH):
            try:
                if fpath.exists():
                    for ln in fpath.read_text(encoding="utf-8", errors="replace").splitlines():
                        if ln.strip():
                            _, pw, _ = parse_crack_line(ln)
                            if pw:
                                seen.add(pw)
            except Exception:
                pass
        return len(seen)

    def refresh_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        best, order = {}, []
        for src, fpath in (("potfile", POTFILE_PATH), ("outfile", OUTFILE_PATH)):
            try:
                if not fpath.exists():
                    continue
                for ln in fpath.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not ln.strip():
                        continue
                    tgt, pw, bssid = parse_crack_line(ln)
                    if not pw:
                        continue
                    cur = best.get(pw)
                    if cur is None:
                        best[pw] = (tgt, pw, bssid, src); order.append(pw)
                    elif not cur[0] and tgt:
                        best[pw] = (tgt, pw, bssid, src)
            except Exception:
                pass
        rows = [best[pw] for pw in order]
        for idx, r in enumerate(rows):
            self.tree.insert("", "end", values=r, tags=(("even" if idx % 2 else "odd"),))
        self.res_count.configure(text=("✅ %d cracked" % len(rows)) if rows else "No results yet",
                                 text_color=(OK if rows else MUTE))

    def copy_pw(self):
        pws = [self.tree.item(i, "values")[1] for i in self.tree.selection()
               if len(self.tree.item(i, "values")) > 1 and self.tree.item(i, "values")[1]]
        if not pws:
            return
        self.clipboard_clear(); self.clipboard_append("\n".join(pws))
        self._set_status("Copied %d password(s)." % len(pws))

    def copy_all(self):
        pws = [self.tree.item(i, "values")[1] for i in self.tree.get_children()
               if len(self.tree.item(i, "values")) > 1 and self.tree.item(i, "values")[1]]
        if not pws:
            return
        self.clipboard_clear(); self.clipboard_append("\n".join(pws))
        self._set_status("Copied all %d password(s)." % len(pws))

    def clear_results(self):
        if not messagebox.askyesno(APP_NAME, "Clear the results list?\n(potfile/outfile are backed up as *.bak)"):
            return
        for fpath in (OUTFILE_PATH, POTFILE_PATH):
            try:
                if fpath.exists():
                    fpath.replace(fpath.with_suffix(fpath.suffix + ".bak"))
            except Exception:
                pass
        self.refresh_results(); self._set_status("Results cleared (backup kept as .bak).")

    def export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="cracked.csv")
        if not p:
            return
        import csv
        with open(p, "w", newline="", encoding="utf-8") as fo:
            w = csv.writer(fo); w.writerow(["essid_or_target", "password", "bssid", "source"])
            for i in self.tree.get_children():
                w.writerow(self.tree.item(i, "values"))
        self._set_status("Exported → %s" % p)

    # ---- tools: wordlist generator + extractor
    def wordlist_gen(self):
        dlg = ctk.CTkToplevel(self); dlg.title("Targeted wordlist"); dlg.geometry("460x580")
        dlg.configure(fg_color=PANEL)
        ctk.CTkLabel(dlg, text="Personal info → targeted wordlist", font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=TEXT).pack(anchor="w", padx=14, pady=(12, 2))
        frm = ctk.CTkScrollableFrame(dlg, fg_color=BG, height=320); frm.pack(fill="both", expand=True, padx=10, pady=8)
        wv, nv = {}, {}
        for lbl in ("First name", "Surname", "Nickname", "Partner", "Pet", "Company/SSID", "City", "Keyword"):
            r = ctk.CTkFrame(frm, fg_color="transparent"); r.pack(fill="x", pady=3)
            ctk.CTkLabel(r, text=lbl, width=110, anchor="w", text_color=MUTE).pack(side="left", padx=6)
            v = ctk.StringVar(); ctk.CTkEntry(r, textvariable=v, width=250).pack(side="left"); wv[lbl] = v
        for lbl in ("Birth year", "Numbers (comma)"):
            r = ctk.CTkFrame(frm, fg_color="transparent"); r.pack(fill="x", pady=3)
            ctk.CTkLabel(r, text=lbl, width=110, anchor="w", text_color=MUTE).pack(side="left", padx=6)
            v = ctk.StringVar(); ctk.CTkEntry(r, textvariable=v, width=250).pack(side="left"); nv[lbl] = v
        opts = ctk.CTkFrame(dlg, fg_color="transparent"); opts.pack(fill="x", padx=12)
        leet = ctk.BooleanVar(value=True); spec = ctk.BooleanVar(value=True)
        comb = ctk.BooleanVar(value=True); ge8 = ctk.BooleanVar(value=False)
        for t, var in (("leet", leet), ("specials", spec), ("combine", comb), ("≥8", ge8)):
            ctk.CTkCheckBox(opts, text=t, variable=var).pack(side="left", padx=6, pady=6)

        def go():
            words = [v.get() for v in wv.values()]
            nums = []
            for v in nv.values():
                nums += v.get().replace(",", " ").split()
            wl = build_profile_wordlist(words, nums, {"leet": leet.get(), "specials": spec.get(),
                                                      "combine": comb.get(), "min_len": 8 if ge8.get() else 0})
            if not wl:
                messagebox.showwarning(APP_NAME, "Fill at least a name or number."); return
            out = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="targeted.txt",
                                               initialdir=self.cfg.get("wordlist_dir"))
            if not out:
                return
            with open(out, "w", encoding="utf-8") as fo:
                fo.write("\n".join(wl) + "\n")
            if messagebox.askyesno(APP_NAME, "Wrote %s candidates.\nUse now as a wordlist?" % human_count(len(wl))):
                if out not in self.wordlists:
                    self.wordlists.append(out); self._refresh_wl()
                self.v_attack.set("Dictionary")
            dlg.destroy()
        ctk.CTkButton(dlg, text="Generate & save…", command=go, fg_color=OK,
                      text_color="#04140c").pack(pady=12)

    def extract_hash(self):
        if not self.cfg.get("john_dir"):
            messagebox.showinfo(APP_NAME, "Set John run/ folder in Settings."); return
        dlg = ctk.CTkToplevel(self); dlg.title("Extract hash"); dlg.geometry("430x180"); dlg.configure(fg_color=PANEL)
        ctk.CTkLabel(dlg, text="File type", text_color=MUTE).pack(anchor="w", padx=12, pady=(12, 0))
        tv = ctk.StringVar(value=EXTRACTORS[0][0])
        ctk.CTkOptionMenu(dlg, variable=tv, values=[e[0] for e in EXTRACTORS], width=380,
                          fg_color=CARD2, button_color=ACCENT2).pack(padx=12, pady=6)

        def go():
            entry = next(e for e in EXTRACTORS if e[0] == tv.get())
            tool = find_extractor(self.cfg.get("john_dir"), entry[1])
            if not tool:
                messagebox.showwarning(APP_NAME, "Tool not found: %s" % entry[1]); return
            infile = filedialog.askopenfilename(title="File to extract from")
            if not infile:
                return
            try:
                r = subprocess.run(build_extractor_cmd(tool, infile, self.tools.get("perl") or "perl"),
                                   capture_output=True, text=True, env=self._perl_env(),
                                   timeout=180, creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            except Exception as ex:
                messagebox.showerror(APP_NAME, str(ex)); return
            h = clean_john_hash(r.stdout or "")
            if not h:
                messagebox.showerror(APP_NAME, "No hash produced.\n" + (r.stderr or "")[:300]); return
            out = infile + ".hash.txt"
            with open(out, "w", encoding="utf-8") as fo:
                fo.write(h + "\n")
            self.hashfile = out; self._add_caps([out]); self._update_target()
            mode = guess_hc_mode(h)
            if mode:
                for lbl, mm in HASH_MODES:
                    if mm == mode:
                        self.v_hashmode.set(lbl); break
            messagebox.showinfo(APP_NAME, "Extracted → target set.\nSuggested -m: %s" % entry[2])
            dlg.destroy()
        ctk.CTkButton(dlg, text="Choose file & extract…", command=go, fg_color=ACCENT,
                      text_color="#04121a").pack(pady=16)

    # ---- tools: analysis + benchmarks
    def do_benchmark_all(self):
        hc = self.tools.get("hashcat")
        if not hc:
            messagebox.showwarning(APP_NAME, "hashcat not found."); return
        self._show("Dashboard"); self.log_box.delete("1.0", "end"); self._set_status("Benchmarking Wi-Fi modes…")
        modes = [m for m, _ in BENCH_MODES if m in ("22000", "22001", "16800")]

        def worker():
            for m in modes:
                self.ev.put(("log", "=== hashcat -b -m %s ===" % m))
                try:
                    r = subprocess.run([hc, "-b", "-m", m], cwd=cwd_for([hc]), capture_output=True,
                                       text=True, timeout=300,
                                       creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
                    for ln in (r.stdout or "").splitlines():
                        if "Speed" in ln or "Hash.Mode" in ln:
                            self.ev.put(("log", ln.strip()))
                except Exception as e:
                    self.ev.put(("log", "error: %s" % e))
            self.ev.put(("log", "[benchmark done]"))
            self.ev.put(("status_txt", "Benchmark done."))
        threading.Thread(target=worker, daemon=True).start()

    def do_targets(self):
        if not self.hashfile:
            messagebox.showinfo(APP_NAME, "Load a .hc22000 target first."); return
        tg = parse_hc22000(self.hashfile)
        if not tg:
            messagebox.showinfo(APP_NAME, "No WPA entries parsed."); return
        txt = "\n".join("%-24s  %-6s  %s" % (e, t, m) for e, t, m in tg)
        messagebox.showinfo(APP_NAME + " · targets", "ESSID / type / AP-MAC\n\n" + txt[:3500])

    def do_identify_cap(self):
        hcx = self.tools.get("hcxpcapngtool")
        if not self.capfile or not hcx:
            messagebox.showinfo(APP_NAME, "Need a .pcap capture and hcxpcapngtool (or use Convert .pcap)."); return
        self._show("Dashboard"); self._run([hcx, "--all", "-o", os.devnull, self.capfile])

    def do_stats(self):
        p = filedialog.askopenfilename(title="Wordlist", initialdir=self.cfg.get("wordlist_dir"))
        if not p:
            return
        try:
            s = wordlist_stats(p)
            messagebox.showinfo(APP_NAME, "Wordlist: %s\n\nlines: %s\nusable (≥8): %s\nmin/avg/max: %s / %s / %s"
                                % (os.path.basename(p), human_count(s["total"]), human_count(s["ge8"]),
                                   s["min"], s["avg"], s["max"]))
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))

    def do_merge(self):
        ps = filedialog.askopenfilenames(title="Wordlists to merge", initialdir=self.cfg.get("wordlist_dir"))
        if not ps:
            return
        out = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="merged.txt")
        if not out:
            return
        try:
            n = merge_dedupe_files(list(ps), out)
            messagebox.showinfo(APP_NAME, "Wrote %s unique lines →\n%s" % (human_count(n), out))
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))

    def do_mutate(self):
        src = filedialog.askopenfilename(title="Wordlist to mutate", initialdir=self.cfg.get("wordlist_dir"))
        if not src:
            return
        out = os.path.splitext(src)[0] + "_mutated.txt"
        try:
            suff = ["", "1", "12", "123", "1234", "!", "01", "07"] + [str(y) for y in range(1970, 2031)]
            n = 0
            with open(src, "r", encoding="utf-8", errors="ignore") as fi, open(out, "w", encoding="utf-8") as fo:
                for w in fi:
                    w = w.strip()
                    if not w:
                        continue
                    for s in suff:
                        cand = w + s
                        if len(cand) >= 8:
                            fo.write(cand + "\n"); n += 1
            messagebox.showinfo(APP_NAME, "Wrote %s candidates →\n%s" % (human_count(n), out))
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))

    def do_genpattern(self):
        dlg = ctk.CTkToplevel(self); dlg.title("Pattern list"); dlg.geometry("360x230"); dlg.configure(fg_color=PANEL)
        ctk.CTkLabel(dlg, text="Prefix (e.g. 040 for SI mobile)", text_color=MUTE).pack(anchor="w", padx=12, pady=(12, 0))
        pv = ctk.StringVar(value="040"); ctk.CTkEntry(dlg, textvariable=pv).pack(fill="x", padx=12)
        ctk.CTkLabel(dlg, text="Digits after prefix", text_color=MUTE).pack(anchor="w", padx=12, pady=(8, 0))
        dv = ctk.StringVar(value="6"); ctk.CTkEntry(dlg, textvariable=dv).pack(fill="x", padx=12)

        def go():
            out = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="pattern.txt")
            if not out:
                return
            try:
                cap, full = gen_pattern_list(out, prefix=pv.get(), digits=int(dv.get() or "6"))
                messagebox.showinfo(APP_NAME, "Wrote %s of %s combos →\n%s" % (human_count(cap), human_count(full), out))
                dlg.destroy()
            except Exception as e:
                messagebox.showerror(APP_NAME, str(e))
        ctk.CTkButton(dlg, text="Generate…", command=go, fg_color=ACCENT, text_color="#04121a").pack(pady=14)

    def do_pmk_info(self):
        messagebox.showinfo(APP_NAME + " · precomputed PMK",
                            "Rainbow tables do NOT work for WPA (the salt is the ESSID).\n\n"
                            "Per-network alternative — precompute PMKs for ONE ESSID, then crack fast:\n"
                            "  hashcat -m 22001 (WPA-PMK) with precomputed PMKs  (~200 MH/s vs ~290 kH/s).\n\n"
                            "Only worth it when cracking the same network repeatedly.")

    def show_tools_info(self):
        info = ["Detected tools:"]
        for k, v in self.tools.items():
            info.append("  %-16s: %s" % (k, v or "NOT FOUND"))
        info.append("")
        info.append("GPU: " + self.gpu_name)
        messagebox.showinfo(APP_NAME + " · environment", "\n".join(info))

    def do_identify_hash(self):
        """Fast, offline identify (no hashcat backend init): file-type + signature +
        hex-length heuristics. hashcat --identify is slow and times out on network files."""
        if not self.hashfile:
            messagebox.showinfo(APP_NAME, "Load a target hash first (Target tab)."); return
        low = self.hashfile.lower()
        if low.endswith((".hc22000", ".22000", ".hccapx")):
            messagebox.showinfo(APP_NAME + " · hash identify",
                                "Wi-Fi handshake file.\n\n➤  Hash mode:  22000  (WPA-PMKID/EAPOL)")
            return
        line = ""
        try:
            with open(self.hashfile, "r", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    if ln.strip():
                        line = ln.strip(); break
        except Exception as e:
            messagebox.showerror(APP_NAME, "Can't read file: %s" % e); return
        if not line:
            messagebox.showwarning(APP_NAME, "File is empty."); return
        tok = clean_john_hash(line) if ("$" in line or "*" in line) else line
        mode = guess_hc_mode(tok if tok.startswith("$") else line)
        if mode:
            name = next((lbl for lbl, m in HASH_MODES if m == mode), mode)
            hint = "➤  Hash mode:  %s" % name
        else:
            h = line.split(":")[0].strip()
            hexonly = h and all(c in "0123456789abcdefABCDEF" for c in h)
            guesses = {32: "0 (MD5)  or  1000 (NTLM)", 40: "100 (SHA1)", 64: "1400 (SHA2-256)",
                       96: "10800 (SHA2-384)", 128: "1700 (SHA2-512)"}
            if hexonly and len(h) in guesses:
                hint = "Looks like a %d-hex hash  →  try:  %s" % (len(h), guesses[len(h)])
            else:
                hint = ("Couldn't auto-identify the signature.\n"
                        "Pick the Hash type manually on the Attack tab.")
        messagebox.showinfo(APP_NAME + " · hash identify", "Input:  %s…\n\n%s" % (line[:52], hint))

    def save_settings(self):
        for k, v in self.setting_vars.items():
            self.cfg.set(k, v.get())
        self.cfg.set("notify_sound", self.v_notify.get()); self.cfg.set("workload", self.v_workload.get())
        self.cfg.set("theme", self.v_theme.get()); self.cfg.save()
        self.tools.update(locate_all(self.cfg))
        self._set_status("Settings saved. Tools re-detected.")
        messagebox.showinfo(APP_NAME, "Saved.\nhashcat: %s\naircrack: %s" %
                            (self.tools.get("hashcat") or "—", self.tools.get("aircrack") or "—"))

    # ---- misc
    def _set_status(self, msg):
        self.title("%s %s   —   %s" % (APP_NAME, APP_VERSION, msg))

    def _flash(self):
        try:
            self.deiconify(); self.lift(); self.attributes("-topmost", True)
            self.after(1500, lambda: self.attributes("-topmost", False))
        except Exception:
            pass

    def _apply_status(self, js):
        try:
            speed = sum(d.get("speed", 0) for d in js.get("devices", []))
            self.c_speed.configure(text=human_count(speed) + "H/s", text_color=ACCENT)
            if speed > 0:
                self.bench_speed[self.hash_mode()] = speed
                self.spark.append(speed); self._draw_spark()
            prog = js.get("progress", [0, 0])
            if prog and prog[1]:
                frac = prog[0] / prog[1]
                self.progress.set(min(1.0, frac))
                self.c_prog.configure(text="%.1f%%" % (frac * 100))
            eta = "—"
            est = js.get("estimated_stop"); now = time.time()
            if isinstance(est, (int, float)) and est > now + 1:
                eta = fmt_duration(est - now)
            elif speed > 0 and prog and len(prog) > 1 and prog[1] > prog[0]:
                eta = fmt_duration((prog[1] - prog[0]) / speed)
            self.c_eta.configure(text=eta, text_color=WARN)
            rec = js.get("recovered_hashes", [0, 0])
            self.c_rec.configure(text="%s/%s" % (rec[0], rec[1]), text_color=OK)
            temps = [d.get("temp", -1) for d in js.get("devices", []) if d.get("temp", -1) >= 0]
            if temps:
                self.c_temp.configure(text="%d°C" % max(temps))
        except Exception:
            pass

    def _pump(self):
        try:
            while True:
                kind, payload = self.ev.get_nowait()
                if kind == "log":
                    self.log_box.insert("end", payload + "\n"); self.log_box.see("end")
                elif kind == "cmd":
                    self.log_box.insert("end", "$ " + payload + "\n"); self.log_box.see("end")
                elif kind == "error":
                    self.log_box.insert("end", "[ERROR] " + payload + "\n")
                elif kind == "status":
                    self._apply_status(payload)
                elif kind == "status_txt":
                    self._set_status(payload)
                elif kind == "estimate":
                    self._set_status("Ready.")
                    messagebox.showinfo(APP_NAME + " · time estimate", payload)
                elif kind == "identify":
                    self._set_status("Ready.")
                    messagebox.showinfo(APP_NAME + " · hash identify", payload)
                elif kind == "converted":
                    self.hashfile = payload; self._add_caps([payload]); self._update_target()
                    self._set_status("Converted on server → %s" % os.path.basename(payload))
                    if self.watch.get("autocrack"):
                        self.watch["autocrack"] = False
                        if not self.runner.is_running() and not self.queue_active:
                            self.start_auto()
                elif kind == "watch_new":
                    self._handle_watch_new(payload)
                elif kind == "convert_fail":
                    self.watch["autocrack"] = False
                    self._set_status("Convert failed.")
                    messagebox.showwarning(APP_NAME + " · convert", payload)
                elif kind == "done":
                    self.log_box.insert("end", "\n[finished, exit %s]\n" % payload); self.log_box.see("end")
                    self.refresh_results()
                    new = self._log_new_cracks()
                    self.refresh_history()
                    cracked = new > 0
                    if self.auto["active"]:
                        self._auto_advance(cracked)
                    elif self.queue_active:
                        self._queue_advance(cracked)
                    else:
                        self._set_status("Done (exit %s)." % payload)
                        if cracked:
                            notify(self.cfg, APP_NAME, "Password cracked!", cracked=True); self._flash()
                        elif self.cfg.get("notify_sound", True):
                            notify(self.cfg, APP_NAME, "Job finished — no crack.", cracked=False)
        except queue.Empty:
            pass
        self.after(200, self._pump)

    def _on_close(self):
        self.watch["active"] = False
        self.auto["active"] = False
        self.queue_active = False
        try:
            self.runner.stop()
        except Exception:
            pass
        self.destroy()


def main():
    app = PineCrack2()
    app.mainloop()


if __name__ == "__main__":
    main()
