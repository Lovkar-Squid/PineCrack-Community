#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PineCrack - WPA/WPA2 handshake cracking studio (GUI front-end)
================================================================
A desktop front-end that orchestrates standard, publicly available security
tools (hashcat, aircrack-ng, hcxtools) to recover Wi-Fi passwords from
handshakes/PMKIDs you have captured (e.g. with a WiFi Pineapple).

    AUTHORIZED USE ONLY. Only test networks you OWN or have explicit written
    permission to assess. Cracking Wi-Fi you are not authorized to test is
    illegal in most jurisdictions and is NOT the purpose of this tool.

This program does not capture, deauth or attack anything - it only cracks
handshakes you already possess, offline, on your own machine.

Run:  python pinecrack.py            (GUI)
      python pinecrack.py --selftest (headless logic check, no GUI deps)
"""

import os
import sys
import json
import shutil
import subprocess
import threading
import queue
import time
from pathlib import Path

APP_NAME = "PineCrack"
APP_VERSION = "1.3"
HASH_MODE_WPA = "22000"   # WPA-PBKDF2-PMKID+EAPOL (modern combined mode)

if getattr(sys, "frozen", False):          # PyInstaller .exe: keep the exe folder clean
    APP_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "PineCrack"
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        APP_DIR = Path(sys.executable).resolve().parent
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
else:
    APP_DIR = Path(__file__).resolve().parent
    BUNDLE_DIR = APP_DIR
CONFIG_PATH = APP_DIR / "pinecrack_config.json"
BUNDLED_CONFIG = BUNDLE_DIR / "pinecrack_config.json"
WORDLISTS_DIR = BUNDLE_DIR / "wordlists"   # starter wordlists shipped with the app (rockyou, ...)
POTFILE_PATH = APP_DIR / "pinecrack.potfile"
OUTFILE_PATH = APP_DIR / "cracked.txt"


def parse_crack_line(ln):
    """Parse one hashcat potfile/outfile line -> (target, password, bssid).
    Pure/testable. Handles the WPA-22000 outfile row
    (hash:ap_mac:client_mac:ESSID:password), PMKID/EAPOL star-separated
    hashlines, and generic hash[:salt]:password."""
    ln = (ln or "").strip()
    if not ln:
        return ("", "", "")
    parts = ln.split(":")
    if len(parts) < 2:
        return ("", ln, "")            # bare token = plain password (outfile-format 2)
    pw = parts[-1]

    def ishex(s):
        s = s.replace(" ", "")
        return len(s) > 0 and all(c in "0123456789abcdefABCDEF" for c in s)

    def fmtmac(s):
        s = s.replace(" ", "")
        return ":".join(s[i:i + 2] for i in range(0, 12, 2)).lower() if (ishex(s) and len(s) == 12) else s

    # WPA-22000 outfile:  hash:ap_mac:client_mac:ESSID:password
    if len(parts) >= 5 and len(parts[-4].replace(" ", "")) == 12 and ishex(parts[-4]) and ishex(parts[-3]):
        return (parts[-2], pw, fmtmac(parts[-4]))
    # PMKID/EAPOL hashline: WPA*<type>*<hash>*<ap_mac>*<sta_mac>*<essid_hex>[*..]:password
    if "*" in parts[0]:
        f = parts[0].split("*")
        essid, bssid = "", ""
        for cand in reversed(f):                    # ESSID: last hex field that decodes to text
            if len(cand) == 12 and ishex(cand):     # skip 12-hex MAC fields
                continue
            try:
                d = bytes.fromhex(cand).decode("utf-8")
                if d and d.isprintable():
                    essid = d
                    break
            except Exception:
                pass
        for cand in f:                              # BSSID: first 12-hex field (AP MAC)
            if len(cand) == 12 and ishex(cand):
                bssid = fmtmac(cand)
                break
        return (essid or (parts[0][:22] + "..."), pw, bssid)
    # generic hash[:salt]:password
    tgt = parts[0]
    return (tgt[:34] + ("..." if len(tgt) > 34 else ""), pw, "")

AUTHORIZED_NOTICE = (
    "AUTHORIZED USE ONLY - crack only handshakes from networks you own or "
    "are explicitly permitted to test."
)

# Wi-Fi related hashcat modes (for benchmark / info)
BENCH_MODES = [("22000", "WPA-PBKDF2-PMKID+EAPOL"),
               ("22001", "WPA-PMK-PMKID+EAPOL"),
               ("16800", "WPA-PMKID-PBKDF2"),
               ("2500", "WPA/WPA2 (legacy hccapx)")]

# Common hashcat hash modes (label, -m number). "custom" = user types the number.
HASH_MODES = [
    ("22000 - WPA-PMKID/EAPOL (Wi-Fi)", "22000"),
    ("0 - MD5", "0"),
    ("100 - SHA1", "100"),
    ("1400 - SHA2-256", "1400"),
    ("1700 - SHA2-512", "1700"),
    ("1000 - NTLM (Windows)", "1000"),
    ("3200 - bcrypt", "3200"),
    ("1800 - sha512crypt (Linux $6$)", "1800"),
    ("7400 - sha256crypt (Linux $5$)", "7400"),
    ("500 - md5crypt (Linux $1$)", "500"),
    ("400 - phpass (WordPress/Joomla)", "400"),
    ("5600 - NetNTLMv2", "5600"),
    ("5500 - NetNTLMv1", "5500"),
    ("13100 - Kerberos TGS-REP (kerberoast)", "13100"),
    ("18200 - Kerberos AS-REP", "18200"),
    ("1100 - Domain Cached Creds (DCC)", "1100"),
    ("2100 - DCC2 (mscash2)", "2100"),
    ("13400 - KeePass", "13400"),
    ("11300 - Bitcoin/Litecoin wallet", "11300"),
    ("6211 - TrueCrypt", "6211"),
    ("13000 - RAR5", "13000"),
    ("12500 - RAR3-hp", "12500"),
    ("17200 - PKZIP", "17200"),
    ("13600 - WinZip", "13600"),
    ("9600 - MS Office 2013", "9600"),
    ("9500 - MS Office 2010", "9500"),
    ("25400 - PDF 1.4-1.6", "25400"),
    ("16800 - WPA-PMKID-PBKDF2", "16800"),
    ("2500 - WPA (legacy hccapx)", "2500"),
    ("Other (custom -m number)", "custom"),
]

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
DEFAULTS = {
    "hashcat_path": "",
    "hcxpcapngtool_path": "",
    "aircrack_path": "",
    "wordlist_dir": "",
    "loot_dir": "",
    "rules_dir": "",
    "workload": "3",
    "theme": "dark",
    "extra_flags": "",
    "prince_path": "",
    "kwp_path": "",
    "kwp_base": "",
    "kwp_keymap": "",
    "kwp_route": "",
    "pcfg_path": "",
    "pcfg_ruleset": "",
    "statsproc_path": "",
    "john_dir": "",
    "perl_path": "",
    "server_host": "",
    "server_user": "",
    "server_key": "",
    "server_hcx": "hcxpcapngtool",
    "profiles": {},
}


class Config:
    def __init__(self):
        self.data = dict(DEFAULTS)
        self.load()

    def load(self):
        # 1) config baked into the .exe (paths, server, profiles) so it runs standalone
        try:
            if BUNDLED_CONFIG.exists() and BUNDLED_CONFIG.resolve() != CONFIG_PATH.resolve():
                self.data.update(json.loads(BUNDLED_CONFIG.read_text(encoding="utf-8")))
        except Exception:
            pass
        # 2) user overrides saved next to the app / in %LOCALAPPDATA%\PineCrack
        try:
            if CONFIG_PATH.exists():
                self.data.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except Exception:
            pass
        # 3) frozen "fat" build: repoint bundled tool paths to the extracted tools/ dir
        if getattr(sys, "frozen", False):
            bt = BUNDLE_DIR / "tools"
            if bt.exists():
                for k in ("prince_path", "kwp_path", "kwp_base", "kwp_keymap", "kwp_route",
                          "statsproc_path", "pcfg_path", "john_dir", "server_key"):
                    v = str(self.data.get(k, "") or "").replace("/", "\\")
                    if "\\tools\\" in v:
                        self.data[k] = str(bt / v.split("\\tools\\", 1)[1])
        self.data.setdefault("profiles", {})

    def save(self):
        try:
            CONFIG_PATH.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def get(self, k, default=""):
        return self.data.get(k, default)

    def set(self, k, v):
        self.data[k] = v


# ----------------------------------------------------------------------------
# Tool discovery
# ----------------------------------------------------------------------------
COMMON_DIRS = [
    r"C:\hashcat", r"C:\Tools\hashcat", r"C:\Program Files\hashcat",
    r"C:\hcxtools", r"C:\Tools\hcxtools",
    r"C:\Program Files\Aircrack-ng", r"C:\aircrack-ng", r"C:\Tools\aircrack-ng",
    r"C:\strawberry\perl\bin", r"C:\Strawberry\perl\bin", r"D:\Claude\strawberry\perl\bin",
    str(Path.home() / "Downloads"),
]


def find_tool(names, configured=""):
    if configured and Path(configured).exists():
        return configured
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    for d in COMMON_DIRS:
        base = Path(d)
        if not base.exists():
            continue
        for n in names:
            cand = base / (n if n.lower().endswith(".exe") or os.name != "nt" else n + ".exe")
            if cand.exists():
                return str(cand)
            try:
                for sub in base.rglob(n if n.lower().endswith(".exe") or os.name != "nt" else n + ".exe"):
                    return str(sub)
            except Exception:
                pass
    return ""


def locate_all(cfg):
    exe = ".exe" if os.name == "nt" else ""
    return {
        "hashcat": find_tool(["hashcat" + exe, "hashcat"], cfg.get("hashcat_path")),
        "hcxpcapngtool": find_tool(["hcxpcapngtool" + exe, "hcxpcapngtool"], cfg.get("hcxpcapngtool_path")),
        "aircrack": find_tool(["aircrack-ng" + exe, "aircrack-ng"], cfg.get("aircrack_path")),
        "perl": find_tool(["perl" + exe, "perl"], cfg.get("perl_path")),
    }


# ----------------------------------------------------------------------------
# Mask presets (useful for local / Slovenian Wi-Fi passwords)
# ----------------------------------------------------------------------------
MASK_PRESETS = [
    ("8 digits (min WPA len)", "?d?d?d?d?d?d?d?d"),
    ("9 digits (SI phone 0XXXXXXXX)", "?d?d?d?d?d?d?d?d?d"),
    ("10 digits", "?d?d?d?d?d?d?d?d?d?d"),
    ("12 digits", "?d?d?d?d?d?d?d?d?d?d?d?d"),
    ("Date DDMMYYYY", "?d?d?d?d?d?d?d?d"),
    ("8 lowercase letters", "?l?l?l?l?l?l?l?l"),
    ("8 lower + digits", "?l?l?l?l?l?l?l?d"),
    ("Capital + 7 lower", "?u?l?l?l?l?l?l?l"),
    ("Capital + 6 lower + digit", "?u?l?l?l?l?l?l?d"),
    ("Word(6 lower) + 2 digits", "?l?l?l?l?l?l?d?d"),
    ("Word(5 lower) + 4 digits (year)", "?l?l?l?l?l?d?d?d?d"),
    ("2 upper + 6 digits", "?u?u?d?d?d?d?d?d"),
    ("8 alnum lower (hex)", "?h?h?h?h?h?h?h?h"),
    ("Brute: all lowercase ?l x8", "?l?l?l?l?l?l?l?l"),
    ("Brute: ALL printable ?a x8 (very slow)", "?a?a?a?a?a?a?a?a"),
]

MASK_HELP_TEXT = (
    "MASK = a template. Each ?x stands for EXACTLY ONE character.\n"
    "Type literal characters as-is; the ?x tokens are placeholders.\n\n"
    "BUILT-IN CHARSETS\n"
    "  ?l   a-z             lowercase (26)\n"
    "  ?u   A-Z             uppercase (26)\n"
    "  ?d   0-9             digits (10)\n"
    "  ?s   ! @ # $ % - . ...   symbols + space (33)\n"
    "  ?a   ?l ?u ?d ?s     all printable ASCII (95)\n"
    "  ?b   0x00-0xff       raw bytes (256, rarely needed)\n"
    "  ?h   0-9 a-f         lowercase hex\n"
    "  ?H   0-9 A-F         uppercase hex\n\n"
    "CUSTOM CHARSETS  (the -1 / -2 boxes below the mask)\n"
    "  Put e.g.  ?l?d  in the -1 box   ->  then ?1 in the mask means a-z0-9\n"
    "  The -2 box  ->  ?2 in the mask.   (?3, ?4 also possible)\n"
    "  Handy for a known alphabet, e.g. -1 = abc123-.  for a domain-like pw.\n\n"
    "EXAMPLES\n"
    "  ?d?d?d?d?d?d?d?d        8 digits              (10^8)\n"
    "  ?u?l?l?l?l?d?d          Abcde12 shape\n"
    "  Geslo?d?d?d             the word 'Geslo' + 3 digits\n"
    "  ?l?l?l?l?l?l?l?l        8 lowercase letters   (26^8)\n"
    "  -1 = ?l?d , mask ?1?1?1?1?1?1   6 chars from a-z0-9\n"
    "  ?a?a?a?a?a?a            6 of anything  (short only!)\n\n"
    "TIPS\n"
    "  - Each extra ?a multiplies the work ~95x  ->  keep ?a masks short (<= 7-8).\n"
    "  - Don't know the length? tick 'Increment' and set min/max length.\n"
    "  - Put the most likely structure first; add ?s / ?a only when needed.\n"
    "  - The blue number next to the Mask box is the keyspace (how many guesses).\n"
)


def mask_keyspace(mask):
    sizes = {"d": 10, "l": 26, "u": 26, "s": 33, "a": 95, "h": 16, "H": 16, "b": 256}
    total = 1
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            total *= sizes.get(mask[i + 1], 1)
            i += 2
        else:
            i += 1
    return total


def human_time(seconds):
    if seconds <= 0 or seconds != seconds:
        return "n/a"
    units = [("y", 31536000), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1)]
    out = []
    for name, size in units:
        if seconds >= size:
            v = int(seconds // size)
            seconds -= v * size
            out.append(f"{v}{name}")
        if len(out) >= 2:
            break
    return " ".join(out) if out else "0s"


def human_count(n):
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(n) < 1000:
            return f"{n:.1f}{unit}" if unit else f"{int(n)}"
        n /= 1000.0
    return f"{n:.1f}E"


# ----------------------------------------------------------------------------
# Pure utilities (wordlist tools, capture parsing) - unit testable
# ----------------------------------------------------------------------------
def gen_pattern_list(out_path, prefix="", digits=8, limit=5000000):
    """Write prefix + zero-padded numbers 0..10^digits-1 (capped at limit)."""
    n = 10 ** max(0, int(digits))
    capped = min(n, int(limit))
    with open(out_path, "w", encoding="utf-8") as f:
        for i in range(capped):
            f.write("%s%0*d\n" % (prefix, digits, i))
    return capped, n


def wordlist_stats(path, sample_cap=20000000):
    total = ge8 = ssum = mx = 0
    mn = None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\n")
            if not w:
                continue
            total += 1
            L = len(w)
            if L >= 8:
                ge8 += 1
            mn = L if mn is None else min(mn, L)
            mx = max(mx, L)
            ssum += L
            if total >= sample_cap:
                break
    return {"total": total, "ge8": ge8, "min": mn or 0, "max": mx,
            "avg": round(ssum / total, 1) if total else 0}


def merge_dedupe_files(paths, out_path):
    seen = set()
    n = 0
    with open(out_path, "w", encoding="utf-8") as fo:
        for p in paths:
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fi:
                    for line in fi:
                        w = line.rstrip("\n")
                        if w and w not in seen:
                            seen.add(w)
                            fo.write(w + "\n")
                            n += 1
            except Exception:
                pass
    return n


def parse_hc22000(path, limit=300):
    """Return list of (essid, type, mac_ap) tuples parsed from a .hc22000 file."""
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split("*")
                if len(parts) >= 6 and parts[0].upper().startswith("WPA"):
                    typ = {"01": "PMKID", "02": "EAPOL"}.get(parts[1], parts[1])
                    try:
                        essid = bytes.fromhex(parts[5]).decode("utf-8", "replace")
                    except Exception:
                        essid = parts[5]
                    out.append((essid, typ, parts[3]))
                if len(out) >= limit:
                    break
    except Exception:
        pass
    return out


# ----------------------------------------------------------------------------
# Command builders (pure functions - unit testable)
# ----------------------------------------------------------------------------
def build_hashcat_cmd(hashcat, hashfile, attack, wordlists, rules, mask, workload="3",
                      extra="", potfile=str(POTFILE_PATH), outfile=str(OUTFILE_PATH),
                      optimized=False, increment=False, device="", session="",
                      charsets=None, inc_min="", inc_max="", markov_threshold="", mode=HASH_MODE_WPA):
    """attack: dict / rules / mask / combinator / hybrid_wm (a6) / hybrid_mw (a7)."""
    cmd = [hashcat, "-m", str(mode)]
    wl = list(wordlists)
    rules_list = rules if isinstance(rules, (list, tuple)) else ([rules] if rules else [])
    if attack == "dict":
        cmd += ["-a", "0", hashfile] + wl
    elif attack == "rules":
        cmd += ["-a", "0", hashfile] + wl
        for r in rules_list:
            if r:
                cmd += ["-r", r]
    elif attack == "mask":
        cmd += ["-a", "3", hashfile, mask]
    elif attack == "combinator":
        cmd += ["-a", "1", hashfile] + wl[:2]
    elif attack == "hybrid_wm":
        cmd += ["-a", "6", hashfile, (wl[0] if wl else "<wordlist>"), mask]
    elif attack == "hybrid_mw":
        cmd += ["-a", "7", hashfile, mask, (wl[0] if wl else "<wordlist>")]
    else:
        raise ValueError("unknown attack: %s" % attack)
    for i, cs in enumerate(charsets or [], start=1):
        if cs:
            cmd += ["-%d" % i, cs]
    if increment and attack in ("mask", "hybrid_wm", "hybrid_mw"):
        cmd += ["--increment"]
        if inc_min:
            cmd += ["--increment-min", str(inc_min)]
        if inc_max:
            cmd += ["--increment-max", str(inc_max)]
    if markov_threshold and attack == "mask":
        cmd += ["--markov-threshold", str(markov_threshold)]
    if optimized:
        cmd += ["-O"]
    if device:
        cmd += ["-d", str(device)]
    if session:
        cmd += ["--session", session]
    cmd += ["-w", str(workload or "3")]
    cmd += ["-o", outfile, "--outfile-format", "2"]
    cmd += ["--potfile-path", potfile]
    cmd += ["--status", "--status-json", "--status-timer", "2"]
    if extra:
        cmd += extra.split()
    return cmd


def build_aircrack_cmd(aircrack, capfile, wordlist, bssid=""):
    cmd = [aircrack, "-w", wordlist]
    if bssid:
        cmd += ["-b", bssid]
    cmd += [capfile]
    return cmd


def build_convert_cmd(hcxtool, infile, outfile):
    return [hcxtool, "-o", outfile, infile]


def build_benchmark_cmd(hashcat, mode=HASH_MODE_WPA):
    return [hashcat, "-b", "-m", str(mode)]


def build_hashcat_stdin_cmd(hashcat, hashfile, workload="3", extra="",
                            potfile=str(POTFILE_PATH), outfile=str(OUTFILE_PATH),
                            optimized=False, device="", session="", mode=HASH_MODE_WPA):
    """hashcat consuming candidates from stdin (for PRINCE / kwp / PCFG pipes)."""
    cmd = [hashcat, "-m", str(mode), "-a", "0", hashfile]
    if optimized:
        cmd += ["-O"]
    if device:
        cmd += ["-d", str(device)]
    if session:
        cmd += ["--session", session]
    cmd += ["-w", str(workload or "3"), "-o", outfile, "--outfile-format", "2",
            "--potfile-path", potfile, "--status", "--status-json", "--status-timer", "2"]
    if extra:
        cmd += extra.split()
    return cmd


def build_prince_cmd(prince, wordlist):
    return [prince, wordlist]


def build_kwp_cmd(kwp, base, keymap, route):
    return [kwp, base, keymap, route]


def build_pcfg_cmd(pcfg, ruleset=""):
    cmd = [sys.executable, pcfg] if str(pcfg).lower().endswith(".py") else [pcfg]
    if ruleset:
        cmd += ["-r", ruleset]
    return cmd


def build_statsproc_cmd(sp, hcstat, mask=""):
    cmd = [sp]
    if mask:
        cmd += [mask]
    cmd += [hcstat]
    return cmd


# John-the-Ripper *2john extractors: (label, tool filename, suggested -m modes)
EXTRACTORS = [
    ("ZIP archive", "zip2john", "17200 / 17210 / 13600"),
    ("RAR archive", "rar2john", "13000 (RAR5) / 12500 (RAR3)"),
    ("7-Zip archive", "7z2john.pl", "11600"),
    ("MS Office (doc/xls/ppt)", "office2john.py", "9400-9700"),
    ("PDF", "pdf2john.py", "10500 / 10700 / 25400"),
    ("KeePass (kdbx)", "keepass2john", "13400"),
    ("SSH private key", "ssh2john.py", "22911 / 22921"),
    ("PuTTY key", "putty2john.py", "22931"),
    ("BitLocker", "bitlocker2john", "22100"),
]


def clean_john_hash(raw):
    """Reduce a John *2john output line ('name:HASH[:extra...]') to the single
    hashcat-usable token. Archive/office/pdf/keepass hashes are the '$...' field
    and contain no internal ':' - so we return the first '$'-prefixed (or long
    hex) field, dropping the filename prefix and John's trailing uid:gid fields."""
    line = ""
    for ln in (raw or "").splitlines():
        if ln.strip():
            line = ln.strip()
            break
    if not line:
        return ""
    fields = line.split(":")
    for fld in fields:
        if fld.startswith("$") or fld.startswith("WPA*") or \
           (len(fld) >= 32 and all(c in "0123456789abcdefABCDEF" for c in fld)):
            return fld
    return fields[1] if len(fields) >= 2 else line


def guess_hc_mode(h):
    """Best-effort hashcat -m from a hash's signature (for auto-selecting mode)."""
    h = h or ""
    for pref, mode in (
        ("$zip2$", "13600"), ("$pkzip2$", "17200"),
        ("$rar5$", "13000"), ("$RAR3$", "12500"), ("$rar3$", "12500"),
        ("$office$*2013", "9600"), ("$office$*2010", "9500"), ("$office$", "9600"),
        ("$pdf$", "25400"), ("$keepass$", "13400"),
        ("$krb5tgs$", "13100"), ("$krb5asrep$", "18200"), ("$bitcoin$", "11300"),
    ):
        if h.startswith(pref):
            return mode
    return ""


def fmt_duration(secs):
    """Human-readable duration from seconds: 45s / 2m 5s / 1h 3m / 2d 4h."""
    secs = int(max(0, round(secs)))
    if secs < 60:
        return "%ds" % secs
    if secs < 3600:
        return "%dm %ds" % (secs // 60, secs % 60)
    if secs < 86400:
        return "%dh %dm" % (secs // 3600, (secs % 3600) // 60)
    return "%dd %dh" % (secs // 86400, (secs % 86400) // 3600)


LEET_MAP = {"a": "@4", "e": "3", "i": "1", "o": "0", "s": "$5",
            "t": "7", "g": "9", "b": "8", "l": "1"}


def ascii_fold(s):
    """Fold Slovenian/diacritic letters to ASCII (people often type passwords
    without diacritics): Laptuš -> Laptus, Žnidaršič -> Znidarsic."""
    table = {"š": "s", "Š": "S", "č": "c", "Č": "C", "ž": "z", "Ž": "Z",
             "đ": "d", "Đ": "D", "ć": "c", "Ć": "C", "á": "a", "é": "e", "í": "i"}
    return "".join(table.get(ch, ch) for ch in s)


def leet_variants(word, cap=512):
    """Leet forms of a word. If the number of substitutable positions is small
    enough, generate the FULL per-character product - so MIXED forms such as
    M@rk0L4ptu5 (one 'a' -> @, the other 'a' -> 4) are included. For longer
    words it falls back to a bounded set (original + single-class + full)."""
    opts = []
    for ch in word:
        subs = LEET_MAP.get(ch.lower(), "")
        opts.append([ch] + list(subs))
    total = 1
    for o in opts:
        total *= len(o)
    if total <= 1:
        return {word}
    if total <= cap:
        import itertools
        return {"".join(c) for c in itertools.product(*opts)}
    out = {word}
    present = [c for c in set(word.lower()) if c in LEET_MAP]
    for c in present:                       # swap ONE letter class at a time
        for rep in LEET_MAP[c]:
            out.add("".join(rep if ch.lower() == c else ch for ch in word))
    out.add("".join(LEET_MAP.get(ch.lower(), ch)[0] for ch in word))
    out.add("".join(LEET_MAP.get(ch.lower(), ch)[-1] for ch in word))
    return out


def build_profile_wordlist(words, numbers, opts=None):
    """CUPP-style targeted wordlist from personal data (names, years, ...).
    words   : base tokens (first/last name, nick, pet, city, keyword, ...)
    numbers : years / meaningful numbers (birth year, house no., ...)
    opts    : {leet, specials, combine, min_len, max_out}
    For AUTHORIZED auditing of your own accounts only."""
    opts = opts or {}
    use_leet = bool(opts.get("leet", True))
    use_specials = bool(opts.get("specials", True))
    use_combine = bool(opts.get("combine", True))
    min_len = int(opts.get("min_len") or 0)
    cap = int(opts.get("max_out") or 300000)

    words = [w.strip() for w in words if w and str(w).strip()]
    folded = [ascii_fold(w) for w in words]
    words = list(dict.fromkeys(words + [w for w in folded if w not in words]))
    numbers = [str(n).strip() for n in numbers if str(n).strip()]

    bases = set()
    for w in words:
        for v in (w.lower(), w.upper(), w.capitalize(), w):
            if v:
                bases.add(v)
    if use_combine:
        for a in words:
            for b in words:
                if a.lower() != b.lower():
                    bases.add(a.capitalize() + b.capitalize())
                    bases.add(a.lower() + b.lower())

    # expand every base with leet variants BEFORE affixing, so leet forms also
    # get years/specials (e.g. p@ssword2024!) - partial and full substitutions.
    if use_leet:
        leetbases = set()
        for b in bases:
            leetbases |= leet_variants(b)
        bases = leetbases

    STD_NUMS = ["1", "12", "123", "1234", "01", "007", "69", "2023", "2024", "2025"]
    nums = list(dict.fromkeys(numbers + STD_NUMS))
    SPECIALS = ["!", ".", "?", "@", "#", "*", "123", "!!"]

    out = set()
    for b in bases:
        if not b:
            continue
        out.add(b)
        for n in nums:
            out.add(b + n)
        for n in numbers:
            out.add(n + b)
        if use_specials:
            for s in SPECIALS:
                out.add(b + s)
            for n in numbers:
                out.add(b + n + "!")
    for n in numbers:
        out.add(n)
        for m in numbers:
            if n != m:
                out.add(n + m)

    if min_len:
        out = {w for w in out if len(w) >= min_len}
    return sorted(out)[:cap]


_LINE_COUNT_CACHE = {}


def count_lines(path):
    """Fast line count with (path,mtime,size) caching."""
    try:
        st = os.stat(path)
    except Exception:
        return 0
    key = (path, st.st_mtime, st.st_size)
    if key in _LINE_COUNT_CACHE:
        return _LINE_COUNT_CACHE[key]
    n = 0
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                n += chunk.count(b"\n")
    except Exception:
        return 0
    _LINE_COUNT_CACHE[key] = n
    return n


def rule_count(path):
    """Number of active rules in a .rule file (blank/# ignored). 1 if none."""
    if not path or not os.path.exists(path):
        return 1
    try:
        n = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    n += 1
        return max(1, n)
    except Exception:
        return 1


def estimate_candidates(atk, wordlists, rules_file="", mask=""):
    """Total candidate count for an attack, or None if not determinable."""
    wl_lines = sum(count_lines(w) for w in (wordlists or []) if w and os.path.exists(w))
    if atk == "dict":
        return wl_lines or None
    if atk == "rules":
        return (wl_lines * rule_count(rules_file)) or None
    if atk == "mask":
        return mask_keyspace(mask) or None
    if atk in ("hybrid_wm", "hybrid_mw"):
        return (wl_lines * mask_keyspace(mask)) or None
    if atk == "combinator" and len([w for w in (wordlists or []) if os.path.exists(w)]) >= 2:
        ok = [w for w in wordlists if os.path.exists(w)]
        return (count_lines(ok[0]) * count_lines(ok[1])) or None
    return None   # prince / kwp / pcfg -> keyspace not known ahead of time


def parse_bench_speed(text):
    """Pull the top Speed line out of a hashcat benchmark -> H/s (float)."""
    import re
    m = re.search(r"Speed\.#[*\d]+\.*:\s*([\d.]+)\s*([kMGT]?)H/s", text or "")
    if not m:
        return 0.0
    mult = {"": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}.get(m.group(2), 1)
    return float(m.group(1)) * mult


def notify(cfg, title, message, cracked=False):
    """Local sound + optional phone push via ntfy.sh (topic from settings)."""
    try:
        import winsound
        if cracked:
            for fr in (784, 1047, 1319):
                winsound.Beep(fr, 130)
        else:
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
    except Exception:
        pass
    topic = ""
    try:
        topic = (cfg.get("ntfy_topic", "") or "").strip()
    except Exception:
        topic = ""
    if topic:
        try:
            import urllib.request
            req = urllib.request.Request(
                "https://ntfy.sh/" + topic, data=message.encode("utf-8"),
                headers={"Title": title, "Priority": "high" if cracked else "default",
                         "Tags": "tada" if cracked else "white_check_mark"})
            urllib.request.urlopen(req, timeout=6)
        except Exception:
            pass


def build_extractor_cmd(toolpath, infile, perl="perl"):
    low = str(toolpath).lower()
    if low.endswith(".py"):
        return [sys.executable, toolpath, infile]
    if low.endswith(".pl"):
        return [perl or "perl", toolpath, infile]
    return [toolpath, infile]


def find_extractor(john_dir, filename):
    if not john_dir:
        return shutil.which(filename) or ""
    d = Path(john_dir)
    for cand in (filename, filename + ".exe"):
        if (d / cand).exists():
            return str(d / cand)
    try:
        for m in d.rglob(filename):
            return str(m)
    except Exception:
        pass
    return ""


# ----------------------------------------------------------------------------
# Job runner - runs a subprocess in a thread, streams events to a queue
# ----------------------------------------------------------------------------
class JobRunner:
    def __init__(self, event_queue):
        self.q = event_queue
        self.proc = None
        self.thread = None
        self._stop = False
        self._gen = None

    def is_running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, cmd, cwd=None):
        if self.is_running():
            return False
        self._stop = False
        self.thread = threading.Thread(target=self._run, args=(cmd, cwd), daemon=True)
        self.thread.start()
        return True

    def _run(self, cmd, cwd):
        self.q.put(("cmd", " ".join(_quote(c) for c in cmd)))
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE, text=True, bufsize=1,
                creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
            )
        except FileNotFoundError:
            self.q.put(("error", "Tool not found: %s" % cmd[0]))
            self.q.put(("done", -1))
            return
        except Exception as e:
            self.q.put(("error", str(e)))
            self.q.put(("done", -1))
            return
        for line in self.proc.stdout:
            if self._stop:
                break
            line = line.rstrip("\n")
            if not line:
                continue
            handled = False
            if line.startswith("{") and '"progress"' in line:
                try:
                    self.q.put(("status", json.loads(line)))
                    handled = True
                except Exception:
                    handled = False
            if not handled:
                self.q.put(("log", line))
        rc = self.proc.wait() if self.proc else -1
        self.q.put(("done", rc))

    def start_pipe(self, gen_cmd, cons_cmd, cwd=None):
        if self.is_running():
            return False
        self._stop = False
        self.thread = threading.Thread(target=self._run_pipe, args=(gen_cmd, cons_cmd, cwd), daemon=True)
        self.thread.start()
        return True

    def _run_pipe(self, gen_cmd, cons_cmd, cwd):
        self.q.put(("cmd", " ".join(_quote(c) for c in gen_cmd) + " | " + " ".join(_quote(c) for c in cons_cmd)))
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            self._gen = subprocess.Popen(gen_cmd, cwd=cwd, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, creationflags=flags)
            self.proc = subprocess.Popen(cons_cmd, cwd=cwd, stdin=self._gen.stdout,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, bufsize=1, creationflags=flags)
            self._gen.stdout.close()
        except FileNotFoundError as e:
            self.q.put(("error", "Tool not found (%s)" % e)); self.q.put(("done", -1)); return
        except Exception as e:
            self.q.put(("error", str(e))); self.q.put(("done", -1)); return
        for line in self.proc.stdout:
            if self._stop:
                break
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{") and '"progress"' in line:
                try:
                    self.q.put(("status", json.loads(line))); continue
                except Exception:
                    pass
            self.q.put(("log", line))
        rc = self.proc.wait() if self.proc else -1
        try:
            self._gen.terminate()
        except Exception:
            pass
        self.q.put(("done", rc))

    def send(self, key):
        try:
            if self.is_running() and self.proc.stdin:
                self.proc.stdin.write(key)
                self.proc.stdin.flush()
        except Exception:
            pass

    def stop(self):
        self._stop = True
        try:
            if self._gen:
                self._gen.terminate()
        except Exception:
            pass
        try:
            if self.is_running():
                self.proc.terminate()
        except Exception:
            pass


def _quote(s):
    s = str(s)
    return '"%s"' % s if (" " in s or ("\\" in s and os.name == "nt")) else s


# ----------------------------------------------------------------------------
# Self-test (headless - no GUI dependency)
# ----------------------------------------------------------------------------
def selftest():
    print("== PineCrack self-test ==")
    import tempfile

    c = build_hashcat_cmd("hashcat", "h.hc22000", "dict", ["rockyou.txt"], "", "")
    assert c[:5] == ["hashcat", "-m", "22000", "-a", "0"], c
    print("[ok] dict")

    c = build_hashcat_cmd("hashcat", "h.hc22000", "rules", ["w.txt"], "best64.rule", "")
    assert "-r" in c and "best64.rule" in c
    print("[ok] rules")

    c = build_hashcat_cmd("hashcat", "h.hc22000", "mask", [], "", "?d?d?d?d?d?d?d?d",
                          optimized=True, increment=True, device="1", session="s1",
                          charsets=["?l?d", "?u"])
    assert c[3:6] == ["-a", "3", "h.hc22000"]
    assert "--increment" in c and "-O" in c and "-d" in c and "--session" in c
    assert "-1" in c and "?l?d" in c and "-2" in c
    print("[ok] mask + options + charsets")

    c = build_hashcat_cmd("hashcat", "h.hc22000", "mask", [], "", "?a?a?a?a?a?a?a?a",
                          increment=True, inc_min="8", inc_max="12")
    assert "--increment-min" in c and "--increment-max" in c and "12" in c
    print("[ok] brute-force increment min/max")

    c = build_hashcat_cmd("hashcat", "h", "mask", [], "", "?d?d?d?d?d?d?d?d", markov_threshold="256")
    assert "--markov-threshold" in c and "256" in c
    print("[ok] markov threshold")

    assert build_prince_cmd("pp64", "wl.txt") == ["pp64", "wl.txt"]
    assert build_kwp_cmd("kwp", "b", "k", "r") == ["kwp", "b", "k", "r"]
    assert build_pcfg_cmd("guess.py", "rs")[0] == sys.executable
    assert build_statsproc_cmd("sp64", "hc.hcstat2", "?d?d")[-1] == "hc.hcstat2"
    sc = build_hashcat_stdin_cmd("hashcat", "h.hc22000")
    assert sc[:5] == ["hashcat", "-m", "22000", "-a", "0"] and "h.hc22000" in sc
    print("[ok] pipe builders (prince/kwp/pcfg/statsproc/stdin)")

    assert build_hashcat_cmd("hashcat", "h", "dict", ["w"], "", "", mode="1000")[:3] == ["hashcat", "-m", "1000"]
    assert build_hashcat_stdin_cmd("hashcat", "h", mode="1000")[:3] == ["hashcat", "-m", "1000"]
    assert len(HASH_MODES) >= 15
    print("[ok] custom hash mode (-m) + %d hash modes" % len(HASH_MODES))

    assert build_extractor_cmd("zip2john.exe", "a.zip") == ["zip2john.exe", "a.zip"]
    assert build_extractor_cmd("office2john.py", "a.docx")[0] == sys.executable
    assert build_extractor_cmd("7z2john.pl", "a.7z")[0] == "perl"
    print("[ok] hash extractors (2john) + %d types" % len(EXTRACTORS))

    c = build_hashcat_cmd("hashcat", "h", "hybrid_wm", ["w.txt"], "", "?d?d?d?d")
    assert c[3:5] == ["-a", "6"] and c.index("w.txt") < c.index("?d?d?d?d")
    print("[ok] hybrid word+mask (a6)")

    c = build_hashcat_cmd("hashcat", "h", "hybrid_mw", ["w.txt"], "", "?d?d")
    assert c[3:5] == ["-a", "7"] and c.index("?d?d") < c.index("w.txt")
    print("[ok] hybrid mask+word (a7)")

    c = build_aircrack_cmd("aircrack-ng", "cap.cap", "rockyou.txt", "AA:BB:CC:DD:EE:FF")
    assert c == ["aircrack-ng", "-w", "rockyou.txt", "-b", "AA:BB:CC:DD:EE:FF", "cap.cap"]
    print("[ok] aircrack")

    assert build_convert_cmd("hcx", "in.pcap", "out.hc22000") == ["hcx", "-o", "out.hc22000", "in.pcap"]
    assert build_benchmark_cmd("hashcat", "16800")[-1] == "16800"
    print("[ok] convert + benchmark")

    # Results table parsing
    assert parse_crack_line("d5355382b8a9b806dcaf99cdaf564eb6:00146c7e4080:001346fe320c:Harkonen:12345678") \
        == ("Harkonen", "12345678", "00:14:6c:7e:40:80"), parse_crack_line(
        "d5355382b8a9b806dcaf99cdaf564eb6:00146c7e4080:001346fe320c:Harkonen:12345678")
    assert parse_crack_line("WPA*01*deadbeef*aabbccddeeff*112233445566*4d794e6574:secretpw") \
        == ("MyNet", "secretpw", "aa:bb:cc:dd:ee:ff"), parse_crack_line(
        "WPA*01*deadbeef*aabbccddeeff*112233445566*4d794e6574:secretpw")
    assert parse_crack_line("5f4dcc3b5aa765d61d8327deb882cf99:hello")[1] == "hello"
    assert parse_crack_line("biscotte") == ("", "biscotte", "")   # bare plain password
    assert parse_crack_line("") == ("", "", "")
    print("[ok] parse_crack_line")

    assert clean_john_hash("secret.zip:$zip2$*0*3*0*abc*def$/zip2$:::::flag.txt") == "$zip2$*0*3*0*abc*def$/zip2$"
    assert clean_john_hash("k.kdbx:$keepass$*1*6000*0*abcd") == "$keepass$*1*6000*0*abcd"
    assert clean_john_hash("") == ""
    assert guess_hc_mode("$zip2$*0*3*x") == "13600"
    assert guess_hc_mode("$office$*2013*100*x") == "9600"
    assert guess_hc_mode("$keepass$*1*x") == "13400"
    print("[ok] clean_john_hash + guess_hc_mode")

    assert fmt_duration(45) == "45s"
    assert fmt_duration(125) == "2m 5s"
    assert fmt_duration(3700) == "1h 1m"
    assert fmt_duration(90000) == "1d 1h"
    print("[ok] fmt_duration")

    wl = build_profile_wordlist(["Marko", "Novak"], ["1998"],
                                {"leet": True, "specials": True, "combine": True})
    for want in ("Marko", "Marko1998", "marko123", "MarkoNovak", "1998", "Marko!", "M@rk0"):
        assert want in wl, want
    wl2 = build_profile_wordlist(["password"], [], {"leet": False, "specials": False,
                                                    "combine": False, "min_len": 8})
    assert wl2 and all(len(w) >= 8 for w in wl2)
    wl3 = build_profile_wordlist(["password"], [], {"leet": True, "specials": False, "combine": False})
    for want in ("p@ssword", "pa$$word", "passw0rd", "p4ssword"):   # PARTIAL leet
        assert want in wl3, want
    assert ascii_fold("Laptuš") == "Laptus"
    wl4 = build_profile_wordlist(["Marko", "Laptuš"], [], {"leet": True, "combine": True})
    assert "M@rk0L4ptu5" in wl4, "mixed leet M@rk0L4ptu5 not generated"
    print("[ok] build_profile_wordlist (%d candidates) + mixed leet" % len(wl))

    assert parse_bench_speed("Speed.#01........:   290.3 kH/s (72ms)") == 290300.0
    assert parse_bench_speed("Speed.#*.........:   1.5 MH/s") == 1500000.0
    import tempfile as _tf
    _wl = os.path.join(_tf.mkdtemp(), "wl.txt")
    open(_wl, "w").write("a\nb\nc\n")
    assert count_lines(_wl) == 3
    assert estimate_candidates("dict", [_wl]) == 3
    assert estimate_candidates("mask", [], "", "?d?d") == 100
    assert estimate_candidates("prince", [_wl]) is None
    print("[ok] estimate helpers")

    assert mask_keyspace("?d?d?d?d?d?d?d?d") == 10 ** 8
    assert mask_keyspace("?l?l?l?l?l?l?l?l") == 26 ** 8
    print("[ok] keyspace 8 digits=%s / 8 lower=%s" %
          (human_count(10 ** 8), human_count(26 ** 8)))

    d = tempfile.mkdtemp()
    a = os.path.join(d, "a.txt"); b = os.path.join(d, "b.txt"); m = os.path.join(d, "m.txt")
    open(a, "w").write("password\n12345678\nhello\npassword\n")
    open(b, "w").write("12345678\nqwertyui\n")
    cap, full = gen_pattern_list(os.path.join(d, "p.txt"), prefix="040", digits=6, limit=100)
    assert cap == 100
    print("[ok] gen_pattern_list capped:", cap, "of", human_count(full))
    st = wordlist_stats(a)
    assert st["total"] == 4 and st["ge8"] == 3, st   # password,12345678,password >= 8
    print("[ok] wordlist_stats:", st)
    n = merge_dedupe_files([a, b], m)
    assert n == 4, n   # password,12345678,hello,qwertyui
    print("[ok] merge_dedupe unique lines:", n)

    open(os.path.join(d, "t.hc22000"), "w").write(
        "WPA*02*abc*aabbccddeeff*112233445566*4d794e6574*x*y\n")
    tg = parse_hc22000(os.path.join(d, "t.hc22000"))
    assert tg and tg[0][0] == "MyNet" and tg[0][1] == "EAPOL", tg
    print("[ok] parse_hc22000 ESSID:", tg[0])

    assert len(MASK_PRESETS) >= 10
    assert Config().get("workload") == "3"
    print("\nAll self-tests passed.")
    return 0


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
def run_gui():
    try:
        import customtkinter as ctk
        from tkinter import filedialog, messagebox, ttk
        import tkinter as tk
    except Exception as e:
        print("GUI requires customtkinter. Install with:  pip install customtkinter")
        print("Import error:", e)
        return 1

    cfg = Config()
    ctk.set_appearance_mode(cfg.get("theme", "dark"))
    ctk.set_default_color_theme("dark-blue")
    tools = locate_all(cfg)
    ev = queue.Queue()
    runner = JobRunner(ev)

    app = ctk.CTk()
    app.title(f"{APP_NAME} {APP_VERSION} - WPA cracking studio")
    app.geometry("1180x820")
    app.minsize(1000, 700)

    state = {"hashfile": "", "capfile": "", "captures": [], "wordlists": [], "run_before": 0}
    autostate = {"active": False, "queue": [], "idx": 0}
    bench_speed = {}   # mode -> measured H/s (populated live during runs)

    header = ctk.CTkFrame(app, corner_radius=0, fg_color=("#1f2937", "#0b1220"))
    header.pack(fill="x")
    ctk.CTkLabel(header, text="⚡ PineCrack", font=ctk.CTkFont(size=22, weight="bold")).pack(side="left", padx=16, pady=10)
    ctk.CTkLabel(header, text=AUTHORIZED_NOTICE, text_color="#f59e0b", font=ctk.CTkFont(size=11)).pack(side="left", padx=8)
    gpu_lbl = ctk.CTkLabel(header, text="", font=ctk.CTkFont(size=11), text_color="#38bdf8")
    gpu_lbl.pack(side="right", padx=16)

    tabs = ctk.CTkTabview(app, corner_radius=10)
    tabs.pack(fill="both", expand=True, padx=12, pady=(8, 4))
    for name in ["1 · Handshakes", "2 · Attack", "3 · Run", "Results", "Tools", "Settings"]:
        tabs.add(name)

    status_bar = ctk.CTkLabel(app, text="Ready.", anchor="w", font=ctk.CTkFont(size=11))
    status_bar.pack(fill="x", padx=14, pady=(0, 6))

    def set_status(msg):
        status_bar.configure(text=msg)

    def _cwd_for(cmd):
        # hashcat must run from its own folder (needs ./OpenCL, ./modules)
        exe = str(cmd[0]) if cmd else ""
        if os.path.basename(exe).lower().startswith("hashcat") and os.path.dirname(exe):
            return os.path.dirname(exe)
        return str(APP_DIR)

    def _run_cmd(cmd):
        log_box.delete("1.0", "end")
        progress.set(0)
        for k in stat_vars:
            stat_vars[k].configure(text="—")
        if not runner.start(cmd, cwd=_cwd_for(cmd)):
            messagebox.showinfo(APP_NAME, "A job is already running.")

    # ======================= TAB 1: HANDSHAKES ==========================
    t1 = tabs.tab("1 · Handshakes")
    ctk.CTkLabel(t1, text="Import captured handshakes (.pcap .pcapng .cap .hccapx .hc22000 .22000)",
                 font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=10, pady=(10, 4))
    row1 = ctk.CTkFrame(t1, fg_color="transparent"); row1.pack(fill="x", padx=10)
    cap_list = tk.Listbox(t1, height=9, bg="#0b1220", fg="#d1d5db", selectbackground="#2563eb",
                          highlightthickness=0, borderwidth=0)

    def refresh_caplist():
        cap_list.delete(0, "end")
        for p in state["captures"]:
            cap_list.insert("end", os.path.basename(p))

    def add_captures(paths):
        for p in paths:
            if p and p not in state["captures"]:
                state["captures"].append(p)
        refresh_caplist()
        set_status("%d capture(s) loaded." % len(state["captures"]))

    def import_files():
        paths = filedialog.askopenfilenames(title="Select capture(s)",
                initialdir=cfg.get("loot_dir") or "/",
                filetypes=[("Captures", "*.pcap *.pcapng *.cap *.hccapx *.hc22000 *.22000"), ("All files", "*.*")])
        if paths:
            add_captures(list(paths))

    def import_from_loot():
        # Auto-scan the configured loot share directly. pathlib handles UNC
        # (\\server\share) paths reliably; Tk's askdirectory does not, and it
        # never shows files anyway -> looked "empty".
        base = cfg.get("loot_dir") or ""
        if not base or not os.path.isdir(base):
            base = filedialog.askdirectory(title="Loot folder", initialdir=base or "/")
            if not base:
                return
        found = []
        for ext in ("*.pcap", "*.pcapng", "*.cap", "*.hccapx", "*.hc22000", "*.22000"):
            try:
                for x in Path(base).rglob(ext):
                    if x.is_file() and x.stat().st_size > 0:
                        found.append(str(x))
            except Exception:
                pass
        found = sorted(set(found))
        if found:
            add_captures(found)
            set_status("Pulled %d capture(s) from loot: %s" % (len(found), base))
        else:
            messagebox.showinfo(APP_NAME, "No capture files found in:\n%s" % base)

    def use_selected():
        sel = cap_list.curselection()
        if not sel:
            return
        p = state["captures"][sel[0]]
        if p.lower().endswith((".hc22000", ".22000", ".hccapx")):
            state["hashfile"] = p
        else:
            state["capfile"] = p
        target_lbl.configure(text=_target_text()); update_preview()
        set_status("Selected: %s" % os.path.basename(p))

    ctk.CTkButton(row1, text="＋ Import capture…", command=import_files, width=160).pack(side="left", padx=(0, 8), pady=8)
    ctk.CTkButton(row1, text="📁 Pull from loot…", command=import_from_loot, width=160).pack(side="left", padx=8, pady=8)
    ctk.CTkButton(row1, text="✔ Use selected as target", command=use_selected, width=190).pack(side="left", padx=8, pady=8)
    cap_list.pack(fill="both", expand=True, padx=10, pady=(4, 6))

    def _target_text():
        return ("Target hash: %s      Capture: %s" %
                (os.path.basename(state["hashfile"]) or "— (convert a .pcap first)",
                 os.path.basename(state["capfile"]) or "—"))

    target_lbl = ctk.CTkLabel(t1, text=_target_text(), justify="left", text_color="#93c5fd")
    target_lbl.pack(anchor="w", padx=10, pady=(0, 4))

    def convert_on_server_async(src):
        tabs.set("3 · Run"); log_box.delete("1.0", "end")
        set_status("Uploading to server + converting …")

        def worker():
            try:
                import paramiko
            except Exception:
                ev.put(("log", "[server-convert] paramiko missing -> run: pip install paramiko")); ev.put(("done", -1)); return
            try:
                host = cfg.get("server_host"); user = cfg.get("server_user")
                key = cfg.get("server_key"); hcx = cfg.get("server_hcx") or "hcxpcapngtool"
                cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if key:
                    cli.connect(host, 22, user, key_filename=key, timeout=20)
                else:
                    cli.connect(host, 22, user, timeout=20)
                sf = cli.open_sftp()
                rin = "/tmp/pc_conv_" + os.path.basename(src)
                rout = rin + ".hc22000"
                ev.put(("log", "[server-convert] uploading %s ..." % os.path.basename(src)))
                sf.put(src, rin)
                ev.put(("log", "[server-convert] running hcxpcapngtool ..."))
                _i, _o, _e = cli.exec_command("%s -o %s %s 2>&1" % (hcx, rout, rin))
                for ln in _o.read().decode("utf-8", "replace").splitlines()[:40]:
                    ev.put(("log", ln))
                local = str(Path(src).with_suffix(".hc22000"))
                try:
                    sf.get(rout, local); ev.put(("converted", local))
                except Exception:
                    ev.put(("log", "[server-convert] no .hc22000 produced (no handshake in capture?)"))
                cli.exec_command("rm -f '%s' '%s'" % (rin, rout))
                sf.close(); cli.close(); ev.put(("done", 0))
            except Exception as ex:
                ev.put(("log", "[server-convert] ERROR: %s" % ex)); ev.put(("done", -1))
        threading.Thread(target=worker, daemon=True).start()

    def convert_selected():
        sel = cap_list.curselection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a .pcap/.cap first."); return
        src = state["captures"][sel[0]]
        if tools["hcxpcapngtool"]:
            out = str(Path(src).with_suffix(".hc22000"))
            set_status("Converting %s …" % os.path.basename(src)); tabs.set("3 · Run")
            _run_cmd(build_convert_cmd(tools["hcxpcapngtool"], src, out))
            state["hashfile"] = out
            if os.path.exists(out):
                add_captures([out])
            target_lbl.configure(text=_target_text())
        elif cfg.get("server_host"):
            convert_on_server_async(src)
        else:
            messagebox.showwarning(APP_NAME, "No local hcxpcapngtool and no server configured.\n"
                                   "Set the server (Settings) or install hcxtools.")

    ctk.CTkButton(t1, text="🔄 Convert selected .pcap → .hc22000 (hashcat format)",
                  command=convert_selected).pack(anchor="w", padx=10, pady=(0, 4))

    def load_hashfile():
        p = filedialog.askopenfilename(title="Hash file (any type - NTLM/MD5/bcrypt/...)")
        if not p:
            return
        state["hashfile"] = p
        if p not in state["captures"]:
            state["captures"].append(p); refresh_caplist()
        target_lbl.configure(text=_target_text()); update_preview()
        set_status("Target hash file: %s  (pick Hash type on tab 2)" % os.path.basename(p))

    ctk.CTkButton(t1, text="🎯 Load hash file (any type — NTLM, MD5, bcrypt, ZIP…)",
                  command=load_hashfile).pack(anchor="w", padx=10, pady=(0, 10))

    # ======================= TAB 2: ATTACK ==============================
    t2 = tabs.tab("2 · Attack")
    hm_frame = ctk.CTkFrame(t2, fg_color="transparent"); hm_frame.pack(fill="x", padx=10, pady=(8, 0))
    ctk.CTkLabel(hm_frame, text="Hash type", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=6)
    hashmode_var = ctk.StringVar(value=HASH_MODES[0][0])
    ctk.CTkOptionMenu(hm_frame, variable=hashmode_var, values=[h[0] for h in HASH_MODES], width=320,
                      command=lambda *_: update_preview()).pack(side="left", padx=6)
    ctk.CTkLabel(hm_frame, text="custom -m").pack(side="left", padx=(12, 2))
    custmode_var = ctk.StringVar(value="")
    ctk.CTkEntry(hm_frame, textvariable=custmode_var, width=70, placeholder_text="1000").pack(side="left", padx=2)
    grid = ctk.CTkFrame(t2, fg_color="transparent"); grid.pack(fill="x", padx=10, pady=6)
    ctk.CTkLabel(grid, text="Engine").grid(row=0, column=0, sticky="w", padx=6, pady=4)
    engine_var = ctk.StringVar(value="hashcat (GPU)")
    ctk.CTkOptionMenu(grid, variable=engine_var, values=["hashcat (GPU)", "aircrack-ng (CPU)"],
                      command=lambda *_: update_preview()).grid(row=0, column=1, sticky="w", padx=6, pady=4)
    ctk.CTkLabel(grid, text="Attack mode").grid(row=0, column=2, sticky="w", padx=6, pady=4)
    attack_var = ctk.StringVar(value="Dictionary")
    ctk.CTkOptionMenu(grid, variable=attack_var, width=200,
                      values=["Dictionary", "Dictionary + Rules", "Mask / brute-force",
                              "Combinator", "Hybrid: word + mask", "Hybrid: mask + word",
                              "PRINCE", "Keyboard-walk", "PCFG"],
                      command=lambda *_: update_preview()).grid(row=0, column=3, sticky="w", padx=6, pady=4)
    ctk.CTkLabel(grid, text="Workload").grid(row=0, column=4, sticky="w", padx=6, pady=4)
    workload_var = ctk.StringVar(value=cfg.get("workload", "3"))
    ctk.CTkOptionMenu(grid, variable=workload_var, values=["1", "2", "3", "4"], width=64,
                      command=lambda *_: update_preview()).grid(row=0, column=5, padx=6, pady=4)

    ctk.CTkLabel(t2, text="Wordlists", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(4, 0))
    wl_frame = ctk.CTkFrame(t2, fg_color="transparent"); wl_frame.pack(fill="x", padx=10)
    wl_list = tk.Listbox(t2, height=4, bg="#0b1220", fg="#d1d5db", selectbackground="#2563eb",
                         highlightthickness=0, borderwidth=0)

    def refresh_wl():
        wl_list.delete(0, "end")
        for w in state["wordlists"]:
            wl_list.insert("end", w)
        update_preview()

    def add_wordlist():
        p = filedialog.askopenfilename(title="Wordlist", initialdir=cfg.get("wordlist_dir") or "/",
                                       filetypes=[("Wordlists", "*.txt *.lst *.dic *.gz"), ("All", "*.*")])
        if p and p not in state["wordlists"]:
            state["wordlists"].append(p); refresh_wl()

    def quick_add(name):
        p = str(Path(cfg.get("wordlist_dir")) / name)
        if p not in state["wordlists"]:
            state["wordlists"].append(p); refresh_wl()

    def rm_wordlist():
        sel = wl_list.curselection()
        if sel:
            del state["wordlists"][sel[0]]; refresh_wl()

    ctk.CTkButton(wl_frame, text="＋ Add…", command=add_wordlist, width=78).pack(side="left", padx=(0, 5), pady=6)
    ctk.CTkButton(wl_frame, text="wpa_reliable", width=104, command=lambda: quick_add("wpa_reliable.txt")).pack(side="left", padx=3)
    ctk.CTkButton(wl_frame, text="rockyou", width=72, command=lambda: quick_add("rockyou.txt")).pack(side="left", padx=3)
    ctk.CTkButton(wl_frame, text="xato", width=52, command=lambda: quick_add("xato-10m.txt")).pack(side="left", padx=3)
    ctk.CTkButton(wl_frame, text="sl_all", width=60, command=lambda: quick_add("slovenian_all.txt")).pack(side="left", padx=3)
    ctk.CTkButton(wl_frame, text="sl_ascii", width=72, command=lambda: quick_add("slovenian_ascii.txt")).pack(side="left", padx=3)
    ctk.CTkButton(wl_frame, text="－ Remove", width=84, command=rm_wordlist).pack(side="left", padx=6)
    wl_list.pack(fill="x", padx=10, pady=(2, 6))

    rm_frame = ctk.CTkFrame(t2, fg_color="transparent"); rm_frame.pack(fill="x", padx=10, pady=2)
    ctk.CTkLabel(rm_frame, text="Rules file").grid(row=0, column=0, sticky="w", padx=6)
    rules_var = ctk.StringVar(value="")
    ctk.CTkEntry(rm_frame, textvariable=rules_var, width=300, placeholder_text="e.g. rules\\best64.rule").grid(row=0, column=1, padx=6, pady=3)

    def pick_rules():
        p = filedialog.askopenfilename(title="Rule file", filetypes=[("Rules", "*.rule"), ("All", "*.*")])
        if p:
            rules_var.set(p)
    ctk.CTkButton(rm_frame, text="…", width=32, command=pick_rules).grid(row=0, column=2, padx=2)
    ctk.CTkLabel(rm_frame, text="Mask preset").grid(row=1, column=0, sticky="w", padx=6)
    preset_var = ctk.StringVar(value=MASK_PRESETS[0][0])
    ctk.CTkOptionMenu(rm_frame, variable=preset_var, values=[p[0] for p in MASK_PRESETS], width=300,
                      command=lambda *_: apply_preset()).grid(row=1, column=1, padx=6, pady=3)
    ctk.CTkLabel(rm_frame, text="Mask").grid(row=2, column=0, sticky="w", padx=6)
    mask_var = ctk.StringVar(value=MASK_PRESETS[0][1])
    ctk.CTkEntry(rm_frame, textvariable=mask_var, width=300).grid(row=2, column=1, padx=6, pady=3)
    mask_info = ctk.CTkLabel(rm_frame, text="", text_color="#93c5fd"); mask_info.grid(row=2, column=3, padx=8, sticky="w")
    ctk.CTkButton(rm_frame, text="❓ Mask help", width=96,
                  command=lambda: show_mask_help()).grid(row=2, column=2, padx=4)

    def show_mask_help():
        w = ctk.CTkToplevel(app); w.title("Mask legend & custom masks"); w.geometry("580x540")
        try:
            w.attributes("-topmost", True)
        except Exception:
            pass
        box = ctk.CTkTextbox(w, wrap="word", font=ctk.CTkFont(family="Consolas", size=12))
        box.pack(fill="both", expand=True, padx=10, pady=10)
        box.insert("1.0", MASK_HELP_TEXT)
        box.configure(state="disabled")
        ctk.CTkButton(w, text="Close", command=w.destroy).pack(pady=(0, 10))

    def apply_preset():
        for name, m in MASK_PRESETS:
            if name == preset_var.get():
                mask_var.set(m); break
        update_preview()

    adv = ctk.CTkFrame(t2, fg_color="transparent"); adv.pack(fill="x", padx=10, pady=(4, 0))
    ctk.CTkLabel(adv, text="Advanced:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=6, sticky="w")
    opt_var = ctk.BooleanVar(value=False)
    ctk.CTkCheckBox(adv, text="Optimized kernels (-O)", variable=opt_var, command=lambda: update_preview()).grid(row=0, column=1, padx=8)
    inc_var = ctk.BooleanVar(value=False)
    ctk.CTkCheckBox(adv, text="Increment (mask)", variable=inc_var, command=lambda: update_preview()).grid(row=0, column=2, padx=8)
    ctk.CTkLabel(adv, text="Device -d").grid(row=0, column=3, padx=(12, 2))
    device_var = ctk.StringVar(value="")
    ctk.CTkEntry(adv, textvariable=device_var, width=50, placeholder_text="1").grid(row=0, column=4, padx=2)
    ctk.CTkLabel(adv, text="Session").grid(row=0, column=5, padx=(12, 2))
    session_var = ctk.StringVar(value="")
    ctk.CTkEntry(adv, textvariable=session_var, width=90, placeholder_text="name").grid(row=0, column=6, padx=2)
    adv2 = ctk.CTkFrame(t2, fg_color="transparent"); adv2.pack(fill="x", padx=10, pady=(2, 0))
    ctk.CTkLabel(adv2, text="Custom charset -1").grid(row=0, column=0, padx=6)
    cs1_var = ctk.StringVar(value="")
    ctk.CTkEntry(adv2, textvariable=cs1_var, width=130, placeholder_text="?l?d").grid(row=0, column=1, padx=4)
    ctk.CTkLabel(adv2, text="-2").grid(row=0, column=2, padx=2)
    cs2_var = ctk.StringVar(value="")
    ctk.CTkEntry(adv2, textvariable=cs2_var, width=130, placeholder_text="?u?l").grid(row=0, column=3, padx=4)
    ctk.CTkLabel(adv2, text="(use ?1 / ?2 in mask)", text_color="#9ca3af").grid(row=0, column=4, padx=8)

    leg = ctk.CTkFrame(t2, fg_color="transparent"); leg.pack(fill="x", padx=10, pady=(3, 0))
    ctk.CTkLabel(leg, text="Mask keys:   ?l a-z    ?u A-Z    ?d 0-9    ?s symbols    ?a all    ?b bytes     |     ?1 ?2 = your custom -1/-2 sets     |     each ? = 1 character",
                 text_color="#9ca3af", font=ctk.CTkFont(size=11), justify="left").pack(anchor="w", padx=6)

    bf = ctk.CTkFrame(t2, fg_color="transparent"); bf.pack(fill="x", padx=10, pady=(2, 0))
    ctk.CTkLabel(bf, text="Brute-force length (needs Increment)  min").grid(row=0, column=0, padx=6)
    incmin_var = ctk.StringVar(value="")
    ctk.CTkEntry(bf, textvariable=incmin_var, width=50, placeholder_text="8").grid(row=0, column=1, padx=2)
    ctk.CTkLabel(bf, text="max").grid(row=0, column=2, padx=2)
    incmax_var = ctk.StringVar(value="")
    ctk.CTkEntry(bf, textvariable=incmax_var, width=50, placeholder_text="10").grid(row=0, column=3, padx=2)
    ctk.CTkLabel(bf, text="Markov thr").grid(row=0, column=4, padx=(12, 2))
    markov_var = ctk.StringVar(value="")
    ctk.CTkEntry(bf, textvariable=markov_var, width=60, placeholder_text="256").grid(row=0, column=5, padx=2)
    ctk.CTkLabel(bf, text="(mask only)", text_color="#9ca3af").grid(row=0, column=6, padx=6)

    for v in (mask_var, rules_var, device_var, session_var, cs1_var, cs2_var, incmin_var, incmax_var, markov_var, custmode_var):
        v.trace_add("write", lambda *_: update_preview())

    prof = ctk.CTkFrame(t2, fg_color="transparent"); prof.pack(fill="x", padx=10, pady=(6, 0))
    ctk.CTkLabel(prof, text="Profile", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=6)
    prof_name = ctk.StringVar(value="")
    ctk.CTkEntry(prof, textvariable=prof_name, width=150, placeholder_text="profile name").grid(row=0, column=1, padx=4)
    prof_pick = ctk.StringVar(value="")
    prof_menu = ctk.CTkOptionMenu(prof, variable=prof_pick, width=160,
                                  values=(list(cfg.get("profiles", {}).keys()) or ["—"]))
    prof_menu.grid(row=0, column=2, padx=4)

    def collect_profile():
        return {"engine": engine_var.get(), "attack": attack_var.get(), "workload": workload_var.get(),
                "wordlists": list(state["wordlists"]), "rules": rules_var.get(), "mask": mask_var.get(),
                "opt": opt_var.get(), "inc": inc_var.get(), "device": device_var.get(),
                "session": session_var.get(), "cs1": cs1_var.get(), "cs2": cs2_var.get(),
                "inc_min": incmin_var.get(), "inc_max": incmax_var.get(), "markov": markov_var.get(),
                "hashmode": hashmode_var.get(), "custmode": custmode_var.get()}

    def save_profile():
        name = prof_name.get().strip()
        if not name:
            messagebox.showinfo(APP_NAME, "Enter a profile name first."); return
        profs = cfg.get("profiles", {}); profs[name] = collect_profile()
        cfg.set("profiles", profs); cfg.save()
        prof_menu.configure(values=list(profs.keys())); prof_pick.set(name)
        set_status("Profile saved: %s" % name)

    def apply_profile_by_name(name):
        p = (cfg.get("profiles", {}) or {}).get(name)
        if not p:
            return False
        engine_var.set(p.get("engine", "hashcat (GPU)")); attack_var.set(p.get("attack", "Dictionary"))
        workload_var.set(p.get("workload", "3")); state["wordlists"] = list(p.get("wordlists", []))
        rules_var.set(p.get("rules", "")); mask_var.set(p.get("mask", ""))
        opt_var.set(p.get("opt", False)); inc_var.set(p.get("inc", False))
        device_var.set(p.get("device", "")); session_var.set(p.get("session", ""))
        cs1_var.set(p.get("cs1", "")); cs2_var.set(p.get("cs2", ""))
        incmin_var.set(p.get("inc_min", "")); incmax_var.set(p.get("inc_max", ""))
        markov_var.set(p.get("markov", "")); hashmode_var.set(p.get("hashmode", HASH_MODES[0][0]))
        custmode_var.set(p.get("custmode", ""))
        refresh_wl()
        return True

    def load_profile():
        name = prof_pick.get()
        if apply_profile_by_name(name):
            set_status("Profile loaded: %s" % name)

    ctk.CTkButton(prof, text="💾 Save", width=80, command=save_profile).grid(row=0, column=3, padx=6)
    ctk.CTkButton(prof, text="📂 Load", width=80, command=load_profile).grid(row=0, column=4, padx=4)

    ctk.CTkLabel(t2, text="Command preview", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(8, 0))
    preview = ctk.CTkTextbox(t2, height=64, wrap="word"); preview.pack(fill="x", padx=10, pady=(2, 8))

    def _hash_mode():
        for label, m in HASH_MODES:
            if label == hashmode_var.get():
                return (custmode_var.get().strip() or "22000") if m == "custom" else m
        return "22000"

    def _attack_key():
        return {"Dictionary": "dict", "Dictionary + Rules": "rules", "Mask / brute-force": "mask",
                "Combinator": "combinator", "Hybrid: word + mask": "hybrid_wm",
                "Hybrid: mask + word": "hybrid_mw", "PRINCE": "prince",
                "Keyboard-walk": "kwp", "PCFG": "pcfg"}[attack_var.get()]

    def current_plan():
        """Return ('single', cmd) or ('pipe', gen_cmd, consumer_cmd)."""
        if engine_var.get().startswith("aircrack"):
            wl = state["wordlists"][0] if state["wordlists"] else "<wordlist>"
            return ("single", build_aircrack_cmd(tools["aircrack"] or "aircrack-ng",
                                                 state["capfile"] or "<capture.cap>", wl))
        atk = _attack_key()
        if atk in ("prince", "kwp", "pcfg"):
            cons = build_hashcat_stdin_cmd(tools["hashcat"] or "hashcat",
                                           state["hashfile"] or "<target.hc22000>",
                                           workload=workload_var.get(), extra=cfg.get("extra_flags", ""),
                                           optimized=opt_var.get(), device=device_var.get(),
                                           session=session_var.get(), mode=_hash_mode())
            wl0 = state["wordlists"][0] if state["wordlists"] else "<wordlist>"
            if atk == "prince":
                gen = build_prince_cmd(cfg.get("prince_path") or "pp64", wl0)
            elif atk == "kwp":
                gen = build_kwp_cmd(cfg.get("kwp_path") or "kwp", cfg.get("kwp_base") or "<base>",
                                    cfg.get("kwp_keymap") or "<keymap>", cfg.get("kwp_route") or "<route>")
            else:
                gen = build_pcfg_cmd(cfg.get("pcfg_path") or "<pcfg_guesser.py>", cfg.get("pcfg_ruleset", ""))
            return ("pipe", gen, cons)
        return ("single", build_hashcat_cmd(
            tools["hashcat"] or "hashcat", state["hashfile"] or "<target.hc22000>",
            atk, state["wordlists"] or ["<wordlist>"], rules_var.get(), mask_var.get(),
            workload=workload_var.get(), extra=cfg.get("extra_flags", ""),
            optimized=opt_var.get(), increment=inc_var.get(), device=device_var.get(),
            session=session_var.get(), charsets=[cs1_var.get(), cs2_var.get()],
            inc_min=incmin_var.get(), inc_max=incmax_var.get(), markov_threshold=markov_var.get(),
            mode=_hash_mode()))

    def update_preview():
        try:
            plan = current_plan()
            preview.delete("1.0", "end")
            if plan[0] == "single":
                preview.insert("1.0", " ".join(_quote(c) for c in plan[1]))
            else:
                preview.insert("1.0", " ".join(_quote(c) for c in plan[1]) + "   |   " +
                               " ".join(_quote(c) for c in plan[2]))
        except Exception as e:
            preview.delete("1.0", "end"); preview.insert("1.0", "(%s)" % e)
        if _attack_key() in ("mask", "hybrid_mw", "hybrid_wm") and not engine_var.get().startswith("aircrack"):
            ks = mask_keyspace(mask_var.get())
            mask_info.configure(text="mask keyspace ≈ %s  (~%s @ 500 kH/s)" % (human_count(ks), human_time(ks / 500000.0)))
        else:
            mask_info.configure(text="")

    # ======================= TAB 3: RUN =================================
    t3 = tabs.tab("3 · Run")
    ctrl = ctk.CTkFrame(t3, fg_color="transparent"); ctrl.pack(fill="x", padx=10, pady=8)
    start_btn = ctk.CTkButton(ctrl, text="▶ Start", width=110, fg_color="#16a34a", hover_color="#15803d")
    start_btn.pack(side="left", padx=(0, 6))
    ctk.CTkButton(ctrl, text="⏸ Pause", width=90, command=lambda: runner.send("p")).pack(side="left", padx=6)
    ctk.CTkButton(ctrl, text="⏵ Resume", width=90, command=lambda: runner.send("r")).pack(side="left", padx=6)
    ctk.CTkButton(ctrl, text="⏹ Stop", width=88, fg_color="#dc2626", hover_color="#b91c1c",
                  command=lambda: (autostate.update({"active": False}), runner.stop())).pack(side="left", padx=6)
    ctk.CTkButton(ctrl, text="⚡ Auto-crack", width=118, fg_color="#7c3aed", hover_color="#6d28d9",
                  command=lambda: start_auto()).pack(side="left", padx=6)
    ctk.CTkButton(ctrl, text="⏱ Estimate", width=100, command=lambda: do_estimate()).pack(side="left", padx=6)
    ctk.CTkButton(ctrl, text="♻ Restore", width=96, command=lambda: do_restore()).pack(side="left", padx=6)
    stats = ctk.CTkFrame(t3); stats.pack(fill="x", padx=10, pady=4)
    stat_vars = {}
    for i, key in enumerate(["Speed", "Progress", "ETA", "Recovered", "GPU temp"]):
        ctk.CTkLabel(stats, text=key, font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=i, padx=14, pady=(6, 0))
        v = ctk.CTkLabel(stats, text="—", font=ctk.CTkFont(size=14)); v.grid(row=1, column=i, padx=14, pady=(0, 6))
        stat_vars[key] = v
    progress = ctk.CTkProgressBar(t3); progress.set(0); progress.pack(fill="x", padx=12, pady=6)
    log_box = ctk.CTkTextbox(t3, wrap="none"); log_box.pack(fill="both", expand=True, padx=10, pady=(4, 8))

    def log(msg):
        log_box.insert("end", msg + "\n"); log_box.see("end")

    def start_attack():
        if engine_var.get().startswith("aircrack"):
            if not tools["aircrack"]:
                messagebox.showwarning(APP_NAME, "aircrack-ng not found. Set path in Settings."); return
            if not state["capfile"] or not state["wordlists"]:
                messagebox.showwarning(APP_NAME, "aircrack needs a .cap capture and a wordlist."); return
        else:
            if not tools["hashcat"]:
                messagebox.showwarning(APP_NAME, "hashcat not found. Set its path in Settings."); return
            if not state["hashfile"]:
                messagebox.showwarning(APP_NAME, "No target .hc22000. Import & convert a handshake on tab 1."); return
            if _attack_key() in ("dict", "rules", "combinator", "hybrid_wm", "hybrid_mw", "prince") and not state["wordlists"]:
                messagebox.showwarning(APP_NAME, "Add at least one wordlist on tab 2."); return
        tabs.set("3 · Run"); set_status("Running…")
        if not engine_var.get().startswith("aircrack") and not session_var.get().strip():
            session_var.set("pinecrack")   # ensures a session so ♻ Restore works
        state["run_before"] = _count_cracked()
        plan = current_plan()
        if plan[0] == "single":
            _run_cmd(plan[1])
        else:
            log_box.delete("1.0", "end"); progress.set(0)
            for _k in stat_vars:
                stat_vars[_k].configure(text="—")
            if not runner.start_pipe(plan[1], plan[2], cwd=_cwd_for(plan[2])):
                messagebox.showinfo(APP_NAME, "A job is already running.")

    start_btn.configure(command=start_attack)

    # ======================= TAB 4: RESULTS =============================
    t4 = tabs.tab("Results")
    ctk.CTkLabel(t4, text="🔓 Cracked passwords", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=12, pady=(10, 0))
    count_lbl = ctk.CTkLabel(t4, text="No results yet", text_color="#9ca3af")
    count_lbl.pack(anchor="w", padx=12, pady=(0, 6))

    # dark ttk.Treeview theme
    _style = ttk.Style()
    try:
        _style.theme_use("clam")
    except Exception:
        pass
    _style.configure("Crack.Treeview", background="#1b1b21", fieldbackground="#1b1b21",
                     foreground="#e5e7eb", rowheight=28, borderwidth=0, font=("Segoe UI", 10))
    _style.configure("Crack.Treeview.Heading", background="#2a2a33", foreground="#93c5fd",
                     relief="flat", font=("Segoe UI", 10, "bold"))
    _style.map("Crack.Treeview", background=[("selected", "#2563eb")], foreground=[("selected", "white")])
    _style.map("Crack.Treeview.Heading", background=[("active", "#343440")])

    tree_wrap = ctk.CTkFrame(t4, fg_color="#1b1b21")
    tree_wrap.pack(fill="both", expand=True, padx=12, pady=4)
    _cols = ("essid", "pw", "bssid", "src")
    res_tree = ttk.Treeview(tree_wrap, columns=_cols, show="headings", style="Crack.Treeview",
                            selectmode="extended", height=13)
    res_tree.heading("essid", text="ESSID / Target")
    res_tree.heading("pw", text="Password")
    res_tree.heading("bssid", text="BSSID / MAC")
    res_tree.heading("src", text="Source")
    res_tree.column("essid", width=230, anchor="w")
    res_tree.column("pw", width=220, anchor="w")
    res_tree.column("bssid", width=150, anchor="w")
    res_tree.column("src", width=80, anchor="center")
    _vsb = ttk.Scrollbar(tree_wrap, orient="vertical", command=res_tree.yview)
    res_tree.configure(yscrollcommand=_vsb.set)
    _vsb.pack(side="right", fill="y")
    res_tree.pack(side="left", fill="both", expand=True)
    res_tree.tag_configure("odd", background="#1b1b21")
    res_tree.tag_configure("even", background="#22222b")

    def refresh_results():
        for iid in res_tree.get_children():
            res_tree.delete(iid)
        best, order = {}, []   # password -> (target, pw, bssid, src); dedup by password
        # potfile first (carries ESSID + MAC); outfile is usually just the plain password.
        for src, f in (("potfile", POTFILE_PATH), ("outfile", OUTFILE_PATH)):
            try:
                if not f.exists():
                    continue
                for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not ln.strip():
                        continue
                    tgt, pw, bssid = parse_crack_line(ln)
                    if not pw:
                        continue
                    cur = best.get(pw)
                    if cur is None:
                        best[pw] = (tgt, pw, bssid, src)
                        order.append(pw)
                    elif not cur[0] and tgt:      # upgrade an orphan pw to a named (ESSID) hit
                        best[pw] = (tgt, pw, bssid, src)
            except Exception:
                pass
        rows = [best[pw] for pw in order]
        for idx, r in enumerate(rows):
            res_tree.insert("", "end", values=r, tags=(("even" if idx % 2 else "odd"),))
        count_lbl.configure(
            text=("✅ %d password%s cracked" % (len(rows), "" if len(rows) == 1 else "s")
                  if rows else "No results yet — crack something first"),
            text_color=("#86efac" if rows else "#9ca3af"))

    def copy_pw():
        pws = [v[1] for v in (res_tree.item(i, "values") for i in res_tree.selection()) if len(v) > 1 and v[1]]
        if not pws:
            set_status("Select a row first.")
            return
        app.clipboard_clear(); app.clipboard_append("\n".join(pws))
        set_status("Copied %d password(s) to clipboard." % len(pws))

    def copy_all():
        pws = [v[1] for v in (res_tree.item(i, "values") for i in res_tree.get_children()) if len(v) > 1 and v[1]]
        if not pws:
            return
        app.clipboard_clear(); app.clipboard_append("\n".join(pws))
        set_status("Copied all %d password(s)." % len(pws))

    res_tree.bind("<Double-1>", lambda e: copy_pw())

    def export_csv():
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                         initialfile="cracked.csv")
        if not p:
            return
        try:
            import csv
            with open(p, "w", newline="", encoding="utf-8") as fo:
                w = csv.writer(fo)
                w.writerow(["essid_or_target", "password", "bssid", "source"])
                for i in res_tree.get_children():
                    w.writerow(res_tree.item(i, "values"))
            set_status("Exported results -> %s" % p)
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))

    def clear_results():
        if not messagebox.askyesno(APP_NAME, "Clear the results list?\n(potfile/outfile are backed up as *.bak)"):
            return
        for f in (OUTFILE_PATH, POTFILE_PATH):
            try:
                if f.exists():
                    f.replace(f.with_suffix(f.suffix + ".bak"))
            except Exception:
                pass
        refresh_results()
        set_status("Results cleared (backup kept as .bak).")

    rowr = ctk.CTkFrame(t4, fg_color="transparent"); rowr.pack(fill="x", padx=12, pady=(2, 2))
    ctk.CTkButton(rowr, text="↻ Refresh", command=refresh_results, width=96).pack(side="left")
    ctk.CTkButton(rowr, text="📋 Copy password", command=copy_pw, width=150).pack(side="left", padx=8)
    ctk.CTkButton(rowr, text="📋 Copy all", command=copy_all, width=104).pack(side="left")
    ctk.CTkButton(rowr, text="⬇ Export CSV", command=export_csv, width=120).pack(side="left", padx=8)
    ctk.CTkButton(rowr, text="🗑 Clear", command=clear_results, width=88,
                  fg_color="#7f1d1d", hover_color="#991b1b").pack(side="right")
    ctk.CTkLabel(t4, text="Double-click a row to copy its password.", text_color="#6b7280",
                 font=ctk.CTkFont(size=11)).pack(anchor="w", padx=12, pady=(0, 8))

    # ======================= TAB 5: TOOLS ===============================
    t5 = tabs.tab("Tools")
    ts = ctk.CTkScrollableFrame(t5); ts.pack(fill="both", expand=True, padx=6, pady=6)

    def tool_row(title, desc, btn_text, fn):
        f = ctk.CTkFrame(ts); f.pack(fill="x", padx=6, pady=5)
        ctk.CTkLabel(f, text=title, font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=10, pady=(8, 0))
        ctk.CTkLabel(f, text=desc, font=ctk.CTkFont(size=11), text_color="#9ca3af", justify="left").pack(anchor="w", padx=10)
        ctk.CTkButton(f, text=btn_text, command=fn, width=220).pack(anchor="w", padx=10, pady=(4, 10))

    def do_benchmark():
        if not tools["hashcat"]:
            messagebox.showwarning(APP_NAME, "hashcat not found."); return
        tabs.set("3 · Run"); _run_cmd(build_benchmark_cmd(tools["hashcat"]))

    def do_benchmark_all():
        if not tools["hashcat"]:
            messagebox.showwarning(APP_NAME, "hashcat not found."); return
        tabs.set("3 · Run"); log_box.delete("1.0", "end"); set_status("Benchmarking Wi-Fi modes …")
        modes = [m for m, _ in BENCH_MODES if m in ("22000", "22001", "16800")]

        def worker():
            for m in modes:
                ev.put(("log", "\n=== hashcat -b -m %s ===" % m))
                try:
                    p = subprocess.Popen([tools["hashcat"], "-b", "-m", m], stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, bufsize=1,
                                         cwd=os.path.dirname(tools["hashcat"]) or str(APP_DIR),
                                         creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
                    for line in p.stdout:
                        ev.put(("log", line.rstrip("\n")))
                    p.wait()
                except Exception as ex:
                    ev.put(("log", "ERROR: %s" % ex))
            ev.put(("done", 0))
        threading.Thread(target=worker, daemon=True).start()

    def do_identify():
        src = state["capfile"] or state["hashfile"]
        if not src or not tools["hcxpcapngtool"]:
            messagebox.showinfo(APP_NAME, "Need a .pcap and hcxpcapngtool to list networks."); return
        tabs.set("3 · Run"); _run_cmd([tools["hcxpcapngtool"], "--all", "-o", os.devnull, src])

    def do_targets():
        if not state["hashfile"]:
            messagebox.showinfo(APP_NAME, "Select a .hc22000 target on tab 1 first."); return
        tg = parse_hc22000(state["hashfile"])
        if not tg:
            messagebox.showinfo(APP_NAME, "No WPA entries parsed."); return
        txt = "\n".join("%-24s  %-6s  %s" % (e, t, m) for e, t, m in tg)
        messagebox.showinfo(APP_NAME + " · targets in hashfile", "ESSID / type / AP-MAC\n\n" + txt[:3500])

    def do_stats():
        p = filedialog.askopenfilename(title="Wordlist", initialdir=cfg.get("wordlist_dir"))
        if not p:
            return
        set_status("Analyzing %s …" % os.path.basename(p))
        try:
            s = wordlist_stats(p)
            messagebox.showinfo(APP_NAME, "Wordlist: %s\n\nlines: %s\nusable (len >= 8): %s\nmin/avg/max length: %s / %s / %s"
                                % (os.path.basename(p), human_count(s["total"]), human_count(s["ge8"]),
                                   s["min"], s["avg"], s["max"]))
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))
        set_status("Ready.")

    def do_merge():
        ps = filedialog.askopenfilenames(title="Wordlists to merge", initialdir=cfg.get("wordlist_dir"))
        if not ps:
            return
        out = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="merged.txt")
        if not out:
            return
        set_status("Merging + deduping …")
        try:
            n = merge_dedupe_files(list(ps), out)
            messagebox.showinfo(APP_NAME, "Wrote %s unique lines →\n%s" % (human_count(n), out))
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))
        set_status("Ready.")

    def do_mutate():
        src = filedialog.askopenfilename(title="Wordlist to mutate", initialdir=cfg.get("wordlist_dir"))
        if not src:
            return
        out = str(Path(src).with_name(Path(src).stem + "_mutated.txt"))
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

    def do_genpattern():
        dlg = ctk.CTkToplevel(app); dlg.title("Generate pattern list"); dlg.geometry("360x230")
        ctk.CTkLabel(dlg, text="Prefix (e.g. 040 for SI mobile)").pack(anchor="w", padx=12, pady=(12, 0))
        pv = ctk.StringVar(value="040"); ctk.CTkEntry(dlg, textvariable=pv).pack(fill="x", padx=12)
        ctk.CTkLabel(dlg, text="Digits after prefix").pack(anchor="w", padx=12, pady=(8, 0))
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
        ctk.CTkButton(dlg, text="Generate…", command=go).pack(pady=14)

    def do_wordlist_gen():
        dlg = ctk.CTkToplevel(app); dlg.title("Targeted wordlist creator"); dlg.geometry("470x600")
        try:
            dlg.attributes("-topmost", True)
        except Exception:
            pass
        ctk.CTkLabel(dlg, text="Personal info  →  targeted wordlist",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=14, pady=(12, 2))
        ctk.CTkLabel(dlg, text="For auditing your OWN accounts/network. Fill what you know; leave the rest blank.",
                     text_color="#9ca3af", font=ctk.CTkFont(size=11), wraplength=430, justify="left").pack(anchor="w", padx=14)
        frm = ctk.CTkScrollableFrame(dlg, height=300); frm.pack(fill="both", expand=True, padx=10, pady=8)
        word_fields = ["First name", "Surname", "Nickname", "Partner", "Pet",
                       "Company / SSID", "City", "Keyword 1", "Keyword 2"]
        num_fields = ["Birth year", "Other year", "Numbers (comma-sep)"]
        vars_w, vars_n = {}, {}
        rr = 0
        for lbl in word_fields:
            ctk.CTkLabel(frm, text=lbl, width=120, anchor="w").grid(row=rr, column=0, padx=6, pady=3, sticky="w")
            v = ctk.StringVar(); ctk.CTkEntry(frm, textvariable=v, width=250).grid(row=rr, column=1, padx=6, pady=3)
            vars_w[lbl] = v; rr += 1
        for lbl in num_fields:
            ctk.CTkLabel(frm, text=lbl, width=120, anchor="w").grid(row=rr, column=0, padx=6, pady=3, sticky="w")
            v = ctk.StringVar(); ctk.CTkEntry(frm, textvariable=v, width=250, placeholder_text="e.g. 1998, 0402").grid(row=rr, column=1, padx=6, pady=3)
            vars_n[lbl] = v; rr += 1

        optf = ctk.CTkFrame(dlg, fg_color="transparent"); optf.pack(fill="x", padx=12)
        leet_v = ctk.BooleanVar(value=True); spec_v = ctk.BooleanVar(value=True)
        comb_v = ctk.BooleanVar(value=True); ge8_v = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(optf, text="leet (a→@)", variable=leet_v).grid(row=0, column=0, padx=4, pady=6)
        ctk.CTkCheckBox(optf, text="specials", variable=spec_v).grid(row=0, column=1, padx=4)
        ctk.CTkCheckBox(optf, text="combine", variable=comb_v).grid(row=0, column=2, padx=4)
        ctk.CTkCheckBox(optf, text="≥8 (WPA)", variable=ge8_v).grid(row=0, column=3, padx=4)

        def go():
            words = [v.get() for v in vars_w.values()]
            nums = []
            for v in vars_n.values():
                nums += v.get().replace(",", " ").split()
            wl = build_profile_wordlist(words, nums, {
                "leet": leet_v.get(), "specials": spec_v.get(),
                "combine": comb_v.get(), "min_len": 8 if ge8_v.get() else 0})
            if not wl:
                messagebox.showwarning(APP_NAME, "Nothing generated — fill at least a name or a number.")
                return
            out = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="targeted.txt",
                                               initialdir=cfg.get("wordlist_dir"))
            if not out:
                return
            try:
                with open(out, "w", encoding="utf-8") as f:
                    f.write("\n".join(wl) + "\n")
            except Exception as e:
                messagebox.showerror(APP_NAME, str(e)); return
            set_status("Targeted wordlist: %s candidates → %s" % (human_count(len(wl)), os.path.basename(out)))
            if messagebox.askyesno(APP_NAME, "Wrote %s candidates →\n%s\n\nUse it now as a Dictionary wordlist?"
                                   % (human_count(len(wl)), out)):
                if out not in state["wordlists"]:
                    state["wordlists"].append(out); refresh_wl()
                attack_var.set("Dictionary"); update_preview()
            dlg.destroy()
        ctk.CTkButton(dlg, text="Generate & save…", command=go).pack(pady=(4, 12))

    def show_tools_info():
        info = ["Detected tools:"]
        for k, v in tools.items():
            info.append(f"  {k:16s}: {v or 'NOT FOUND'}")
        info.append("")
        try:
            g = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"],
                               capture_output=True, text=True, timeout=8)
            info.append("GPU: " + (g.stdout.strip() or "n/a"))
        except Exception:
            info.append("GPU: nvidia-smi not available")
        messagebox.showinfo(APP_NAME + " · environment", "\n".join(info))

    tool_row("Benchmark GPU (mode 22000)", "Measure WPA hashes/sec on your GPU.", "Run benchmark", do_benchmark)
    tool_row("Benchmark all Wi-Fi modes", "Benchmark 22000 / 22001 / 16800 in one run.", "Run full benchmark", do_benchmark_all)
    tool_row("List targets in .hc22000", "Parse the selected target file -> ESSID / type / AP-MAC.", "Show targets", do_targets)
    tool_row("List networks in capture", "Show handshakes/ESSIDs in the selected .pcap (hcxpcapngtool).", "Analyze capture", do_identify)
    tool_row("Wordlist stats", "Count lines, usable length >= 8, min/avg/max length.", "Analyze a wordlist…", do_stats)
    tool_row("Merge + dedupe wordlists", "Combine several wordlists into one unique list.", "Merge…", do_merge)
    tool_row("Mutate wordlist (+digits/years)", "Append 1/123/!/1970-2030 to each word, keep len >= 8.", "Mutate…", do_mutate)
    tool_row("Generate pattern / phone list", "prefix + N digits (e.g. 040 + 6) -> wordlist file.", "Generate…", do_genpattern)
    tool_row("Targeted wordlist (name, year, …)", "CUPP-style: build a wordlist from personal info you provide.", "Create…", do_wordlist_gen)
    def do_extract():
        if not cfg.get("john_dir"):
            messagebox.showinfo(APP_NAME, "Set the John-the-Ripper 'run' folder in Settings (john_dir).\n"
                                "Get JtR jumbo (its Windows build ships the *2john tools): openwall.com/john")
            return
        dlg = ctk.CTkToplevel(app); dlg.title("Extract hash from file"); dlg.geometry("440x190")
        ctk.CTkLabel(dlg, text="File type").pack(anchor="w", padx=12, pady=(12, 0))
        tv = ctk.StringVar(value=EXTRACTORS[0][0])
        ctk.CTkOptionMenu(dlg, variable=tv, values=[e[0] for e in EXTRACTORS], width=380).pack(padx=12)

        def go():
            entry = next(e for e in EXTRACTORS if e[0] == tv.get())
            tool = find_extractor(cfg.get("john_dir"), entry[1])
            if not tool:
                messagebox.showwarning(APP_NAME, "Tool not found in john_dir: %s" % entry[1]); return
            infile = filedialog.askopenfilename(title="File to extract a hash from")
            if not infile:
                return
            out = infile + ".hash.txt"
            set_status("Extracting hash …")
            try:
                r = subprocess.run(build_extractor_cmd(tool, infile), capture_output=True, text=True,
                                   timeout=180, creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            except Exception as ex:
                messagebox.showerror(APP_NAME, str(ex)); return
            h = clean_john_hash(r.stdout or "")
            if not h:
                messagebox.showerror(APP_NAME, "No hash produced.\n" + (r.stderr or "")[:400]); return
            with open(out, "w", encoding="utf-8") as f:
                f.write(h + "\n")
            state["hashfile"] = out
            if out not in state["captures"]:
                state["captures"].append(out); refresh_caplist()
            # auto-select the matching hashcat mode when the signature is recognised
            picked = ""
            mode = guess_hc_mode(h)
            if mode:
                for lbl, mm in HASH_MODES:
                    if mm == mode:
                        hashmode_var.set(lbl); picked = lbl; break
            target_lbl.configure(text=_target_text()); update_preview()
            set_status("Extracted → %s" % os.path.basename(out))
            messagebox.showinfo(APP_NAME,
                "Extracted hash → %s  (set as target).\n\n%s\nSuggested -m: %s"
                % (os.path.basename(out),
                   ("Hash type auto-set to:  %s" % picked) if picked else "Now pick the Hash type on tab 2.",
                   entry[2]))
            dlg.destroy()
        ctk.CTkButton(dlg, text="Choose file & extract…", command=go).pack(pady=16)

    tool_row("Extract hash from file (zip/rar/office/pdf/…)",
             "Run John's *2john tools to pull a crackable hash out of a file, then set it as target.",
             "Extract…", do_extract)

    def do_identify_hash():
        if not state["hashfile"] or not tools["hashcat"]:
            messagebox.showinfo(APP_NAME, "Load a hash file (tab 1) and set hashcat path in Settings."); return
        tabs.set("3 · Run"); _run_cmd([tools["hashcat"], "--identify", state["hashfile"]])

    tool_row("Identify hash mode", "hashcat --identify on the loaded hash file → suggests -m numbers.", "Identify", do_identify_hash)

    def do_pmk_info():
        messagebox.showinfo(APP_NAME + " · precomputed PMK",
                            "Rainbow tables do NOT work for WPA (the salt is the ESSID).\n\n"
                            "Per-network alternative - precompute PMKs for ONE ESSID, then crack fast:\n"
                            "  coWPAtty:  genpmk -f wordlist -d out.pmk -s \"ESSID\"\n"
                            "  or hashcat -m 2501 (WPA-PMK) with precomputed PMKs.\n\n"
                            "Only worth it when cracking the same network repeatedly.")

    tool_row("Precomputed PMK (WPA 'rainbow')", "Why rainbow tables don't apply to WPA + the per-ESSID alternative.", "Explain", do_pmk_info)
    tool_row("Environment / tool check", "Show detected tool paths and GPU info.", "Show info", show_tools_info)

    # ======================= TAB 6: SETTINGS ============================
    t6 = tabs.tab("Settings")
    sf = ctk.CTkScrollableFrame(t6); sf.pack(fill="both", expand=True, padx=6, pady=6)
    setting_vars = {}

    def setting_row(label, key, browse="file"):
        f = ctk.CTkFrame(sf, fg_color="transparent"); f.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(f, text=label, width=170, anchor="w").pack(side="left", padx=6)
        var = ctk.StringVar(value=cfg.get(key, "")); setting_vars[key] = var
        ctk.CTkEntry(f, textvariable=var, width=520).pack(side="left", padx=6)
        if browse:
            ctk.CTkButton(f, text="…", width=36,
                          command=lambda: var.set((filedialog.askopenfilename() if browse == "file" else filedialog.askdirectory()) or var.get())).pack(side="left", padx=4)

    setting_row("hashcat.exe", "hashcat_path", "file")
    setting_row("hcxpcapngtool.exe", "hcxpcapngtool_path", "file")
    setting_row("aircrack-ng.exe", "aircrack_path", "file")
    setting_row("Wordlist folder", "wordlist_dir", "dir")
    setting_row("Loot folder (SMB)", "loot_dir", "dir")
    setting_row("Rules folder", "rules_dir", "dir")
    setting_row("Extra hashcat flags", "extra_flags", None)
    setting_row("princeprocessor (pp64.exe)", "prince_path", "file")
    setting_row("kwprocessor (kwp.exe)", "kwp_path", "file")
    setting_row("kwp base file", "kwp_base", "file")
    setting_row("kwp keymap file", "kwp_keymap", "file")
    setting_row("kwp route file", "kwp_route", "file")
    setting_row("PCFG guesser (.py/.exe)", "pcfg_path", "file")
    setting_row("PCFG ruleset dir", "pcfg_ruleset", "dir")
    setting_row("John run/ folder (*2john tools)", "john_dir", "dir")
    setting_row("Server host (SSH convert)", "server_host", None)
    setting_row("Server user", "server_user", None)
    setting_row("Server SSH key", "server_key", "file")
    setting_row("Server hcxpcapngtool", "server_hcx", None)
    setting_row("Phone push — ntfy.sh topic", "ntfy_topic", None)
    notif_f = ctk.CTkFrame(sf, fg_color="transparent"); notif_f.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(notif_f, text="Notify on finish", width=170, anchor="w").pack(side="left", padx=6)
    notify_snd_var = ctk.BooleanVar(value=bool(cfg.get("notify_sound", True)))
    ctk.CTkCheckBox(notif_f, text="sound + alert when a job finishes / cracks a password",
                    variable=notify_snd_var).pack(side="left", padx=6)
    theme_f = ctk.CTkFrame(sf, fg_color="transparent"); theme_f.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(theme_f, text="Theme", width=170, anchor="w").pack(side="left", padx=6)
    theme_var = ctk.StringVar(value=cfg.get("theme", "dark"))
    ctk.CTkOptionMenu(theme_f, variable=theme_var, values=["dark", "light", "system"],
                      command=lambda v: ctk.set_appearance_mode(v)).pack(side="left", padx=6)

    def save_settings():
        for k, v in setting_vars.items():
            cfg.set(k, v.get())
        cfg.set("theme", theme_var.get()); cfg.set("workload", workload_var.get())
        cfg.set("notify_sound", notify_snd_var.get()); cfg.save()
        tools.update(locate_all(cfg)); set_status("Settings saved. Tools re-detected.")
        messagebox.showinfo(APP_NAME, "Saved.\nhashcat: %s\nhcxtools: %s\naircrack: %s" %
                            (tools["hashcat"] or "—", tools["hcxpcapngtool"] or "—", tools["aircrack"] or "—"))

    ctk.CTkButton(sf, text="💾 Save settings", command=save_settings, width=160).pack(anchor="w", padx=10, pady=10)
    ctk.CTkButton(sf, text="🔎 Auto-detect tools now",
                  command=lambda: (tools.update(locate_all(cfg)), show_tools_info())).pack(anchor="w", padx=10)

    def _count_cracked():
        seen = set()
        for f in (OUTFILE_PATH, POTFILE_PATH):
            try:
                if f.exists():
                    for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
                        if ln.strip():
                            _, pw, _ = parse_crack_line(ln)
                            if pw:
                                seen.add(pw)
            except Exception:
                pass
        return len(seen)

    def _flash():
        try:
            app.deiconify(); app.lift(); app.attributes("-topmost", True)
            app.after(1500, lambda: app.attributes("-topmost", False))
        except Exception:
            pass

    def _measure_speed(mode):
        hc = tools.get("hashcat")
        if not hc:
            return 0.0
        try:
            r = subprocess.run([hc, "-b", "-m", str(mode)], cwd=_cwd_for([hc]),
                               capture_output=True, text=True, timeout=180,
                               creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            return parse_bench_speed(r.stdout or "")
        except Exception:
            return 0.0

    def do_estimate():
        if engine_var.get().startswith("aircrack"):
            messagebox.showinfo(APP_NAME, "Estimate is for hashcat attacks."); return
        atk = _attack_key()
        n = estimate_candidates(atk, state["wordlists"], rules_var.get(), mask_var.get())
        if not n:
            messagebox.showinfo(APP_NAME, "Can't estimate this attack.\n(Need a wordlist/mask; PRINCE/PCFG keyspace isn't known up front.)")
            return
        mode = _hash_mode()
        set_status("Estimating… measuring GPU speed for -m %s (a few seconds)…" % mode)

        def worker():
            speed = bench_speed.get(mode) or _measure_speed(mode)
            if speed:
                bench_speed[mode] = speed
                msg = ("Attack: %s\nCandidates: %s\nGPU speed: %s H/s  (-m %s)\n\n"
                       "➤  Estimated time:  ~%s" %
                       (atk, human_count(n), human_count(speed), mode, fmt_duration(n / speed)))
            else:
                msg = "Candidates: %s\n\nCould not measure GPU speed — run a benchmark first (Tools)." % human_count(n)
            ev.put(("estimate", msg))
        threading.Thread(target=worker, daemon=True).start()

    def do_restore():
        hc = tools.get("hashcat")
        if not hc:
            messagebox.showwarning(APP_NAME, "hashcat not found (Settings)."); return
        if runner.is_running():
            messagebox.showinfo(APP_NAME, "A job is already running."); return
        sess = session_var.get().strip() or "pinecrack"
        tabs.set("3 · Run"); set_status("Resuming session '%s'…" % sess)
        state["run_before"] = _count_cracked()
        _run_cmd([hc, "--session", sess, "--restore"])

    def start_auto():
        if runner.is_running():
            messagebox.showinfo(APP_NAME, "A job is already running."); return
        if not state["hashfile"]:
            messagebox.showwarning(APP_NAME, "Select/convert a target hash first (tab 1)."); return
        names = sorted((cfg.get("profiles", {}) or {}).keys())
        if not names:
            messagebox.showwarning(APP_NAME, "No profiles saved (Attack tab → Save)."); return
        autostate.update({"active": True, "queue": names, "idx": 0})
        set_status("⚡ Auto-crack 1/%d — %s" % (len(names), names[0]))
        apply_profile_by_name(names[0])
        app.after(350, start_attack)

    def _auto_advance(cracked_now):
        if not autostate["active"]:
            return
        if cracked_now:
            autostate["active"] = False
            set_status("⚡ Auto-crack: PASSWORD FOUND ✅")
            notify(cfg, APP_NAME, "Auto-crack found the password!", cracked=True); _flash()
            return
        autostate["idx"] += 1
        if autostate["idx"] >= len(autostate["queue"]):
            autostate["active"] = False
            set_status("⚡ Auto-crack: all profiles done — not found.")
            notify(cfg, APP_NAME, "Auto-crack finished — password not found.", cracked=False)
            return
        name = autostate["queue"][autostate["idx"]]
        set_status("⚡ Auto-crack %d/%d — %s" % (autostate["idx"] + 1, len(autostate["queue"]), name))
        apply_profile_by_name(name)
        app.after(600, start_attack)

    def pump():
        try:
            while True:
                kind, payload = ev.get_nowait()
                if kind == "log":
                    log(payload)
                elif kind == "cmd":
                    log("$ " + payload)
                elif kind == "error":
                    log("[ERROR] " + payload)
                elif kind == "status":
                    _apply_status(payload)
                elif kind == "converted":
                    state["hashfile"] = payload
                    if payload not in state["captures"]:
                        state["captures"].append(payload); refresh_caplist()
                    target_lbl.configure(text=_target_text()); update_preview()
                    set_status("Converted on server → %s" % os.path.basename(payload))
                elif kind == "estimate":
                    set_status("Ready.")
                    messagebox.showinfo(APP_NAME + " · time estimate", payload)
                elif kind == "done":
                    log("\n[finished, exit code %s]" % payload)
                    refresh_results()
                    cracked_now = _count_cracked() > state.get("run_before", 0)
                    if autostate["active"]:
                        _auto_advance(cracked_now)
                    else:
                        set_status("Done (exit %s)." % payload)
                        if cracked_now:
                            notify(cfg, APP_NAME, "Password cracked!", cracked=True); _flash()
                        elif cfg.get("notify_sound", True):
                            notify(cfg, APP_NAME, "Job finished — no crack.", cracked=False)
        except queue.Empty:
            pass
        app.after(200, pump)

    def _apply_status(js):
        try:
            speed = sum(d.get("speed", 0) for d in js.get("devices", []))
            stat_vars["Speed"].configure(text=human_count(speed) + "H/s")
            if speed > 0:
                bench_speed[_hash_mode()] = speed   # feeds the ⏱ Estimate
            prog = js.get("progress", [0, 0])
            if prog and prog[1]:
                frac = prog[0] / prog[1]; progress.set(min(1.0, frac))
                stat_vars["Progress"].configure(text="%.2f%%" % (frac * 100))
            # ETA = time LEFT. hashcat's estimated_stop is a Unix timestamp;
            # convert it to a remaining duration, else derive from speed + progress.
            eta_txt = "—"
            est = js.get("estimated_stop")
            now = time.time()
            if isinstance(est, (int, float)) and est > now + 1:
                eta_txt = fmt_duration(est - now)
            elif speed > 0 and prog and len(prog) > 1 and prog[1] > prog[0]:
                eta_txt = fmt_duration((prog[1] - prog[0]) / speed)
            elif prog and len(prog) > 1 and prog[1] and prog[0] >= prog[1]:
                eta_txt = "done"
            stat_vars["ETA"].configure(text=eta_txt)
            rec = js.get("recovered_hashes", [0, 0])
            stat_vars["Recovered"].configure(text="%s/%s" % (rec[0], rec[1]))
            temps = [d.get("temp", -1) for d in js.get("devices", []) if d.get("temp", -1) >= 0]
            if temps:
                stat_vars["GPU temp"].configure(text="%d°C" % max(temps))
        except Exception:
            pass

    try:
        g = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                           capture_output=True, text=True, timeout=6)
        if g.stdout.strip():
            gpu_lbl.configure(text="GPU: " + g.stdout.strip().splitlines()[0])
    except Exception:
        pass

    if not tools["hashcat"]:
        set_status("hashcat not detected -> Settings -> set its path (see README).")
    update_preview(); refresh_results(); app.after(200, pump); app.mainloop()
    return 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    return run_gui()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
