# PineCrack — Community Edition

A modern, GUI front-end for **hashcat / aircrack-ng / hcxtools** that makes recovering
WPA/WPA2 Wi-Fi passwords (and many other hash types) from captured handshakes fast and friendly.

Dark, dashboard-style interface built with `customtkinter`. Point it at a handshake and a
wordlist and go — with live speed/ETA, an auto-crack pipeline, a job queue, crack history, and more.

> ## ⚠️ Legal — authorized use only
> PineCrack is for **security research, education, and testing networks/files you own or are
> explicitly permitted to assess**. Cracking Wi-Fi or hashes you are not authorized to test is
> illegal in most countries. **You are solely responsible for how you use this tool.**

---

## 💬 Community & support

Get help, report bugs, and hear about new releases on our Discord:

**➡️ https://discord.gg/bfS674hZ**

---

## ✨ Features

- **Dashboard** with live stat cards (speed / progress / ETA / recovered / GPU temp) and a live speed graph
- **Attacks:** dictionary, rules (with rule stacking), mask / brute-force (with increment), hybrid, combinator, PRINCE, keyboard-walk, PCFG — any hashcat `-m` mode
- **⚡ Auto-crack pipeline** — runs your profiles in order, stops when it cracks
- **≡ Job queue** — line up several targets/attacks, run them back-to-back (overnight)
- **🗂 Sessions** — Stop and later ♻ Restore from the last checkpoint
- **🕘 Crack history** — persistent log + per-day chart + CSV export
- **👁 Watch-folder** — drop a new capture in your loot folder → auto-convert + auto-crack
- **🩺 Handshake check**, **⏱ pre-run time estimate**, **🌡 GPU temp guard**, GPU picker
- **Targeted wordlist creator** (name/surname/year → leet variants), **hash extractor** (zip/office/pdf/keepass…), robust offline **hash identifier**
- Desktop notifications (sound + optional ntfy phone push)
- **Starter wordlists included** (`common-passwords.txt`, `top-10k.txt`)

## 🧩 Requirements

- **[hashcat](https://hashcat.net)** installed (e.g. `C:\hashcat`) — the actual cracking engine
- An **NVIDIA/AMD GPU + drivers** (CPU works but is slow)
- To run from source: **Python 3.11+** (the `.exe` needs no Python)
- **Optional — only for converting `.pcap`/`.cap` captures to `.hc22000`:**
  PineCrack looks for a converter in this order → a local **`hcxpcapngtool.exe`** (set its path in Settings)
  → **WSL + hcxtools** → an **SSH server** (if you configure one in Settings).
  The Windows installer can set up **WSL + hcxtools** for you automatically — just tick
  *“Set up WSL + hcxtools”* during setup. If you already have `.hc22000` files, you don’t need any of this.

## 📦 What's included — installer/exe vs. running from source

**The Release `.exe` and the installer are self-contained.** They bundle:

- the starter wordlists (`common-passwords.txt`, `top-10k.txt`), and
- the advanced candidate generators + extractors: **PRINCE** (princeprocessor), **keyboard-walk** (kwprocessor), **statsprocessor**, **PCFG**, and **John the Ripper Jumbo** (the `*2john` hash extractors).

You only add **hashcat** yourself (the cracking engine), and optionally **WSL + hcxtools** for `.pcap`
conversion and **Strawberry Perl** for John's `.pl` extractors (7‑Zip archives). All three are offered as
**installer checkboxes** (hashcat + aircrack‑ng from official sites, WSL + hcxtools, Strawberry Perl), or
as *"PineCrack – Install …"* Start‑Menu shortcuts you can run later.

> ### ⚠️ Running from source (`git clone`) does **not** include everything
> To keep the repository small, the **213 MB `tools/` folder and the built `.exe` are not committed to git**.
> A clone gives you the app **plus the starter wordlists only**. If you run from source you must install
> anything you want to use and set its path in **Settings → tool paths**:
>
> - **hashcat** (required) — <https://hashcat.net>
> - **hcxpcapngtool** or **WSL + hcxtools** — for `.pcap → .hc22000` conversion
> - **PRINCE / kwprocessor / statsprocessor** — <https://github.com/hashcat>
> - **PCFG cracker** — <https://github.com/lakiw/pcfg_cracker>
> - **John the Ripper Jumbo** (zip/office/pdf/keepass extraction) — <https://www.openwall.com/john/>
>
> **TL;DR — want everything out of the box? Use the installer or the `.exe`.** Running from source is for
> developers who don't mind installing the back-end tools themselves.

## 🚀 Quick start

**Option A — run from source**
```bat
git clone https://github.com/Lovkar-Squid/PineCrack-Community.git
cd PineCrack-Community
run.bat            :: installs customtkinter + paramiko, then launches
```

**Option B — download the `.exe`** from the [Releases](../../releases) page and run it. No Python needed.

Then in the app: **Settings** → set your **hashcat path** (auto-detected if in `C:\hashcat`),
your **Wordlist folder** and **Loot/handshake folder**. The bundled starter wordlists work out of the box.

## 🔑 Cracking a Wi-Fi handshake

1. **Target** → import your `.hc22000` (or a `.pcap`/`.cap` → **Convert**) → **Use selected**
2. **Attack** → pick a profile (or attack + wordlist) — e.g. `common-passwords.txt` + `best66` rules
3. **Start** (or **⚡ Auto-crack**) → watch the Dashboard → cracked password appears in **Results**

## 🔄 Converting `.pcap` / `.cap` captures to `.hc22000`

hashcat cracks the `.hc22000` format, so raw Wi-Fi captures must be converted first.
Click **Convert** on the **Target** page and PineCrack picks the first available method:

1. **Local `hcxpcapngtool.exe`** — set its path in **Settings** (fastest if you already have hcxtools on Windows).
2. **WSL + hcxtools** — no Windows binary needed. Set it up once, either:
   - tick **“Set up WSL + hcxtools”** in the installer, **or**
   - run **Start Menu → “PineCrack – Set up WSL”** (installs Ubuntu + `apt install hcxtools`).
   A first-time WSL install may ask you to **restart Windows**, then re-run that shortcut.
3. **SSH server** — optional; if you fill in host/user/key in **Settings**, conversion runs on that machine.

> Tip: WSL converts files on your local drives (`C:\`, `D:\`). Copy captures off a network share first —
> WSL can’t read `\\server\share` paths.

## 🛠 Building the `.exe` yourself

```bat
build_exe.bat      :: PyInstaller onefile with icon, version, config + wordlists bundled
```

## 🤝 Contributing

Issues and PRs welcome. Keep it cross-platform-friendly where possible; the cracking back-ends
(hashcat/aircrack/hcxtools) are external tools the app orchestrates.

## 📜 Version history

See **[CHANGELOG.md](CHANGELOG.md)** for what changed in each release (current: **v2.2**).

## 📄 License

[MIT](LICENSE) — and, again: **authorized testing only.**

The installer/`.exe` bundle third-party tools that each keep **their own license**:
hashcat-utils, **princeprocessor**, **kwprocessor**, **statsprocessor** (MIT), **PCFG cracker** (GNU GPL),
and **John the Ripper Jumbo** (GPLv2). hashcat itself is MIT and is installed separately by the user.
These are unmodified redistributions — see each upstream project for its full license text.
