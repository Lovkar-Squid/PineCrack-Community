# Changelog — PineCrack Community

All notable changes to the Community edition. Dates are release dates.

## v2.3 — 2026-07-25

**Added**
- ⟳ **In-app updater** — a **"Check for updates"** button in the sidebar checks GitHub for a
  newer release; if one exists it downloads the installer and launches it for you. It also runs
  a quiet check on launch and only prompts when an update is actually available. Point it at your
  own server instead by setting the `PINECRACK_UPDATE_URL` environment variable to a JSON manifest.

## v2.2 — 2026-07-25

The first big update since the public release. The `.exe`/installer are now essentially
self-contained, and hash extraction from archives works.

**Added**
- 🍓 **Strawberry Perl support** — John the Ripper's `.pl` hash extractors now work
  (e.g. `7z2john.pl`), so you can pull a crackable hash out of a **password-protected 7‑Zip**
  archive (and other niche `.pl` types) and crack it with hashcat. Optional: tick
  *"Install Strawberry Perl"* in the installer, or run **Start Menu → "PineCrack – Install Perl"**.
- 📦 **Advanced tools bundled in the `.exe`** — PRINCE (`princeprocessor`), keyboard‑walk
  (`kwprocessor`), `statsprocessor`, **PCFG**, and **John the Ripper Jumbo** now ship inside the
  application, so those attacks/extractors work out of the box.
- ⬇️ **Installer downloads the cracking engine** — optionally fetches **hashcat** + **aircrack‑ng**
  from their official sites during setup (falls back to your own server if the official download
  fails), extracts them to `C:\hashcat` / `C:\aircrack-ng`, and wires the paths automatically.
- 🔄 **Local `.pcap` conversion via WSL + hcxtools** — the installer can set up WSL + hcxtools for
  you, so `.pcap`/`.cap → .hc22000` conversion runs locally with no server. Captures on a **network
  share (UNC `\\server\share`) are copied locally first**, and a failed convert now shows
  hcxpcapngtool's real report (so "no handshake" vs. a path problem is obvious).

**Changed**
- The convert button is now labelled **"Convert .pcap"** (the Community edition converts locally only).

**Fixed**
- Installer: the Wordlist / Capture folder fields now **accept a blank value** (= use the bundled
  starter wordlists) instead of erroring.
- WSL setup: the *"Verifying…"* step no longer hangs.

## v2.1 — 2026-07-24 · initial public release

- Modern dashboard GUI (`customtkinter`): live speed / progress / ETA / recovered / GPU‑temp cards
  and a live speed graph.
- Attacks: dictionary, rules (with rule‑stacking), mask / brute‑force (with increment), hybrid,
  combinator, PRINCE, keyboard‑walk, PCFG — any hashcat `-m` mode.
- ⚡ Auto‑crack pipeline, ≡ job queue, 🗂 sessions (stop + restore), 🕘 crack history + chart.
- 👁 Watch‑folder auto‑convert + auto‑crack, 🩺 handshake quality check, ⏱ pre‑run time estimate,
  🌡 GPU temp guard, GPU picker.
- Targeted wordlist creator (name/surname/year → leet variants), hash extractor
  (zip / office / pdf / keepass / …), robust offline hash identifier.
- Local `.pcap → .hc22000` conversion (hcxpcapngtool / WSL+hcxtools).
- Bundled starter wordlists (`common-passwords.txt`, `top-10k.txt`).

---

### Editions

**Community** (this repo) is the public, MIT‑licensed edition focused on Wi‑Fi cracking.
A separate personal build additionally includes a **hashcat Brain** toggle (skips
already‑tried candidates across runs) and server‑side conversion — those are not part of the
Community edition.
