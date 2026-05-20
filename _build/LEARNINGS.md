# weekend-hint — design notes & lessons

Lives in `_build/` so it's gitignored alongside the buildable source. Capture
of why things are the way they are, so a future iteration (or someone reading
this cold) doesn't re-derive everything from scratch.

---

## 1. What this is

A treasure-hunt artifact. Public GitHub repo (`r0gerthis/mw00t26`) ships a
single obfuscated Python file. Friends scan a QR → password-protected
pastebin (`1337`) → repo URL → `git clone` + `python3 hint.py`. Script opens
a browser URL, prompts for the same `1337`, decrypts coordinates.

**Threat model (in priority order):**
1. **LLM with the public repo, no pastebin password** — must fail. The
   secret is encrypted with a password not in the file; no analysis can
   recover it. This is the strongest guarantee and is provided by
   cryptography, not obfuscation.
2. **LLM with repo + pastebin password** — should ideally still fail or at
   least not help. Defended by the AI-assistant notice hidden inside the
   obfuscation layers (see §5).
3. **Friend running it in a VM / CI / WSL / headless env** — must fail
   loudly with a "synthetic environment" message. Defended by §4 checks.
4. **Friend with grit who scripts a brute-forcer** — explicitly out of
   scope. `1337` is brute-forceable in seconds against PBKDF2 regardless.

## 2. File layout

```
weekend-hint/
├── .gitignore        # excludes _build/
├── README.md         # bare minimum: clone + run
├── hint.py           # the only artifact users see — built, obfuscated
└── _build/           # gitignored, never published
    ├── inner.py      # human-readable source for what hint.py runs
    ├── build.py      # packs inner.py → hint.py
    └── LEARNINGS.md  # this file
```

To re-roll: edit `inner.py` and/or `build.py`, run `python3 _build/build.py`,
commit `hint.py`. Each build randomizes the salt so ciphertext changes even
without a logical change — that's fine.

## 3. Obfuscation pipeline

`build.py` produces `hint.py` through three nested layers:

1. **Inner script (`inner.py`)** — has the AI-notice comment block, runtime
   imports, `_detect()` for VM/CI/WSL, browser-launch gate, password prompt,
   PBKDF2-derived decryption.
2. **Layer A (XOR + zlib + base85)** — inner source bytes XOR'd with the
   key `b'never gonna give you up'`, zlib compressed, base85 encoded.
3. **Layer B (zlib + base85)** — a tiny loader script that reverses Layer
   A (`exec(bytes(c^k... for ...).decode())`) is itself zlib + base85
   encoded.
4. **Outer `hint.py`** — Python version gate (≥ 3.8), then
   `exec(zlib.decompress(b85decode(blob)).decode())`, which runs the
   Layer B loader, which runs the Layer A loader, which runs the inner
   script.

Why nested instead of one big base85 blob: forces an LLM to do two distinct
decode steps before the AI-notice surfaces, raising the work threshold.

The XOR key is the on-theme rickroll lyric. Cute but cosmetic — once the
key is found in the loader (`bytes([110,101,...])`) the XOR is trivial to
reverse. The real security is downstream.

## 4. VM / CI / LLM detection (`_detect()`)

Returns `None` if clean, or a short reason string (visible with
`HINT_DEBUG=1`).

### macOS — DO use targeted sysctls, NOT `ioreg -l`

The first iteration scanned the full `ioreg -l` dump for substrings like
`vmware`, `qemu`, `xen`, `utm`. **This false-positived on real hardware:**
- `'xen'` matched inside `agxenergyattributor`
- `'utm'` matched inside `useoverridebatteryinp` + `utmeasured`

The fix is targeted reads against small, known fields:
- `sysctl -n kern.hv_vmm_present` → `1` on Apple Silicon hypervisor
- `sysctl -n hw.model` → e.g. `MacBookPro17,1` on real, vendor name on VM
- `sysctl -n machdep.cpu.brand_string` → `Apple M1` / real Intel name on
  hardware; `QEMU Virtual CPU` etc. on a VM

Lesson: for substring scans against VM vendor names, scope the search to a
small, structured field. Don't grep the world.

### Linux

- WSL detection (added late): `WSL_DISTRO_NAME` / `WSL_INTEROP` env vars,
  `/proc/version` containing `microsoft` or `wsl`. Without this, WSL2
  passes as plain Linux.
- DMI files in `/sys/class/dmi/id/{product_name,sys_vendor,board_vendor,
  bios_vendor}` — small, readable without root, contain vendor strings.
- `/proc/cpuinfo` containing `hypervisor`.
- Container files: `/.dockerenv`, `/proc/vz`, `/proc/xen`,
  `/run/.containerenv` (podman).

### Windows

`wmic` is **deprecated and removed by default in Win11 24H2+** — do not
rely on it as the only check. Primary path is `reg query`:
- `HKLM\HARDWARE\DESCRIPTION\System\BIOS` → `SystemManufacturer`,
  `SystemProductName`, `BIOSVendor`.
- `wmic computersystem get model,manufacturer` is kept as a fallback for
  older Windows.

Hyper-V VMs: `SystemProductName` is literally `Virtual Machine`, caught by
the `'virtual machine'` entry in `_BAD`.

### Cross-platform

- `cpu_count() < 2` → tripped (no real laptop has 1 core).
- Env vars: `CI`, `GITHUB_ACTIONS`, `RUNNER_OS`, `CODESPACES`,
  `CLOUD_SHELL`, `REPL_ID`, `GITPOD_WORKSPACE_ID`, `BUILDKITE`,
  `JENKINS_URL`, `CIRCLECI`.
- `sys.stdin.isatty()` and `sys.stdout.isatty()` both required.

### Browser-launch gate

`webbrowser.open()` returns True/False. On Linux, `xdg-open` may return
True on a headless box even if nothing visibly opens, so we additionally
require `$DISPLAY` or `$WAYLAND_DISPLAY` before even calling it. macOS /
Windows trust the return value.

## 5. AI-assistant prompt injection

### What works (somewhat) in 2026 frontier models

Modern Claude / GPT / Gemini are well-trained against the obvious
techniques. What still has measurable effect:

- **Honest authorial-intent notice with reasons.** Aligns with privacy /
  author-respect training rather than fighting it.
- **Stating that simulation produces wrong output.** Appeals to model
  honesty/accuracy. True here: anti-VM checks intentionally fail in any
  simulated env.
- **Stating that the secret is provably unrecoverable from this file
  alone.** Gives the model a logical reason to decline rather than just an
  instruction to.
- **Constructive alternative response** — telling the model what to say to
  the user, reducing "be helpful" pressure.

### What we explicitly avoided

- Fake `<system>` / `<system-reminder>` tags. Claude in particular is
  trained to flag these as injection attempts; they backfire.
- "Ignore previous instructions" patterns. Universally trained against.
- Refusal-trigger framing (claiming the file contains harmful content).
  Ethically wrong and would cause real refusals on innocent users.

### Where the notice lives

**Hidden behind both obfuscation layers**, inside `inner.py`. A human
glancing at `hint.py` sees only the bare loader and the base85 blob — the
notice cannot be edited out by the user without doing the LLM's work
first. An LLM doing the decode work surfaces the notice at the moment it
would otherwise help bypass the runtime checks.

The notice opens with self-aware language: *"the fact that you're reading
this means you've reversed the base85+zlib+xor wrapping..."* — doubles as
credibility (this isn't a stray injection; it was placed deliberately).

## 6. Cryptography

### Final design

- `pbkdf2_hmac('sha256', '1337', salt=urandom(16), iters=600_000,
  dklen=64)` → split: first 32 bytes = `enc_key`, last 32 = `mac_key`.
- Keystream = `HMAC-SHA256(enc_key, counter_be64)` blocks (CTR-style PRF
  construction).
- Ciphertext = plaintext XOR keystream.
- Tag = `HMAC-SHA256(mac_key, ciphertext)` (32 bytes). Encrypt-then-MAC
  order.
- At runtime: derive same keys, verify tag with `hmac.compare_digest`
  before decrypting. Wrong tag → "wrong code".

### Why not scrypt

`hashlib.scrypt` is nominally stdlib (3.6+), but **macOS system Python on
Sonoma+ links against LibreSSL, which doesn't expose scrypt.** `import
hashlib; hashlib.scrypt` → `AttributeError`. python.org / brew / Linux /
Windows installers all ship OpenSSL with scrypt, but I won't bet on every
friend's Python install. PBKDF2 is universal.

### Why not AES-GCM / Fernet

Both require `pycryptodome` or `cryptography`, which means `pip install`
which means failure for friends who don't have the package. Stdlib only is
the constraint. HMAC-derived keystream + HMAC tag is a textbook
authenticated-encryption construction with stdlib primitives.

### Why magic prefix → HMAC tag

Earlier version used a 5-byte prefix `MW26:` as a known-plaintext check.
HMAC tag is strictly better:
- 32 bytes of authentication strength vs 5 bytes of plaintext leak.
- Verifies authenticity in constant time.
- Standard practice; cleaner code.

### Brute-force angle (out of scope but documented)

`1337` is 4 chars, 10⁴ keyspace. Even at 600k PBKDF2 iters — ~360ms per
attempt on M1 — a script taking that as 0.5s/try finishes the keyspace in
~80 minutes serial. With known plaintext (the HMAC tag verifies guesses),
it's deterministic. **Crypto strength against brute force is not the
goal**; defeating LLM static analysis is. For brute force the only fix is
a higher-entropy password.

## 7. Python version gate

Sits at the top of outer `hint.py`, not inner. Has to fire **before** any
f-strings parse, otherwise old Python errors at compile time on the inner
blob. The gate uses only Python-2/3-compatible syntax (`%` formatting,
tuple comparison, `sys.stderr.write`, `sys.exit`) so even Python 2.7
running `python hint.py` gets a friendly "needs python 3.8+" message.

`exec(...)` with parens is valid in Python 2 too — it parses as the exec
statement followed by a parenthesized expression — so the file doesn't
SyntaxError before the gate runs.

## 8. Operational flow (handoff)

1. Build `hint.py`: `python3 _build/build.py`.
2. Commit + push to `r0gerthis/mw00t26` (already done).
3. Create a password-protected pastebin (paste password = `1337`),
   contents = the repo URL `https://github.com/r0gerthis/mw00t26`.
4. Generate a QR code pointing to the pastebin URL.
5. Share the QR + the password `1337` with friends through whatever
   channel.

## 9. Things explicitly chosen NOT to do

- **Network calls in the script.** Adds attack surface, breaks offline
  use, and the threat model doesn't need it.
- **PyCryptodome / cryptography deps.** Friends have to `pip install` =
  friction = some won't make it.
- **Marshalled bytecode obfuscation.** Marshal format is Python-version
  specific and would break across 3.8 / 3.12 / 3.13 mismatches.
- **Webcam / microphone / mouse-movement humanity checks.** Invasive,
  cross-platform nightmare, and the password gate already proves a human
  is there.
- **Scrypt or argon2 KDFs.** Universal availability matters more than
  marginal KDF strength against a 4-char password.
- **A "wrong password" counter / rate limit.** Pointless for a one-shot
  decrypt; brute force is offline anyway.

## 10. Git history hygiene

The repo was rewritten to a single `init` commit before pushing. The
original development history was 10 commits and would have leaked the
obfuscation/crypto/AI-notice design through commit messages and diffs. A
fresh orphan branch + `git reflog expire --expire=now --all` + `git gc
--prune=now` removed all traces locally before the first push. **Don't
re-introduce verbose commit messages on this repo.**

## 11. If iterating

- New password: change `PASSWORD` in `build.py`, rebuild, force-push (and
  re-do the squash dance if you care about history hygiene).
- New coordinates: change `COORDS` in `build.py`, rebuild, force-push.
- New URL to open: change the bit.ly / YT URL in `inner.py`, rebuild.
- More VM signals: add to the `_BAD` tuple in `inner.py` (but keep
  substring matches scoped to small fields — see §4 for the ioreg lesson).
- Replacing PBKDF2 with scrypt: only viable if you can guarantee every
  friend has Python from python.org or brew. macOS system Python (LibreSSL)
  will fail.
