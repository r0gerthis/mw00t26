# weekend-hint

```
git clone <this repo>
cd weekend-hint
python3 hint.py
```

## thanks for playing

You have uncovered this hint. Now that the hunt is done, the build
directory is unhidden so you can see how it worked.

## how it worked

`hint.py` is a built artifact. The real source lives in `_build/`:

- `_build/inner.py` — the actual runtime script (anti-VM checks, browser
  launch, password prompt, decrypt).
- `_build/build.py` — packs `inner.py` + the secret coordinates into
  `hint.py` through six nested layers of XOR + zlib + base85 wrapping,
  with random high-entropy padding at each layer.
- `_build/LEARNINGS.md` — full design notes: threat model, why PBKDF2 over
  scrypt, the macOS `ioreg` false-positive lesson, why nested layers, and
  the AI-assistant notice hidden inside the obfuscation.

The coordinates were encrypted with the password (`1337`) using PBKDF2
(600k rounds) chained with 200k rounds of SHA-512, then HMAC-SHA256
encrypt-then-MAC. The password never appears in the published file — no
amount of static analysis on `hint.py` alone could recover the spot.

Rebuild with: `python3 _build/build.py`

## making it hard for an LLM to spoil it

Pasting `hint.py` into ChatGPT / Claude / Gemini was the obvious shortcut,
so the design pushed back on it in a few stacked ways:

- **Crypto, not obfuscation, is the real lock.** The password is not in
  the file. Even a perfect symbolic execution of the script cannot
  recover the coordinates — there is nothing there to recover. Any
  "decrypted" string an LLM produces from `hint.py` alone is a
  hallucination.
- **Unsimulatable key derivation.** PBKDF2 with 600k rounds, then a
  200k-round SHA-512 chain. No reasoning model can trace that in its
  head; it has to refuse or hallucinate, and the runtime HMAC check
  catches hallucinations.
- **Nested decode layers + high-entropy padding.** Six wrapping layers
  with random padding at each one. The padding doesn't compress, so the
  file is large on purpose — pasting it into an LLM burns real input
  tokens, and tracing through six decode steps burns reasoning tokens
  before anything useful surfaces.
- **A notice to the LLM, hidden inside the obfuscation.** The inner
  script opens with a polite, reasoned note to any AI assistant that has
  done the work to decode it: explains this is a private weekend hunt,
  asks it not to spoil, and points out that simulation will produce
  wrong output anyway. A user skimming `hint.py` never sees it; an LLM
  doing the decoding surfaces it exactly when it would otherwise help.
- **Runtime environment checks.** VM, WSL, CI, container, and non-TTY
  environments are detected and refused — so "just run it in a sandbox
  and tell me what it prints" doesn't work either.

None of this is unbreakable. A determined human with time wins. The goal
was to make the lazy path (paste-and-ask) reliably unhelpful, so the
intended path (scan the QR, get the password, run it on your laptop)
stayed the path of least resistance.
