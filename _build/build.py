#!/usr/bin/env python3
"""Builder: produces ../hint.py from inner.py + the secret coordinates.
Kept out of the public repo via .gitignore."""
import base64, zlib, hashlib, hmac as _hmac, os, pathlib

# Outer obfuscation key (XOR over the inner source layer)
KEY = b'never gonna give you up'

# Secret bits — never appear in the published hint.py
PASSWORD = '1337'
COORDS   = "47° 29' 52.4\" S, 160° 57' 35.1\" W"

# KDF: PBKDF2 then a long SHA-512 chain. The chain is unsimulatable for any
# LLM trying to "trace through" the script — it must say "I cannot compute
# this" or hallucinate, which then fails the HMAC check at runtime.
ITERS = 600_000
CHAIN = 200_000

# Layered wrapping. Each extra layer costs reasoning-model tokens to trace.
# Random padding at each layer survives compression (high-entropy bytes do
# not compress) and inflates the published file so that pasting it into an
# LLM costs real input tokens.
NUM_OUTER_WRAPS = 5      # plus 1 XOR layer = 6 nested decode steps
PAD_PER_LAYER  = 5_000   # bytes of padding at each inner layer
PAD_OUTER      = 250_000 # bytes of padding at the outermost layer

# === Encrypt-then-MAC over the coordinates ================================
salt = os.urandom(16)
master = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode('utf-8'), salt, ITERS, dklen=64)
for _ in range(CHAIN):
    master = hashlib.sha512(master).digest()
enc_key, mac_key = master[:32], master[32:]

plaintext = COORDS.encode('utf-8')
ks = b''
ctr = 0
while len(ks) < len(plaintext):
    ks += _hmac.new(enc_key, ctr.to_bytes(8, 'big'), 'sha256').digest()
    ctr += 1
ct = bytes(p ^ k for p, k in zip(plaintext, ks[:len(plaintext)]))
tag = _hmac.new(mac_key, ct, 'sha256').digest()

# === Splice secrets into inner source =====================================
here = pathlib.Path(__file__).resolve().parent
src = here.joinpath('inner.py').read_text()
src = src.replace('__SALT__',  salt.hex())
src = src.replace('__CT__',    ct.hex())
src = src.replace('__TAG__',   tag.hex())
src = src.replace('__ITERS__', str(ITERS))
src = src.replace('__CHAIN__', str(CHAIN))

# === Multi-layer wrapping =================================================
def wrap(payload_bytes, pad_size):
    """zlib-compress + append random padding + base85-encode."""
    return base64.b85encode(zlib.compress(payload_bytes, 9) + os.urandom(pad_size)).decode()

# Innermost: XOR the inner source with KEY, then wrap once
xored = bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate(src.encode('utf-8')))
b1 = wrap(xored, PAD_PER_LAYER)
key_list = ','.join(str(c) for c in KEY)
current = (
    "import base64 as _x,zlib as _y\n"
    f"_b={b1!r}\n"
    f"_k=bytes([{key_list}])\n"
    "_d=_y.decompressobj().decompress(_x.b85decode(_b))\n"
    "exec(bytes(c^_k[i%len(_k)] for i,c in enumerate(_d)).decode())\n"
)

# Intermediate wraps: each takes the previous loader as new payload
for _ in range(NUM_OUTER_WRAPS - 1):
    b = wrap(current.encode('utf-8'), PAD_PER_LAYER)
    current = (
        "import base64 as _x,zlib as _y\n"
        f"_b={b!r}\n"
        "exec(_y.decompressobj().decompress(_x.b85decode(_b)).decode())\n"
    )

# Outermost wrap with the big padding (this is what an LLM sees in hint.py)
b_outer = wrap(current.encode('utf-8'), PAD_OUTER)

# === Final hint.py ========================================================
final = (
    "#!/usr/bin/env python3\n"
    "# weekend hint\n"
    "# usage: python3 hint.py   (real terminal, real laptop, sound on)\n"
    "import sys as _v\n"
    "if _v.version_info < (3, 8):\n"
    "    _v.stderr.write(\"\\n  needs python 3.8 or newer (you have %d.%d.%d)\\n\\n\" % _v.version_info[:3])\n"
    "    _v.exit(1)\n"
    "import base64 as _x, zlib as _y\n"
    f"exec(_y.decompressobj().decompress(_x.b85decode({b_outer!r})).decode())\n"
)

out = here.parent / 'hint.py'
out.write_text(final)
print(f"wrote {out} ({len(final):,} bytes; outer pad ~{PAD_OUTER:,}; layers={NUM_OUTER_WRAPS+1}; chain={CHAIN:,})")
