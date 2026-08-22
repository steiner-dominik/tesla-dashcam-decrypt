# tesla-dashcam-decrypt

Batch-decrypt an entire Tesla `EncryptedClips` folder (firmware 2026.20+) on your
computer, into a sibling `DecryptedClips` folder. The original `EncryptedClips`
is only ever read — never modified.

---

> ## ⚠️ Not affiliated with Tesla
>
> **This is an independent, unofficial, community-built tool. It is NOT
> affiliated with, authorized by, endorsed by, sponsored by, or connected to
> Tesla, Inc. in any way.**
>
> "Tesla", "TeslaCam", "Sentry Mode" and "Dashcam" are trademarks of Tesla, Inc.,
> used here purely to describe what this tool interoperates with.
>
> Provided **as-is, without warranty of any kind**. Use it only on footage from a
> vehicle on your own Tesla account. You are responsible for complying with
> Tesla's terms of service and with any recording/privacy laws that apply where
> you live.

---

## 🙏 Credit

This project is built on the original reverse-engineering and decryptor by
**[@XGxF3](https://github.com/XGxF3)** — see
**[XGxF3/tesla-dashcam-decrypt](https://github.com/XGxF3/tesla-dashcam-decrypt)**
and its excellent write-up.

The hard part — working out the eCryptfs paging scheme, the MD5 per-page IV
derivation, and the key-request flow — was done there first. All credit for the
original discovery goes to them. This version extends that work with:

- support for **every file type** in the folder, not just `.mp4`
- output to a **parallel `DecryptedClips` folder** so originals stay untouched
- a **byte-exact match** to the official viewer's key-request format
- honest reporting of files that **cannot** be decrypted outside the car

Original work is MIT licensed; this derivative keeps the same license.

## How it works

Tesla stores each recording as an encrypted eCryptfs container. The scheme was
verified against Tesla's *intentionally-unminified* `encryptfs.js` from
`dashcam.tesla.com` (they ship it unminified "for transparency"):

- **Cipher:** AES-128-CBC over 4096-byte pages, after two 4096-byte header pages.
- **Per-page IV:** `MD5( MD5(file_key) + ascii(page_number) )`, zero-padded to 32 bytes.
- **Key retrieval:** the second header page holds *key-escrow metadata* (VIN, key
  id, timestamp, an EC public key, and a wrapped key). Only that metadata is
  POSTed to `/api/1/decrypt/batch`, which returns the per-file AES key. The
  video/photo bytes stay on your machine — same guarantee as the browser viewer.

Your token authenticates you as the account the clips belong to; the server will
only return keys for footage recorded by a vehicle on that account.

### What can and can't be decrypted

| File | Decryptable here? | Why |
|------|-------------------|-----|
| `*.mp4` clips | ✅ | carry per-file key escrow |
| per-clip `-README_de.txt` | ✅ | carry per-file key escrow |
| `event.json`, `thumb.png` | ❌ | **no** embedded key escrow — only the vehicle can decrypt these |
| top-level `-README_de.txt` | ✅ (copied) | already plaintext on the drive |

`event.json` / `thumb.png` are encrypted but were never escrowed for out-of-car
decryption, so neither this tool nor Tesla's own web viewer can open them. They
are reported and skipped, not corrupted.

Concretely: every `.mp4` carries its own key-escrow block in its second header
page, which is what the key endpoint unwraps for you. On `event.json` and
`thumb.png` that entire page is **zero-filled** — there is nothing to send and
nothing for Tesla to unwrap. The per-file key exists only under the vehicle's own
master key, which never leaves the car.

### Workaround: decrypt them in the car first

You can have the vehicle decrypt clips for you, which covers the files this tool
can't touch:

1. In the car, open the **Dashcam** app.
2. Select the clip(s) you want.
3. Tap the **unlock / decrypt** button (bottom right, near the playback-speed
   control) and let it write the decrypted copies back to the USB drive.

Those clips then land outside `EncryptedClips` as ordinary files — including
`event.json` and `thumb.png` — and need no key request at all.

This matches Tesla's own on-drive `-README_de.txt`, which describes the same
in-app "Entschlüsseln" button, and has been
[reported by owners in the wild](https://x.com/DerekBFSD/status/2084114777396380123).
You can also turn encryption off entirely under
**Vehicle → Safety → Encrypt Dashcam Recordings**.

> **Note:** the zero-filled escrow page on `event.json` / `thumb.png` looks more
> like an oversight than a deliberate choice — the metadata sidecars simply
> didn't get the same treatment as the video files. If a future firmware starts
> escrowing them with the same per-file keys, **this tool will pick them up
> automatically**: it keys off the escrow block being present, not off the file
> extension. Nothing here would need to change.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Getting your token

1. Open [dashcam.tesla.com](https://dashcam.tesla.com) and log in.
2. DevTools → Network. Drop any encrypted clip into the page.
3. Click a `/api/1/` request → Headers → copy the value after `Authorization: Bearer `.

The token expires quickly — grab a fresh one each session. Prefer passing it via
a file or env var so it stays out of your shell history:

```bash
export TESLA_TOKEN="eyJ..."          # or: --token-file token.txt
```

(Pasting the whole `Bearer eyJ...` value works too; the prefix is stripped.)

## Usage

Point it at your drive, its `TeslaCam` folder, or `EncryptedClips` directly:

```bash
python tesla_dashcam_decrypt.py /Volumes/TESLA
```

Decrypted files land in `DecryptedClips/` next to `EncryptedClips/`, mirroring the
original folder structure. Common options:

```
-o, --output DIR      Output folder (default: DecryptedClips next to EncryptedClips)
--token / --token-file / $TESLA_TOKEN
--dry-run             Scan and report; fetch no keys, write nothing
--overwrite           Re-decrypt files already present in the output
--batch-size N        Files per key request (default: 30, same as the viewer)
--remux               Losslessly remux each decrypted .mp4 (ffmpeg faststart)
--no-copy-plaintext   Don't copy already-unencrypted files into the output
```

Do a `--dry-run` first to see the breakdown without touching the network.

## Safety properties

- **Originals are never written to.** The tool refuses to place output inside
  `EncryptedClips`, and only ever opens source files read-only.
- **Nothing is written until your token actually works.** No output folder is
  created until Tesla has answered a real key request, so a bad or expired token
  leaves your disk completely untouched.
- **Atomic output.** Files are decrypted to a temp file and renamed on success,
  so an interrupted run can't leave a truncated file that a later run mistakes
  for a finished one.
- **Damaged containers are left alone**, never copied through — a broken file
  must not end up in the output looking like a successful decryption.
- **A failed `--remux` keeps the good decrypted file** rather than discarding it.

## Requirements

Python 3.9+, plus `pycryptodome` and `requests`. `ffmpeg` is only needed for
`--remux`.

## Security notes

- Only key-escrow metadata is uploaded; footage never leaves your machine.
- `.env`, `token.txt`, `EncryptedClips/`, and `DecryptedClips/` are gitignored.
- Never commit real clips or tokens.

## License

MIT — same as the original project this is based on.
