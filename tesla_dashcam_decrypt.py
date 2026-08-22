#!/usr/bin/env python3
"""
Tesla Dashcam Batch Decryptor
=============================
Decrypt a whole TeslaCam USB drive's ``EncryptedClips`` folder locally.

    ┌──────────────────────────────────────────────────────────────────────┐
    │  DISCLAIMER — NOT AFFILIATED WITH TESLA                              │
    │                                                                      │
    │  This is an independent, unofficial, community-built tool. It is     │
    │  NOT affiliated with, authorized by, endorsed by, sponsored by, or   │
    │  connected to Tesla, Inc. in any way. "Tesla", "TeslaCam", "Sentry   │
    │  Mode" and "Dashcam" are trademarks of Tesla, Inc., used here only   │
    │  to describe what this tool interoperates with (nominative use).     │
    │                                                                      │
    │  Provided as-is, without warranty of any kind. Use it only on        │
    │  footage from a vehicle on your own Tesla account. You are           │
    │  responsible for complying with Tesla's terms of service and with    │
    │  any recording/privacy laws that apply where you live.               │
    └──────────────────────────────────────────────────────────────────────┘

CREDIT
------
Based on the original reverse-engineering and decryptor by **@XGxF3**:
https://github.com/XGxF3/tesla-dashcam-decrypt
The encryption scheme (eCryptfs paging, the MD5 per-page IV derivation, and the
key-request flow) was worked out there first. This version extends that work
with support for every file type, a safe parallel-output layout, and a
byte-exact match to the official viewer's key-request format.
Original work is MIT licensed; this derivative keeps the same license.

HOW IT WORKS
------------
Tesla firmware 2026.20+ stores dashcam/Sentry recordings on the USB stick as
encrypted eCryptfs containers under ``TeslaCam/EncryptedClips``. The official
viewer at https://dashcam.tesla.com decrypts them one drag-and-drop at a time.
This tool reproduces that flow for the entire folder at once.

What leaves your machine: only the small per-file key-escrow metadata
(VIN, key id, timestamp, an EC public key and a wrapped key) is POSTed to
Tesla's key endpoint, which returns the per-file AES key. The video/photo
bytes are decrypted locally and never uploaded — same guarantee as the browser.

The scheme was verified against Tesla's intentionally-unminified
``encryptfs.js`` bundle:
  - AES-128-CBC, 4096-byte eCryptfs pages, two 4096-byte header pages first
  - per-page IV = MD5( MD5(file_key) + ascii(page_number) )  padded to 32 bytes
  - the API ``id`` is just a client-chosen correlation token, echoed back

Output goes to a sibling ``DecryptedClips`` folder; the original
``EncryptedClips`` is only ever read, never modified.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

import requests
from Crypto.Cipher import AES

# Keep the emoji output from crashing on consoles/redirects that aren't UTF-8.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DISCLAIMER = (
    "Unofficial community tool — NOT affiliated with, endorsed by, or "
    "connected to Tesla, Inc. Use on your own footage only."
)

# ── Tesla API ───────────────────────────────────────────────────────────────

TESLA_API_BASE = "https://dashcam.tesla.com"
DECRYPT_BATCH_URL = f"{TESLA_API_BASE}/api/1/decrypt/batch"
DEFAULT_BATCH_SIZE = 30  # matches the web viewer

# ── eCryptfs container layout ───────────────────────────────────────────────

PAGE_SIZE = 4096
HEADER_SIZE = 2 * PAGE_SIZE          # two header pages precede the payload
MAGIC = 0x3C81B7F5                   # magic1 ^ magic2
VERSION_FLAGS = 0x03000002           # value at offset 16 in real files

# Second header page (offset 0x1000) holds the key-escrow metadata that the
# key endpoint needs. Absent (all-zero) on files the car did not escrow.
ESCROW_OFFSET = PAGE_SIZE
FULL_PUBKEY_LEN = 65                 # uncompressed EC point (0x04 ...)
VIN_LEN = 17
WRAPPED_KEY_LEN = 12 + 16 + 16       # 44


# ── Container parsing ───────────────────────────────────────────────────────

@dataclass
class Escrow:
    """Key-request metadata read from the second header page."""
    vin: str
    key_id: int
    timestamp: int
    wrapped_key: str  # base64
    public_key: str   # base64


PLAIN = "plain"          # not one of ours — already-readable file, copy as-is
CONTAINER = "container"  # valid Tesla eCryptfs container
CORRUPT = "corrupt"      # claims to be ours (magic matches) but header is broken


def classify(head: bytes, file_size: int) -> str:
    """
    Decide what a file is, using the same checks as the official viewer.

    The eCryptfs magic is the discriminator: once it matches, the file *is* one
    of ours, so any later check failing means damaged — never "plaintext". That
    distinction matters, because a damaged container copied verbatim into the
    output would masquerade as a successful decryption.
    """
    if len(head) < 24:
        return PLAIN
    magic1, magic2 = struct.unpack(">II", head[8:16])
    if (magic1 ^ magic2) != MAGIC:
        return PLAIN

    if file_size < HEADER_SIZE or file_size % PAGE_SIZE != 0 or len(head) < HEADER_SIZE:
        return CORRUPT
    if struct.unpack(">I", head[16:20])[0] != VERSION_FLAGS:
        return CORRUPT
    if struct.unpack(">I", head[20:24])[0] != PAGE_SIZE:
        return CORRUPT
    plaintext_size = struct.unpack(">Q", head[:8])[0]
    if not 0 < plaintext_size <= file_size - HEADER_SIZE:
        return CORRUPT
    return CONTAINER


def read_plaintext_size(head: bytes) -> int:
    return struct.unpack(">Q", head[:8])[0]


def read_escrow(head: bytes) -> Escrow | None:
    """
    Parse the escrow metadata (second header page). Returns None when the page
    is empty — those files were not escrowed for out-of-car decryption and can
    only be decrypted inside the vehicle.

    Mirrors Tesla's variable-length public-key scan: the EC point is normally
    65 bytes but a leading zero byte may be trimmed, so the VIN/timestamp
    boundary is located instead of assumed.
    """
    if head[ESCROW_OFFSET:ESCROW_OFFSET + 16] == b"\x00" * 16:
        return None

    cur = ESCROW_OFFSET
    key_id = struct.unpack(">I", head[cur:cur + 4])[0]
    cur += 4

    min_pub = FULL_PUBKEY_LEN - 8
    ts_start = cur + FULL_PUBKEY_LEN
    ts_max = ts_start + VIN_LEN
    while ts_start <= ts_max and head[ts_start] != 0:
        ts_start += 1
    if ts_start <= ts_max and head[ts_start] == 0:
        pub_len = ts_start - VIN_LEN - cur
    else:
        pub_len = FULL_PUBKEY_LEN
    if pub_len < min_pub or pub_len > FULL_PUBKEY_LEN or head[cur] != 0x04:
        pub_len = FULL_PUBKEY_LEN

    public_key = head[cur:cur + pub_len]
    cur += pub_len
    vin = head[cur:cur + VIN_LEN].decode("ascii", errors="replace")
    cur += VIN_LEN
    timestamp = struct.unpack(">Q", head[cur:cur + 8])[0]
    cur += 8
    wrapped_key = head[cur:cur + WRAPPED_KEY_LEN]

    if not vin or vin[0] == "\x00" or public_key[0] != 0x04:
        return None
    if len(wrapped_key) != WRAPPED_KEY_LEN:
        return None

    return Escrow(
        vin=vin.rstrip("\x00"),
        key_id=key_id,
        timestamp=timestamp,
        wrapped_key=base64.b64encode(wrapped_key).decode("ascii"),
        public_key=base64.b64encode(public_key).decode("ascii"),
    )


# ── Decryption ──────────────────────────────────────────────────────────────

def decrypt_file(src: Path, dst: Path, plaintext_size: int, key: bytes) -> int:
    """
    Decrypt one eCryptfs container to ``dst``. Returns bytes written.

    Writes to a temp file and renames on success, so an interrupted run can
    never leave a truncated file that a later run mistakes for a finished one.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(f".{dst.name}.part")

    root_iv = hashlib.md5(key).digest()
    iv_buf = bytearray(32)
    iv_buf[:len(root_iv)] = root_iv

    try:
        written = 0
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fin.seek(HEADER_SIZE)
            page = 0
            while written < plaintext_size:
                enc = fin.read(PAGE_SIZE)
                if len(enc) != PAGE_SIZE:
                    raise ValueError("truncated ciphertext page")
                digits = str(page).encode("ascii")
                iv_buf[len(root_iv):len(root_iv) + len(digits)] = digits
                derived_iv = hashlib.md5(bytes(iv_buf)).digest()
                plain = AES.new(key, AES.MODE_CBC, derived_iv).decrypt(enc)
                remaining = plaintext_size - written
                if remaining < len(plain):
                    plain = plain[:remaining]
                fout.write(plain)
                written += len(plain)
                page += 1

        if written != plaintext_size:
            raise ValueError("decrypted output shorter than declared size")
        os.replace(tmp, dst)
        return written
    finally:
        tmp.unlink(missing_ok=True)


def remux_mp4(path: Path) -> None:
    """Losslessly rewrite an MP4 in place so QuickTime is happy (faststart)."""
    tmp = path.with_name(f".{path.name}.remux.mp4")
    try:
        subprocess.run(
            ["ffmpeg", "-y", "-i", str(path), "-c", "copy",
             "-movflags", "faststart", str(tmp)],
            check=True, capture_output=True, text=True,
        )
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ── Discovery ───────────────────────────────────────────────────────────────

SKIP_NAMES = {".DS_Store", "Thumbs.db"}


def find_encrypted_root(start: Path) -> Path:
    """Accept the drive root, TeslaCam, or EncryptedClips itself."""
    if start.name == "EncryptedClips" and start.is_dir():
        return start
    for cand in (start / "EncryptedClips", start / "TeslaCam" / "EncryptedClips"):
        if cand.is_dir():
            return cand
    raise SystemExit(
        f"Could not find an 'EncryptedClips' folder under {start}. "
        "Point me at your drive, its TeslaCam folder, or EncryptedClips directly."
    )


@dataclass
class Job:
    src: Path
    dst: Path
    rel: Path
    kind: str            # PLAIN | CONTAINER | CORRUPT
    plaintext_size: int = 0
    escrow: Escrow | None = None
    corr_id: str = ""    # correlation id echoed by the API


def copy_plaintext_files(jobs: list[Job], overwrite: bool) -> int:
    """Copy already-unencrypted files (e.g. the folder README) straight through."""
    copied = 0
    for j in jobs:
        if j.dst.exists() and not overwrite:
            continue
        j.dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(j.src, j.dst)
        copied += 1
    return copied


def build_jobs(enc_root: Path, out_root: Path) -> tuple[list[Job], list[Path]]:
    """Scan the tree. Returns (jobs, unreadable_paths)."""
    jobs: list[Job] = []
    unreadable: list[Path] = []
    for src in sorted(enc_root.rglob("*")):
        if not src.is_file() or src.name in SKIP_NAMES or src.name.startswith("._"):
            continue
        rel = src.relative_to(enc_root)
        try:
            size = src.stat().st_size
            with open(src, "rb") as f:
                head = f.read(HEADER_SIZE)
        except OSError as e:
            print(f"  [!] cannot read {rel}: {e}")
            unreadable.append(src)
            continue

        dst = out_root / rel
        kind = classify(head, size)
        if kind == CONTAINER:
            jobs.append(Job(
                src, dst, rel, kind,
                plaintext_size=read_plaintext_size(head),
                escrow=read_escrow(head),
                corr_id=str(uuid.uuid4()),
            ))
        else:
            jobs.append(Job(src, dst, rel, kind))
    return jobs, unreadable


# ── Key fetching ────────────────────────────────────────────────────────────

def get_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Origin": TESLA_API_BASE,
        "Referer": f"{TESLA_API_BASE}/",
    })
    return s


def fetch_keys(session: requests.Session,
               batch: list[Job]) -> tuple[dict[str, bytes], dict[str, str]]:
    """
    POST escrow metadata for a batch.
    Returns ({corr_id: aes_key}, {corr_id: error_message}).
    """
    items = [{
        "id": j.corr_id,
        "vin": j.escrow.vin,
        "key_id": j.escrow.key_id,
        "timestamp": j.escrow.timestamp,
        "wrapped_key": j.escrow.wrapped_key,
        "public_key": j.escrow.public_key,
    } for j in batch]

    resp = session.post(DECRYPT_BATCH_URL, json={"items": items}, timeout=30)
    if resp.status_code == 401:
        raise SystemExit(
            "401 Unauthorized — your token is invalid or expired. Grab a fresh "
            "one from dashcam.tesla.com (see README) and try again."
        )
    resp.raise_for_status()

    keys: dict[str, bytes] = {}
    errors: dict[str, str] = {}
    for result in resp.json().get("results", []):
        cid = result.get("id")
        if result.get("error"):
            errors[cid] = str(result["error"])
            continue
        raw = result.get("key")
        if not raw:
            errors[cid] = "response contained no key"
            continue
        try:
            keys[cid] = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as e:
            errors[cid] = f"malformed key in response ({e})"
    return keys, errors


# ── Main ────────────────────────────────────────────────────────────────────

def resolve_token(args) -> str:
    token = ""
    if args.token:
        token = args.token
    elif args.token_file:
        path = Path(args.token_file)
        if not path.is_file():
            raise SystemExit(f"Token file not found: {path}")
        token = path.read_text()
    elif os.environ.get("TESLA_TOKEN"):
        token = os.environ["TESLA_TOKEN"]
    else:
        raise SystemExit(
            "No token. Pass --token, --token-file, or set TESLA_TOKEN. "
            "Prefer the env var or a file so the token stays out of your shell history."
        )

    token = token.strip()
    # Tolerate pasting the whole header value.
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        raise SystemExit("The token you supplied is empty.")
    return token


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Batch-decrypt a Tesla EncryptedClips folder into a sibling "
                    f"DecryptedClips folder. {DISCLAIMER}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("input", type=Path,
                        help="Drive root, TeslaCam folder, or EncryptedClips folder")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="Output folder (default: 'DecryptedClips' next to EncryptedClips)")
    parser.add_argument("--token", help="Tesla bearer token (see README)")
    parser.add_argument("--token-file", help="File containing the bearer token")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                        help=f"Files per key request (default: {DEFAULT_BATCH_SIZE})")
    parser.add_argument("--no-copy-plaintext", action="store_true",
                        help="Do not copy already-unencrypted files (e.g. the folder README) into the output")
    parser.add_argument("--overwrite", action="store_true",
                        help="Re-decrypt files even if they already exist in the output")
    parser.add_argument("--remux", action="store_true",
                        help="Losslessly remux each decrypted .mp4 with ffmpeg (faststart)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Scan and report, but fetch no keys and write nothing")
    args = parser.parse_args()

    print(f"\nℹ️   {DISCLAIMER}")

    if args.batch_size < 1:
        raise SystemExit("--batch-size must be at least 1.")
    if args.remux and shutil.which("ffmpeg") is None:
        raise SystemExit("--remux needs ffmpeg on your PATH, but it wasn't found.")
    if not args.input.exists():
        raise SystemExit(f"Input not found: {args.input}")

    enc_root = find_encrypted_root(args.input)
    out_root = args.output or (enc_root.parent / "DecryptedClips")
    enc_res, out_res = enc_root.resolve(), out_root.resolve()
    if out_res == enc_res or enc_res in out_res.parents:
        raise SystemExit(
            "Refusing to write inside EncryptedClips — the originals must stay untouched."
        )

    print(f"\n🔍  EncryptedClips: {enc_root}")
    print(f"📂  Output:         {out_root}\n")

    jobs, unreadable = build_jobs(enc_root, out_root)
    encrypted = [j for j in jobs if j.kind == CONTAINER]
    decryptable = [j for j in encrypted if j.escrow]
    no_key = [j for j in encrypted if not j.escrow]
    plaintext = [j for j in jobs if j.kind == PLAIN]
    corrupt = [j for j in jobs if j.kind == CORRUPT]

    print(f"    {len(encrypted)} encrypted, {len(plaintext)} already-plaintext file(s)")
    print(f"    {len(decryptable)} decryptable, {len(no_key)} without an embedded key")
    if corrupt:
        print(f"    {len(corrupt)} damaged container(s) — will be left alone")
    print()

    if args.dry_run:
        for j in decryptable:
            print(f"  🔓  would decrypt  {j.rel}")
        for j in no_key:
            print(f"  🔒  no key (car only)  {j.rel}")
        for j in corrupt:
            print(f"  ⚠️   damaged  {j.rel}")
        print("\nDry run — nothing written.")
        return

    todo = [j for j in decryptable if args.overwrite or not j.dst.exists()]
    skipped = len(decryptable) - len(todo)

    # Resolve the token up front (fail fast) before writing anything.
    session = get_session(resolve_token(args)) if todo else None

    if skipped:
        print(f"  ⏭  {skipped} already decrypted (use --overwrite to redo)\n")

    copied = 0
    if not todo:
        # Nothing to decrypt, so there is no token to prove out. Only refresh the
        # plaintext copies if an earlier successful run already made the folder.
        if out_root.exists() and not args.no_copy_plaintext:
            copied = copy_plaintext_files(plaintext, args.overwrite)

    ok = err = 0
    token_proven = False
    for start in range(0, len(todo), args.batch_size):
        batch = todo[start:start + args.batch_size]
        print(f"🔑  Fetching keys for {len(batch)} file(s)…")
        try:
            keys, key_errors = fetch_keys(session, batch)
        except requests.RequestException as e:
            print(f"  [!] request failed: {e}")
            err += len(batch)
            continue

        # The token just worked against Tesla, so it is now safe to create output.
        if not token_proven:
            token_proven = True
            if not args.no_copy_plaintext:
                copied = copy_plaintext_files(plaintext, args.overwrite)

        for j in batch:
            key = keys.get(j.corr_id)
            if key is None:
                reason = key_errors.get(j.corr_id, "not present in the response")
                print(f"  [!] no key for {j.rel}: {reason}")
                err += 1
                continue
            try:
                written = decrypt_file(j.src, j.dst, j.plaintext_size, key)
            except Exception as e:  # noqa: BLE001 - report and keep going
                print(f"  [ERROR] {j.rel}: {e}")
                err += 1
                continue

            # A remux failure must not cost us the good decrypted file.
            if args.remux and j.dst.suffix.lower() == ".mp4":
                try:
                    remux_mp4(j.dst)
                except Exception as e:  # noqa: BLE001
                    print(f"  [warn] remux failed for {j.rel}, keeping raw output: {e}")
            print(f"  🔓  {j.rel}  ({human_size(written)})")
            ok += 1

    print(f"\n{'=' * 60}")
    print(f"✅  {ok} decrypted, {copied} copied, {skipped} skipped, {err} failed")
    if unreadable:
        print(f"⚠️   {len(unreadable)} file(s) could not be read at all.")
    if corrupt:
        print(f"⚠️   {len(corrupt)} file(s) look like damaged containers and were "
              "left alone (not copied, to avoid passing them off as decrypted).")
    if no_key:
        names = sorted({j.rel.name for j in no_key})
        shown = ", ".join(names[:3]) + ("…" if len(names) > 3 else "")
        print(f"🔒  {len(no_key)} file(s) carry no embedded key and were left out "
              f"({shown}). These can only be decrypted inside the vehicle.")
    print(f"📁  {out_root}")


if __name__ == "__main__":
    main()
