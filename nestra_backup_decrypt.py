#!/usr/bin/env python3
"""Open a Nestra backup file on a computer, without the app.

Nestra backups are meant to be readable by you, forever, without us. This
script opens one with the password you chose when you made it, checks that
nothing in it was changed, and writes out:

  data.json      your records (people, documents, fields, notes) as text
  manifest.json  what the backup says it contains
  files/         your scanned pages and photos, as the original image bytes

Needs Python 3.9+ and two common libraries:

    pip install cryptography argon2-cffi

Run:

    python nestra_backup_decrypt.py MyBackup.dvault  output-folder

It asks for the password (nothing is shown as you type) and never sends
anything anywhere. The format is described in BACKUP_FORMAT.md.
"""
import argparse
import base64
import getpass
import hashlib
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

try:
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.exit("Please run:  pip install cryptography argon2-cffi")

MAGIC = "VAULTX"
TAG = 16
SEGMENT = 64 * 1024


class BackupError(Exception):
    pass


def read_outer(path: Path):
    """The outer file is a ZIP with a readable header and the sealed payload."""
    try:
        with zipfile.ZipFile(path) as z:
            header_bytes = z.read("header.json")
            payload = z.read("payload.bin")
    except (zipfile.BadZipFile, KeyError) as e:
        raise BackupError("This is not a Nestra backup file.") from e
    header = json.loads(header_bytes)
    if header.get("magic") != MAGIC:
        raise BackupError("This is not a Nestra backup file.")
    if header.get("format") != 1:
        raise BackupError(f"Unknown backup format {header.get('format')}.")
    return header_bytes, header, payload


def derive_key(password: str, header: dict) -> bytes:
    kdf = header["kdf"]
    if kdf["name"] != "argon2id":
        raise BackupError("Unknown key derivation.")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=base64.b64decode(kdf["salt"]),
        time_cost=kdf["t"],
        memory_cost=kdf["m"],  # in KiB
        parallelism=kdf["p"],
        hash_len=32,
        type=Type.ID,
        version=19,
    )


def open_payload(key: bytes, header_bytes: bytes, header: dict, payload: bytes) -> bytes:
    """AES-256-GCM in numbered segments, tied to the header.

    Each segment's nonce is: 7 random bytes (from the header) + the segment
    number (4 bytes, big endian) + 1 byte that is 1 only on the last segment.
    The header's SHA-256 is the associated data. So a segment that was moved,
    removed, added, or taken from another backup fails to open.
    """
    prefix = base64.b64decode(header["nonce"])
    size = header.get("segment_size", SEGMENT)
    aad = hashlib.sha256(header_bytes).digest()
    sealed_size = size + TAG
    if len(payload) < TAG:
        raise BackupError("The backup is damaged (too short).")
    count = (len(payload) + sealed_size - 1) // sealed_size
    aes = AESGCM(key)
    out = io.BytesIO()
    for i in range(count):
        chunk = payload[i * sealed_size : (i + 1) * sealed_size]
        last = i == count - 1
        nonce = prefix + struct.pack(">I", i) + bytes([1 if last else 0])
        try:
            out.write(aes.decrypt(nonce, chunk, aad))
        except InvalidTag as e:
            raise BackupError(
                "Wrong password, or the backup was changed or damaged."
            ) from e
    return out.getvalue()


def extract(plain: bytes, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(plain)) as z:
        manifest = json.loads(z.read("manifest.json"))
        # Every file is checked against the hash the backup recorded for it.
        for name, info in manifest.get("files", {}).items():
            try:
                data = z.read(name)
            except KeyError:
                continue  # listed under "missing"; the app reports these too
            if hashlib.sha256(data).hexdigest() != info["sha256"]:
                raise BackupError(f"{name} does not match its recorded hash.")
            target = out_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (out_dir / "data.json").write_bytes(z.read("data.json"))
        (out_dir / "manifest.json").write_bytes(z.read("manifest.json"))
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description="Open a Nestra backup without the app.")
    ap.add_argument("backup", type=Path, help="the .dvault file")
    ap.add_argument("out", type=Path, help="folder to write the contents to")
    ap.add_argument("--password", help="(avoid: it shows in your shell history)")
    args = ap.parse_args()
    password = args.password or getpass.getpass("Backup password: ")
    try:
        header_bytes, header, payload = read_outer(args.backup)
        print("Working out the key (this takes a few seconds on purpose)...")
        key = derive_key(password, header)
        plain = open_payload(key, header_bytes, header, payload)
        manifest = extract(plain, args.out)
    except BackupError as e:
        print(f"Could not open it: {e}", file=sys.stderr)
        return 1
    counts = manifest.get("counts", {})
    print(
        f"Opened. {sum(counts.values())} records and "
        f"{len(manifest.get('files', {}))} files written to {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
