# Nestra backup format (version 1)

A Nestra backup is one file (`.dvault`). This page describes it, so that your
backups stay readable without the app. `nestra_backup_decrypt.py` in this
folder implements exactly this, in about 100 lines.

## Layout

The file is a ZIP archive with no compression ("stored") and two entries:

| Entry | Contents |
|---|---|
| `header.json` | Plain text. Not secret, holds no personal data. |
| `payload.bin` | Your data, encrypted. |

`header.json` looks like this (the values here are examples):

```json
{
  "magic": "VAULTX",
  "format": 1,
  "app": "doc_vault",
  "created_at": 1763000000000,
  "kdf": { "name": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "<base64, 16 bytes>" },
  "segment_size": 65536,
  "nonce": "<base64, 7 bytes>"
}
```

## The key

`key = Argon2id(password as UTF-8, salt, memory = m KiB, passes = t, lanes = p)`,
version 0x13, 32 bytes of output. The password is the one chosen when the
backup was made. Your vault's own keys are never in the file.

## The payload

`payload.bin` is cut into pieces ("segments"). Each piece holds up to 64 KiB
of data plus a 16-byte authentication tag, encrypted with **AES-256-GCM**.

For segment number `i` (counting from 0):

- **Nonce (12 bytes)** = the 7 `nonce` bytes from the header, then `i` as a
  4-byte big-endian number, then one byte that is `1` for the last segment and
  `0` for all others.
- **Associated data** = SHA-256 of the exact bytes of `header.json`.
- **Ciphertext** = the encrypted data followed by its 16-byte tag.

Because of the number, the last-segment flag and the header hash, a segment
that is moved, removed, added, or taken from another backup fails to open.

## Inside the payload

Once decrypted, the payload is another stored ZIP archive:

| Entry | Contents |
|---|---|
| `manifest.json` | Format, app, record counts, and the SHA-256 and size of every file |
| `data.json` | `{"tables": {...}, "extras": {...}}`: your records as JSON |
| `files/<id>` | One scanned page or photo, as the original image bytes |
| `thumbs/<id>` | The small preview of a file |

`extras` holds app-specific data. Card CVVs are stored there (`extras.cvv`)
only if you turned on CVV storage and passed the fingerprint check when you
made the backup. They are readable text inside the encrypted payload, so keep
the backup password strong. The script writes them out with the rest of
`data.json`.

## Checking it yourself

Make a backup in the app, run the script, and compare. If anything is changed
in the file, or the password is wrong, decryption fails: that is the
authentication tag doing its job.
