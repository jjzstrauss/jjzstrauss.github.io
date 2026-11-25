#!/usr/bin/env python3
"""Encrypt the private tutoring folder into the public site.

    python3 tools/build_tutoring.py

Reads every file in  tutoring-private/  (never uploaded: it is in .gitignore),
encrypts it with a key made from your password, and writes the results to
tutoring/data/  under random-looking names. The page tutoring/index.html asks for
the password and decrypts in the visitor's browser, so GitHub only ever stores
scrambled data: file names, folder names and contents are all hidden.

Crypto: PBKDF2-HMAC-SHA256 (600,000 rounds) -> 256-bit key; AES-256-GCM per file.
Needs the 'cryptography' package:  pip install cryptography
"""
import getpass, hashlib, hmac, json, mimetypes, os, sys, time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("This script needs the 'cryptography' package. Run:  pip install cryptography")

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tutoring-private"
OUT = ROOT / "tutoring" / "data"
CACHE = ROOT / ".tutoring-cache.json"     # local only (gitignored): remembers what is already encrypted
ITER = 600_000
SKIP = {".DS_Store", "Thumbs.db", "desktop.ini"}


def derive(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITER, 32)


def seal(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, data, None)


def main():
    if not SRC.is_dir():
        SRC.mkdir()
        sys.exit(f"Created {SRC.name}/. Put your tutoring files in it (folders are fine), then run this again.")
    OUT.mkdir(parents=True, exist_ok=True)
    meta_path = OUT / "meta.json"
    cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}

    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        salt = bytes.fromhex(meta["salt"])
        pw = getpass.getpass("Tutoring password: ")
        key = derive(pw, salt)
        try:   # confirm it is the same password the site already uses
            blob = (OUT / "manifest.bin").read_bytes()
            AESGCM(key).decrypt(blob[:12], blob[12:], None)
        except Exception:
            ans = input("That is not the current password. Change the password and re-encrypt everything? [y/N] ")
            if ans.strip().lower() != "y":
                sys.exit("Nothing changed.")
            pw2 = getpass.getpass("Type the new password again: ")
            if pw2 != pw:
                sys.exit("The passwords did not match. Nothing changed.")
            salt = os.urandom(16); key = derive(pw, salt); cache = {}
            meta = {"salt": salt.hex(), "iter": ITER}
    else:
        pw = getpass.getpass("Choose a tutoring password (12+ characters recommended): ")
        if getpass.getpass("Type it again: ") != pw:
            sys.exit("The passwords did not match. Nothing changed.")
        if len(pw) < 10:
            print("Warning: short passwords are easier to guess. Consider 12+ characters.")
        salt = os.urandom(16); key = derive(pw, salt)
        meta = {"salt": salt.hex(), "iter": ITER}

    # names on disk are an HMAC of the path, so they are stable but reveal nothing
    def file_id(rel: str) -> str:
        return hmac.new(key, rel.encode("utf-8"), "sha256").hexdigest()[:24]

    entries, keep, new_cache, changed = [], {"meta.json", "manifest.bin"}, {}, 0
    for p in sorted(SRC.rglob("*")):
        if not p.is_file() or p.name in SKIP or p.name.startswith("."):
            continue
        rel = p.relative_to(SRC).as_posix()
        data = p.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        fid = file_id(rel)
        target = OUT / f"{fid}.bin"
        if cache.get(rel) != digest or not target.exists():
            target.write_bytes(seal(key, data)); changed += 1
        new_cache[rel] = digest
        keep.add(target.name)
        entries.append({"id": fid, "path": rel, "size": len(data),
                        "type": mimetypes.guess_type(p.name)[0] or "application/octet-stream",
                        "modified": time.strftime("%Y-%m-%d", time.localtime(p.stat().st_mtime))})

    manifest = {"updated": time.strftime("%Y-%m-%d %H:%M"), "files": entries}
    (OUT / "manifest.bin").write_bytes(seal(key, json.dumps(manifest).encode("utf-8")))
    meta_path.write_text(json.dumps(meta))
    removed = 0
    for f in OUT.iterdir():
        if f.name not in keep:
            f.unlink(); removed += 1
    CACHE.write_text(json.dumps(new_cache))
    print(f"Done: {len(entries)} files ({changed} encrypted now, {removed} old removed).")
    print("Publish with:  git add tutoring && git commit -m 'Update tutoring' && git push")


if __name__ == "__main__":
    main()
