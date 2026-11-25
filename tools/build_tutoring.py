#!/usr/bin/env python3
"""Encrypt the private tutoring folder into the public site, with one password per student.

    python3 tools/build_tutoring.py

Folder layout (tutoring-private/ is never uploaded: it is in .gitignore):

    tutoring-private/
        Shared/                  optional: every student sees these
            AP Calculus BC/...
        Students/
            Kaiden/              only Kaiden's password opens this (plus Shared)
            Nolan/
            ...

Passwords live in .tutoring-passwords.json (also never uploaded). The script creates a
password for every new student folder and prints it, and creates a master password for
you that opens everything. Edit that file to change a password, then run this again.

How it is protected: every file is encrypted (AES-256-GCM) with its own random key. Each
student gets a private index, encrypted with a key made from their password
(PBKDF2-HMAC-SHA256, 600,000 rounds), that lists only their files and those files' keys.
GitHub only ever stores scrambled data: names, folders and contents are all hidden.
Needs the 'cryptography' package:  pip install cryptography
"""
import base64, hashlib, json, mimetypes, os, secrets, sys, time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("This script needs the 'cryptography' package. Run:  pip install cryptography")

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tutoring-private"
OUT = ROOT / "tutoring" / "data"
PASSWORDS = ROOT / ".tutoring-passwords.json"   # local only
CACHE = ROOT / ".tutoring-cache.json"           # local only: file keys, so unchanged files are not re-encrypted
ITER = 600_000
SKIP = {".DS_Store", "Thumbs.db", "desktop.ini"}
MASTER = "(you: master password)"

WORDS = ("amber apple arrow aspen atlas basil beacon birch bison bloom brook cactus canyon cedar cello "
         "cliff clover comet coral cosmos cricket crystal delta dune eagle ember falcon fern fjord forest "
         "galaxy garnet geyser glacier granite harbor hazel heron horizon iris island ivy jade jasper "
         "juniper kayak kestrel lagoon lantern laurel lemon lilac lotus lunar maple marble meadow mesa "
         "meteor mint monsoon moss nectar nova oasis ocean olive onyx orbit orchid otter panda pebble "
         "pepper pine planet plum polar prairie prism quartz quill raven reef ridge river robin saffron "
         "sage sequoia shadow sierra sparrow spruce summit sunset tango thunder tide tiger topaz tundra "
         "tulip valley velvet violet walnut willow winter zephyr zinc").split()


def new_password():
    return "-".join(secrets.choice(WORDS) for _ in range(3)) + "-" + str(secrets.randbelow(90) + 10)


def derive(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITER, 32)


def seal(key, data):
    iv = os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, data, None)


def files_under(folder):
    if not folder.is_dir():
        return []
    return [p for p in sorted(folder.rglob("*"))
            if p.is_file() and p.name not in SKIP and not p.name.startswith(".")]


def main():
    if not SRC.is_dir() or not any(SRC.iterdir()):
        (SRC / "Shared").mkdir(parents=True, exist_ok=True)
        (SRC / "Students").mkdir(parents=True, exist_ok=True)
        sys.exit("Set up tutoring-private/Shared and tutoring-private/Students.\n"
                 "Make one folder per student inside Students (first names only), add files, then run this again.")
    (SRC / "Shared").mkdir(exist_ok=True)
    (SRC / "Students").mkdir(exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    pw = json.loads(PASSWORDS.read_text()) if PASSWORDS.exists() else {}
    cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    cache.setdefault("files", {}); cache.setdefault("indexes", {})
    meta_path = OUT / "meta.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    if "indexes" not in meta:          # first run of this version: fresh salt
        meta = {"salt": secrets.token_hex(16), "iter": ITER}
    salt = bytes.fromhex(meta["salt"])

    students = sorted(d.name for d in (SRC / "Students").iterdir() if d.is_dir() and not d.name.startswith("."))
    created = []
    if MASTER not in pw:
        pw[MASTER] = new_password(); created.append(MASTER)
    for s in students:
        if s not in pw:
            pw[s] = new_password(); created.append(s)
    PASSWORDS.write_text(json.dumps(pw, indent=2, ensure_ascii=False))
    os.chmod(PASSWORDS, 0o600)

    # 1. encrypt every file once, each with its own random key
    entries, keep, changed = {}, {"meta.json"}, 0
    for p in files_under(SRC / "Shared") + files_under(SRC / "Students"):
        rel = p.relative_to(SRC).as_posix()
        data = p.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        c = cache["files"].get(rel)
        if not c or c["sha"] != digest or not (OUT / f"{c['id']}.bin").exists():
            c = {"id": secrets.token_hex(12), "key": base64.b64encode(os.urandom(32)).decode(), "sha": digest}
            (OUT / f"{c['id']}.bin").write_bytes(seal(base64.b64decode(c["key"]), data)); changed += 1
        cache["files"][rel] = c
        keep.add(f"{c['id']}.bin")
        entries[rel] = {"id": c["id"], "key": c["key"], "size": len(data),
                        "type": mimetypes.guess_type(p.name)[0] or "application/octet-stream",
                        "modified": time.strftime("%Y-%m-%d", time.localtime(p.stat().st_mtime))}
    cache["files"] = {k: v for k, v in cache["files"].items() if k in entries}

    # 2. one private index per person, listing only what they may open
    def listing(prefixes, strip):
        out = []
        for rel, e in entries.items():
            if any(rel.startswith(pre) for pre in prefixes):
                shown = rel
                for pre, label in strip:
                    if rel.startswith(pre):
                        shown = label + rel[len(pre):]; break
                out.append(dict(e, path=shown))
        return out

    now = time.strftime("%Y-%m-%d %H:%M")
    people = [(s, {"name": s, "role": "student", "updated": now,
                   "files": listing(["Shared/", f"Students/{s}/"],
                                    [("Shared/", "For everyone/"), (f"Students/{s}/", "Just for you/")])})
              for s in students]
    people.append((MASTER, {"name": "Johannes", "role": "tutor", "updated": now,
                            "files": listing(["Shared/", "Students/"], [("Shared/", "For everyone/")])}))
    index_ids = []
    for who, man in people:
        iid = cache["indexes"].get(who) or secrets.token_hex(12)
        cache["indexes"][who] = iid
        (OUT / f"{iid}.bin").write_bytes(seal(derive(pw[who], salt), json.dumps(man).encode("utf-8")))
        index_ids.append(iid); keep.add(f"{iid}.bin")
    cache["indexes"] = {k: v for k, v in cache["indexes"].items() if k in pw}
    secrets.SystemRandom().shuffle(index_ids)     # order reveals nothing
    meta["indexes"] = index_ids
    meta_path.write_text(json.dumps(meta))

    removed = 0
    for f in OUT.iterdir():
        if f.name not in keep:
            f.unlink(); removed += 1
    CACHE.write_text(json.dumps(cache)); os.chmod(CACHE, 0o600)

    print(f"Done: {len(entries)} files for {len(students)} students ({changed} encrypted now, {removed} old removed).")
    if created:
        print("\nNew passwords (also saved in .tutoring-passwords.json, which is never uploaded):")
        for who in created:
            print(f"  {who:<26} {pw[who]}")
    unused = [k for k in pw if k != MASTER and k not in students]
    if unused:
        print("\nNote: these passwords no longer open anything (no matching folder):", ", ".join(unused))
    print("\nPublish with:  git add tutoring && git commit -m 'Update tutoring' && git push")


if __name__ == "__main__":
    main()
