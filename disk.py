#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
disk.py v6 — Audit disque : NAVIGATEURS + SYSTÈME, identifiants en clair.

Sortie courte et utile :
  1. NAVIGATEURS   : site | identifiant | mot de passe   (Chrome/Chromium/Brave/Edge/
                     Vivaldi/Opera/Firefox/Thunderbird, profils natifs + snap + flatpak)
  2. SYSTÈME       : mot de passe de session, WiFi/PSK, trousseau, PPP, Samba, PIN…
  3. APPLICATIONS  : FileZilla, Remmina, Docker, rclone, Pidgin…
  4. CLÉS          : résumé (fixtures de test masquées)

Exemples
    sudo python3 disk.py
    sudo python3 disk.py --wordlist rockyou.txt
    sudo python3 disk.py -v --all          # avec origine/fichier et tout le détail
"""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Optional

warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    from Crypto.Cipher import AES, DES3
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

try:
    import crypt as _crypt
except ImportError:
    _crypt = None

try:
    import win32crypt
    HAVE_DPAPI = True
except ImportError:
    HAVE_DPAPI = False

OSNAME = platform.system()
IS_WIN, IS_MAC, IS_LINUX = OSNAME == "Windows", OSNAME == "Darwin", OSNAME == "Linux"
M32 = 0xFFFFFFFF
IV_SPACES = b" " * 16
OPENSSL = shutil.which("openssl")


# =========================================================================== #
#  Contexte
# =========================================================================== #

def real_home() -> Path:
    u = os.environ.get("SUDO_USER")
    if u and u != "root":
        try:
            import pwd
            return Path(pwd.getpwnam(u).pw_dir)
        except (KeyError, ImportError):
            pass
    return Path(os.environ.get("HOME", "~")).expanduser()


def fix_session_env() -> None:
    uid = os.environ.get("SUDO_UID")
    if not os.environ.get("XDG_RUNTIME_DIR") and uid:
        os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS") and uid:
        b = f"/run/user/{uid}/bus"
        if os.path.exists(b):
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={b}"


def ensure_crypto(auto=True) -> None:
    """pycryptodome absent -> venv auto (sinon openssl prend le relais)."""
    if HAVE_CRYPTO or not auto or os.environ.get("DISK_REEXEC") == "1":
        return
    cache = real_home() / ".cache" / "disk-audit"
    py = cache / "venv" / "bin" / "python3"
    if not py.exists():
        try:
            cache.mkdir(parents=True, exist_ok=True)
            sys.stderr.write("[i] préparation de pycryptodome (1re fois)…\n")
            subprocess.run([sys.executable, "-m", "venv", str(cache / "venv")],
                           check=True, timeout=300, stdout=subprocess.DEVNULL)
            subprocess.run([str(py), "-m", "pip", "install", "-q", "--upgrade", "pip"],
                           timeout=300, stdout=subprocess.DEVNULL)
            subprocess.run([str(py), "-m", "pip", "install", "-q", "pycryptodome"],
                           check=True, timeout=600, stdout=subprocess.DEVNULL)
        except Exception as e:
            sys.stderr.write(f"[i] venv impossible ({e}) → repli openssl\n")
            return
    try:
        if subprocess.run([str(py), "-c", "import Crypto"], capture_output=True,
                          timeout=20).returncode == 0:
            fix_session_env()
            os.execve(str(py), [str(py)] + sys.argv,
                      dict(os.environ, DISK_REEXEC="1", HOME=str(real_home())))
    except Exception:
        pass


fix_session_env()
HOME = real_home()


# =========================================================================== #
#  Crypto (pycryptodome sinon openssl)
# =========================================================================== #

def _openssl(cipher, key, iv, data):
    if not OPENSSL or not data or len(data) % 8:
        return None
    try:
        r = subprocess.run([OPENSSL, "enc", "-d", f"-{cipher}", "-K", key.hex(),
                            "-iv", iv.hex(), "-nopad"], input=data,
                           capture_output=True, timeout=60)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def _unpad(b, n=16):
    if not b:
        return b""
    p = b[-1]
    return b[:-p] if 1 <= p <= n else b


def aes_cbc_dec(key, iv, data, pad=True):
    out = None
    if HAVE_CRYPTO:
        try:
            out = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
        except Exception:
            out = None
    if out is None:
        out = _openssl({16: "aes-128-cbc", 24: "aes-192-cbc", 32: "aes-256-cbc"}[len(key)],
                       key, iv, data)
    if out is None:
        return None
    return _unpad(out) if pad else out


def des3_cbc_dec(key, iv, data, pad=True):
    out = None
    if HAVE_CRYPTO:
        try:
            out = DES3.new(key, DES3.MODE_CBC, iv).decrypt(data)
        except Exception:
            out = None
    if out is None:
        out = _openssl("des-ede3-cbc", key, iv, data)
    if out is None:
        return None
    return _unpad(out, 8) if pad else out


def aes_ctr_dec(key, iv, data):
    if HAVE_CRYPTO:
        try:
            from Crypto.Util import Counter
            return AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=0)).decrypt(data)
        except Exception:
            pass
    return _openssl("aes-256-ctr", key, iv, data)


# =========================================================================== #
#  Modèle
# =========================================================================== #

@dataclass
class Finding:
    categorie: str            # Navigateur | Système | Application | Clé | Divers
    service: str = ""         # site / cible affichée
    compte: str = ""          # identifiant
    secret: str = ""          # mot de passe / hash
    type_: str = ""           # sous-type (wifi, trousseau, rsa…)
    origine: str = ""         # navigateur / logiciel
    chemin: str = ""
    etat: str = "clair"
    poids: int = 0            # 3 = à montrer, 0 = annexe


def read_text(path, limit=4_000_000):
    try:
        raw = Path(path).read_bytes()[:limit]
    except OSError:
        return None
    if not raw or b"\x00" in raw[:2048]:
        return None
    return raw.decode("utf-8", "replace")


def short(p):
    p, h = str(p), str(HOME)
    return "~" + p[len(h):] if p.startswith(h) else p


def trunc(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


# =========================================================================== #
#  Hachages
# =========================================================================== #

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b64_24(b2, b1, b0, n):
    w = (b2 << 16) | (b1 << 8) | b0
    o = []
    for _ in range(n):
        o.append(ITOA64[w & 0x3F]); w >>= 6
    return "".join(o)


def md5_crypt(secret, salt):
    s = salt.encode()
    m = hashlib.md5(secret + b"$1$" + s)
    alt = hashlib.md5(secret + s + secret).digest()
    i = len(secret)
    while i > 0:
        m.update(alt[:min(i, 16)]); i -= 16
    i = len(secret)
    while i:
        m.update(b"\x00" if (i & 1) else secret[:1]); i >>= 1
    final = m.digest()
    for i in range(1000):
        h = hashlib.md5()
        h.update(final if (i & 1) else secret)
        if i % 3: h.update(s)
        if i % 7: h.update(secret)
        h.update(secret if (i & 1) else final)
        final = h.digest()
    return (_b64_24(final[0], final[6], final[12], 4) + _b64_24(final[1], final[7], final[13], 4)
            + _b64_24(final[2], final[8], final[14], 4) + _b64_24(final[3], final[9], final[15], 4)
            + _b64_24(final[4], final[10], final[5], 4) + _b64_24(0, 0, final[11], 2))


_SHA512_ENC = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26),
               (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
               (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38),
               (18, 39, 60), (40, 61, 19), (62, 20, 41)]
_SHA256_ENC = [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
               (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29)]


def sha_crypt(secret, salt, rounds, use512=True):
    H = hashlib.sha512 if use512 else hashlib.sha256
    ds = H().digest_size
    s = salt.encode()
    B = H(secret + s + secret).digest()
    A = H(); A.update(secret); A.update(s)
    i = len(secret)
    while i > 0:
        A.update(B[:min(i, ds)]); i -= ds
    i = len(secret)
    while i:
        A.update(B if (i & 1) else secret); i >>= 1
    A = A.digest()
    DP = H()
    for _ in range(len(secret)):
        DP.update(secret)
    DP = DP.digest()
    P = (DP * (len(secret) // ds + 1))[:len(secret)]
    DS = H()
    for _ in range(16 + A[0]):
        DS.update(s)
    DS = DS.digest()
    S = (DS * (len(s) // ds + 1))[:len(s)]
    C = A
    for i in range(rounds):
        h = H()
        h.update(P if (i & 1) else C)
        if i % 3: h.update(S)
        if i % 7: h.update(P)
        h.update(C if (i & 1) else P)
        C = h.digest()
    enc = _SHA512_ENC if use512 else _SHA256_ENC
    return "".join(_b64_24(C[a], C[b], C[c], 4) for a, b, c in enc) + _b64_24(0, 0, C[-1], 2)


def hash_password(pwd, stored):
    if _crypt:
        try:
            r = _crypt.crypt(pwd, stored)
            if r:
                return r
        except Exception:
            pass
    pb = pwd.encode()
    m = re.match(r"^\$1\$([^$]{1,8})\$", stored)
    if m:
        return "$1$%s$%s" % (m.group(1), md5_crypt(pb, m.group(1)))
    for tag, u512 in (("6", True), ("5", False)):
        m = re.match(r"^\$%s\$(?:rounds=(\d+)\$)?([^$]{1,16})\$" % tag, stored)
        if m:
            r = int(m.group(1)) if m.group(1) else 5000
            pre = ("rounds=%d$" % r) if m.group(1) else ""
            return "$%s$%s%s$%s" % (tag, pre, m.group(2), sha_crypt(pb, m.group(2), r, u512))
    return None


def _mangle(w):
    yield w
    yield w.lower()
    yield w.upper()
    yield w.capitalize()
    for suf in ("0", "1", "12", "123", "1234", "!", "!!", "2024", "2025", "2026", "@", "#"):
        yield w + suf
        yield w.capitalize() + suf
    leet = w.lower().replace("a", "@").replace("e", "3").replace("i", "1").replace("o", "0")
    if leet != w.lower():
        yield leet
        yield leet + "!"


def crack(targets, wordlist):
    found, groups, by_hash = {}, {}, {h: n for n, h in targets}
    for name, h in targets:
        groups.setdefault(h.rsplit("$", 1)[0] + "$", []).append((name, h))
    try:
        words = [w.strip().decode("utf-8", "replace")
                 for w in open(wordlist, "rb") if w.strip()]
    except OSError as e:
        print(f"  [!] {e}")
        return found
    print(f"[*] Cassage : {len(targets)} hash, {len(words)} mots…")
    todo = set(groups)
    for w in words:
        if not todo:
            break
        for cand in _mangle(w):
            for pref in list(todo):
                got = hash_password(cand, groups[pref][0][1])
                if got in by_hash:
                    found[by_hash[got]] = cand
                    print(f"  \033[32m✓\033[0m {by_hash[got]} → {cand}")
                    todo.discard(pref); groups.pop(pref, None)
    return found


# =========================================================================== #
#  Système : passwd / shadow / WiFi / PPP / Samba
# =========================================================================== #

RE_PASSWD = re.compile(r"^([\w.\-]{1,32}):([^:]*):(\d+):(\d+):([^:]*):([^:]*):(.*)$")
RE_SHADOW = re.compile(r"^([\w.\-]{1,32}):([^:]*):(\d+):(\d+):(\d+):(\d+):([^:]*):([^:]*):(.*)$")
LOGIN_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish", "/bin/dash",
                "/usr/bin/zsh", "/usr/bin/fish", "/usr/bin/bash"}
ALGOS = [(r"^\$y\$", "yescrypt"), (r"^\$7\$", "scrypt"), (r"^\$6\$", "sha512"),
         (r"^\$5\$", "sha256"), (r"^\$2[abxy]\$", "bcrypt"), (r"^\$1\$", "md5"),
         (r"^\$argon2", "argon2"), (r"^\{CRYPT\}", "DES")]


def parse_passwd(text, path):
    out = []
    for line in text.splitlines():
        m = RE_PASSWD.match(line)
        if m:
            n, pw, uid, gid, _, home, shell = m.groups()
            out.append(Finding("Système", type_="compte", service=n, compte=n,
                               secret=pw if pw not in ("x", "") else "",
                               chemin=path, origine=f"uid={uid} home={home} shell={shell}",
                               etat=shell))
    return out


def parse_shadow(text, path):
    out = []
    for line in text.splitlines():
        m = RE_SHADOW.match(line)
        if not m:
            continue
        n, h = m.group(1), m.group(2)
        if h in ("", "!"):
            algo = "aucun"
        elif h.startswith("!"):
            algo = "désactivé"
        elif h == "*":
            algo = "verrouillé"
        else:
            algo = next((a for p, a in ALGOS if re.match(p, h)), "inconnu")
        out.append(Finding("Système", type_="hash", service=n, compte=n,
                           secret=h, chemin=path, origine=algo, etat="hash"))
    return out


def parse_nm(path):
    out = []
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str
    try:
        cp.read_string(Path(path).read_text(errors="replace"))
    except Exception:
        return out
    ssid = cp.get("wifi", "ssid", fallback="") or cp.get("connection", "id", fallback="")
    for sec, key in (("wifi-security", "psk"), ("802-1x", "password"),
                     ("802-1x", "private-key-password")):
        if cp.has_option(sec, key):
            v = cp.get(sec, key).strip('"')
            if v:
                out.append(Finding("Système", type_="wifi", service=ssid or "?",
                                   compte=cp.get("802-1x", "identity", fallback="WiFi"),
                                   secret=v, chemin=path, origine="NetworkManager"))
    return out


def parse_wpa(path):
    txt = read_text(path) or ""
    out = []
    for blk in re.findall(r"network\s*=\s*\{(.*?)\}", txt, re.S):
        ssid = re.search(r'ssid\s*=\s*"?([^"\n]+)"?', blk)
        psk = re.search(r'psk\s*=\s*"?([^"\n]+)"?', blk)
        if ssid and psk:
            out.append(Finding("Système", type_="wifi", service=ssid.group(1).strip(),
                               compte="PSK", secret=psk.group(1).strip(),
                               chemin=path, origine="wpa_supplicant"))
    return out


def parse_ppp(path):
    out = []
    for line in (read_text(path) or "").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        p = line.split()
        if len(p) >= 3 and p[2] not in ("*", ""):
            out.append(Finding("Système", type_="ppp", service=p[1], compte=p[0],
                               secret=p[2], chemin=path, origine="PPP"))
    return out


def parse_kv_creds(text, path, origine, typ="app"):
    out = []
    for m in re.finditer(r"(?im)^\s*(user(?:name)?|login|pass(?:word)?|psk|token)\s*[:=]\s*(\S+)", text):
        out.append(Finding("Application", type_=typ, service=os.path.basename(path),
                           compte=m.group(1), secret=m.group(2), chemin=path, origine=origine))
    return out


def scan_system(findings, roots):
    for r in roots:
        for rel, fn in (("etc/shadow", parse_shadow), ("etc/passwd", parse_passwd)):
            p = Path(r) / rel
            if p.exists():
                findings += fn(read_text(str(p)) or "", str(p))
        for d in ("etc/NetworkManager/system-connections", "etc/wpa_supplicant"):
            p = Path(r) / d
            if p.is_dir():
                for f in p.iterdir():
                    findings += parse_nm(str(f)) if f.suffix == ".nmconnection" else parse_wpa(str(f))
        for rel in ("etc/ppp/chap-secrets", "etc/ppp/pap-secrets"):
            p = Path(r) / rel
            if p.exists():
                findings += parse_ppp(str(p))


# =========================================================================== #
#  Trousseau GNOME / KDE
# =========================================================================== #

def keyring_items():
    """Toutes les entrées du trousseau : (label, attributs, secret)."""
    items = []
    try:
        import gi
        gi.require_version("Secret", "1")
        from gi.repository import Secret
        svc = Secret.Service.get_sync(Secret.ServiceFlags.LOAD_COLLECTIONS, None)
        for coll in svc.get_collections():
            coll.load_items_sync(Secret.ItemFlags.LOAD_SECRETS, None)
            for it in coll.get_items():
                try:
                    sec = it.get_secret().get_text()
                except Exception:
                    sec = ""
                if sec:
                    items.append((it.get_label() or "", dict(it.get_attributes() or {}), sec))
        if items:
            return items
    except Exception:
        pass
    if not shutil.which("secret-tool"):
        return items
    for args in (["secret-tool", "search", "--all", "--unlock"],
                 ["secret-tool", "search", "--all", "xdg:schema", ""],
                 ["secret-tool", "search", "--all", "application", ""]):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=25)
            if r.returncode or not r.stdout.strip():
                continue
            cur = {}
            for line in r.stdout.splitlines():
                if line.startswith("["):
                    if cur.get("secret"):
                        items.append((cur.get("label", ""), cur, cur["secret"]))
                    cur = {}
                elif " = " in line:
                    k, v = line.split(" = ", 1)
                    cur[k.strip()] = v.strip()
            if cur.get("secret"):
                items.append((cur.get("label", ""), cur, cur["secret"]))
            if items:
                return items
        except Exception:
            continue
    return items


def scan_keyring(findings):
    for label, attrs, secret in keyring_items():
        svc = (attrs.get("service") or attrs.get("server") or attrs.get("host")
               or attrs.get("url") or label or "trousseau")
        user = attrs.get("username") or attrs.get("user") or attrs.get("account") or ""
        if attrs.get("application") in ("chrome", "chromium", "brave", "microsoft-edge"):
            svc = f"{label} ({attrs['application']})"
        findings.append(Finding("Système", type_="trousseau", service=svc, compte=user,
                                secret=secret, origine="trousseau GNOME"))
    for d in (HOME / ".local/share/kwalletd",):
        if d.is_dir():
            for f in d.glob("*.kwl"):
                findings.append(Finding("Système", type_="kwallet", service=f.stem,
                                        compte="(KDE)", secret="à ouvrir avec kwalletmanager",
                                        chemin=str(f), origine="KWallet", poids=2))


# =========================================================================== #
#  Navigateurs
# =========================================================================== #

def chromium_installs():
    c, out = HOME / ".config", []
    var = HOME / ".var/app"
    out += [
        ("Chrome", c / "google-chrome"), ("Chromium", c / "chromium"),
        ("Brave", c / "BraveSoftware/Brave-Browser"), ("Edge", c / "microsoft-edge"),
        ("Vivaldi", c / "vivaldi"), ("Opera", c / "opera"),
        ("Chrome", var / "com.google.Chrome/config/google-chrome"),
        ("Chromium", var / "org.chromium.Chromium/config/chromium"),
        ("Brave", var / "com.brave.Browser/config/BraveSoftware/Brave-Browser"),
        ("Edge", var / "com.microsoft.Edge/config/microsoft-edge"),
        ("Vivaldi", var / "com.vivaldi.Vivaldi/config/vivaldi"),
        ("Opera", var / "com.opera.Opera/config/opera"),
        ("Chromium", HOME / "snap/chromium/common/chromium"),
        ("Chrome", HOME / "snap/google-chrome/common/google-chrome"),
    ]
    if IS_WIN:
        loc = Path(os.environ.get("LOCALAPPDATA", HOME / "AppData/Local"))
        out += [("Chrome", loc / "Google/Chrome/User Data"),
                ("Edge", loc / "Microsoft/Edge/User Data"),
                ("Brave", loc / "BraveSoftware/Brave-Browser/User Data")]
    return [(n, p) for n, p in out if p.exists()]


KEYRING_ATTR = {"Chrome": "chrome", "Chromium": "chromium", "Brave": "brave",
                "Edge": "microsoft-edge", "Vivaldi": "vivaldi", "Opera": "opera"}


def chromium_keys(label, keyring_pw):
    keys = []
    if IS_LINUX:
        attr = KEYRING_ATTR.get(label, "chrome")
        if shutil.which("secret-tool"):
            for a in (attr, "chrome", "chromium"):
                try:
                    o = subprocess.run(["secret-tool", "lookup", "application", a],
                                       capture_output=True, timeout=15).stdout.strip()
                    if o:
                        k = base64.b64decode(o + b"=" * (-len(o) % 4))
                        if len(k) in (16, 24, 32):
                            keys.append(k)
                except Exception:
                    pass
        keys.append(hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16))
    elif IS_MAC:
        try:
            pw = subprocess.run(["security", "find-generic-password", "-w", "-s",
                                 f"{label} Safe Storage"], capture_output=True,
                                timeout=20).stdout.strip()
            if pw:
                keys.append(hashlib.pbkdf2_hmac("sha1", pw, b"saltysalt", 1003, 16))
        except Exception:
            pass
    elif IS_WIN and HAVE_DPAPI:
        try:
            ls = json.loads(Path(keyring_pw).read_text())  # unused placeholder
        except Exception:
            pass
    seen, u = set(), []
    for k in keys:
        if k and k not in seen:
            seen.add(k); u.append(k)
    return u


def chromium_decrypt(enc, key):
    if not enc:
        return ""
    if enc[:3] in (b"v10", b"v11", b"v20"):
        if HAVE_CRYPTO and (IS_WIN or enc[:3] == b"v20"):
            try:
                return AES.new(key, AES.MODE_GCM, nonce=enc[3:15]).decrypt_and_verify(
                    enc[15:-16], enc[-16:]).decode("utf-8", "replace")
            except Exception:
                pass
        pt = aes_cbc_dec(key, IV_SPACES, enc[3:])
        return pt.decode("utf-8", "replace") if pt is not None else None
    if HAVE_DPAPI and IS_WIN:
        try:
            return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1].decode("utf-8", "replace")
        except Exception:
            return None
    return enc.decode("utf-8", "replace")


def pick_key(samples, keys):
    best, bok = None, -1
    for k in keys:
        ok = sum(1 for e in samples if (chromium_decrypt(e, k) or "").isprintable()
                 and chromium_decrypt(e, k))
        if ok > bok:
            best, bok = k, ok
    return best


def _cols(conn, t):
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({t})")}
    except sqlite3.Error:
        return set()


def _copy(db):
    try:
        t = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite"); t.close()
        shutil.copy2(db, t.name)
        return t.name
    except OSError:
        return None


def scan_chromium(findings):
    for label, base in chromium_installs():
        profiles = [base] if (base / "Login Data").exists() else []
        profiles += [d for d in sorted(base.glob("*"))
                     if d.is_dir() and (d.name == "Default" or d.name.startswith("Profile"))]
        profiles = [p for p in profiles if (p / "Login Data").exists()]
        if not profiles:
            continue
        keys = chromium_keys(label, None)
        tmp = _copy(profiles[0] / "Login Data")
        samples = []
        if tmp:
            try:
                samples = [r[0] for r in sqlite3.connect(tmp).execute(
                    "SELECT password_value FROM logins WHERE length(password_value)>0 LIMIT 30")]
            finally:
                os.unlink(tmp)
        key = pick_key(samples, keys)
        for prof in profiles:
            tmp = _copy(prof / "Login Data")
            if not tmp:
                continue
            try:
                conn = sqlite3.connect(tmp)
                for url, user, enc in conn.execute(
                        "SELECT origin_url, username_value, password_value FROM logins"):
                    if not user and not enc:
                        continue
                    host = re.sub(r"^www\.", "", (re.match(r"(?:https?://)?([^/:]+)", url or "") or
                                                  re.match(r"", "")).group(1) if url else "") or url
                    pwd = chromium_decrypt(enc, key) if key else None
                    findings.append(Finding("Navigateur", service=host,
                                            compte=user or "(sans identifiant)",
                                            secret=pwd if pwd is not None else "<clé indisponible>",
                                            origine=label, chemin=str(prof),
                                            etat="clair" if pwd is not None else "chiffré",
                                            type_="web"))
                conn.close()
            except sqlite3.Error:
                pass
            finally:
                os.unlink(tmp)


def firefox_profiles():
    bases = [HOME / ".mozilla/firefox",
             HOME / "snap/firefox/common/.mozilla/firefox",
             HOME / ".var/app/org.mozilla.firefox/.mozilla/firefox",
             HOME / ".thunderbird",
             HOME / "snap/thunderbird/common/.thunderbird",
             HOME / ".var/app/org.mozilla.Thunderbird/.thunderbird"]
    if IS_WIN:
        bases += [Path(os.environ.get("APPDATA", HOME)) / "Mozilla/Firefox",
                  Path(os.environ.get("APPDATA", HOME)) / "Thunderbird"]
    out = []
    for b in bases:
        if b.exists():
            for p in b.glob("*"):
                if p.is_dir() and any((p / f).exists() for f in
                                      ("logins.json", "key4.db", "signons.sqlite")):
                    out.append(p)
    return out


def _der(d, o=0):
    t = d[o]; o += 1
    ln = d[o]; o += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(d[o:o + n], "big"); o += n
    return t, d[o:o + ln], o + ln


def firefox_master_key(profile):
    db = profile / "key4.db"
    if not db.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        row = conn.execute("SELECT item1,item2 FROM metaData WHERE id='password'").fetchone()
        if not row:
            return None
        gsalt, item2 = row
        _, seq, _ = _der(item2, 0)
        _, _alg, off = _der(seq, 0)
        _, params, _ = _der(seq, off)
        esalt = iters = None
        p = 0
        while p < len(params):
            t, v, p = _der(params, p)
            if t == 0x04:
                esalt = v
            elif t == 0x02:
                iters = int.from_bytes(v, "big")
        if not esalt or not iters:
            return None
        hp = hashlib.sha1(gsalt).digest()
        chp = hashlib.sha1(hp + esalt + b"\x00" * max(0, 20 - len(esalt))).digest()
        k1 = hashlib.sha1(chp + gsalt + esalt).digest()
        pbe = hashlib.pbkdf2_hmac("sha1", k1, gsalt, iters, 32)
        for (a11,) in conn.execute("SELECT a11 FROM nssPrivate"):
            if not a11:
                continue
            dec = des3_cbc_dec(pbe[:24], b"\x04\x0e" + b"\x00" * 6, a11, pad=False)
            if not dec or dec[0] != 0x30:
                continue
            octs, o = [], 0
            def walk(b, depth=0):
                nonlocal o
                o = 0
                while o < len(b):
                    try:
                        t, v, o = _der(b, o)
                    except Exception:
                        return
                    if t == 0x04 and len(v) in (16, 24, 32):
                        octs.append(v)
                    elif t in (0x30, 0x31) and depth < 6:
                        sub, save = v, o
                        walk(sub, depth + 1)
                        o = save
            walk(dec)
            if octs:
                return octs[0]
    except sqlite3.Error:
        return None
    return None


def _ff_decrypt(b64, key):
    if not b64:
        return ""
    if not key:
        return "<clé absente>"
    try:
        blob = base64.b64decode(b64)
        _, outer, _ = _der(blob, 0)
        _, inner, off = _der(outer, 0)
        _, iv, _ = _der(inner, 0)
        _, ct, _ = _der(outer, off)
        pt = des3_cbc_dec(key[:24], iv, ct, pad=False)
        return _unpad(pt, 8).decode("utf-8", "replace") if pt else "<échec>"
    except Exception:
        return "<échec>"


def scan_firefox(findings):
    for prof in firefox_profiles():
        key = firefox_master_key(prof)
        name = "Thunderbird" if "thunderbird" in str(prof).lower() else "Firefox"
        for fn in ("logins.json", "logins-backup.json"):
            f = prof / fn
            if not f.exists():
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            for e in data.get("logins", []):
                host = e.get("hostname", "")
                pwd = _ff_decrypt(e.get("encryptedPassword", ""), key)
                findings.append(Finding("Navigateur", service=re.sub(r"^www\.", "", host),
                                        compte=e.get("usernameField", "") or "(sans identifiant)",
                                        secret=pwd, origine=name, chemin=str(prof),
                                        etat="clair" if key and not pwd.startswith("<") else "chiffré",
                                        type_="web"))
        sq = prof / "signons.sqlite"
        if sq.exists():
            tmp = _copy(sq)
            if tmp:
                try:
                    conn = sqlite3.connect(tmp)
                    for host, user, enc in conn.execute(
                            "SELECT hostname,encryptedUsername,encryptedPassword FROM moz_logins"):
                        if enc:
                            pwd = _ff_decrypt(enc.decode("utf-8", "replace")
                                              if isinstance(enc, bytes) else enc, key)
                            findings.append(Finding("Navigateur", service=re.sub(r"^www\.", "", host),
                                                    compte=user or "", secret=pwd, origine=name,
                                                    chemin=str(prof), type_="web"))
                    conn.close()
                except sqlite3.Error:
                    pass
                finally:
                    os.unlink(tmp)


# =========================================================================== #
#  Applications
# =========================================================================== #

RCLONE_KEY = bytes([0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d, 0x6b, 0xfd, 0x7c, 0x63,
                    0xc8, 0x86, 0xa9, 0x2b, 0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb,
                    0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38])


def scan_apps(findings):
    # FileZilla
    for f in (HOME / ".config/filezilla").glob("*.xml"):
        txt = read_text(str(f)) or ""
        for m in re.finditer(r"<Host>([^<]*)</Host>.*?<User>([^<]*)</User>.*?"
                             r"<Pass[^>]*>([^<]*)</Pass>", txt, re.S):
            try:
                pw = base64.b64decode(m.group(3)).decode("utf-8", "replace")
            except Exception:
                pw = m.group(3)
            findings.append(Finding("Application", type_="ftp", service=m.group(1),
                                    compte=m.group(2), secret=pw, chemin=str(f),
                                    origine="FileZilla"))
    # Remmina
    for f in (HOME / ".local/share/remmina").glob("*.remmina"):
        cp = configparser.ConfigParser(interpolation=None)
        try:
            cp.read_string((read_text(str(f)) or "").replace("%", "%%"))
        except Exception:
            continue
        if cp.has_option("remmina", "password"):
            try:
                pw = base64.b64decode(cp.get("remmina", "password")).decode("utf-8", "replace")
            except Exception:
                pw = cp.get("remmina", "password")
            findings.append(Finding("Application", type_="rdp", service=f.stem,
                                    compte=cp.get("remmina", "username", fallback=""),
                                    secret=pw, chemin=str(f), origine="Remmina"))
    # Docker
    dc = HOME / ".docker/config.json"
    if dc.exists():
        try:
            for host, v in (json.loads(dc.read_text()).get("auths") or {}).items():
                if v.get("auth"):
                    u, _, p = base64.b64decode(v["auth"]).decode().partition(":")
                    findings.append(Finding("Application", type_="registry", service=host,
                                            compte=u, secret=p, chemin=str(dc), origine="Docker"))
        except Exception:
            pass
    # rclone
    rc = HOME / ".config/rclone/rclone.conf"
    if rc.exists():
        for m in re.finditer(r"\[([^\]]+)\][^\[]*?(?:user\s*=\s*(\S+))?[^\[]*?pass\s*=\s*(\S+)",
                             rc.read_text(errors="replace"), re.S):
            try:
                raw = base64.urlsafe_b64decode(m.group(3) + "=" * (-len(m.group(3)) % 4))
                pw = (aes_ctr_dec(RCLONE_KEY, b"\x00" * 16, raw) or b"").decode("utf-8", "replace")
            except Exception:
                pw = m.group(3)
            findings.append(Finding("Application", type_="cloud", service=m.group(1),
                                    compte=m.group(2) or "", secret=pw or m.group(3),
                                    chemin=str(rc), origine="rclone"))
    # Pidgin
    pg = HOME / ".purple/accounts.xml"
    if pg.exists():
        txt = read_text(str(pg)) or ""
        for m in re.finditer(r"<name>([^<]+)</name>\s*<password>([^<]*)</password>", txt):
            findings.append(Finding("Application", type_="im", service=m.group(1),
                                    compte=m.group(1), secret=m.group(2),
                                    chemin=str(pg), origine="Pidgin"))
    # credentials génériques
    for rel, org in ((".smbcredentials", "Samba"), (".config/msmtp/config", "msmtp"),
                     (".aws/credentials", "AWS"), (".config/gcloud/credentials.db", "gcloud")):
        p = HOME / rel
        if p.exists():
            findings += parse_kv_creds(read_text(str(p)) or "", str(p), org)
    # netrc / git
    for rel, org, typ in ((".netrc", "netrc", "web"), (".git-credentials", "Git", "web")):
        p = HOME / rel
        if p.exists():
            txt = read_text(str(p)) or ""
            for m in re.finditer(r"machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)", txt):
                findings.append(Finding("Application", type_=typ, service=m.group(1),
                                        compte=m.group(2), secret=m.group(3),
                                        chemin=str(p), origine=org))
            for m in re.finditer(r"://([^:@/\s]+):([^@/\s]+)@([^/\s]+)", txt):
                findings.append(Finding("Application", type_=typ, service=m.group(3),
                                        compte=m.group(1), secret=m.group(2),
                                        chemin=str(p), origine=org))
    # thunderbird/autres
    for rel in (".ssh/config",):
        p = HOME / rel
        if p.exists():
            for m in re.finditer(r"(?im)^\s*Host\s+(\S+)[\s\S]*?^\s*User\s+(\S+)",
                                 read_text(str(p)) or "", re.M):
                findings.append(Finding("Application", type_="ssh", service=m.group(1),
                                        compte=m.group(2), secret="", chemin=str(p),
                                        origine="ssh_config"))


# =========================================================================== #
#  Clés
# =========================================================================== #

def scan_keys(paths, findings):
    for p in paths:
        low = os.path.basename(p).lower()
        if not (low.endswith((".pem", ".key", ".ppk")) or low in
                ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")):
            continue
        txt = read_text(p, 200_000)
        if not txt or "PRIVATE KEY" not in txt:
            continue
        kind = "OPENSSH" if "OPENSSH" in txt else (
            "ENCRYPTED" if ("ENCRYPTED PRIVATE KEY" in txt or "Proc-Type: 4,ENCRYPTED" in txt)
            else "PEM")
        etat = "chiffrée" if kind == "ENCRYPTED" else "clair"
        poids = 3 if re.search(r"/(\.ssh|\.config|\.ollama|ssl/private|fwupd)/", p) else \
            (0 if re.search(r"/(usr/share/doc|usr/lib|dist-packages|site-packages|"
                            r"snap/[^/]+/\d+/usr|test|sample|toolchain)/", p) else 1)
        findings.append(Finding("Clé", type_=kind, service=os.path.basename(p),
                                compte="", secret="", chemin=p, etat=etat, poids=poids))


# =========================================================================== #
#  Parcours
# =========================================================================== #

EXACT = {".env", "credentials", ".netrc", "_netrc", ".git-credentials", ".npmrc",
         ".pypirc", ".pgpass", ".my.cnf", ".htpasswd", ".s3cfg", ".msmtprc",
         ".gitconfig", ".wgetrc", "id_rsa", "id_ed25519", "id_ecdsa",
         "appsettings.json", "wp-config.php", "passwd", "shadow", "group"}
EXCL = {"$RECYCLE.BIN", "System Volume Information", "node_modules", "__pycache__",
        ".cache", "proc", "sys", "dev", "dist-packages", "site-packages"}


def interesting(p):
    n = os.path.basename(p).lower()
    return n in EXACT or n.startswith(".env") or n.endswith(
        (".pem", ".key", ".ppk", ".nmconnection")) or "history" in n


def walk(roots):
    out = []
    for r in roots:
        st = [os.path.abspath(r)]
        while st:
            cur = st.pop()
            try:
                with os.scandir(cur) as it:
                    for e in it:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                if e.name not in EXCL:
                                    st.append(e.path)
                            elif e.is_file(follow_symlinks=False) and interesting(e.path):
                                out.append(e.path)
                        except OSError:
                            continue
            except OSError:
                continue
    return out


def analyse(paths):
    res = []
    def job(p):
        try:
            if os.path.getsize(p) > 4_000_000:
                return []
            low = os.path.basename(p).lower()
            t = read_text(p)
            if not t:
                return []
            if low == "shadow":
                return parse_shadow(t, p)
            if low == "passwd":
                return parse_passwd(t, p)
            if low == ".netrc":
                return [Finding("Application", type_="web", service=m.group(1),
                                compte=m.group(2), secret=m.group(3), chemin=p, origine="netrc")
                        for m in re.finditer(r"machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)", t)]
            if low == ".git-credentials":
                return [Finding("Application", type_="web", service=m.group(3),
                                compte=m.group(1), secret=m.group(2), chemin=p, origine="Git")
                        for m in re.finditer(r"://([^:@/\s]+):([^@/\s]+)@([^/\s]+)", t)]
            if low in ("passwd",) or low.endswith((".ini", ".conf", ".cfg")):
                cp = configparser.ConfigParser(interpolation=None)
                try:
                    cp.read_string(t)
                    return [Finding("Divers", service=os.path.basename(p), compte=f"{s}.{k}",
                                    secret=v, chemin=p, origine="config")
                            for s in cp.sections() for k, v in cp.items(s)
                            if re.search(r"(?i)pass|secret|token|key|user|login", k) and 0 < len(v) < 120]
                except Exception:
                    return []
            return []
        except OSError:
            return []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(job, paths):
            res += r
    return res


# =========================================================================== #
#  Rendu
# =========================================================================== #

def table(headers, rows, widths, indent="  "):
    if not rows:
        return
    print(indent + "  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print(indent + "  ".join("─" * w for w in widths))
    for r in rows:
        print(indent + "  ".join(trunc(c, w).ljust(w) for c, w in zip(r, widths)))


def print_report(findings, opts):
    creds = [f for f in findings if f.categorie == "Navigateur"]
    seen, uc = set(), []
    for f in sorted(creds, key=lambda x: (x.service.lower(), x.compte.lower())):
        k = (f.service.lower(), f.compte.lower(), f.secret)
        if k not in seen:
            seen.add(k); uc.append(f)

    sysf = [f for f in findings if f.categorie == "Système"]
    apps = [f for f in findings if f.categorie == "Application"]
    keys = [f for f in findings if f.categorie == "Clé"]

    print("\n" + "═" * 90)
    print(f"  AUDIT DISQUE — {len(uc)} identifiant(s) navigateur · {len(sysf)} secret(s) système")
    print("═" * 90)

    print(f"\n▌ NAVIGATEURS ({len(uc)})\n")
    if uc:
        hdr = ["SITE / APPLICATION", "IDENTIFIANT", "MOT DE PASSE"]
        w = [30, 26, 30]
        if opts.verbose:
            hdr += ["ORIGINE"]; w += [16]
        table(hdr, [[f.service, f.compte, f.secret] +
                    ([f"{f.origine}"] if opts.verbose else []) for f in uc], w)
    else:
        print("  (aucun mot de passe navigateur trouvé)")

    print(f"\n▌ SYSTÈME ({len(sysf)})\n")
    rows = []
    for f in sorted(sysf, key=lambda x: (x.type_ != "compte", x.type_ != "hash", x.service)):
        if f.type_ == "compte":
            if f.etat in LOGIN_SHELLS or f.secret:
                rows.append(["compte", f.service, f.secret or "(pas de hash)", f.origine])
        elif f.type_ == "hash":
            rows.append(["mot de passe session", f.compte, trunc(f.secret, 34), f.origine])
        else:
            rows.append([f.type_, f.service, f.secret, f.origine])
    table(["TYPE", "CIBLE", "SECRET", "ORIGINE"], rows, [22, 24, 34, 18])
    h = [f for f in sysf if f.type_ == "hash" and f.secret.startswith("$")]
    if h:
        print(f"\n  → {len(h)} hash cassable(s) : sudo python3 disk.py --wordlist mots.txt")

    if apps:
        print(f"\n▌ APPLICATIONS ({len(apps)})\n")
        table(["TYPE", "SERVICE", "IDENTIFIANT", "MOT DE PASSE"],
              [[f.origine, f.service, f.compte, f.secret] for f in apps], [14, 26, 22, 26])

    show_keys = [k for k in keys if k.poids >= 2 or opts.all]
    if show_keys:
        print(f"\n▌ CLÉS PRIVÉES ({len(show_keys)} / {len(keys)})\n")
        table(["ÉTAT", "TYPE", "FICHIER"],
              [[k.etat, k.type_, short(k.chemin)] for k in show_keys], [10, 12, 60])

    if opts.all:
        div = [f for f in findings if f.categorie == "Divers"]
        if div:
            print(f"\n▌ DIVERS ({len(div)})\n")
            table(["SOURCE", "CLÉ", "VALEUR"], [[f.service, f.compte, f.secret] for f in div],
                  [26, 30, 30])

    print("\n" + "═" * 90 + "\n")


# =========================================================================== #
#  Main
# =========================================================================== #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/")
    ap.add_argument("--auto-mounts", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--no-browsers", action="store_true")
    ap.add_argument("--no-files", action="store_true")
    ap.add_argument("--no-keyring", action="store_true")
    ap.add_argument("--no-auto-venv", action="store_true")
    ap.add_argument("--wordlist")
    ap.add_argument("--keyring-password")
    ap.add_argument("--report", metavar="PREFIXE")
    args = ap.parse_args()

    ensure_crypto(not args.no_auto_venv)
    fix_session_env()

    if not HAVE_CRYPTO:
        print("\033[33m[i]\033[0m pycryptodome absent → repli openssl (AES/3DES OK, "
              "Windows v20 limité)")

    findings = []

    if not args.no_browsers:
        print("[*] Navigateurs…")
        for fn in (scan_chromium, scan_firefox):
            try:
                fn(findings)
            except Exception as e:
                print(f"  [!] {fn.__name__}: {e}")

    print("[*] Système…")
    scan_system(findings, [args.root])
    if not args.no_keyring:
        try:
            scan_keyring(findings)
        except Exception as e:
            print(f"  [!] trousseau: {e}")
    scan_apps(findings)

    if not args.no_files:
        print("[*] Fichiers…")
        paths = walk([args.root])
        findings += analyse(paths)
        scan_keys(paths, findings)

    seen, uniq = set(), []
    for f in findings:
        k = (f.categorie, f.service, f.compte, f.secret, f.type_)
        if k not in seen:
            seen.add(k); uniq.append(f)

    if args.wordlist:
        tg = [(f.compte, f.secret) for f in uniq
              if f.categorie == "Système" and f.type_ == "hash" and f.secret.startswith("$")]
        if tg:
            for name, pwd in crack(tg, args.wordlist).items():
                for f in uniq:
                    if f.compte == name and f.type_ == "hash":
                        f.secret = pwd; f.origine = "cassé ✓"

    print_report(uniq, args)

    if args.report:
        with open(f"{args.report}.json", "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in uniq], fh, indent=2, ensure_ascii=False)
        with open(f"{args.report}.csv", "w", newline="", encoding="utf-8") as fh:
            wr = csv.DictWriter(fh, fieldnames=list(asdict(uniq[0]).keys()))
            wr.writeheader(); wr.writerows([asdict(f) for f in uniq])
        print(f"→ {args.report}.json / .csv")


if __name__ == "__main__":
    main()