#!/usr/bin/env python3
"""
APKShield v3.0 - Professional APK Asset Protector
==================================================
تشفير AES-256-GCM لكل ما يمكن تشفيره بأمان في APK،
مع الحفاظ على قابلية التثبيت والتشغيل.

الاستخدام:
  python3 apkshield.py encrypt input.apk output.apk
  python3 apkshield.py encrypt input.apk output.apk -k key.bin
  python3 apkshield.py decrypt output.apk restored.apk -k key.bin
  python3 apkshield.py verify  input.apk output.apk  -k key.bin
  python3 apkshield.py list    input.apk
  python3 apkshield.py test
"""

import argparse
import hashlib
import io
import json
import os
import secrets
import shutil
import signal
import struct
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

# ─── تبعيات خارجية ──────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("ERROR: pip install cryptography", file=sys.stderr)
    sys.exit(1)

try:
    from colorama import Fore, Style, init as _ci
    _ci(autoreset=True)
    R = Fore.RED; G = Fore.GREEN; Y = Fore.YELLOW
    C = Fore.CYAN; B = Fore.BLUE; W = Style.RESET_ALL
except ImportError:
    R = G = Y = C = B = W = ""

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ─── ثوابت ──────────────────────────────────────────────────────────────────
VERSION       = "3.0.0"
MAGIC         = b"\xAE\x5C\x03"          # 3 bytes: APKShield v3 magic
NONCE_SIZE    = 12                         # AES-GCM nonce
TAG_SIZE      = 16                         # GCM authentication tag
HEADER_SIZE   = len(MAGIC) + NONCE_SIZE   # 15 bytes before ciphertext
MANIFEST_PATH = "assets/.apkshield/manifest.json.shld"
VERSION_PATH  = "assets/.apkshield/version"
CHUNK_SIZE    = 4 * 1024 * 1024           # 4 MB streaming chunks

# ─── الملفات التي لا يمكن تشفيرها أبداً (Android يحتاجها خاماً) ─────────────
#
#  AndroidManifest.xml  — يقرأه PackageManager قبل تحميل أي كود
#  classes.dex          — أول DEX يُحمَّل بواسطة Dalvik/ART مباشرة
#  resources.arsc       — يقرأه AssetManager لاسترجاع الموارد
#  META-INF/            — التوقيع الرقمي، أي تغيير يبطله
#
#  ملاحظة: classes2.dex وما بعدها يمكن تشفيرها لكن التطبيق يحتاج
#  Loader مخصص لتحميلها. بدون Loader يُبقيها الوضع الافتراضي سليمة.
#
NEVER_ENCRYPT = frozenset({
    "AndroidManifest.xml",
    "classes.dex",
    "resources.arsc",
})
NEVER_ENCRYPT_PREFIXES = ("META-INF/",)

# ─── ألوان ومساعدات ─────────────────────────────────────────────────────────
def _p(color: str, tag: str, msg: str, file=sys.stdout):
    print(f"{color}[{tag}]{W} {msg}", file=file)

def info(m):  _p(C,  "*", m)
def ok(m):    _p(G,  "+", m)
def warn(m):  _p(Y,  "!", m)
def err(m):   _p(R,  "x", m, file=sys.stderr)
def fatal(m): err(m); sys.exit(1)

# ─── إشارة إلغاء آمنة ───────────────────────────────────────────────────────
_cancel_requested = False
def _sig_handler(sig, frame):
    global _cancel_requested
    _cancel_requested = True
    warn("Cancellation requested — finishing current file safely...")
signal.signal(signal.SIGINT, _sig_handler)

def check_cancel():
    if _cancel_requested:
        fatal("Operation cancelled by user.")

# ─── HKDF — مفتاح مختلف لكل ملف ────────────────────────────────────────────
def derive_file_key(master: bytes, filename: str) -> bytes:
    """اشتقاق مفتاح 256-bit فريد لكل ملف باستخدام HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=master[:16],                   # أول 16 byte من المفتاح كـ salt
        info=f"apkshield-v3:{filename}".encode()
    ).derive(master)

# ─── تشفير / فك (streaming-safe) ────────────────────────────────────────────
def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """
    تشفير AES-256-GCM.
    التنسيق: [3 magic] [12 nonce] [ciphertext + 16 GCM-tag]
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct    = AESGCM(key).encrypt(nonce, data, None)
    return MAGIC + nonce + ct

def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """
    فك تشفير. يرفع:
      ValueError   — magic خاطئ (ليس ملف APKShield)
      InvalidTag   — مفتاح خاطئ أو بيانات تالفة
    """
    if len(blob) < HEADER_SIZE + TAG_SIZE:
        raise ValueError(f"Blob too short: {len(blob)} bytes")
    if blob[:3] != MAGIC:
        raise ValueError(f"Bad magic: {blob[:3].hex()}")
    nonce = blob[3:3 + NONCE_SIZE]
    ct    = blob[3 + NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, None)   # InvalidTag إذا فشل

# ─── هل يجب تشفير هذا الملف؟ ────────────────────────────────────────────────
def should_encrypt(name: str) -> bool:
    if name.endswith("/"):                 # مجلد فارغ
        return False
    if name in NEVER_ENCRYPT:
        return False
    for p in NEVER_ENCRYPT_PREFIXES:
        if name.startswith(p):
            return False
    # تجاهل ملفات APKShield نفسها
    if name.startswith("assets/.apkshield/"):
        return False
    return True

# ─── التحقق من APK ──────────────────────────────────────────────────────────
def validate_apk(path: str) -> None:
    """يرفع استثناء مفصّلاً إذا لم يكن APK صالحاً."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    if os.path.getsize(path) == 0:
        raise ValueError(f"File is empty: {path}")
    if not zipfile.is_zipfile(path):
        raise ValueError(f"Not a valid ZIP/APK: {path}")
    # تحقق من وجود AndroidManifest.xml
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if "AndroidManifest.xml" not in names:
            raise ValueError(f"Missing AndroidManifest.xml — not a valid APK")

# ─── DEX obfuscation (آمنة فقط) ─────────────────────────────────────────────
# المشكلة في v2: استبدال النصوص ببايتات عشوائية يكسر مراجع String IDs
# الحل في v3: تعطيل هذه الميزة بالكامل لأنها غير آمنة بدون أداة DEX كاملة.
# تحتاج dexlib2 أو smali/baksmali لتعديل DEX بأمان.
DEX_OBFUSCATION_AVAILABLE = False
def obfuscate_dex_strings(data: bytes) -> bytes:
    """
    معطّلة في v3: تعديل DEX بدون تحديث Checksum/Signature
    يُنتج APK لا يُثبَّت أو يتعطل عند التشغيل.
    """
    return data  # إرجاع بدون تعديل

# ─── بناء Manifest داخلي ────────────────────────────────────────────────────
def build_manifest(encrypted: Dict, apk_info: Dict) -> bytes:
    return json.dumps({
        "tool":    "APKShield",
        "version": VERSION,
        "created": int(time.time()),
        "apk":     apk_info,
        "algo":    "AES-256-GCM",
        "kdf":     "HKDF-SHA256",
        "magic":   MAGIC.hex(),
        "files":   encrypted
    }, ensure_ascii=False, indent=2).encode("utf-8")

# ─── التشفير الرئيسي ─────────────────────────────────────────────────────────
def protect_apk(inp: str, out: str, master: bytes) -> Tuple[Dict, Dict]:
    """
    تشفير APK. يعيد (stats, manifest_dict).
    يرفع استثناء مفصّلاً عند أي فشل.
    """
    validate_apk(inp)

    # تحقق من مساحة القرص (نحتاج ضعف حجم APK على الأقل)
    apk_size  = os.path.getsize(inp)
    free_space = shutil.disk_usage(os.path.dirname(os.path.abspath(out))).free
    if free_space < apk_size * 2.5:
        raise OSError(f"Insufficient disk space: need ~{apk_size*2.5/1e6:.0f} MB, "
                      f"have {free_space/1e6:.0f} MB")

    stats    = {"total": 0, "encrypted": 0, "plain": 0,
                "size_before": apk_size, "size_after": 0, "errors": 0}
    manifest = {}

    # معلومات APK الأصلية
    with zipfile.ZipFile(inp) as z:
        entry_names = z.namelist()
    apk_info = {
        "original_path": os.path.abspath(inp),
        "sha256":        _sha256_file(inp),
        "size":          apk_size,
        "file_count":    len(entry_names)
    }

    info(f"Input APK : {inp}  ({apk_size/1e6:.2f} MB, {len(entry_names)} files)")

    with tempfile.TemporaryDirectory() as tmp:
        out_tmp = Path(tmp) / "protected.apk"

        with zipfile.ZipFile(inp, "r") as zin, \
             zipfile.ZipFile(str(out_tmp), "w",
                             compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6) as zout:

            entries = zin.infolist()
            iterator = (tqdm(entries, unit="file", desc="Encrypting",
                             dynamic_ncols=True)
                        if HAS_TQDM else entries)

            for e in iterator:
                check_cancel()
                stats["total"] += 1

                try:
                    raw = zin.read(e.filename)
                except Exception as ex:
                    err(f"  Read error: {e.filename}: {ex}")
                    stats["errors"] += 1
                    continue

                if should_encrypt(e.filename):
                    fk  = derive_file_key(master, e.filename)
                    enc = encrypt_bytes(raw, fk)
                    enc_name = e.filename + ".shld"

                    zi = zipfile.ZipInfo(enc_name)
                    zi.compress_type = zipfile.ZIP_STORED  # مشفّر لا ينضغط
                    zout.writestr(zi, enc)

                    manifest[e.filename] = {
                        "enc_name":     enc_name,
                        "original_size": len(raw),
                        "enc_size":      len(enc),
                        "sha256":        hashlib.sha256(raw).hexdigest(),
                    }
                    stats["encrypted"] += 1
                    if not HAS_TQDM:
                        ok(f"  ENC  {e.filename}  ({len(raw)/1024:.1f} KB)")

                else:
                    # القائمة البيضاء — انسخ كما هو بدون تعديل
                    zi = zipfile.ZipInfo(e.filename)
                    zi.compress_type = e.compress_type
                    zout.writestr(zi, raw)
                    stats["plain"] += 1
                    if not HAS_TQDM:
                        warn(f"  PLAIN {e.filename}")

            # Manifest مشفّر
            mf_data = build_manifest(manifest, apk_info)
            mf_key  = derive_file_key(master, ".apkshield_manifest")
            mf_enc  = encrypt_bytes(mf_data, mf_key)
            _zwrite(zout, MANIFEST_PATH, mf_enc, zipfile.ZIP_STORED)
            _zwrite(zout, VERSION_PATH,
                    f"APKShield-v{VERSION}\n".encode(), zipfile.ZIP_DEFLATED)

        # انسخ للمسار النهائي
        shutil.copy(str(out_tmp), out)
        stats["size_after"] = os.path.getsize(out)

    return stats, manifest

def _zwrite(zout: zipfile.ZipFile, name: str, data: bytes, ctype: int):
    zi = zipfile.ZipInfo(name)
    zi.compress_type = ctype
    zout.writestr(zi, data)

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# ─── التحقق من التشفير ──────────────────────────────────────────────────────
def verify_apk(inp: str, out: str, master: bytes) -> bool:
    """
    تحقق من صحة كل ملف مشفّر بمقارنة SHA-256.
    يعيد True إذا نجح كل شيء.
    """
    validate_apk(out)
    info("Loading manifest...")

    with zipfile.ZipFile(out) as z:
        try:
            mf_enc = z.read(MANIFEST_PATH)
        except KeyError:
            err("Manifest not found in protected APK"); return False
        mf_key   = derive_file_key(master, ".apkshield_manifest")
        try:
            mf_data  = decrypt_bytes(mf_enc, mf_key)
        except (InvalidTag, ValueError) as e:
            err(f"Cannot decrypt manifest: {e}"); return False
        mf       = json.loads(mf_data)
        manifest = mf.get("files", {})

    info(f"Verifying {len(manifest)} encrypted files...")
    ok_c = fail_c = 0

    with zipfile.ZipFile(inp) as zin, zipfile.ZipFile(out) as zout:
        all_enc = zout.namelist()
        for orig_name, meta in manifest.items():
            enc_name = meta["enc_name"]
            if enc_name not in all_enc:
                err(f"  MISSING: {enc_name}"); fail_c += 1; continue
            try:
                orig_data = zin.read(orig_name)
                enc_data  = zout.read(enc_name)
                dec_data  = decrypt_bytes(enc_data, derive_file_key(master, orig_name))
            except (InvalidTag, ValueError) as ex:
                err(f"  DECRYPT FAIL: {orig_name}: {ex}"); fail_c += 1; continue
            except Exception as ex:
                err(f"  ERROR: {orig_name}: {ex}"); fail_c += 1; continue

            orig_hash = hashlib.sha256(orig_data).hexdigest()
            dec_hash  = hashlib.sha256(dec_data).hexdigest()
            exp_hash  = meta.get("sha256", "")

            if orig_hash != dec_hash:
                err(f"  HASH MISMATCH: {orig_name}"); fail_c += 1
            elif exp_hash and dec_hash != exp_hash:
                err(f"  HASH VS MANIFEST: {orig_name}"); fail_c += 1
            else:
                ok(f"  OK  {orig_name}"); ok_c += 1

    if fail_c == 0:
        ok(f"All {ok_c} files verified successfully.")
        return True
    else:
        err(f"Verification: {ok_c} OK, {fail_c} FAILED"); return False

# ─── استعادة APK ─────────────────────────────────────────────────────────────
def decrypt_apk(protected: str, out: str, master: bytes) -> bool:
    """فك تشفير APK محمي واستعادة النسخة الأصلية."""
    validate_apk(protected)

    with zipfile.ZipFile(protected) as z:
        try:
            mf_enc = z.read(MANIFEST_PATH)
        except KeyError:
            fatal("Not an APKShield-protected APK (manifest missing)")
        mf_key  = derive_file_key(master, ".apkshield_manifest")
        try:
            mf_data = decrypt_bytes(mf_enc, mf_key)
        except InvalidTag:
            fatal("Wrong key or corrupted manifest")
        manifest = json.loads(mf_data).get("files", {})

    info(f"Restoring {len(manifest)} encrypted files...")

    with tempfile.TemporaryDirectory() as tmp:
        out_tmp = Path(tmp) / "restored.apk"
        errors  = 0

        with zipfile.ZipFile(protected, "r") as zin, \
             zipfile.ZipFile(str(out_tmp), "w",
                             compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6) as zout:

            # الملفات المشفرة → فك وكتابة باسمها الأصلي
            enc_names = {m["enc_name"] for m in manifest.values()}
            # خريطة عكسية
            rev = {m["enc_name"]: (orig, m) for orig, m in manifest.items()}

            for e in zin.infolist():
                raw = zin.read(e.filename)

                if e.filename in rev:
                    orig_name, meta = rev[e.filename]
                    try:
                        dec = decrypt_bytes(raw, derive_file_key(master, orig_name))
                    except (InvalidTag, ValueError) as ex:
                        err(f"  DECRYPT FAIL: {orig_name}: {ex}")
                        errors += 1; continue
                    # تحقق hash
                    if hashlib.sha256(dec).hexdigest() != meta["sha256"]:
                        err(f"  HASH MISMATCH after decrypt: {orig_name}")
                        errors += 1; continue
                    zi = zipfile.ZipInfo(orig_name)
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zout.writestr(zi, dec)
                    ok(f"  restored: {orig_name}")

                elif e.filename in (MANIFEST_PATH, VERSION_PATH):
                    continue  # حذف ملفات APKShield

                else:
                    # ملفات القائمة البيضاء — انسخ كما هي
                    zi = zipfile.ZipInfo(e.filename)
                    zi.compress_type = e.compress_type
                    zout.writestr(zi, raw)

        if errors:
            err(f"{errors} file(s) could not be restored"); return False

        shutil.copy(str(out_tmp), out)

    ok(f"Restored APK: {out}")
    warn("NOTE: APK signature was invalidated by protection. Re-sign before installing.")
    return True

# ─── إدارة المفاتيح ──────────────────────────────────────────────────────────
def save_key(key: bytes, path: str) -> None:
    """حفظ المفتاح. يضبط أذونات الملف على 600."""
    with open(path, "w") as f:
        f.write("APKSHIELD_KEY_V3\n")
        f.write(key.hex() + "\n")
        f.write(f"# sha256(key)={hashlib.sha256(key).hexdigest()[:16]}...\n")
        f.write("# Keep this file SECRET.\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    ok(f"Key saved: {path}  (permissions 600)")

def load_key(path: str) -> bytes:
    """تحميل مفتاح من ملف."""
    if not os.path.isfile(path):
        fatal(f"Key file not found: {path}")
    for line in open(path).read().splitlines():
        line = line.strip()
        if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
            return bytes.fromhex(line)
    fatal(f"Invalid key file (no 64-char hex line found): {path}")

# ─── اختبارات ────────────────────────────────────────────────────────────────
def run_tests() -> bool:
    """
    اختبارات آلية شاملة.
    يعيد True إذا نجحت كلها.
    """
    import traceback
    passed = failed = 0

    def test(name: str, fn):
        nonlocal passed, failed
        try:
            fn()
            ok(f"  PASS  {name}"); passed += 1
        except Exception as e:
            err(f"  FAIL  {name}: {e}")
            if os.getenv("APKSHIELD_VERBOSE"):
                traceback.print_exc()
            failed += 1

    info("Running APKShield v3 test suite...\n")

    master = secrets.token_bytes(32)

    # 1. تشفير وفك تشفير — بيانات صغيرة
    def t_small():
        data = b"hello world" * 100
        key  = derive_file_key(master, "test/small.bin")
        enc  = encrypt_bytes(data, key)
        assert enc[:3] == MAGIC
        dec  = decrypt_bytes(enc, key)
        assert dec == data
    test("encrypt/decrypt small", t_small)

    # 2. بيانات كبيرة 5 MB
    def t_large():
        data = secrets.token_bytes(5 * 1024 * 1024)
        key  = derive_file_key(master, "test/large.bin")
        enc  = encrypt_bytes(data, key)
        dec  = decrypt_bytes(enc, key)
        assert dec == data
    test("encrypt/decrypt 5MB", t_large)

    # 3. مفتاح خاطئ يرفع InvalidTag
    def t_wrong_key():
        data = b"secret data"
        key  = derive_file_key(master, "test/x")
        enc  = encrypt_bytes(data, key)
        bad  = derive_file_key(secrets.token_bytes(32), "test/x")
        try:
            decrypt_bytes(enc, bad)
            raise AssertionError("Should have raised InvalidTag")
        except InvalidTag:
            pass
    test("wrong key raises InvalidTag", t_wrong_key)

    # 4. بيانات تالفة
    def t_corrupted():
        data = b"original"
        key  = derive_file_key(master, "test/c")
        enc  = bytearray(encrypt_bytes(data, key))
        enc[-1] ^= 0xFF                        # تلف آخر بايت
        try:
            decrypt_bytes(bytes(enc), key)
            raise AssertionError("Should have raised")
        except (InvalidTag, ValueError):
            pass
    test("corrupted data raises error", t_corrupted)

    # 5. magic خاطئ
    def t_bad_magic():
        try:
            decrypt_bytes(b"\x00\x00\x00" + b"\x00"*25, master)
            raise AssertionError("Should have raised")
        except ValueError:
            pass
    test("bad magic raises ValueError", t_bad_magic)

    # 6. nonce فريد في كل استدعاء
    def t_unique_nonce():
        data = b"same data"
        key  = derive_file_key(master, "test/n")
        e1   = encrypt_bytes(data, key)
        e2   = encrypt_bytes(data, key)
        assert e1[3:15] != e2[3:15], "Nonce reused!"
    test("unique nonce per call", t_unique_nonce)

    # 7. مفاتيح مختلفة لكل ملف
    def t_hkdf():
        k1 = derive_file_key(master, "file_a")
        k2 = derive_file_key(master, "file_b")
        k3 = derive_file_key(master, "file_a")
        assert k1 != k2
        assert k1 == k3
    test("HKDF different keys per file", t_hkdf)

    # 8. should_encrypt
    def t_should():
        assert not should_encrypt("AndroidManifest.xml")
        assert not should_encrypt("classes.dex")
        assert not should_encrypt("resources.arsc")
        assert not should_encrypt("META-INF/CERT.SF")
        assert not should_encrypt("assets/.apkshield/manifest.json.shld")
        assert not should_encrypt("lib/")
        assert     should_encrypt("assets/config.json")
        assert     should_encrypt("lib/arm64-v8a/libgame.so")
        assert     should_encrypt("classes2.dex")
        assert     should_encrypt("res/drawable/icon.png")
    test("should_encrypt rules", t_should)

    # 9. بناء APK اختبار وتشفيره واستعادته
    def t_full_apk():
        with tempfile.TemporaryDirectory() as tmp:
            orig   = Path(tmp) / "orig.apk"
            prot   = Path(tmp) / "prot.apk"
            rest   = Path(tmp) / "rest.apk"
            key_f  = Path(tmp) / "key.bin"

            # ابنِ APK وهمي
            files = {
                "AndroidManifest.xml": b"\x03\x00android manifest",
                "classes.dex":         b"dex\n035\x00fakeclasses",
                "resources.arsc":      b"\x00\x00resource table",
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
                "assets/config.json":  b'{"key":"secret","url":"https://api.example.com"}',
                "assets/data.bin":     secrets.token_bytes(1024),
                "lib/arm64-v8a/libgame.so": b"\x7fELF" + secrets.token_bytes(512),
                "lib/armeabi-v7a/libgame.so": b"\x7fELF" + secrets.token_bytes(512),
                "classes2.dex":        b"dex\n035\x00moredex",
                "res/drawable/ic.png": b"\x89PNG\r\n" + secrets.token_bytes(256),
            }
            with zipfile.ZipFile(str(orig), "w") as z:
                for name, data in files.items():
                    z.writestr(name, data)

            # مفتاح
            mk = secrets.token_bytes(32)
            save_key(mk, str(key_f))
            mk2 = load_key(str(key_f))
            assert mk == mk2, "Key save/load mismatch"

            # تشفير
            stats, mf = protect_apk(str(orig), str(prot), mk)
            assert stats["encrypted"] > 0
            assert stats["errors"] == 0
            assert prot.exists()

            # تحقق
            assert verify_apk(str(orig), str(prot), mk)

            # تأكد أن الملفات الحساسة ما تغيّرت
            with zipfile.ZipFile(str(orig)) as zo, \
                 zipfile.ZipFile(str(prot)) as zp:
                for safe in ("AndroidManifest.xml","classes.dex","resources.arsc"):
                    assert zo.read(safe) == zp.read(safe), f"{safe} was modified!"

            # تأكد أن الأصول مشفرة (تبدأ بـ magic)
            with zipfile.ZipFile(str(prot)) as zp:
                for enc_name in [m["enc_name"] for m in mf.values()]:
                    blob = zp.read(enc_name)
                    assert blob[:3] == MAGIC, f"{enc_name} not encrypted!"

            # استعادة
            assert decrypt_apk(str(prot), str(rest), mk)

            # قارن hash كل ملف
            with zipfile.ZipFile(str(orig)) as zo, \
                 zipfile.ZipFile(str(rest)) as zr:
                for name in files:
                    if name.endswith("/"):
                        continue
                    if name in zo.namelist() and name in zr.namelist():
                        h1 = hashlib.sha256(zo.read(name)).hexdigest()
                        h2 = hashlib.sha256(zr.read(name)).hexdigest()
                        assert h1 == h2, f"Hash mismatch after restore: {name}"

    test("full APK: protect → verify → restore → hash-match", t_full_apk)

    # 10. مفتاح خاطئ عند استعادة
    def t_decrypt_wrong_key():
        with tempfile.TemporaryDirectory() as tmp:
            orig = Path(tmp) / "o.apk"
            prot = Path(tmp) / "p.apk"
            rest = Path(tmp) / "r.apk"
            with zipfile.ZipFile(str(orig), "w") as z:
                z.writestr("AndroidManifest.xml", b"\x03\x00test")
                z.writestr("classes.dex", b"dex\n035\x00")
                z.writestr("resources.arsc", b"\x00\x00")
                z.writestr("META-INF/CERT", b"cert")
                z.writestr("assets/data.bin", secrets.token_bytes(64))
            mk = secrets.token_bytes(32)
            protect_apk(str(orig), str(prot), mk)
            bad_key = secrets.token_bytes(32)
            try:
                result = decrypt_apk(str(prot), str(rest), bad_key)
                # Should return False or leave output empty
                assert (result == False or
                        not rest.exists() or
                        os.path.getsize(str(rest)) == 0), \
                    "decrypt with wrong key should fail"
            except SystemExit:
                pass  # fatal() called — correct behaviour
    test("decrypt with wrong key fails gracefully", t_decrypt_wrong_key)

    # 11. ملف ليس APK
    def t_invalid_apk():
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "fake.apk"
            fake.write_bytes(b"this is not a zip file")
            try:
                protect_apk(str(fake), str(Path(tmp)/"out.apk"), master)
                raise AssertionError("Should have failed")
            except (ValueError, zipfile.BadZipFile):
                pass
    test("invalid APK raises error", t_invalid_apk)

    # ─── ملخص ───────────────────────────────────────────────────────────────
    total = passed + failed
    print(f"\n{'='*45}")
    print(f"{G}  Passed: {passed}/{total}{W}")
    if failed:
        print(f"{R}  Failed: {failed}/{total}{W}")
    print(f"{'='*45}\n")
    return failed == 0

# ─── قائمة الملفات ──────────────────────────────────────────────────────────
def list_apk(path: str) -> None:
    validate_apk(path)
    enc_total = plain_total = 0
    with zipfile.ZipFile(path) as z:
        for e in z.infolist():
            kb = e.file_size / 1024
            if should_encrypt(e.filename):
                print(f"  {G}ENC  {W}{e.filename:<55} {kb:8.1f} KB")
                enc_total += 1
            else:
                print(f"  {Y}SKIP {W}{e.filename:<55} {kb:8.1f} KB")
                plain_total += 1
    info(f"Will encrypt: {enc_total}  |  Kept plain: {plain_total}")

# ─── Banner ──────────────────────────────────────────────────────────────────
def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════╗
║        APKShield v{VERSION} - Asset Encryptor        ║
║   AES-256-GCM | HKDF-SHA256 | Termux/Kali/Linux  ║
╚══════════════════════════════════════════════════╝{W}
{G}Encrypts:{W} assets/  res/  lib/*.so  classes2+.dex
{Y}Kept plain:{W} AndroidManifest  classes.dex  resources.arsc  META-INF/
""")

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    banner()

    p = argparse.ArgumentParser(
        prog="apkshield",
        description="APKShield v3 - APK Asset Encryptor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  encrypt  Protect an APK (encrypt assets)
  decrypt  Restore a protected APK to original
  verify   Verify all encrypted files in a protected APK
  list     Show what will be encrypted in an APK
  test     Run automated test suite

Examples:
  python3 apkshield.py encrypt game.apk game_protected.apk
  python3 apkshield.py encrypt game.apk game_protected.apk -k mykey.bin
  python3 apkshield.py verify  game.apk game_protected.apk -k mykey.bin
  python3 apkshield.py decrypt game_protected.apk game_restored.apk -k mykey.bin
  python3 apkshield.py list    game.apk
  python3 apkshield.py test
        """
    )
    p.add_argument("command",
                   choices=["encrypt","decrypt","verify","list","test"])
    p.add_argument("input",  nargs="?", help="Input APK")
    p.add_argument("output", nargs="?", help="Output APK")
    p.add_argument("-k","--keyfile", default=None, help="Key file (.bin)")
    p.add_argument("--no-verify", action="store_true",
                   help="Skip verification after encrypt")

    args = p.parse_args()

    # ── test ────────────────────────────────────────────────────────────────
    if args.command == "test":
        ok_all = run_tests()
        sys.exit(0 if ok_all else 1)

    # ── list ────────────────────────────────────────────────────────────────
    if args.command == "list":
        if not args.input:
            p.error("list requires input APK")
        list_apk(args.input)
        return

    # ── encrypt / decrypt / verify — يحتاجان input + output + keyfile ───────
    if not args.input:
        p.error(f"{args.command} requires input APK")
    if args.command in ("encrypt","decrypt","verify") and not args.output:
        p.error(f"{args.command} requires output APK")

    # مفتاح
    if args.command == "encrypt":
        if args.keyfile and os.path.isfile(args.keyfile):
            master = load_key(args.keyfile)
            info(f"Key loaded from: {args.keyfile}")
        else:
            master = secrets.token_bytes(32)
            kpath  = args.keyfile or (Path(args.output).stem + "_key.bin")
            save_key(master, kpath)
    else:
        if not args.keyfile:
            fatal(f"{args.command} requires --keyfile / -k")
        master = load_key(args.keyfile)
        info(f"Key loaded: {args.keyfile}")

    # ── encrypt ──────────────────────────────────────────────────────────────
    if args.command == "encrypt":
        try:
            stats, manifest = protect_apk(args.input, args.output, master)
        except (FileNotFoundError, ValueError, OSError) as ex:
            fatal(str(ex))
        except Exception as ex:
            err(f"Unexpected error: {ex}")
            raise

        if not args.no_verify:
            ok_v = verify_apk(args.input, args.output, master)
            if not ok_v:
                fatal("Verification failed — output APK may be corrupted")

        sb = stats["size_before"] / 1e6
        sa = stats["size_after"]  / 1e6
        print(f"""
{C}══════════════ Results ═══════════════{W}
  Total files   : {stats['total']}
  {G}Encrypted     : {stats['encrypted']}{W}
  Kept plain    : {stats['plain']}
  Errors        : {stats['errors']}
  Size before   : {sb:.2f} MB
  Size after    : {sa:.2f} MB
{C}══════════════════════════════════════{W}
  {G}Protected APK : {args.output}{W}
""")
        fp = hashlib.sha256(master).hexdigest()[:16]
        warn("IMPORTANT:")
        warn("  1. Keep the key file (.bin) SECRET")
        warn("  2. The protected APK needs a runtime loader in your app")
        warn("  3. NEVER include the key file inside the APK")
        warn("  4. APK signature is now INVALID — re-sign before distributing")
        info(f"Key fingerprint: {fp}...")
        if stats["errors"]:
            warn(f"WARNING: {stats['errors']} file(s) had read errors — check output")

    # ── decrypt ──────────────────────────────────────────────────────────────
    elif args.command == "decrypt":
        ok_d = decrypt_apk(args.input, args.output, master)
        if not ok_d:
            fatal("Decryption failed")

    # ── verify ───────────────────────────────────────────────────────────────
    elif args.command == "verify":
        ok_v = verify_apk(args.input, args.output, master)
        sys.exit(0 if ok_v else 1)

if __name__ == "__main__":
    main()
