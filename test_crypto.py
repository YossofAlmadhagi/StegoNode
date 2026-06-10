"""
اختبار شامل لمنطق التشفير — بدون واجهة رسومية
يختبر: V27 تشفير/فك، الترقية من تنسيق قديم، حالات الحافة
"""
import sys, os, hashlib, hmac, struct, tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

V27_MARKERS       = [b"SHIELD_V27"]
OLD_MARKERS       = [b"SHIELD_V26_GOLD", b"SHIELD_GOLD_V25", b"SHIELD_GOLD_V23"]
SECURE_V2_MARKERS = [b"SECURE_V2"]
ALL_MARKERS       = V27_MARKERS + OLD_MARKERS + SECURE_V2_MARKERS

# ─── دوال التشفير الأساسية (مطابقة لما في stegano_shield.py) ───────────────

def derive_keys(psw, salt):
    kdf  = PBKDF2HMAC(hashes.SHA256(), 64, salt, 200_000, default_backend())
    full = kdf.derive(psw.encode('utf-8'))
    return full[:32], full[32:]

def derive_key_v2(psw, salt):
    """SECURE_V2: مفتاح 32 بايت فقط، 100000 iteration"""
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100_000, default_backend())
    return kdf.derive(psw.encode('utf-8'))

def _aes_decrypt(ak, iv, enc_payload):
    decryptor = Cipher(algorithms.AES(ak), modes.CBC(iv), default_backend()).decryptor()
    unpadder  = padding.PKCS7(128).unpadder()
    return (unpadder.update(decryptor.update(enc_payload) + decryptor.finalize())
            + unpadder.finalize())

def _extract_clean_image(content):
    for m in ALL_MARKERS:
        idx = content.find(m)
        if idx != -1:
            return content[:idx]
    return content

def encrypt(img_bytes, secret_bytes, secret_name, psw):
    file_name    = secret_name.encode('utf-8')
    name_len     = struct.pack(">I", len(file_name))
    full_payload = name_len + file_name + secret_bytes

    salt, iv = os.urandom(16), os.urandom(16)
    ak, hk   = derive_keys(psw, salt)

    encryptor = Cipher(algorithms.AES(ak), modes.CBC(iv), default_backend()).encryptor()
    padder    = padding.PKCS7(128).padder()
    enc_data  = (encryptor.update(padder.update(full_payload) + padder.finalize())
                 + encryptor.finalize())

    sig      = hmac.new(hk, enc_data, hashlib.sha256).digest()
    enc_size = struct.pack(">Q", len(enc_data))
    clean    = _extract_clean_image(img_bytes)
    return clean + b"SHIELD_V27" + salt + iv + sig + enc_size + enc_data

def _find_marker(content):
    for m in V27_MARKERS:
        if m in content: return m, "v27"
    for m in OLD_MARKERS:
        if m in content: return m, "old_shield"
    for m in SECURE_V2_MARKERS:
        if m in content: return m, "secure_v2"
    return None, None

def decrypt(content, psw):
    found_m, fmt = _find_marker(content)
    if not found_m:
        raise Exception("لا توجد بيانات مشفرة")

    idx      = content.rfind(found_m)
    raw_data = content[idx + len(found_m):]

    if fmt == "secure_v2":
        if len(raw_data) < 96:
            raise Exception("ملف SECURE_V2 تالف")
        stored_hash = raw_data[:64].decode('ascii')
        salt        = raw_data[64:80]
        iv          = raw_data[80:96]
        enc_payload = raw_data[96:]
        ak          = derive_key_v2(psw, salt)
        try:
            data = _aes_decrypt(ak, iv, enc_payload)
        except Exception:
            raise Exception("كلمة مرور خاطئة أو الملف تالف (SECURE_V2)")
        computed = hashlib.sha256(data).hexdigest()
        if computed != stored_hash:
            raise Exception("كلمة مرور خاطئة أو الملف تالف (SECURE_V2)")
        return data, "recovered_v2.bin"

    salt, iv, sig = raw_data[:16], raw_data[16:32], raw_data[32:64]
    ak, hk = derive_keys(psw, salt)

    if fmt == "old_shield":
        enc_payload = raw_data[64:]
        if not hmac.compare_digest(sig, hmac.new(hk, enc_payload, hashlib.sha256).digest()):
            raise Exception("كلمة مرور خاطئة (تنسيق قديم)")
        data = _aes_decrypt(ak, iv, enc_payload)
        name = "recovered_old.bin"
    else:
        if len(raw_data) < 72:
            raise Exception("الملف تالف")
        enc_size    = struct.unpack(">Q", raw_data[64:72])[0]
        enc_payload = raw_data[72:72 + enc_size]
        if len(enc_payload) != enc_size:
            raise Exception(f"بيانات ناقصة: متوقع {enc_size} وجد {len(enc_payload)}")
        if not hmac.compare_digest(sig, hmac.new(hk, enc_payload, hashlib.sha256).digest()):
            raise Exception("كلمة مرور خاطئة (V27)")
        dec_payload = _aes_decrypt(ak, iv, enc_payload)
        if len(dec_payload) < 4:
            raise Exception("الملف تالف")
        name_len = struct.unpack(">I", dec_payload[:4])[0]
        name     = dec_payload[4:4 + name_len].decode('utf-8')
        data     = dec_payload[4 + name_len:]

    return data, name

def make_old_format(img_bytes, secret_bytes, psw, marker):
    """صنع ملف بتنسيق قديم مزيّف: بدون enc_size وبدون اسم مدمج"""
    salt, iv = os.urandom(16), os.urandom(16)
    ak, hk   = derive_keys(psw, salt)
    encryptor = Cipher(algorithms.AES(ak), modes.CBC(iv), default_backend()).encryptor()
    padder    = padding.PKCS7(128).padder()
    enc_data  = (encryptor.update(padder.update(secret_bytes) + padder.finalize())
                 + encryptor.finalize())
    sig = hmac.new(hk, enc_data, hashlib.sha256).digest()
    return img_bytes + marker + salt + iv + sig + enc_data

def make_secure_v2_format(img_bytes, secret_bytes, psw):
    """صنع ملف بتنسيق SECURE_V2 الأصلي: sha256_hex(64)+salt(16)+iv(16)+enc"""
    original_hash = hashlib.sha256(secret_bytes).hexdigest().encode()  # 64 bytes ASCII
    salt, iv = os.urandom(16), os.urandom(16)
    ak = derive_key_v2(psw, salt)
    encryptor = Cipher(algorithms.AES(ak), modes.CBC(iv), default_backend()).encryptor()
    padder    = padding.PKCS7(128).padder()
    enc_data  = (encryptor.update(padder.update(secret_bytes) + padder.finalize())
                 + encryptor.finalize())
    return img_bytes + b"SECURE_V2" + original_hash + salt + iv + enc_data

# ─── تشغيل الاختبارات ────────────────────────────────────────────────────────

FAKE_IMG    = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4
SECRET_DATA = b"Secret binary data for testing purposes - repeated block." * 80
SECRET_NAME = "my_document.pdf"
PASSWORD    = "P@ssw0rd_Test!2024"
WRONG_PSW   = "wrongpassword"

OK   = "\033[92m✔\033[0m"
FAIL = "\033[91m✘\033[0m"
errors = []

def test(name, fn):
    try:
        fn(); print(f"  {OK} {name}")
    except Exception as e:
        print(f"  {FAIL} {name}:  {e}")
        errors.append(name)

print("\n══════════════════════════════════════════════════")
print("   STEGANO SHIELD — اختبار شامل لمنطق التشفير")
print("══════════════════════════════════════════════════\n")

print("[1] تشفير وفك تشفير V27")
enc_v27 = None

def t_enc():
    global enc_v27
    enc_v27 = encrypt(FAKE_IMG, SECRET_DATA, SECRET_NAME, PASSWORD)
    assert b"SHIELD_V27" in enc_v27
    assert len(enc_v27) > len(FAKE_IMG)

def t_dec():
    d, n = decrypt(enc_v27, PASSWORD)
    assert d == SECRET_DATA, f"حجم خاطئ: {len(d)} vs {len(SECRET_DATA)}"
    assert n == SECRET_NAME, f"اسم خاطئ: {n}"

def t_wrong_psw():
    try:
        decrypt(enc_v27, WRONG_PSW); raise Exception("يجب أن يفشل!")
    except Exception as e:
        assert "خاطئة" in str(e), f"رسالة خطأ غير متوقعة: {e}"

def t_large():
    data = os.urandom(2 * 1024 * 1024)   # 2MB
    enc  = encrypt(FAKE_IMG, data, "large.bin", PASSWORD)
    d, n = decrypt(enc, PASSWORD)
    assert d == data and n == "large.bin"

def t_arabic_name():
    enc = encrypt(FAKE_IMG, b"test", "ملف_سري_مهم.docx", PASSWORD)
    _, n = decrypt(enc, PASSWORD)
    assert n == "ملف_سري_مهم.docx", f"اسم عربي خاطئ: {n}"

def t_empty():
    enc = encrypt(FAKE_IMG, b"", "empty.txt", PASSWORD)
    d, _ = decrypt(enc, PASSWORD)
    assert d == b""

def t_special_psw():
    p = "!@#$%^&*()-+=[]{}|;:'\",.<>?`~"
    enc = encrypt(FAKE_IMG, SECRET_DATA, "x.bin", p)
    d, _ = decrypt(enc, p)
    assert d == SECRET_DATA

test("التشفير V27", t_enc)
test("فك التشفير بكلمة صحيحة", t_dec)
test("رفض كلمة مرور خاطئة", t_wrong_psw)
test("ملف كبير 2MB", t_large)
test("اسم ملف عربي", t_arabic_name)
test("ملف فارغ", t_empty)
test("كلمة مرور بحروف خاصة", t_special_psw)

print("\n[2] التوافق مع الإصدارات القديمة")

def t_old(marker):
    old_enc = make_old_format(FAKE_IMG, SECRET_DATA, PASSWORD, marker)
    d, _ = decrypt(old_enc, PASSWORD)
    assert d == SECRET_DATA

test("قراءة V26", lambda: t_old(b"SHIELD_V26_GOLD"))
test("قراءة V25", lambda: t_old(b"SHIELD_GOLD_V25"))
test("قراءة V23", lambda: t_old(b"SHIELD_GOLD_V23"))

def t_old_wrong_psw():
    old_enc = make_old_format(FAKE_IMG, SECRET_DATA, PASSWORD, b"SHIELD_V26_GOLD")
    try:
        decrypt(old_enc, WRONG_PSW); raise Exception("يجب أن يفشل!")
    except Exception as e:
        assert "خاطئة" in str(e)

test("رفض كلمة مرور خاطئة للإصدار القديم", t_old_wrong_psw)

print("\n[3] الترقية من قديم إلى V27")

def t_upgrade_v26():
    new_psw  = "NewPassword_V27!"
    old_enc  = make_old_format(FAKE_IMG, SECRET_DATA, PASSWORD, b"SHIELD_V26_GOLD")
    d, name  = decrypt(old_enc, PASSWORD)
    # إعادة التشفير بـ V27 مع الصورة النظيفة كناقل
    clean    = _extract_clean_image(old_enc)
    new_enc  = encrypt(clean, d, "upgraded_file.bin", new_psw)
    d2, n2   = decrypt(new_enc, new_psw)
    assert d2 == SECRET_DATA, "بيانات بعد الترقية لا تتطابق"
    assert b"SHIELD_V27" in new_enc

def t_clean_carrier():
    # التأكد من أن الناقل يُنظَّف قبل إعادة التشفير (لا يحتوي بيانات قديمة)
    old_enc = make_old_format(FAKE_IMG, SECRET_DATA, PASSWORD, b"SHIELD_V26_GOLD")
    clean   = _extract_clean_image(old_enc)
    assert clean == FAKE_IMG, "استخراج الصورة النظيفة فشل"

test("ترقية V26 → V27 مع تنظيف الناقل", t_upgrade_v26)
test("استخراج الصورة النظيفة من ملف مشفر قديم", t_clean_carrier)

print("\n[4] حالات الحافة")

def t_no_marker():
    try:
        decrypt(b"regular file no marker here", PASSWORD)
        raise Exception("يجب أن يفشل!")
    except Exception as e:
        assert "لا توجد" in str(e)

def t_double_encrypt():
    # V27 فوق V27 — فك التشفير يجب أن يصل للطبقة الداخلية (rfind)
    inner = encrypt(FAKE_IMG, b"inner data", "inner.txt", PASSWORD)
    outer = encrypt(inner, SECRET_DATA, SECRET_NAME, "outer_pass")
    # فك الخارجي
    d_out, n_out = decrypt(outer, "outer_pass")
    assert d_out == SECRET_DATA
    # الملف الداخلي لا يزال صالحاً
    d_in, n_in = decrypt(inner, PASSWORD)
    assert d_in == b"inner data"

def t_marker_in_image_data():
    # صورة تحتوي صدفةً على بصمة SHIELD_V27 في بياناتها
    tricky = FAKE_IMG + b"SHIELD_V27" + b"\x00" * 50
    enc    = encrypt(tricky, SECRET_DATA, SECRET_NAME, PASSWORD)
    d, n   = decrypt(enc, PASSWORD)
    assert d == SECRET_DATA, "فشل مع بصمة مزيفة في الصورة"

test("رفض ملف بدون بصمة", t_no_marker)
test("تشفير مزدوج V27 فوق V27", t_double_encrypt)
test("مقاومة بصمة مزيفة في بيانات الصورة", t_marker_in_image_data)

print("\n[5] دعم SECURE_V2 (النسخة القديمة Pro v2.0)")

def t_secure_v2_dec():
    """فك تشفير ملف SECURE_V2 أصلي"""
    enc = make_secure_v2_format(FAKE_IMG, SECRET_DATA, PASSWORD)
    assert b"SECURE_V2" in enc
    d, _ = decrypt(enc, PASSWORD)
    assert d == SECRET_DATA, f"بيانات SECURE_V2 لا تتطابق: {len(d)} vs {len(SECRET_DATA)}"

def t_secure_v2_wrong_psw():
    """رفض كلمة مرور خاطئة لـ SECURE_V2"""
    enc = make_secure_v2_format(FAKE_IMG, SECRET_DATA, PASSWORD)
    try:
        decrypt(enc, WRONG_PSW)
        raise Exception("يجب أن يفشل!")
    except Exception as e:
        assert "خاطئة" in str(e) or "SECURE_V2" in str(e), f"رسالة خطأ غير متوقعة: {e}"

def t_secure_v2_hash_integrity():
    """التحقق أن SHA256 يكتشف التلاعب"""
    enc = make_secure_v2_format(FAKE_IMG, SECRET_DATA, PASSWORD)
    # نفسد آخر بايت
    tampered = enc[:-1] + bytes([(enc[-1] ^ 0xFF)])
    try:
        decrypt(tampered, PASSWORD)
        raise Exception("يجب أن يفشل!")
    except Exception as e:
        assert "خاطئة" in str(e) or "SECURE_V2" in str(e)

def t_secure_v2_upgrade():
    """ترقية SECURE_V2 → V27 مع الحفاظ على البيانات"""
    enc_v2 = make_secure_v2_format(FAKE_IMG, SECRET_DATA, PASSWORD)
    # فك التشفير القديم
    d, _   = decrypt(enc_v2, PASSWORD)
    assert d == SECRET_DATA
    # إعادة التشفير كـ V27 بكلمة مرور جديدة
    clean  = _extract_clean_image(enc_v2)
    new_psw = "NewV27_Password!"
    new_enc = encrypt(clean, d, "upgraded.bin", new_psw)
    assert b"SHIELD_V27" in new_enc
    assert b"SECURE_V2"  not in new_enc
    d2, n2 = decrypt(new_enc, new_psw)
    assert d2 == SECRET_DATA, "بيانات بعد ترقية SECURE_V2 → V27 لا تتطابق"

def t_secure_v2_clean_carrier():
    """التأكد من تنظيف الناقل من بصمة SECURE_V2"""
    enc    = make_secure_v2_format(FAKE_IMG, SECRET_DATA, PASSWORD)
    clean  = _extract_clean_image(enc)
    assert clean == FAKE_IMG, "استخراج الصورة النظيفة من SECURE_V2 فشل"
    assert b"SECURE_V2" not in clean

test("فك تشفير SECURE_V2 بكلمة صحيحة",    t_secure_v2_dec)
test("رفض كلمة مرور خاطئة (SECURE_V2)",    t_secure_v2_wrong_psw)
test("كشف التلاعب بـ SHA256 (SECURE_V2)",   t_secure_v2_hash_integrity)
test("ترقية SECURE_V2 → V27",               t_secure_v2_upgrade)
test("تنظيف الناقل من بصمة SECURE_V2",      t_secure_v2_clean_carrier)

# ── النتيجة ──────────────────────────────────────────────────────────────────
print("\n══════════════════════════════════════════════════")
if errors:
    print(f"  \033[91mفشل {len(errors)} اختبار:\033[0m")
    for e in errors: print(f"    ✘ {e}")
    sys.exit(1)
else:
    total = 7 + 4 + 2 + 3 + 5
    print(f"  \033[92mجميع {total} اختبارات نجحت ✔\033[0m")
    sys.exit(0)
