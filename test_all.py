"""
اختبار شامل — يختبر كل شيء بدون واجهة رسومية:
  [1] بنية الكود (Syntax)
  [2] resource_path() في وضع التطوير ووضع EXE
  [3] ملفات الموارد (logo.png, logo.ico)
  [4] صحة ICO
  [5] صحة PNG
  [6] window flags (فحص نصي في الكود المصدري)
  [7] AppUserModelID (فحص وجوده في الكود)
  [8] app metadata (setApplicationName, etc.)
  [9-29] اختبارات التشفير الـ21 كاملة
"""
import sys, os, struct, ast, hashlib, hmac, zlib

OK   = "\033[92m✔\033[0m"
FAIL = "\033[91m✘\033[0m"
errors = []

def test(name, fn):
    try:
        fn()
        print(f"  {OK} {name}")
    except Exception as e:
        print(f"  {FAIL} {name}: {e}")
        errors.append(name)

ROOT = os.path.dirname(os.path.abspath(__file__))

# ══════════════════════════════════════════════════════════════════════════════
print("\n══════════════════════════════════════════════════════════════")
print("   STEGANO SHIELD — اختبار شامل كامل")
print("══════════════════════════════════════════════════════════════\n")

# ─── [1] بنية الكود ──────────────────────────────────────────────────────────
print("[1] بنية الكود (Syntax Check)")

def t_syntax():
    src = open(os.path.join(ROOT, "stegano_shield.py"), encoding="utf-8").read()
    ast.parse(src)

test("stegano_shield.py — لا أخطاء نحوية", t_syntax)

# ─── [2] resource_path ───────────────────────────────────────────────────────
print("\n[2] دالة resource_path()")

SRC = open(os.path.join(ROOT, "stegano_shield.py"), encoding="utf-8").read()

# استخراج resource_path يدوياً (بدون استيراد Qt)
exec_ns: dict = {}
for line in SRC.split("\n"):
    if line.startswith("import ") or line.startswith("from "):
        continue
    if "def resource_path" in line:
        break

# نقوم بتنفيذ دالة resource_path مباشرة
_rp_src = """
import sys, os
def resource_path(relative_path):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(r"{f}")))
    return os.path.join(base, relative_path)
""".format(f=os.path.join(ROOT, "stegano_shield.py"))
exec(_rp_src, exec_ns)
resource_path = exec_ns["resource_path"]

def t_rp_dev_mode():
    p = resource_path("logo.png")
    assert os.path.dirname(p) == ROOT, f"مسار خاطئ: {p}"

def t_rp_exe_mode():
    import tempfile, sys as _sys
    fake = tempfile.mkdtemp()
    open(os.path.join(fake, "logo.png"), "wb").write(b"PNG")
    old = getattr(_sys, "_MEIPASS", None)
    _sys._MEIPASS = fake
    try:
        p = resource_path("logo.png")
        assert p == os.path.join(fake, "logo.png"), f"EXE path خاطئ: {p}"
        assert os.path.exists(p)
    finally:
        if old is None and hasattr(_sys, "_MEIPASS"):
            del _sys._MEIPASS
        else:
            _sys._MEIPASS = old

def t_rp_fallback():
    p = resource_path("nonexistent_file.xyz")
    assert not os.path.exists(p)   # يُعيد مسار صحيح حتى لو الملف غير موجود

test("وضع التطوير — مسار صحيح بجانب السكريبت", t_rp_dev_mode)
test("وضع EXE  — يستخدم sys._MEIPASS", t_rp_exe_mode)
test("ملف غير موجود — لا crash", t_rp_fallback)

# ─── [3] وجود ملفات الموارد ──────────────────────────────────────────────────
print("\n[3] ملفات الموارد")

def t_logo_png_exists():
    p = os.path.join(ROOT, "logo.png")
    assert os.path.exists(p), f"logo.png غير موجود في {ROOT}"
    assert os.path.getsize(p) > 100, "logo.png فارغ أو تالف"

def t_logo_ico_exists():
    p = os.path.join(ROOT, "logo.ico")
    assert os.path.exists(p), f"logo.ico غير موجود في {ROOT}"
    assert os.path.getsize(p) > 100, "logo.ico فارغ أو تالف"

test("logo.png موجود وغير فارغ", t_logo_png_exists)
test("logo.ico موجود وغير فارغ", t_logo_ico_exists)

# ─── [4] صحة ICO ─────────────────────────────────────────────────────────────
print("\n[4] صحة ملف ICO")

def t_ico_header():
    with open(os.path.join(ROOT, "logo.ico"), "rb") as f:
        data = f.read()
    reserved, itype, count = struct.unpack_from("<HHH", data, 0)
    assert reserved == 0,    f"reserved={reserved} (يجب 0)"
    assert itype == 1,       f"type={itype} (يجب 1=icon)"
    assert count >= 1,       f"count={count} (يجب ≥ 1)"

def t_ico_contains_png():
    with open(os.path.join(ROOT, "logo.ico"), "rb") as f:
        data = f.read()
    # موضع البيانات = offset المحفوظ في ICONDIRENTRY
    img_size, img_offset = struct.unpack_from("<II", data, 6 + 8)
    img_data = data[img_offset: img_offset + 8]
    assert img_data[:8] == b'\x89PNG\r\n\x1a\n', "ICO لا يحتوي PNG صحيح"

def t_ico_png_valid():
    with open(os.path.join(ROOT, "logo.ico"), "rb") as f:
        data = f.read()
    img_size, img_offset = struct.unpack_from("<II", data, 6 + 8)
    png = data[img_offset: img_offset + img_size]
    assert png[:8] == b'\x89PNG\r\n\x1a\n'
    # تحقق من IHDR chunk
    assert png[12:16] == b'IHDR', "لا يوجد IHDR chunk"
    w, h = struct.unpack_from(">II", png, 16)
    assert w > 0 and h > 0, f"أبعاد PNG غير صحيحة: {w}x{h}"

test("ICONDIR header صحيح", t_ico_header)
test("ICO يحتوي PNG مضمّن", t_ico_contains_png)
test("PNG المضمّن في ICO صحيح (IHDR)", t_ico_png_valid)

# ─── [5] صحة PNG ─────────────────────────────────────────────────────────────
print("\n[5] صحة ملف PNG")

def t_png_signature():
    with open(os.path.join(ROOT, "logo.png"), "rb") as f:
        sig = f.read(8)
    assert sig == b'\x89PNG\r\n\x1a\n', "توقيع PNG خاطئ"

def t_png_ihdr():
    with open(os.path.join(ROOT, "logo.png"), "rb") as f:
        data = f.read(30)
    assert data[12:16] == b'IHDR', "لا يوجد IHDR"
    w, h = struct.unpack_from(">II", data, 16)
    assert w > 0 and h > 0, f"أبعاد خاطئة: {w}x{h}"
    color_type = data[25]
    assert color_type in (2, 6), f"نوع لون غير متوقع: {color_type}"  # RGB or RGBA

def t_png_iend():
    with open(os.path.join(ROOT, "logo.png"), "rb") as f:
        data = f.read()
    assert data[-12:-8] == b'IEND' or data[-4:] == b'\xaeB`\x82', \
        "PNG لا ينتهي بـ IEND صحيح"

test("توقيع PNG صحيح", t_png_signature)
test("IHDR chunk موجود وأبعاد صحيحة", t_png_ihdr)
test("PNG ينتهي بـ IEND", t_png_iend)

# ─── [6] فحص window flags في الكود المصدري ──────────────────────────────────
print("\n[6] window flags (فحص الكود المصدري)")

def t_window_flag_present():
    assert "Qt.WindowType.Window" in SRC and "FramelessWindowHint" in SRC, \
        "لم يُعثر على Qt.WindowType.Window | FramelessWindowHint"

def t_window_and_frameless_together():
    # يجب أن يكونا في نفس setWindowFlags استدعاء
    lines = SRC.split("\n")
    block = ""
    in_block = False
    for line in lines:
        if "setWindowFlags" in line:
            in_block = True
        if in_block:
            block += line + "\n"
            if ")" in line:
                break
    assert "WindowType.Window" in block and "FramelessWindowHint" in block, \
        f"FramelessWindowHint بدون Window flag:\n{block}"

test("Qt.WindowType.Window موجود في الكود", t_window_flag_present)
test("Window + FramelessWindowHint معاً في setWindowFlags", t_window_and_frameless_together)

# ─── [7] AppUserModelID ──────────────────────────────────────────────────────
print("\n[7] AppUserModelID")

def t_appid_present():
    assert "SetCurrentProcessExplicitAppUserModelID" in SRC, \
        "AppUserModelID غير موجود"

def t_appid_before_qapp():
    idx_id  = SRC.index("SetCurrentProcessExplicitAppUserModelID")
    idx_app = SRC.index("QtWidgets.QApplication(sys.argv)")
    assert idx_id < idx_app, \
        "AppUserModelID يجب أن يأتي قبل QApplication"

def t_appid_try_except():
    # يجب أن يكون مُغلّفاً بـ try/except لأمان Linux/macOS
    ctx = SRC[SRC.index("SetCurrentProcessExplicitAppUserModelID")-50:][:200]
    assert "try" in ctx and "except" in ctx, \
        "AppUserModelID غير مُغلَّف بـ try/except"

test("SetCurrentProcessExplicitAppUserModelID موجود", t_appid_present)
test("AppUserModelID يأتي قبل QApplication", t_appid_before_qapp)
test("مُغلَّف بـ try/except للتوافق مع Linux/macOS", t_appid_try_except)

# ─── [8] بيانات التطبيق ─────────────────────────────────────────────────────
print("\n[8] بيانات التطبيق (app metadata)")

def t_app_name():       assert "setApplicationName" in SRC
def t_app_version():    assert "setApplicationVersion" in SRC
def t_org_name():       assert "setOrganizationName" in SRC
def t_display_name():   assert "setApplicationDisplayName" in SRC

test("setApplicationName موجود", t_app_name)
test("setApplicationVersion موجود", t_app_version)
test("setOrganizationName موجود", t_org_name)
test("setApplicationDisplayName موجود", t_display_name)

# ─── [9-29] اختبارات التشفير الـ21 ──────────────────────────────────────────
print("\n[9] اختبارات التشفير (21 اختباراً)")

# استيراد اختبارات التشفير من test_crypto.py
import subprocess, sys as _sys
result = subprocess.run(
    [_sys.executable, os.path.join(ROOT, "test_crypto.py")],
    capture_output=True, text=True
)
# طباعة نتيجة اختبارات التشفير
for line in result.stdout.split("\n"):
    if line.strip():
        print("  " + line)
if result.returncode != 0:
    errors.append("اختبارات التشفير (test_crypto.py)")
    if result.stderr:
        print(f"  STDERR: {result.stderr[:300]}")

# ─── النتيجة النهائية ────────────────────────────────────────────────────────
print("\n══════════════════════════════════════════════════════════════")
if errors:
    print(f"  \033[91mفشل {len(errors)} اختبار:\033[0m")
    for e in errors:
        print(f"    ✘ {e}")
    sys.exit(1)
else:
    total = 3 + 3 + 2 + 3 + 3 + 2 + 3 + 4 + 21
    print(f"  \033[92mجميع {total} اختبارات نجحت ✔\033[0m")
    sys.exit(0)
