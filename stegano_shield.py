import sys, os, hashlib, hmac, glob, struct, ctypes
from PyQt6 import QtWidgets, QtCore, QtGui
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# ─── مسارات الموارد — تعمل في وضع التطوير وداخل EXE (PyInstaller) ──────────
def resource_path(relative_path: str) -> str:
    """
    يُعيد المسار المطلق للملف سواء أُشغّل من المصدر أو من EXE مُجمَّع.
    PyInstaller يضع الملفات المضمّنة في sys._MEIPASS عند تشغيل الـ EXE.
    في وضع التطوير العادي يُعيد المسار بجانب ملف السكريبت.
    """
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)

# ─── تحميل الأيقونة مع fallback آمن ─────────────────────────────────────────
def _load_app_icon() -> QtGui.QIcon:
    """
    يُحمّل الأيقونة بالأولوية: logo.ico ثم logo.png ثم QIcon فارغ.
    يعمل سواء شُغّل البرنامج من المصدر أو من EXE مُجمَّع بـ PyInstaller.
    """
    for name in ("assets/img.ico", "assets/logo.png"):
        path = resource_path(name)
        if os.path.exists(path):
            icon = QtGui.QIcon(path)
            if not icon.isNull():
                return icon
    return QtGui.QIcon()   # fallback آمن — لا crash إذا غابت الملفات


# ─── بصمات الإصدارات ───────────────────────────────────────────────────────
V27_MARKERS    = [b"SHIELD_V27"]
OLD_MARKERS    = [b"SHIELD_V26_GOLD", b"SHIELD_GOLD_V25", b"SHIELD_GOLD_V23"]
SECURE_V2_MARKERS = [b"SECURE_V2"]          # النسخة القديمة Pro v2.0
ALL_MARKERS    = V27_MARKERS + OLD_MARKERS + SECURE_V2_MARKERS


# ══════════════════════════════════════════════════════════════════════════════
# منطق التشفير (QThread)
# ══════════════════════════════════════════════════════════════════════════════
class ShieldWorker(QtCore.QThread):
    log_msg    = QtCore.pyqtSignal(str, str)   # (رسالة, مستوى: ok/err/warn/info)
    finished_ok = QtCore.pyqtSignal()

    def __init__(self, mode, psw, **kwargs):
        super().__init__()
        self.mode, self.psw, self.args = mode, psw, kwargs

    # ── اشتقاق المفاتيح V27 (64 بايت: AES + HMAC) ───────────────────────
    def derive_keys(self, psw, salt):
        kdf  = PBKDF2HMAC(hashes.SHA256(), 64, salt, 200_000, default_backend())
        full = kdf.derive(psw.encode('utf-8'))
        return full[:32], full[32:]

    # ── اشتقاق مفتاح SECURE_V2 (32 بايت AES فقط، 100000 iteration) ──────
    def derive_key_v2(self, psw, salt):
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100_000, default_backend())
        return kdf.derive(psw.encode('utf-8'))

    # ── التشغيل ───────────────────────────────────────────────────────────
    def run(self):
        try:
            if   self.mode == "encrypt": self.encrypt_logic()
            elif self.mode == "decrypt": self.decrypt_logic()
            elif self.mode == "upgrade": self.upgrade_logic()
            elif self.mode == "scan":    self.scan_logic()
            self.finished_ok.emit()
        except Exception as e:
            self.log_msg.emit(f"خطأ: {e}", "err")

    # ── التشفير V27 ────────────────────────────────────────────────────────
    def encrypt_logic(self, img_in=None, sec_in=None, out_p=None,
                      custom_psw=None, override_name=None):
        psw   = custom_psw or self.psw
        img_p = img_in or self.args.get('img')
        sec_p = sec_in or self.args.get('sec')
        out_p = out_p  or self.args.get('out')

        stored_name = override_name or os.path.basename(sec_p)
        file_name   = stored_name.encode('utf-8')
        name_len    = struct.pack(">I", len(file_name))

        with open(sec_p, 'rb') as f:
            data = f.read()

        full_payload = name_len + file_name + data
        salt, iv     = os.urandom(16), os.urandom(16)
        ak, hk       = self.derive_keys(psw, salt)

        encryptor = Cipher(algorithms.AES(ak), modes.CBC(iv), default_backend()).encryptor()
        padder    = padding.PKCS7(128).padder()
        enc_data  = (encryptor.update(padder.update(full_payload) + padder.finalize())
                     + encryptor.finalize())

        sig      = hmac.new(hk, enc_data, hashlib.sha256).digest()
        enc_size = struct.pack(">Q", len(enc_data))

        # استخدام البيانات النظيفة فقط (قبل أي بصمة قديمة) كناقل
        with open(img_p, 'rb') as fi:
            carrier = fi.read()
        clean_carrier = self._extract_clean_image(carrier)

        with open(out_p, 'wb') as fo:
            fo.write(clean_carrier)
            fo.write(b"SHIELD_V27")
            fo.write(salt + iv + sig + enc_size + enc_data)

        self.log_msg.emit(
            f"تم التشفير بنجاح ← {os.path.basename(out_p)}", "ok")

    # ── فك التشفير ────────────────────────────────────────────────────────
    def decrypt_logic(self, target=None, custom_psw=None, is_upgrade=False,
                      extra_markers=None):
        psw  = custom_psw or self.psw
        path = target or self.args.get('img')

        with open(path, 'rb') as f:
            content = f.read()

        found_m, fmt = self._find_marker(content, extra_markers)

        if not found_m:
            if is_upgrade:
                return None, None
            raise Exception("الملف لا يحتوي على بيانات مشفرة.")

        # آخر ظهور للبصمة (rfind) للتعامل مع الصور التي قد تحتوي بصمات صدفية
        idx      = content.rfind(found_m)
        raw_data = content[idx + len(found_m):]
        base_name = os.path.splitext(os.path.basename(path))[0]

        if fmt == "secure_v2":
            # ════ تنسيق SECURE_V2 (النسخة القديمة Pro v2.0) ════
            # الهيكل: sha256_hex(64) + salt(16) + iv(16) + encrypted_data
            if len(raw_data) < 96:
                raise Exception("ملف SECURE_V2 تالف أو مقطوع.")
            stored_hash  = raw_data[:64].decode('ascii', errors='replace')
            salt         = raw_data[64:80]
            iv           = raw_data[80:96]
            enc_payload  = raw_data[96:]
            ak = self.derive_key_v2(psw, salt)
            try:
                actual_data = self._aes_decrypt(ak, iv, enc_payload)
            except Exception:
                raise Exception("كلمة مرور خاطئة أو الملف تالف (SECURE_V2).")
            # التحقق من سلامة البيانات بالهاش
            computed = hashlib.sha256(actual_data).hexdigest()
            if computed != stored_hash:
                raise Exception("كلمة مرور خاطئة أو الملف تالف (SECURE_V2).")
            ext       = self._detect_extension(actual_data)
            orig_name = f"{base_name}_extracted{ext}"
            self.log_msg.emit(
                f"✔ تحقق SHA256 ناجح — الملف سليم 100%", "ok")
            self.log_msg.emit(
                f"نوع الملف المكتشف: {ext.upper().strip('.')}  →  {orig_name}", "info")

        elif fmt == "old_shield":
            # ════ تنسيق SHIELD قديم (V23/V25/V26): بدون enc_size وبدون اسم ════
            salt = raw_data[:16]
            iv   = raw_data[16:32]
            sig  = raw_data[32:64]
            enc_payload = raw_data[64:]
            ak, hk = self.derive_keys(psw, salt)
            if not hmac.compare_digest(
                    sig, hmac.new(hk, enc_payload, hashlib.sha256).digest()):
                raise Exception("كلمة مرور خاطئة.")
            actual_data = self._aes_decrypt(ak, iv, enc_payload)
            ext         = self._detect_extension(actual_data)
            orig_name   = f"{base_name}_extracted{ext}"
            self.log_msg.emit(
                f"نوع الملف المكتشف: {ext.upper().strip('.')}  →  {orig_name}", "info")

        else:
            # ════ تنسيق V27 أو مخصص: مع enc_size واسم مدمج ════
            salt = raw_data[:16]
            iv   = raw_data[16:32]
            sig  = raw_data[32:64]
            ak, hk = self.derive_keys(psw, salt)
            if len(raw_data) < 72:
                raise Exception("الملف تالف أو مقطوع.")
            enc_size    = struct.unpack(">Q", raw_data[64:72])[0]
            enc_payload = raw_data[72:72 + enc_size]
            if len(enc_payload) != enc_size:
                raise Exception(
                    f"بيانات ناقصة: متوقع {enc_size} بايت، وُجد {len(enc_payload)}.")
            if not hmac.compare_digest(
                    sig, hmac.new(hk, enc_payload, hashlib.sha256).digest()):
                raise Exception("كلمة مرور خاطئة.")
            dec_payload = self._aes_decrypt(ak, iv, enc_payload)
            if len(dec_payload) < 4:
                raise Exception("البيانات المفكوكة تالفة.")
            name_len    = struct.unpack(">I", dec_payload[:4])[0]
            orig_name   = dec_payload[4:4 + name_len].decode('utf-8')
            actual_data = dec_payload[4 + name_len:]

        if is_upgrade:
            return actual_data, orig_name

        out_dir    = os.path.join(os.path.dirname(os.path.abspath(path)), "Extracted_Files")
        os.makedirs(out_dir, exist_ok=True)
        final_path = os.path.join(out_dir, orig_name)
        with open(final_path, 'wb') as f:
            f.write(actual_data)
        size_kb = len(actual_data) / 1024
        self.log_msg.emit(
            f"تم الاستخراج: '{orig_name}'  ({size_kb:.1f} KB) → مجلد Extracted_Files", "ok")

    # ── الترقية من إصدارات قديمة ──────────────────────────────────────────
    def upgrade_logic(self):
        fld, old_p, new_p = self.args['fld'], self.args['old_p'], self.args['new_p']
        files   = glob.glob(os.path.join(fld, "*.*"))
        img_ext = ('.png', '.jpg', '.jpeg', '.bmp', '.gif')
        targets = [f for f in files if f.lower().endswith(img_ext)]

        if not targets:
            self.log_msg.emit("لم يتم العثور على صور في المجلد المحدد.", "warn")
            return

        self.log_msg.emit(f"جاري فحص {len(targets)} صورة...", "info")
        count = skipped = 0

        for f in targets:
            fname = os.path.basename(f)
            try:
                data, orig_name = self.decrypt_logic(
                    target=f, custom_psw=old_p, is_upgrade=True)

                if data is None:
                    self.log_msg.emit(f"تخطي (لا توجد بيانات): {fname}", "info")
                    skipped += 1
                    continue

                # استخدام الجزء النظيف من الصورة كناقل (قبل البصمة القديمة)
                with open(f, 'rb') as fi:
                    carrier = fi.read()
                clean = self._extract_clean_image(carrier)

                # ملف مؤقت للبيانات المستخرجة
                tmp_path = f + ".shieldtmp"
                with open(tmp_path, 'wb') as t:
                    t.write(data)

                out_v27 = os.path.splitext(f)[0] + "_V27.png"
                # إعادة التشفير بالاسم الأصلي المحفوظ
                self.encrypt_logic(
                    img_in=f, sec_in=tmp_path,
                    out_p=out_v27, custom_psw=new_p,
                    override_name=orig_name)

                os.remove(tmp_path)
                count += 1

            except Exception as e:
                self.log_msg.emit(f"فشل ({fname}): {e}", "err")
                skipped += 1
                if os.path.exists(f + ".shieldtmp"):
                    try: os.remove(f + ".shieldtmp")
                    except: pass

        self.log_msg.emit(
            f"اكتملت الترقية — ناجح: {count} | متخطى: {skipped}", "ok")

    # ── فحص تشخيصي للملف ─────────────────────────────────────────────────
    def scan_logic(self):
        path = self.args.get('path')
        with open(path, 'rb') as f:
            content = f.read()
        size_kb = len(content) / 1024
        self.log_msg.emit(
            f"فحص: {os.path.basename(path)}  ({size_kb:.1f} KB)", "info")

        # ① البحث عن جميع البصمات المعروفة (SHIELD + SECURE_V2)
        found_known = []
        for m in ALL_MARKERS:
            if m in content:
                idx = content.rfind(m)
                found_known.append((m.decode(), idx))

        if found_known:
            for name, idx in found_known:
                if name.startswith("SECURE_V2"):
                    self.log_msg.emit(
                        f"✔ بصمة SECURE_V2 (النسخة القديمة Pro): [{name}]  عند الموضع {idx}", "ok")
                    self.log_msg.emit(
                        "هذا الملف مشفر بالنسخة القديمة — يدعمه البرنامج تلقائياً. فك التشفير / الترقية يعملان مباشرة.", "ok")
                else:
                    self.log_msg.emit(
                        f"✔ بصمة SHIELD معروفة: [{name}]  عند الموضع {idx}", "ok")
            return

        # ② البحث عن أي تسلسل يبدأ بـ SHIELD أو SECURE (بصمة غير معروفة)
        hits = []
        for prefix in (b"SHIELD", b"SECURE"):
            pos = 0
            while True:
                idx = content.find(prefix, pos)
                if idx == -1:
                    break
                end = idx
                while end < len(content) and (
                        content[end:end+1].isalnum() or
                        content[end:end+1] in (b'_', b'-')):
                    end += 1
                candidate = content[idx:end].decode('ascii', errors='replace')
                hits.append((candidate, idx))
                pos = idx + 1

        if hits:
            self.log_msg.emit(
                f"⚠ وُجدت {len(hits)} بصمة غير معروفة في الملف:", "warn")
            for txt, idx in hits:
                self.log_msg.emit(f"   [{txt}]  عند الموضع {idx}", "warn")
            self.log_msg.emit(
                "انسخ البصمة أعلاه والصقها في حقل 'بصمة مخصصة' ثم أعد المحاولة.", "warn")
        else:
            tail    = content[-40:]
            hex_str = ' '.join(f'{b:02X}' for b in tail)
            self.log_msg.emit("لا توجد بصمة تشفير معروفة في هذا الملف.", "err")
            self.log_msg.emit(f"آخر 40 بايت: {hex_str}", "info")
            self.log_msg.emit(
                "قد يكون الملف غير مشفر، أو مشفر بطريقة مختلفة تماماً.", "warn")

    # ── الترقية من إصدارات قديمة ──────────────────────────────────────────
    def upgrade_logic(self):
        fld, old_p, new_p = self.args['fld'], self.args['old_p'], self.args['new_p']
        custom_marker_txt = self.args.get('custom_marker', '').strip()
        extra_markers     = []
        if custom_marker_txt:
            extra_markers = [custom_marker_txt.encode('ascii', errors='ignore')]
            self.log_msg.emit(
                f"سيتم البحث أيضاً عن البصمة المخصصة: [{custom_marker_txt}]", "info")

        files   = glob.glob(os.path.join(fld, "*.*"))
        img_ext = ('.png', '.jpg', '.jpeg', '.bmp', '.gif')
        targets = [f for f in files if f.lower().endswith(img_ext)]

        if not targets:
            self.log_msg.emit("لم يتم العثور على صور في المجلد المحدد.", "warn")
            return

        self.log_msg.emit(f"جاري فحص {len(targets)} صورة...", "info")
        count = skipped = 0

        for f in targets:
            fname = os.path.basename(f)
            try:
                data, orig_name = self.decrypt_logic(
                    target=f, custom_psw=old_p, is_upgrade=True,
                    extra_markers=extra_markers)

                if data is None:
                    self.log_msg.emit(f"تخطي (لا توجد بصمة): {fname}", "info")
                    skipped += 1
                    continue

                tmp_path = f + ".shieldtmp"
                with open(tmp_path, 'wb') as t:
                    t.write(data)

                out_v27 = os.path.splitext(f)[0] + "_V27.png"
                self.encrypt_logic(
                    img_in=f, sec_in=tmp_path,
                    out_p=out_v27, custom_psw=new_p,
                    override_name=orig_name)

                os.remove(tmp_path)
                count += 1
                self.log_msg.emit(f"تمت ترقية: {fname}", "ok")

            except Exception as e:
                self.log_msg.emit(f"فشل ({fname}): {e}", "err")
                skipped += 1
                if os.path.exists(f + ".shieldtmp"):
                    try: os.remove(f + ".shieldtmp")
                    except: pass

        self.log_msg.emit(
            f"اكتملت الترقية — ناجح: {count} | متخطى: {skipped}", "ok")

    # ── كشف نوع الملف من بياناته الأولى (magic bytes) ─────────────────────
    @staticmethod
    def _detect_extension(data: bytes) -> str:
        """يُعيد الامتداد الصحيح بناءً على أول بايتات الملف"""
        sig = data[:16] if len(data) >= 16 else data

        # ─ فيديو ─
        if sig[4:8] == b'ftyp':                      return '.mp4'
        if sig[:4] in (b'\x00\x00\x00\x14', b'\x00\x00\x00\x18',
                       b'\x00\x00\x00\x1c', b'\x00\x00\x00\x20') \
                and sig[4:8] == b'ftyp':              return '.mp4'
        if sig[:4] == b'\x1a\x45\xdf\xa3':           return '.mkv'
        if sig[:4] == b'RIFF' and sig[8:12] == b'AVI ': return '.avi'
        if sig[:3] == b'FLV':                         return '.flv'
        if sig[:4] == b'\x00\x00\x01\xba':           return '.mpg'
        if sig[:4] == b'\x00\x00\x01\xb3':           return '.mpg'
        if sig[:4] == b'ftyp':                        return '.mp4'
        # MOV يشارك ftyp لكن قد يبدأ بـ 'moov' أو 'wide'
        if sig[4:8] in (b'moov', b'wide', b'mdat'):  return '.mov'

        # ─ صوت ─
        if sig[:3] == b'ID3' or sig[:2] == b'\xff\xfb': return '.mp3'
        if sig[:4] == b'fLaC':                        return '.flac'
        if sig[:4] == b'RIFF' and sig[8:12] == b'WAVE': return '.wav'
        if sig[:4] == b'OggS':                        return '.ogg'
        if sig[:4] == b'M4A ':                        return '.m4a'

        # ─ صور ─
        if sig[:8] == b'\x89PNG\r\n\x1a\n':          return '.png'
        if sig[:2] == b'\xff\xd8':                   return '.jpg'
        if sig[:6] in (b'GIF87a', b'GIF89a'):        return '.gif'
        if sig[:4] == b'RIFF' and sig[8:12] == b'WEBP': return '.webp'
        if sig[:4] == b'BM\x00\x00' or sig[:2] == b'BM': return '.bmp'

        # ─ مستندات ─
        if sig[:4] == b'%PDF':                        return '.pdf'
        if sig[:4] == b'PK\x03\x04':                 return '.zip'   # أيضاً docx/xlsx
        if sig[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': return '.doc'
        if sig[:4] == b'Rar!':                        return '.rar'
        if sig[:6] == b'7z\xbc\xaf\x27\x1c':        return '.7z'

        # ─ نص / برمجة ─
        try:
            sample = data[:512].decode('utf-8', errors='strict')
            if sample.strip().startswith(('<html', '<!DOCTYPE', '<HTML')): return '.html'
            if sample.strip().startswith('{') or sample.strip().startswith('['): return '.json'
            return '.txt'
        except Exception:
            pass

        return '.bin'   # غير معروف

    # ── مساعدات داخلية ────────────────────────────────────────────────────
    def _aes_decrypt(self, ak, iv, enc_payload):
        decryptor = Cipher(algorithms.AES(ak), modes.CBC(iv), default_backend()).decryptor()
        unpadder  = padding.PKCS7(128).unpadder()
        return (unpadder.update(decryptor.update(enc_payload) + decryptor.finalize())
                + unpadder.finalize())

    def _find_marker(self, content, extra_markers=None):
        # V27 — التنسيق الجديد الكامل
        for m in V27_MARKERS:
            if m in content:
                return m, "v27"
        # SHIELD القديم (V23/V25/V26) — بدون enc_size وبدون اسم
        for m in OLD_MARKERS:
            if m in content:
                return m, "old_shield"
        # SECURE_V2 — النسخة القديمة Pro v2.0 (تنسيق مختلف كلياً)
        for m in SECURE_V2_MARKERS:
            if m in content:
                return m, "secure_v2"
        # بصمات مخصصة — تُعامَل كـ old_shield
        if extra_markers:
            for m in extra_markers:
                if m in content:
                    return m, "old_shield"
        return None, None

    def _extract_clean_image(self, content, extra_markers=None):
        """يستخرج بيانات الصورة قبل أي بصمة تشفير"""
        check = ALL_MARKERS + (extra_markers or [])
        for m in check:
            idx = content.find(m)
            if idx != -1:
                return content[:idx]
        return content


# ══════════════════════════════════════════════════════════════════════════════
# مكوّنات الواجهة المخصصة
# ══════════════════════════════════════════════════════════════════════════════

class GradientHeader(QtWidgets.QWidget):
    """شريط عنوان متدرج اللون"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(64)

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        grad = QtGui.QLinearGradient(0, 0, self.width(), 0)
        grad.setColorAt(0.0, QtGui.QColor("#0a1628"))
        grad.setColorAt(0.5, QtGui.QColor("#0d2040"))
        grad.setColorAt(1.0, QtGui.QColor("#0a1628"))
        p.fillRect(self.rect(), grad)
        # خط سفلي متدرج
        line_grad = QtGui.QLinearGradient(0, 0, self.width(), 0)
        line_grad.setColorAt(0.0, QtGui.QColor(0, 195, 255, 0))
        line_grad.setColorAt(0.4, QtGui.QColor(0, 195, 255, 200))
        line_grad.setColorAt(0.6, QtGui.QColor(123, 95, 255, 200))
        line_grad.setColorAt(1.0, QtGui.QColor(123, 95, 255, 0))
        pen = QtGui.QPen(QtGui.QBrush(line_grad), 1.5)
        p.setPen(pen)
        p.drawLine(0, self.height() - 1, self.width(), self.height() - 1)
        p.end()


class LogWidget(QtWidgets.QTextEdit):
    """منطقة السجل مع ألوان حسب المستوى"""
    COLORS = {
        "ok":   "#00e676",
        "err":  "#ff5252",
        "warn": "#ffab40",
        "info": "#40c4ff",
    }
    ICONS = {"ok": "✔", "err": "✘", "warn": "⚠", "info": "ℹ"}

    def append_msg(self, msg: str, level: str = "info"):
        color = self.COLORS.get(level, "#ffffff")
        icon  = self.ICONS.get(level, "·")
        html  = (f'<span style="color:{color};font-weight:bold;">'
                 f'[{icon}]</span>'
                 f'<span style="color:{color};"> {msg}</span>')
        self.append(html)
        sb = self.verticalScrollBar()
        sb.setValue(sb.maximum())


class DropZone(QtWidgets.QFrame):
    """منطقة إسقاط الملف مع تأثير hover"""
    file_dropped = QtCore.pyqtSignal(str)

    def __init__(self, label="", parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setFixedHeight(70)
        self.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        self._label = label
        self._hovered = False
        self.setStyleSheet(self._style(False))

    def _style(self, hovered):
        border = "#00c3ff" if hovered else "#1e3a5f"
        bg     = "#0d1e30" if hovered else "#0b1624"
        return (f"QFrame {{ background: {bg}; border: 1.5px dashed {border};"
                f" border-radius: 8px; }}")

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        color = QtGui.QColor("#00c3ff" if self._hovered else "#3a5f7a")
        p.setPen(QtGui.QPen(color))
        font = p.font(); font.setPointSize(9); p.setFont(font)
        p.drawText(self.rect(), QtCore.Qt.AlignmentFlag.AlignCenter, self._label)
        p.end()

    def enterEvent(self, e):
        self._hovered = True
        self.setStyleSheet(self._style(True))
        self.update()

    def leaveEvent(self, e):
        self._hovered = False
        self.setStyleSheet(self._style(False))
        self.update()

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._hovered = True
            self.setStyleSheet(self._style(True))
            self.update()

    def dragLeaveEvent(self, e):
        self._hovered = False
        self.setStyleSheet(self._style(False))
        self.update()

    def dropEvent(self, e):
        self._hovered = False
        self.setStyleSheet(self._style(False))
        urls = e.mimeData().urls()
        if urls:
            self.file_dropped.emit(urls[0].toLocalFile())
        self.update()

    def mousePressEvent(self, e):
        self.file_dropped.emit("")   # يُشير للنقر (فتح مربع حوار)


class PwdField(QtWidgets.QWidget):
    """حقل كلمة المرور مع زر إظهار/إخفاء"""
    def __init__(self, placeholder="كلمة المرور...", parent=None):
        super().__init__(parent)
        lay = QtWidgets.QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self.edit = QtWidgets.QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        self.edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.edit.setFixedHeight(42)
        self.edit.setStyleSheet("""
            QLineEdit {
                background: #0a1520;
                color: #d0e8f8;
                padding: 0 12px;
                border: 1.5px solid #1e3a5f;
                border-right: none;
                border-radius: 6px 0 0 6px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border-color: #00c3ff;
            }
        """)

        self.eye = QtWidgets.QPushButton("👁")
        self.eye.setFixedSize(42, 42)
        self.eye.setCheckable(True)
        self.eye.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        self.eye.setStyleSheet("""
            QPushButton {
                background: #0a1520;
                border: 1.5px solid #1e3a5f;
                border-left: none;
                border-radius: 0 6px 6px 0;
                font-size: 14px;
            }
            QPushButton:hover  { background: #0d2035; border-color: #00c3ff; }
            QPushButton:checked { background: #0d2035; }
        """)
        self.eye.toggled.connect(
            lambda chk: self.edit.setEchoMode(
                QtWidgets.QLineEdit.EchoMode.Normal if chk
                else QtWidgets.QLineEdit.EchoMode.Password))

        lay.addWidget(self.edit)
        lay.addWidget(self.eye)

    def text(self): return self.edit.text()
    def clear(self): self.edit.clear()


def make_btn(text, accent="#00c3ff", text_color="white", height=44):
    b = QtWidgets.QPushButton(text)
    b.setFixedHeight(height)
    b.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
    r, g, b_val = (int(accent.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
    darker = f"#{max(r-30,0):02x}{max(g-30,0):02x}{max(b_val-30,0):02x}"
    b.setStyleSheet(f"""
        QPushButton {{
            background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                         stop:0 {accent}, stop:1 {darker});
            color: {text_color};
            font-weight: bold;
            font-size: 13px;
            border-radius: 7px;
            border: none;
            padding: 0 16px;
        }}
        QPushButton:hover {{
            background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                         stop:0 {accent}dd, stop:1 {accent}99);
        }}
        QPushButton:pressed {{
            background: {darker};
        }}
        QPushButton:disabled {{
            background: #1a2a3a;
            color: #4a6a8a;
        }}
    """)
    return b


def card_frame():
    f = QtWidgets.QFrame()
    f.setStyleSheet("""
        QFrame {
            background: #0b1928;
            border: 1px solid #1a3050;
            border-radius: 10px;
        }
    """)
    return f


# ══════════════════════════════════════════════════════════════════════════════
# النافذة الرئيسية
# ══════════════════════════════════════════════════════════════════════════════
class SteganoShieldApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.img_p     = ""
        self._drag_pos = None
        self.setFixedSize(720, 815)
        # Window يجب أن يُضاف صراحةً مع FramelessWindowHint وإلا
        # يُحذف من flags فلا تظهر الأيقونة في شريط مهام Windows أبداً
        self.setWindowFlags(
            QtCore.Qt.WindowType.Window |
            QtCore.Qt.WindowType.FramelessWindowHint
        )
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground)
        # ── أيقونة شريط العنوان وشريط المهام ──────────────────────────────
        self.setWindowIcon(_load_app_icon())
        self._build_ui()

    # ── بناء الواجهة ──────────────────────────────────────────────────────
    def _build_ui(self):
        root = QtWidgets.QWidget()
        root.setObjectName("Root")
        root.setStyleSheet("""
            #Root {
                background: #070d18;
                border: 1.5px solid #1a3050;
                border-radius: 14px;
            }
        """)
        self.setCentralWidget(root)
        main_lay = QtWidgets.QVBoxLayout(root)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)

        # ── شريط العنوان ────────────────────────────────────────────────
        header = GradientHeader()
        h_lay  = QtWidgets.QHBoxLayout(header)
        h_lay.setContentsMargins(18, 0, 14, 4)

        shield = QtWidgets.QLabel("🛡")
        shield.setStyleSheet("font-size: 26px; padding-right: 4px;")

        title_block = QtWidgets.QVBoxLayout()
        title_block.setSpacing(0)
        t1 = QtWidgets.QLabel("STEGANO SHIELD")
        t1.setStyleSheet("""
            color: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                   stop:0 #00c3ff, stop:1 #7b5fff);
            font-size: 16px; font-weight: bold; letter-spacing: 2px;
        """)
        t2 = QtWidgets.QLabel("V27 — FINAL GOLD  ·  نظام تشفير إخفاء البيانات")
        t2.setStyleSheet("color: #4a7a9a; font-size: 10px; letter-spacing: 1px;")
        title_block.addWidget(t1)
        title_block.addWidget(t2)

        btn_min   = self._wnd_btn("─", "#f0c040")
        btn_close = self._wnd_btn("✕", "#ff4d4d")
        btn_min.clicked.connect(self.showMinimized)
        btn_close.clicked.connect(self.close)

        h_lay.addWidget(shield)
        h_lay.addLayout(title_block)
        h_lay.addStretch()
        h_lay.addWidget(btn_min)
        h_lay.addSpacing(6)
        h_lay.addWidget(btn_close)
        main_lay.addWidget(header)

        # ── المحتوى ──────────────────────────────────────────────────────
        content = QtWidgets.QWidget()
        content.setStyleSheet("background: transparent;")
        c_lay = QtWidgets.QVBoxLayout(content)
        c_lay.setContentsMargins(18, 14, 18, 14)
        c_lay.setSpacing(12)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1a3050;
                border-radius: 8px;
                background: transparent;
            }
            QTabBar::tab {
                background: #0b1524;
                color: #4a7a9a;
                padding: 9px 22px;
                margin-right: 3px;
                border: 1px solid #1a3050;
                border-bottom: none;
                border-radius: 7px 7px 0 0;
                font-size: 12px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                             stop:0 #0d2a45, stop:1 #0b1928);
                color: #00c3ff;
                border-color: #00c3ff;
            }
            QTabBar::tab:hover:!selected { color: #7bbcda; }
        """)

        tab1 = self._build_tab_single()
        tab2 = self._build_tab_upgrade()
        self.tabs.addTab(tab1, "  🔒  تشفير / فك تشفير  ")
        self.tabs.addTab(tab2, "  ♻  ترقية الإصدار  ")
        c_lay.addWidget(self.tabs)

        # ── سجل العمليات ────────────────────────────────────────────────
        log_card = card_frame()
        log_lay  = QtWidgets.QVBoxLayout(log_card)
        log_lay.setContentsMargins(10, 8, 10, 8)
        log_lay.setSpacing(4)

        log_hdr = QtWidgets.QHBoxLayout()
        lbl_log = QtWidgets.QLabel("📋  سجل العمليات")
        lbl_log.setStyleSheet("color: #4a9aba; font-size: 11px; font-weight: bold;"
                              " background: transparent; border: none;")
        btn_clear = QtWidgets.QPushButton("مسح")
        btn_clear.setFixedSize(52, 22)
        btn_clear.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        btn_clear.setStyleSheet("""
            QPushButton {
                background: #0d1e30; color: #4a7a9a; border: 1px solid #1e3a5f;
                border-radius: 4px; font-size: 10px;
            }
            QPushButton:hover { color: #ff5252; border-color: #ff5252; }
        """)
        log_hdr.addWidget(lbl_log)
        log_hdr.addStretch()
        log_hdr.addWidget(btn_clear)

        self.log = LogWidget()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(155)
        self.log.setStyleSheet("""
            QTextEdit {
                background: #050c15;
                color: #00e676;
                border: none;
                border-radius: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                padding: 4px;
            }
            QScrollBar:vertical {
                background: #0a1520; width: 6px; border-radius: 3px;
            }
            QScrollBar::handle:vertical {
                background: #1e4060; border-radius: 3px; min-height: 20px;
            }
        """)
        btn_clear.clicked.connect(self.log.clear)

        log_lay.addLayout(log_hdr)
        log_lay.addWidget(self.log)
        c_lay.addWidget(log_card)

        main_lay.addWidget(content)

        # رسالة ترحيب
        self.log.append_msg("مرحباً — جاهز للعمل. اختر ملفاً وأدخل كلمة المرور.", "info")

    # ── تبويب التشفير الفردي ───────────────────────────────────────────────
    def _build_tab_single(self):
        w   = QtWidgets.QWidget()
        w.setStyleSheet("background: transparent;")
        lay = QtWidgets.QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)

        # ── بطاقة اختيار الملف ──────────────────────────────────────────
        file_card = card_frame()
        fc_lay    = QtWidgets.QVBoxLayout(file_card)
        fc_lay.setContentsMargins(14, 12, 14, 12)
        fc_lay.setSpacing(8)

        fc_lbl = QtWidgets.QLabel("الصورة الناقلة / الملف المشفر")
        fc_lbl.setStyleSheet("color: #4a9aba; font-size: 11px; font-weight: bold;"
                             " background: transparent; border: none;")
        fc_lay.addWidget(fc_lbl)

        self.drop_zone = DropZone("🖼  اضغط لاختيار صورة أو اسحب وأفلت هنا")
        self.drop_zone.file_dropped.connect(self._on_file_drop)
        fc_lay.addWidget(self.drop_zone)

        self.lbl_file = QtWidgets.QLabel("لم يتم اختيار ملف")
        self.lbl_file.setStyleSheet(
            "color: #3a6a8a; font-size: 11px; background: transparent; border: none;")
        self.lbl_file.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        fc_lay.addWidget(self.lbl_file)
        lay.addWidget(file_card)

        # ── بطاقة كلمة المرور ───────────────────────────────────────────
        psw_card = card_frame()
        pc_lay   = QtWidgets.QVBoxLayout(psw_card)
        pc_lay.setContentsMargins(14, 12, 14, 12)
        pc_lay.setSpacing(6)

        pc_lbl = QtWidgets.QLabel("كلمة المرور")
        pc_lbl.setStyleSheet("color: #4a9aba; font-size: 11px; font-weight: bold;"
                             " background: transparent; border: none;")
        pc_lay.addWidget(pc_lbl)

        self.psw = PwdField("أدخل كلمة المرور...")
        pc_lay.addWidget(self.psw)
        lay.addWidget(psw_card)

        # ── أزرار العمليات ───────────────────────────────────────────────
        btn_row = QtWidgets.QHBoxLayout()
        btn_row.setSpacing(10)

        self.btn_enc = make_btn("🔐  تشفير ملف داخل الصورة", "#1a7fd4")
        self.btn_dec = make_btn("🔓  فك التشفير واستخراج الملف", "#2a9a60")
        self.btn_enc.clicked.connect(self.run_enc)
        self.btn_dec.clicked.connect(self.run_dec)
        btn_row.addWidget(self.btn_enc)
        btn_row.addWidget(self.btn_dec)
        lay.addLayout(btn_row)

        lay.addStretch()
        return w

    # ── تبويب الترقية ──────────────────────────────────────────────────────
    def _build_tab_upgrade(self):
        w   = QtWidgets.QWidget()
        w.setStyleSheet("background: transparent;")
        lay = QtWidgets.QVBoxLayout(w)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        # ── أداة الفحص التشخيصي ──────────────────────────────────────────
        scan_card = card_frame()
        scan_card.setStyleSheet("""
            QFrame { background: #111820; border: 1px solid #1a3a50; border-radius: 10px; }
        """)
        sc_lay = QtWidgets.QVBoxLayout(scan_card)
        sc_lay.setContentsMargins(12, 10, 12, 10)
        sc_lay.setSpacing(6)

        sc_hdr = QtWidgets.QHBoxLayout()
        sc_icon = QtWidgets.QLabel("🔍")
        sc_icon.setStyleSheet("font-size:15px; background:transparent; border:none;")
        sc_lbl  = QtWidgets.QLabel("فحص ملف — اكتشف البصمة المخفية")
        sc_lbl.setStyleSheet("color:#4a9aba; font-size:11px; font-weight:bold;"
                             " background:transparent; border:none;")
        sc_hdr.addWidget(sc_icon); sc_hdr.addWidget(sc_lbl); sc_hdr.addStretch()
        sc_lay.addLayout(sc_hdr)

        sc_hint = QtWidgets.QLabel(
            "إذا قالت الترقية 'لا توجد بصمة'، افحص الملف أولاً لمعرفة بصمته الفعلية.")
        sc_hint.setStyleSheet("color:#3a6a8a; font-size:10px;"
                              " background:transparent; border:none;")
        sc_hint.setWordWrap(True)
        sc_lay.addWidget(sc_hint)

        btn_scan = make_btn("🔍  فحص ملف واكتشاف البصمة", "#1a5a8a", height=36)
        btn_scan.clicked.connect(self.run_scan)
        sc_lay.addWidget(btn_scan)
        lay.addWidget(scan_card)

        # ── بصمة مخصصة ────────────────────────────────────────────────────
        cm_card = card_frame()
        cm_card.setStyleSheet("""
            QFrame { background: #0f1a10; border: 1px solid #1a4025; border-radius: 10px; }
        """)
        cm_lay = QtWidgets.QVBoxLayout(cm_card)
        cm_lay.setContentsMargins(12, 10, 12, 10)
        cm_lay.setSpacing(6)

        cm_lbl = QtWidgets.QLabel(
            "بصمة مخصصة  (اتركها فارغة إذا كانت البصمة معروفة V23/V25/V26)")
        cm_lbl.setStyleSheet("color:#4a9aba; font-size:11px; font-weight:bold;"
                             " background:transparent; border:none;")
        cm_lay.addWidget(cm_lbl)

        self.custom_marker = QtWidgets.QLineEdit()
        self.custom_marker.setPlaceholderText(
            "مثال: SHIELD_V20  أو  STEGANO_OLD  (من نتيجة الفحص أعلاه)")
        self.custom_marker.setFixedHeight(36)
        self.custom_marker.setStyleSheet("""
            QLineEdit {
                background: #0a1520; color: #ffcc44;
                padding: 0 10px; border: 1.5px solid #2a5020;
                border-radius: 6px; font-size: 12px; font-family: monospace;
            }
            QLineEdit:focus { border-color: #5a9040; }
        """)
        cm_lay.addWidget(self.custom_marker)
        lay.addWidget(cm_card)

        # ── كلمات المرور ─────────────────────────────────────────────────
        psw_card = card_frame()
        pc_lay   = QtWidgets.QVBoxLayout(psw_card)
        pc_lay.setContentsMargins(12, 10, 12, 10)
        pc_lay.setSpacing(6)

        lbl_old = QtWidgets.QLabel("كلمة المرور القديمة")
        lbl_old.setStyleSheet("color:#4a9aba; font-size:11px; font-weight:bold;"
                              " background:transparent; border:none;")
        self.old_psw = PwdField("الباسورد القديم...")

        sep = QtWidgets.QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background: #1a3050; border: none;")

        lbl_new = QtWidgets.QLabel("كلمة المرور الجديدة (V27)")
        lbl_new.setStyleSheet("color:#4a9aba; font-size:11px; font-weight:bold;"
                              " background:transparent; border:none;")
        self.new_psw = PwdField("الباسورد الجديد...")

        pc_lay.addWidget(lbl_old)
        pc_lay.addWidget(self.old_psw)
        pc_lay.addWidget(sep)
        pc_lay.addWidget(lbl_new)
        pc_lay.addWidget(self.new_psw)
        lay.addWidget(psw_card)

        # ── زر الترقية ───────────────────────────────────────────────────
        btn_up = make_btn("♻  اختر مجلد الصور وابدأ الترقية إلى V27", "#7b40c4", height=46)
        btn_up.clicked.connect(self.run_up)
        lay.addWidget(btn_up)

        lay.addStretch()
        return w

    # ── زر نافذة ──────────────────────────────────────────────────────────
    def _wnd_btn(self, symbol, color):
        b = QtWidgets.QPushButton(symbol)
        b.setFixedSize(28, 28)
        b.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        b.setStyleSheet(f"""
            QPushButton {{
                background: #0d1e30;
                color: {color};
                border: 1px solid #1e3a5f;
                border-radius: 14px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background: {color}33; border-color: {color}; }}
        """)
        return b

    # ── منطق الأزرار ──────────────────────────────────────────────────────
    def _on_file_drop(self, path):
        if not path:  # نقر بالماوس → فتح مربع حوار
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "اختر صورة أو ملف مشفر", "",
                "الصور وجميع الملفات (*.png *.jpg *.jpeg *.bmp *.gif *.*)")
        if path:
            self.img_p = path
            name = os.path.basename(path)
            size = os.path.getsize(path)
            self.lbl_file.setText(f"📄 {name}  ({size/1024:.1f} KB)")
            self.lbl_file.setStyleSheet(
                "color: #00c3ff; font-size: 11px; background: transparent; border: none;")
            self.log.append_msg(f"تم اختيار: {name}", "info")

    def _validate(self, need_file=True, psw_widget=None):
        if need_file and not self.img_p:
            self._warn("الرجاء اختيار صورة أولاً.")
            return False
        if psw_widget and not psw_widget.text():
            self._warn("الرجاء إدخال كلمة المرور.")
            return False
        return True

    def _warn(self, msg):
        mb = QtWidgets.QMessageBox(self)
        mb.setWindowTitle("تنبيه")
        mb.setText(msg)
        mb.setIcon(QtWidgets.QMessageBox.Icon.Warning)
        mb.setStyleSheet("""
            QMessageBox { background: #0a1520; color: white; }
            QPushButton { background: #1a3a5f; color: white; padding: 6px 20px;
                          border-radius: 5px; border: 1px solid #2a5a8f; }
        """)
        mb.exec()

    def _start_worker(self, worker):
        self._set_buttons_enabled(False)
        worker.log_msg.connect(lambda m, lv: self.log.append_msg(m, lv))
        worker.finished_ok.connect(lambda: self._set_buttons_enabled(True))
        worker.finished.connect(lambda: self._set_buttons_enabled(True))
        worker.start()
        self._worker = worker  # منع garbage collection

    def _set_buttons_enabled(self, enabled):
        self.btn_enc.setEnabled(enabled)
        self.btn_dec.setEnabled(enabled)

    def run_enc(self):
        if not self._validate(need_file=True, psw_widget=self.psw):
            return
        sec, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "اختر الملف السري المراد إخفاؤه")
        if not sec:
            return
        out, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "حفظ الصورة المشفرة", "secure_v27.png", "PNG (*.png)")
        if not out:
            return
        w = ShieldWorker("encrypt", self.psw.text(),
                         img=self.img_p, sec=sec, out=out)
        self._start_worker(w)

    def run_dec(self):
        if not self._validate(need_file=True, psw_widget=self.psw):
            return
        w = ShieldWorker("decrypt", self.psw.text(), img=self.img_p)
        self._start_worker(w)

    def run_scan(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "اختر ملفاً للفحص", "",
            "الصور وجميع الملفات (*.png *.jpg *.jpeg *.bmp *.*)")
        if not path:
            return
        w = ShieldWorker("scan", "", path=path)
        w.log_msg.connect(lambda m, lv: self.log.append_msg(m, lv))
        w.finished.connect(lambda: None)
        w.start()
        self._worker = w

    def run_up(self):
        if not self.old_psw.text():
            self._warn("الرجاء إدخال كلمة المرور القديمة.")
            return
        if not self.new_psw.text():
            self._warn("الرجاء إدخال كلمة المرور الجديدة.")
            return
        fld = QtWidgets.QFileDialog.getExistingDirectory(
            self, "اختر مجلد الصور المراد ترقيتها")
        if not fld:
            return
        self.log.append_msg(f"بدء الترقية من المجلد: {os.path.basename(fld)}", "info")
        w = ShieldWorker("upgrade", "",
                         fld=fld,
                         old_p=self.old_psw.text(),
                         new_p=self.new_psw.text(),
                         custom_marker=self.custom_marker.text().strip())
        self._start_worker(w)

    # ── سحب النافذة ───────────────────────────────────────────────────────
    def mousePressEvent(self, e):
        if e.button() == QtCore.Qt.MouseButton.LeftButton:
            self._drag_pos = e.globalPosition().toPoint()

    def mouseMoveEvent(self, e):
        if self._drag_pos and e.buttons() & QtCore.Qt.MouseButton.LeftButton:
            delta = e.globalPosition().toPoint() - self._drag_pos
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self._drag_pos = e.globalPosition().toPoint()

    def mouseReleaseEvent(self, e):
        self._drag_pos = None


# ══════════════════════════════════════════════════════════════════════════════
# شاشة البداية الاحترافية
# ══════════════════════════════════════════════════════════════════════════════
class SplashScreen(QtWidgets.QWidget):
    """شاشة بداية احترافية بخلفية داكنة، لوغو، وشريط تحميل."""

    DURATION_MS  = 3000   # مدة الظهور (ميلي ثانية)
    TICK_MS      = 30     # دقة تحديث شريط التقدم

    def __init__(self):
        super().__init__()
        # ── إعداد النافذة ──────────────────────────────────────────────────
        self.setWindowFlags(
            QtCore.Qt.WindowType.FramelessWindowHint |
            QtCore.Qt.WindowType.WindowStaysOnTopHint |
            QtCore.Qt.WindowType.SplashScreen
        )
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(480, 340)

        # تمركز في منتصف الشاشة
        screen = QtWidgets.QApplication.primaryScreen().availableGeometry()
        self.move(
            screen.center().x() - self.width()  // 2,
            screen.center().y() - self.height() // 2
        )

        # ── تحميل اللوغو (resource_path يعمل داخل EXE وخارجه) ─────────────
        logo_path  = resource_path("assets/logo.png")
        self._logo = QtGui.QPixmap(logo_path) if os.path.exists(logo_path) else QtGui.QPixmap()

        # ── متغيرات التقدم ─────────────────────────────────────────────────
        self._progress   = 0          # 0 → 100
        self._step       = 100 / (self.DURATION_MS / self.TICK_MS)
        self._dots       = 0          # نقاط متحركة في رسالة الحالة
        self._dot_tick   = 0

        # ── مؤقتات ────────────────────────────────────────────────────────
        self._prog_timer = QtCore.QTimer(self)
        self._prog_timer.timeout.connect(self._tick)
        self._prog_timer.start(self.TICK_MS)

        self._main_win = None         # تُحفظ هنا لتجنب garbage collection

    # ── رسم النافذة ────────────────────────────────────────────────────────
    def paintEvent(self, _):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        W, H = self.width(), self.height()
        radius = 20

        # ① خلفية مستديرة الزوايا متدرجة
        path = QtGui.QPainterPath()
        path.addRoundedRect(QtCore.QRectF(0, 0, W, H), radius, radius)
        bg_grad = QtGui.QLinearGradient(0, 0, 0, H)
        bg_grad.setColorAt(0.0, QtGui.QColor("#0a1628"))
        bg_grad.setColorAt(1.0, QtGui.QColor("#060e18"))
        p.fillPath(path, bg_grad)

        # ② حد خارجي متدرج (توهج سماوي)
        pen_grad = QtGui.QLinearGradient(0, 0, W, H)
        pen_grad.setColorAt(0.0, QtGui.QColor("#00c3ff"))
        pen_grad.setColorAt(1.0, QtGui.QColor("#7b5fff"))
        p.setPen(QtGui.QPen(QtGui.QBrush(pen_grad), 2))
        p.setBrush(QtCore.Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(QtCore.QRectF(1, 1, W-2, H-2), radius, radius)

        # ③ اللوغو في المنتصف
        logo_size = 120
        lx = (W - logo_size) // 2
        ly = 30
        if not self._logo.isNull():
            scaled = self._logo.scaled(
                logo_size, logo_size,
                QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                QtCore.Qt.TransformationMode.SmoothTransformation
            )
            p.drawPixmap(lx + (logo_size - scaled.width())//2,
                         ly + (logo_size - scaled.height())//2, scaled)
        else:
            # رسم درع بسيط كبديل إذا لم يوجد لوغو
            p.setBrush(QtGui.QBrush(QtGui.QColor("#00c3ff")))
            p.setPen(QtCore.Qt.PenStyle.NoPen)
            p.drawEllipse(QtCore.QRectF(lx, ly, logo_size, logo_size))

        # ④ اسم التطبيق
        p.setPen(QtGui.QPen(QtGui.QColor("#e8f0ff")))
        title_font = QtGui.QFont("Arial", 20, QtGui.QFont.Weight.Bold)
        p.setFont(title_font)
        p.drawText(QtCore.QRectF(0, ly + logo_size + 10, W, 36),
                   QtCore.Qt.AlignmentFlag.AlignHCenter, "STEGANO SHIELD")

        # سطر الإصدار
        ver_font = QtGui.QFont("Arial", 10)
        p.setFont(ver_font)
        p.setPen(QtGui.QPen(QtGui.QColor("#00c3ff")))
        p.drawText(QtCore.QRectF(0, ly + logo_size + 46, W, 20),
                   QtCore.Qt.AlignmentFlag.AlignHCenter, "Professional Steganography Suite  v27")

        # ⑤ شريط التقدم
        bar_x, bar_y, bar_w, bar_h = 40, H - 62, W - 80, 8
        # خلفية الشريط
        p.setBrush(QtGui.QBrush(QtGui.QColor("#0d2040")))
        p.setPen(QtGui.QPen(QtGui.QColor("#1a3060"), 1))
        p.drawRoundedRect(QtCore.QRectF(bar_x, bar_y, bar_w, bar_h), 4, 4)
        # التعبئة المتدرجة
        fill_w = int(bar_w * self._progress / 100)
        if fill_w > 0:
            fill_grad = QtGui.QLinearGradient(bar_x, 0, bar_x + bar_w, 0)
            fill_grad.setColorAt(0.0, QtGui.QColor("#00c3ff"))
            fill_grad.setColorAt(1.0, QtGui.QColor("#7b5fff"))
            p.setBrush(QtGui.QBrush(fill_grad))
            p.setPen(QtCore.Qt.PenStyle.NoPen)
            p.drawRoundedRect(QtCore.QRectF(bar_x, bar_y, fill_w, bar_h), 4, 4)

        # ⑥ رسالة الحالة المتحركة
        dots = "." * (self._dots + 1)
        if self._progress < 40:
            msg = f"جارٍ تهيئة النظام{dots}"
        elif self._progress < 75:
            msg = f"جارٍ تحميل المكونات{dots}"
        else:
            msg = f"جارٍ الإطلاق{dots}"

        status_font = QtGui.QFont("Arial", 9)
        p.setFont(status_font)
        p.setPen(QtGui.QPen(QtGui.QColor("#5a7a9a")))
        p.drawText(QtCore.QRectF(0, H - 50, W, 18),
                   QtCore.Qt.AlignmentFlag.AlignHCenter, msg)

        # نسبة مئوية يمين الشريط
        pct_font = QtGui.QFont("Arial", 8, QtGui.QFont.Weight.Bold)
        p.setFont(pct_font)
        p.setPen(QtGui.QPen(QtGui.QColor("#00c3ff")))
        p.drawText(QtCore.QRectF(bar_x + bar_w - 30, bar_y - 18, 50, 16),
                   QtCore.Qt.AlignmentFlag.AlignLeft,
                   f"{int(self._progress)}%")

        # حقوق الملكية
        copy_font = QtGui.QFont("Arial", 7)
        p.setFont(copy_font)
        p.setPen(QtGui.QPen(QtGui.QColor("#2a4060")))
        p.drawText(QtCore.QRectF(0, H - 22, W, 16),
                   QtCore.Qt.AlignmentFlag.AlignHCenter,
                   "© 2026 Yossof Al-madhagi  —  All Rights Reserved")

        p.end()

    # ── دورة التحديث ───────────────────────────────────────────────────────
    def _tick(self):
        self._progress = min(100, self._progress + self._step)

        self._dot_tick += 1
        if self._dot_tick >= 12:
            self._dot_tick = 0
            self._dots = (self._dots + 1) % 3

        self.update()   # إعادة الرسم

        if self._progress >= 100:
            self._prog_timer.stop()
            QtCore.QTimer.singleShot(120, self._launch)

    # ── إطلاق النافذة الرئيسية ─────────────────────────────────────────────
    def _launch(self):
        self._main_win = SteganoShieldApp()
        self._main_win.show()
        self.close()

    # ── السحب لتحريك النافذة ──────────────────────────────────────────────
    def mousePressEvent(self, e):
        if e.button() == QtCore.Qt.MouseButton.LeftButton:
            self._drag = e.globalPosition().toPoint()

    def mouseMoveEvent(self, e):
        if hasattr(self, '_drag') and e.buttons() & QtCore.Qt.MouseButton.LeftButton:
            delta = e.globalPosition().toPoint() - self._drag
            self.move(self.pos() + delta)
            self._drag = e.globalPosition().toPoint()

    def mouseReleaseEvent(self, _):
        self._drag = None


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":

    # ── Windows: AppUserModelID يجب قبل QApplication تماماً ─────────────
    # بدونه يظهر شريط المهام بأيقونة Python الافتراضية بدلاً من الشعار
    APP_ID = "SteganoShield.Pro.V27"
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except AttributeError:
        pass   # Linux / macOS — يُتجاهَل بأمان

    app = QtWidgets.QApplication(sys.argv)

    # ── بيانات التطبيق — تُستخدم بواسطة Windows لتسجيل الأيقونة ─────────
    app.setApplicationName("SteganoShield")
    app.setApplicationDisplayName("Stegano Shield Pro")
    app.setApplicationVersion("27.0")
    app.setOrganizationName("SteganoShield")
    app.setOrganizationDomain("stegano-shield.local")

    app.setLayoutDirection(QtCore.Qt.LayoutDirection.RightToLeft)
    app.setStyle("Fusion")

    # ── تطبيق الأيقونة على مستوى التطبيق كاملاً ──────────────────────────
    app_icon = _load_app_icon()
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)

    splash = SplashScreen()
    splash.show()
    sys.exit(app.exec())
