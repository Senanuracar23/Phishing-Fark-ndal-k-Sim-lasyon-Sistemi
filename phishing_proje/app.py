
"""
Phishing Farkındalık Simülasyon Sistemi
Savunma Modülü: İki Faktörlü Doğrulama (2FA) + Kural Tabanlı Güvenlik Duvarı
Yalnızca eğitim ve farkındalık amacıyla geliştirilmiştir.
Doğuş Üniversitesi — Senanur AÇAR
"""
 
from flask import Flask, request, redirect, send_file, jsonify, render_template_string, session
from flask_cors import CORS
import sqlite3, smtplib, uuid, io, base64, urllib.request, json, os, random, hashlib, time, secrets
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
load_dotenv()
 
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phishingsim-dogus-2026-sabit-key")
 
# ── SESSION / COOKIE AYARLARI ──────────────────────────────────────────────────
IS_PROD = os.environ.get("FLASK_ENV", "development") == "production"
 
app.config['SESSION_COOKIE_SAMESITE'] = 'None' if IS_PROD else 'Lax'
app.config['SESSION_COOKIE_SECURE']   = IS_PROD
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_NAME']     = 'phishsim_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
 
# Dev tunnel'da HTTPS→HTTP proxy olduğundan SESSION_COOKIE_SECURE env ile kontrol edilir; tunnel için FLASK_ENV=production set et.
 
CORS(app,
     supports_credentials=True,
     origins=["*"],
     allow_headers=["Content-Type", "X-Requested-With"],
     methods=["GET", "POST", "DELETE", "OPTIONS"])
 
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
DB_PATH       = os.path.join(BASE_DIR, "phishing_sim.db")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
 
TEMPLATE_SUBJECTS = {
    "bank":     "Hesabınızda Şüpheli İşlem Tespit Edildi",
    "cargo":    "Kargonuz Teslim Bekliyor — Adres Güncelleme Gerekli",
    "password": "Şifreniz Sona Eriyor — Hemen Yenileyin"
}
 
# -----------------------------------------------------------------
# 2FA İÇİN ADMİN MAİL / SMTP AYARLARI (ortam değişkenlerinden okunur)
# -----------------------------------------------------------------

ADMIN_EMAIL  = os.environ.get("ADMIN_EMAIL")        
SMTP_HOST    = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT    = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER    = os.environ.get("SMTP_USER")         
SMTP_PASS    = os.environ.get("SMTP_PASS")          
 
# -----------------------------------------------------------------
# GÜVENLIK DUVARI
# -----------------------------------------------------------------
 
ENGELLENEN_IP     = {"192.168.1.100", "10.0.0.5"}
ENGELLENEN_DOMAIN = {"tempmail.com", "mailinator.com", "trashmail.com", "guerrillamail.com"}
istek_sayaci      = {}
HIZSINIR_PENCERE  = 60
HIZSINIR_ESIK     = 50   
def guvenlik_duvari(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        if ip in ENGELLENEN_IP:
            kaydet_guvenlik_olayi(ip, "ENGELLENEN_IP", request.path)
            return jsonify({"hata": "Erişim reddedildi."}), 403
        simdi = time.time()
        istek_sayaci.setdefault(ip, [])
        istek_sayaci[ip] = [t for t in istek_sayaci[ip] if simdi - t < HIZSINIR_PENCERE]
        if len(istek_sayaci[ip]) >= HIZSINIR_ESIK:
            kaydet_guvenlik_olayi(ip, "HIZ_ASIMI", request.path)
            return jsonify({"hata": "Çok fazla istek. Lütfen bekleyin."}), 429
        istek_sayaci[ip].append(simdi)
        return f(*args, **kwargs)
    return decorated
 
def email_domain_kontrol(email):
    if "@" not in email:
        return False, "Geçersiz e-posta formatı"
    domain = email.split("@")[-1].lower()
    if domain in ENGELLENEN_DOMAIN:
        return False, f"Şüpheli domain engellendi: {domain}"
    return True, "Geçerli"
 
def kaydet_guvenlik_olayi(ip, olay_turu, yol):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO guvenlik_olaylari (ip, olay_turu, yol, zaman) VALUES (?,?,?,?)",
            (ip, olay_turu, yol, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
 
# -----------------------------------------------------------------
# 2FA — ADMIN GİRİŞİ

 
ADMIN_KULLANICI  = "admin"
ADMIN_SIFRE_HASH = hashlib.sha256("gizli123".encode()).hexdigest()
iki_fa_kodlari   = {}
 
def otp_olustur():
      
    return str(secrets.randbelow(900000) + 100000)
 
def otp_mail_gonder(kod):
    """OTP kodunu admin'in kendi mailine SMTP üzerinden gönderir."""
    if not (SMTP_USER and SMTP_PASS and ADMIN_EMAIL):
        raise RuntimeError(
            "SMTP_USER, SMTP_PASS ve ADMIN_EMAIL ortam değişkenleri tanımlı değil."
        )
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "PhishingSim — Giriş Doğrulama Kodunuz"
    msg["From"]    = SMTP_USER
    msg["To"]      = ADMIN_EMAIL
    govde = f"""
    <div style="font-family:Arial;padding:24px;">
      <h2>Giriş Doğrulama Kodu</h2>
      <p>Admin panelinize giriş yapmak için aşağıdaki kodu kullanın. Kod 5 dakika geçerlidir.</p>
      <p style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#e74c3c;">{kod}</p>
      <p style="font-size:12px;color:#888;">Bu isteği siz yapmadıysanız hesabınızın şifresini değiştirin.</p>
    </div>"""
    msg.attach(MIMEText(govde, "html"))
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as sunucu:
        sunucu.login(SMTP_USER, SMTP_PASS)
        sunucu.sendmail(SMTP_USER, ADMIN_EMAIL, msg.as_string())
 
def giris_gerekli(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_giris"):
            if request.path.startswith("/api/"):
                return jsonify({"hata": "Oturum açmanız gerekiyor.", "redirect": "/giris"}), 401
            return redirect("/giris")
        return f(*args, **kwargs)
    return decorated
 
# -----------------------------------------------------------------
# VERİTABANI
# -----------------------------------------------------------------
 
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY, name TEXT, template TEXT, created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT, email TEXT, token TEXT UNIQUE,
            opened INTEGER DEFAULT 0, clicked INTEGER DEFAULT 0, reported INTEGER DEFAULT 0,
            opened_at TEXT, clicked_at TEXT, reported_at TEXT,
            ip_address TEXT, user_agent TEXT, location TEXT, sent_at TEXT,
            mail_durumu TEXT DEFAULT 'bekliyor', mail_hata TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS guvenlik_olaylari (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, olay_turu TEXT, yol TEXT, zaman TEXT
        )
    """)
    for sutun in ["reported INTEGER DEFAULT 0", "reported_at TEXT", "location TEXT",
                  "mail_durumu TEXT DEFAULT 'bekliyor'", "mail_hata TEXT"]:
        try:
            c.execute(f"ALTER TABLE tracking ADD COLUMN {sutun}")
        except Exception:
            pass
    conn.commit()
    conn.close()
 
init_db()
 
# -----------------------------------------------------------------
# YARDIMCI FONKSİYONLAR
# -----------------------------------------------------------------
 
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
 
def sablon_yukle(ad):
    yol = os.path.join(TEMPLATES_DIR, f"{ad}.html")
    with open(yol, encoding="utf-8") as f:
        return f.read()
 
def sablon_isle(ad, **kwargs):
    html = sablon_yukle(ad)
    for anahtar, deger in kwargs.items():
        html = html.replace("{{" + anahtar + "}}", str(deger))
    return html
 
def risk_puani(acildi, tiklandi):
    if tiklandi: return 100
    if acildi:   return 40
    return 0
 
def risk_etiketi(puan):
    if puan >= 100: return "YUKSEK"
    if puan >= 40:  return "ORTA"
    return "DUSUK"
 
def cihaz_tespiti(kullanici_ajani):
    if not kullanici_ajani: return "Bilinmiyor"
    ua = kullanici_ajani.lower()
    if any(k in ua for k in ("mobile", "android", "iphone")): return "Mobil"
    if any(k in ua for k in ("tablet", "ipad")):              return "Tablet"
    return "Masaustu"
 
def konum_al(ip):
    try:
        if ip in ("127.0.0.1", "::1", "localhost"):
            return "Yerel Ag"
        with urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=country,city,status", timeout=3
        ) as r:
            veri = json.loads(r.read())
            if veri.get("status") == "success":
                return f"{veri.get('city', '?')}, {veri.get('country', '?')}"
    except Exception:
        pass
    return "Bilinmiyor"
 
# -----------------------------------------------------------------
# GİRİŞ SAYFALARI
# -----------------------------------------------------------------
 
GIRIS_HTML = """
<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<title>Admin Giris</title>
<style>
  body{font-family:Arial;background:#f4f6f9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}
  .kutu{background:#fff;border-radius:12px;padding:40px 48px;width:360px;box-shadow:0 4px 24px rgba(0,0,0,0.1);}
  h2{color:#1a1a2e;margin:0 0 6px;font-size:22px;}
  .alt{color:#888;font-size:13px;margin-bottom:28px;}
  label{font-size:13px;font-weight:600;color:#444;display:block;margin-bottom:6px;}
  input{width:100%;padding:11px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;
        box-sizing:border-box;margin-bottom:16px;outline:none;}
  input:focus{border-color:#e74c3c;}
  .btn{width:100%;padding:12px;background:#e74c3c;color:#fff;border:none;border-radius:8px;
       font-size:15px;font-weight:600;cursor:pointer;}
  .hata{background:#fdecea;color:#c0392b;border:1px solid #f1948a;border-radius:8px;
        padding:10px 14px;font-size:13px;margin-bottom:16px;}
  .basari{background:#eafaf1;color:#1e8449;border:1px solid #a9dfbf;border-radius:8px;
        padding:10px 14px;font-size:13px;margin-bottom:16px;}
  .logo{font-size:28px;text-align:center;margin-bottom:16px;}
  .rozet{display:inline-block;background:#eafaf1;color:#1e8449;padding:4px 10px;
         border-radius:20px;font-size:11px;font-weight:600;margin-bottom:20px;}
</style></head><body>
<div class="kutu">
  <div class="logo">🎣</div>
  <h2>PhishingSim</h2>
  <div class="alt">Yonetici Girisi</div>
  <span class="rozet">🔐 2FA Korumali</span>
  {% if hata %}<div class="hata">{{ hata }}</div>{% endif %}
  {% if mesaj %}<div class="basari">{{ mesaj }}</div>{% endif %}
  <form method="POST" action="/giris">
    <label>Kullanici Adi</label>
    <input type="text" name="kullanici" placeholder="admin" required>
    <label>Sifre</label>
    <input type="password" name="sifre" placeholder="••••••••" required>
    {% if otp_adimi %}
    <label>2FA Kodu (mailinize gönderildi)</label>
    <input type="text" name="otp" placeholder="123456" maxlength="6" autofocus>
    {% endif %}
    <button class="btn" type="submit">Giris Yap</button>
  </form>
</div>
</body></html>
"""
 
@app.route("/giris", methods=["GET"])
def giris_sayfasi():
    if session.get("admin_giris"):
        return redirect("/admin")
    return render_template_string(GIRIS_HTML, hata=None, mesaj=None, otp_adimi=False)
 
@app.route("/giris", methods=["POST"])
@guvenlik_duvari
def giris_yap():
    kullanici  = request.form.get("kullanici", "")
    sifre      = request.form.get("sifre", "")
    otp        = request.form.get("otp", "").strip()
    sifre_hash = hashlib.sha256(sifre.encode()).hexdigest()
 
    # 1) Kullanıcı adı ve şifre kontrolü — bu doğrulanmadan OTP asla üretilmez
    if kullanici != ADMIN_KULLANICI or sifre_hash != ADMIN_SIFRE_HASH:
        kaydet_guvenlik_olayi(request.remote_addr, "HATALI_GIRIS", "/giris")
        return render_template_string(GIRIS_HTML, hata="Kullanici adi veya sifre hatali.",
                                        mesaj=None, otp_adimi=False)
 
    # 2) OTP formu bossa: her seferinde yeni kod uret
    if not otp:
        kod = otp_olustur()
        iki_fa_kodlari[kullanici] = {
            "kod": kod,
            "son_gecerlilik": datetime.now() + timedelta(minutes=5)
        }
        try:
            otp_mail_gonder(kod)
        except Exception as e:
            kaydet_guvenlik_olayi(request.remote_addr, "OTP_MAIL_HATASI", "/giris")
            return render_template_string(
                GIRIS_HTML,
                hata=f"Dogrulama kodu gonderilemedi: {e}",
                mesaj=None, otp_adimi=False
            )
        return render_template_string(
            GIRIS_HTML,
            hata=None,
            mesaj="Sifre dogru. Dogrulama kodu mail adresinize gonderildi.",
            otp_adimi=True
        )
 
    # 3) OTP formu dolu: kodu dogrula
    kayit = iki_fa_kodlari.get(kullanici)
    if not kayit:
        return render_template_string(GIRIS_HTML, hata="2FA oturumu bulunamadi, tekrar giris yapin.",
                                        mesaj=None, otp_adimi=False)
    if datetime.now() > kayit["son_gecerlilik"]:
        del iki_fa_kodlari[kullanici]
        return render_template_string(GIRIS_HTML, hata="2FA kodunun suresi dolmus, tekrar giris yapin.",
                                        mesaj=None, otp_adimi=False)
    if otp != kayit["kod"]:
        kaydet_guvenlik_olayi(request.remote_addr, "HATALI_OTP", "/giris")
        return render_template_string(GIRIS_HTML, hata="Gecersiz 2FA kodu.",
                                        mesaj=None, otp_adimi=True)
 
    del iki_fa_kodlari[kullanici]
    session["admin_giris"] = True
    session.permanent = True
    return redirect("/admin")
 
@app.route("/cikis")
def cikis():
    session.clear()
    return redirect("/giris")
 
# -----------------------------------------------------------------
# TAKİP ENDPOINT'LERİ (giris_gerekli YOK — kullanici tarafi)
# -----------------------------------------------------------------
 
@app.route("/track_open/<token>")
@guvenlik_duvari
def takip_acilma(token):
    conn = get_db()
    kayit = conn.execute("SELECT * FROM tracking WHERE token=?", (token,)).fetchone()
    if kayit and not kayit["opened"]:
        ip = request.remote_addr
        conn.execute("""
            UPDATE tracking SET opened=1, opened_at=?, ip_address=?, user_agent=?, location=?
            WHERE token=?
        """, (datetime.now().isoformat(), ip,
              request.headers.get("User-Agent", ""), konum_al(ip), token))
        conn.commit()
    conn.close()
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    return send_file(io.BytesIO(gif), mimetype="image/gif")
 
@app.route("/track_click/<token>")
@guvenlik_duvari
def takip_tiklama(token):
    conn = get_db()
    kayit = conn.execute("SELECT * FROM tracking WHERE token=?", (token,)).fetchone()
    if kayit:
        if not kayit["clicked"]:
            ip = request.remote_addr
            conn.execute("""
                UPDATE tracking SET clicked=1, clicked_at=?, ip_address=?, user_agent=?, location=?
                WHERE token=?
            """, (datetime.now().isoformat(), ip,
                  request.headers.get("User-Agent", ""), konum_al(ip), token))
            conn.commit()
        conn.close()
        return redirect("/farkindali")
    conn.close()
    return "Gecersiz baglanti", 404
 
@app.route("/track_report/<token>")
@guvenlik_duvari
def takip_bildirim(token):
    conn = get_db()
    kayit = conn.execute("SELECT * FROM tracking WHERE token=?", (token,)).fetchone()
    if kayit:
        if not kayit["reported"]:
            conn.execute("""
                UPDATE tracking SET reported=1, reported_at=?, user_agent=?, ip_address=?
                WHERE token=?
            """, (datetime.now().isoformat(),
                  request.headers.get("User-Agent", ""),
                  request.remote_addr, token))
            conn.commit()
        conn.close()
        return render_template_string("""
        <!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>Bildirim Alindi</title>
        <style>body{font-family:Arial;background:#d4edda;display:flex;justify-content:center;
        align-items:center;height:100vh;margin:0;}
        .kutu{background:#fff;border:2px solid #28a745;border-radius:12px;padding:40px;
        max-width:500px;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,0.1);}
        h1{color:#28a745;}.rozet{background:#28a745;color:#fff;padding:8px 20px;
        border-radius:20px;font-size:14px;}</style></head>
        <body><div class="kutu">
        <div style="font-size:60px">✅</div><h1>Tesekkurler!</h1>
        <p>Bu maili supeheli olarak bildirdiniz.</p>
        <p>Bu bir <strong>phishing simulasyonuydu</strong>. Dogru tepkiyi verdiniz!</p>
        <br><span class="rozet">Guvenlik farkindaliginiz yuksek</span>
        </div></body></html>""")
    conn.close()
    return "Gecersiz baglanti", 404
 
@app.route("/farkindali")
def farkindali_sayfasi():
    return render_template_string("""
    <!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
    <title>Bu Bir Phishing Testidir</title>
    <style>body{font-family:Arial;background:#fff3cd;display:flex;justify-content:center;
    align-items:center;min-height:100vh;margin:0;}
    .kutu{background:#fff;border:2px solid #ffc107;border-radius:12px;padding:40px;
    max-width:520px;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,0.1);}
    h1{color:#dc3545;}ul{text-align:left;color:#555;font-size:14px;line-height:1.9;margin:16px 0;}
    .rozet{background:#dc3545;color:#fff;padding:8px 20px;border-radius:20px;font-size:14px;}
    </style></head>
    <body><div class="kutu">
    <div style="font-size:60px">⚠️</div><h1>Bu Bir Phishing Testidir!</h1>
    <p style="color:#555;">Gercek bir saldiri olsaydi hesap bilgileriniz calinabilirdi.</p>
    <ul>
      <li>Gonderen adresini her zaman kontrol edin</li>
      <li>Baglanti uzerine gelin, gercek URL yi gorun</li>
      <li>Aciliyet iceren mesajlara dikkat edin</li>
      <li>Supeheli e-postalari IT ye bildirin</li>
    </ul>
    <span class="rozet">Lutfen supeheli e-postalara dikkat edin</span>
    </div></body></html>""")
 
# -----------------------------------------------------------------
# API
# -----------------------------------------------------------------
 
@app.route("/api/campaigns", methods=["POST"])
@guvenlik_duvari
@giris_gerekli
def kampanya_olustur():
    veri = request.json
    if not veri or not veri.get("name") or not veri.get("template"):
        return jsonify({"error": "Kampanya adı ve şablonu zorunludur."}), 400
    kampanya_id = str(uuid.uuid4())[:8]
    conn = get_db()
    conn.execute(
        "INSERT INTO campaigns (id, name, template, created_at) VALUES (?,?,?,?)",
        (kampanya_id, veri["name"], veri["template"], datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return jsonify({"campaign_id": kampanya_id, "message": "Kampanya olusturuldu"})
 
 
@app.route("/api/send", methods=["POST"])
@guvenlik_duvari
@giris_gerekli
def mail_gonder():
    veri        = request.json
    if not veri:
        return jsonify({"error": "Geçersiz istek gövdesi."}), 400
 
    kampanya_id = veri.get("campaign_id")
    emailler    = veri.get("emails", [])
    temel_url   = veri.get("base_url", "http://localhost:5000").rstrip("/")
    smtp_ayar   = veri.get("smtp_config", None)
 
    if not kampanya_id:
        return jsonify({"error": "campaign_id zorunludur."}), 400
    if not emailler:
        return jsonify({"error": "En az bir e-posta adresi gereklidir."}), 400
 
    conn = get_db()
    kampanya = conn.execute("SELECT * FROM campaigns WHERE id=?", (kampanya_id,)).fetchone()
    if not kampanya:
        conn.close()
        return jsonify({"error": "Kampanya bulunamadi"}), 404
 
    sablon_adi = kampanya["template"]
    konu       = TEMPLATE_SUBJECTS.get(sablon_adi, "Guvenlik Bildirimi")
    sonuclar   = []
 
    for email in emailler:
        gecerli, gerekce = email_domain_kontrol(email)
        if not gecerli:
            kaydet_guvenlik_olayi(request.remote_addr, "ENGELLENEN_DOMAIN", email)
            sonuclar.append({"email": email, "status": "engellendi", "error": gerekce, "token": None})
            continue
 
        token        = str(uuid.uuid4())
        acilma_url   = f"{temel_url}/track_open/{token}"
        tiklama_url  = f"{temel_url}/track_click/{token}"
        bildirim_url = f"{temel_url}/track_report/{token}"
 
        try:
            html = sablon_isle(
                sablon_adi,
                open_url     = acilma_url,
                click_url    = tiklama_url,
                report_url   = bildirim_url,
                token_short  = token[:6].upper(),
                email        = email,
                current_time = datetime.now().strftime("%d.%m.%Y %H:%M")
            )
        except FileNotFoundError:
            conn.close()
            return jsonify({"error": f"Şablon bulunamadı: {sablon_adi}"}), 500
 
        conn.execute("""
            INSERT OR IGNORE INTO tracking (campaign_id, email, token, sent_at, mail_durumu)
            VALUES (?,?,?,?,?)
        """, (kampanya_id, email, token, datetime.now().isoformat(), "gonderiliyor"))
        conn.commit()
 
        if smtp_ayar and smtp_ayar.get("host"):
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = konu
                msg["From"]    = smtp_ayar["from"]
                msg["To"]      = email
                msg.attach(MIMEText(html, "html"))
                with smtplib.SMTP_SSL(smtp_ayar["host"], smtp_ayar.get("port", 465)) as sunucu:
                    sunucu.login(smtp_ayar["user"], smtp_ayar["password"])
                    sunucu.sendmail(smtp_ayar["from"], email, msg.as_string())
                conn.execute(
                    "UPDATE tracking SET mail_durumu=?, mail_hata=NULL WHERE token=?",
                    ("gonderildi", token)
                )
                sonuclar.append({"email": email, "token": token, "status": "gonderildi", "error": None})
 
            except smtplib.SMTPAuthenticationError:
                hata_mesaji = "SMTP kimlik dogrulama hatasi — Gmail icin Uygulama Sifresi kullanin"
                conn.execute("UPDATE tracking SET mail_durumu=?, mail_hata=? WHERE token=?",
                             ("hata", hata_mesaji, token))
                sonuclar.append({"email": email, "token": token, "status": "hata", "error": hata_mesaji})
 
            except smtplib.SMTPRecipientsRefused:
                hata_mesaji = "Alici adresi reddedildi"
                conn.execute("UPDATE tracking SET mail_durumu=?, mail_hata=? WHERE token=?",
                             ("hata", hata_mesaji, token))
                sonuclar.append({"email": email, "token": token, "status": "hata", "error": hata_mesaji})
 
            except Exception as e:
                hata_mesaji = str(e)[:200]
                conn.execute("UPDATE tracking SET mail_durumu=?, mail_hata=? WHERE token=?",
                             ("hata", hata_mesaji, token))
                sonuclar.append({"email": email, "token": token, "status": "hata", "error": hata_mesaji})
        else:
            conn.execute("UPDATE tracking SET mail_durumu=? WHERE token=?", ("simulasyon", token))
            sonuclar.append({
                "email":      email,
                "token":      token,
                "status":     "simulasyon",
                "error":      None,
                "open_url":   acilma_url,
                "click_url":  tiklama_url,
                "report_url": bildirim_url
            })
 
    conn.commit()
    conn.close()
 
    return jsonify({
        "total":      len(sonuclar),
        "sent":       sum(1 for s in sonuclar if s["status"] == "gonderildi"),
        "simulation": sum(1 for s in sonuclar if s["status"] == "simulasyon"),
        "error":      sum(1 for s in sonuclar if s["status"] == "hata"),
        "blocked":    sum(1 for s in sonuclar if s["status"] == "engellendi"),
        "results":    sonuclar
    })
 
 
@app.route("/api/stats/<kampanya_id>")
@guvenlik_duvari
@giris_gerekli
def kampanya_istatistik(kampanya_id):
    conn = get_db()
    satirlar = conn.execute("""
        SELECT email, opened, clicked, reported,
               opened_at, clicked_at, reported_at,
               ip_address, user_agent, location,
               mail_durumu, mail_hata
        FROM tracking WHERE campaign_id=?
    """, (kampanya_id,)).fetchall()
    conn.close()
 
    kullanicilar = []
    toplam_gonderilen = toplam_acilan = toplam_tiklanan = toplam_bildirilen = 0
    mail_durumu_ozet = {"gonderildi": 0, "simulasyon": 0, "hata": 0, "engellendi": 0}
 
    for satir in satirlar:
        puan = risk_puani(satir["opened"], satir["clicked"])
        toplam_gonderilen += 1
        toplam_acilan     += satir["opened"]
        toplam_tiklanan   += satir["clicked"]
        toplam_bildirilen += satir["reported"] or 0
        durum = satir["mail_durumu"] or "bilinmiyor"
        if durum in mail_durumu_ozet:
            mail_durumu_ozet[durum] += 1
        kullanicilar.append({
            "email":       satir["email"],
            "opened":      bool(satir["opened"]),
            "clicked":     bool(satir["clicked"]),
            "reported":    bool(satir["reported"]),
            "opened_at":   satir["opened_at"],
            "clicked_at":  satir["clicked_at"],
            "reported_at": satir["reported_at"],
            "ip":          satir["ip_address"],
            "device":      cihaz_tespiti(satir["user_agent"]),
            "location":    satir["location"] or "--",
            "risk_score":  puan,
            "risk_label":  risk_etiketi(puan),
            "mail_status": durum,
            "mail_error":  satir["mail_hata"] or None
        })
 
    return jsonify({
        "campaign_id":         kampanya_id,
        "total_sent":          toplam_gonderilen,
        "total_opened":        toplam_acilan,
        "total_clicked":       toplam_tiklanan,
        "total_reported":      toplam_bildirilen,
        "open_rate":           round(toplam_acilan    / toplam_gonderilen * 100, 1) if toplam_gonderilen else 0,
        "click_rate":          round(toplam_tiklanan  / toplam_gonderilen * 100, 1) if toplam_gonderilen else 0,
        "report_rate":         round(toplam_bildirilen / toplam_gonderilen * 100, 1) if toplam_gonderilen else 0,
        "mail_status_summary": mail_durumu_ozet,
        "users": sorted(kullanicilar, key=lambda x: x["risk_score"], reverse=True)
    })
 
 
@app.route("/api/campaigns", methods=["GET"])
@guvenlik_duvari
@giris_gerekli
def kampanyalari_listele():
    conn = get_db()
    satirlar = conn.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(s) for s in satirlar])
 
 
@app.route("/api/campaigns/<kampanya_id>", methods=["DELETE"])
@guvenlik_duvari
@giris_gerekli
def kampanya_sil(kampanya_id):
    conn = get_db()
    conn.execute("DELETE FROM campaigns WHERE id=?", (kampanya_id,))
    conn.execute("DELETE FROM tracking WHERE campaign_id=?", (kampanya_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})
 
 
@app.route("/api/guvenlik-olaylari")
@guvenlik_duvari
@giris_gerekli
def guvenlik_olaylari():
    conn = get_db()
    satirlar = conn.execute(
        "SELECT * FROM guvenlik_olaylari ORDER BY zaman DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return jsonify([dict(s) for s in satirlar])
 
 
# -----------------------------------------------------------------
# ADMIN PANEL
# -----------------------------------------------------------------
 
@app.route("/admin")
@giris_gerekli
def admin_panel():
    return render_template_string(open(os.path.join(BASE_DIR, "admin.html"), encoding="utf-8").read())
 
 
# -----------------------------------------------------------------
# AUTH KONTROL
# -----------------------------------------------------------------
 
@app.route("/api/auth-check")
def auth_check():
    if session.get("admin_giris"):
        return jsonify({"authenticated": True})
    return jsonify({"authenticated": False, "redirect": "/giris"}), 401
 
 
if __name__ == "__main__":
    env = os.environ.get("FLASK_ENV", "development")
    print(f"PhishingSim basladi (env={env}): http://localhost:5000")
    print("Admin: http://localhost:5000/giris")
    if not (SMTP_USER and SMTP_PASS and ADMIN_EMAIL):
        print("\n[UYARI] 2FA mail gönderimi için SMTP_USER, SMTP_PASS ve ADMIN_EMAIL "
              "ortam değişkenlerini ayarlamanız gerekiyor.\n")
    if not IS_PROD:
        print("\n[UYARI] Dev tunnel kullanıyorsan:")
        print("  Windows : set FLASK_ENV=production && python app.py")
        print("  Mac/Linux: FLASK_ENV=production python app.py\n")
    app.run(debug=(not IS_PROD), port=5000)