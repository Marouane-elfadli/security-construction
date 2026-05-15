"""
AI Construction Site Safety Monitor — v11 (SECURED)
Flask backend — with:
  - Flask-Login  (session auth)
  - SQLite DB    (users + audit log)
  - HTTPS redirect
  - Rate limiting (Flask-Limiter)
  - Upload validation (MIME + size)
  - Security headers (Flask-Talisman)
  - Accounting logs
"""

import os, base64, io, json, hashlib, secrets, logging, smtplib, random, string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Load .env if present (optional — pip install python-dotenv)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system env vars

# Google OAuth (optional — pip install flask-dance)
try:
    from flask_dance.contrib.google import make_google_blueprint, google as google_oauth
    GOOGLE_OAUTH_AVAILABLE = True
except ImportError:
    GOOGLE_OAUTH_AVAILABLE = False
from pathlib import Path
from typing import List, Dict, Tuple
from functools import wraps

import cv2
import numpy as np
from PIL import Image

from flask import (
    Flask, request, jsonify, send_from_directory,
    redirect, url_for, session, g
)
from flask_cors import CORS
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3

# ─── Only import ultralytics when models exist ──────────────────────────────
try:
    from ultralytics import YOLO
    YOLO_AVAILABLE = True
except ImportError:
    YOLO_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DB_PATH  = BASE_DIR / "safetymonitor.db"

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── HTTPS Redirect (disable in dev with ENV var) ─────────────
FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "0") == "1"

@app.before_request
def redirect_http_to_https():
    if FORCE_HTTPS and not request.is_secure and request.headers.get("X-Forwarded-Proto", "http") != "https":
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

# ── Security headers ─────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    if FORCE_HTTPS:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ── CORS — restrict to same origin only ──────────────────────
CORS(app, origins=os.environ.get("ALLOWED_ORIGINS", "http://localhost:5000").split(","))

# ── Rate Limiter ──────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://"
)

# ── Google OAuth Blueprint (registered lazily so .env is loaded first) ──
def register_google_oauth():
    if not GOOGLE_OAUTH_AVAILABLE:
        return
    gclient = os.environ.get("GOOGLE_CLIENT_ID", "")
    gsecret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    if not gclient or not gsecret:
        return
    if "google" in app.blueprints:
        return  # already registered
    google_bp = make_google_blueprint(
        client_id=gclient,
        client_secret=gsecret,
        scope=["openid",
               "https://www.googleapis.com/auth/userinfo.email",
               "https://www.googleapis.com/auth/userinfo.profile"],
        redirect_to="google_login_callback",
    )
    app.register_blueprint(google_bp, url_prefix="/login/google")

# ── Flask-Login ───────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_page"

# ── Logging (accounting) ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(BASE_DIR / "audit.log"),
        logging.StreamHandler()
    ]
)
audit_log = logging.getLogger("audit")

# ─────────────────────────────────────────────────────────────
# UPLOAD VALIDATION
# ─────────────────────────────────────────────────────────────
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/webp", "image/bmp"}
MAX_UPLOAD_BYTES   = 10 * 1024 * 1024  # 10 MB

def validate_image_upload(file):
    """Returns (pil_image, error_string). error_string is None if OK."""
    # Size check
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_UPLOAD_BYTES:
        return None, f"Image trop grande ({size // 1024 // 1024}MB > 10MB)"

    # MIME check via Pillow (not trusting Content-Type header)
    try:
        pil_img = Image.open(file.stream)
        pil_img.verify()                        # raises on corrupt files
        file.stream.seek(0)
        pil_img = Image.open(file.stream).convert("RGB")
    except Exception as e:
        return None, f"Fichier image invalide : {e}"

    return pil_img, None

# ─────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'viewer',
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login  DATETIME
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            username   TEXT,
            event      TEXT NOT NULL,
            ip         TEXT,
            details    TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS analyses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            username    TEXT,
            ip          TEXT,
            risk_score  INTEGER,
            risk_level  TEXT,
            n_persons   INTEGER,
            n_violators INTEGER,
            image_b64   TEXT,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS email_verifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token       TEXT UNIQUE NOT NULL,
            username    TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'viewer',
            email       TEXT NOT NULL,
            code        TEXT NOT NULL,
            expires_at  DATETIME NOT NULL,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

    """)
    # Create default admin if no users exist
    cursor = db.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        pw_hash = hash_password("admin123")
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", pw_hash, "admin")
        )
        print("✅ Default admin created — user: admin / pass: admin123")
        print("⚠️  Change password immediately in production!")
    # Migration: add email column if missing
    try:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT")
        db.commit()
    except Exception:
        pass  # column already exists
    # Migration: add image_b64 column if missing
    try:
        db.execute("ALTER TABLE analyses ADD COLUMN image_b64 TEXT")
        db.commit()
    except Exception:
        pass  # column already exists
    db.commit()
    db.close()

# ─────────────────────────────────────────────────────────────
# EMAIL UTILITIES
# ─────────────────────────────────────────────────────────────
def generate_verification_code(length=6):
    """Generate a random numeric verification code."""
    return "".join(random.choices(string.digits, k=length))

def send_verification_email(to_email: str, username: str, code: str) -> bool:
    """Send a verification code email. Returns True on success.
    SMTP credentials are read from env at call time so .env changes
    take effect without restarting the server."""
    # Read credentials fresh every call (supports .env reload)
    smtp_host     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port     = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user     = os.environ.get("SMTP_USER", "")
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    email_from    = os.environ.get("EMAIL_FROM", smtp_user)

    if not smtp_user or not smtp_password:
        # Dev mode: print code to console instead of sending
        print(f"[DEV] Verification code for {username} ({to_email}): {code}")
        return True
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"SafetyMonitor — Code de vérification : {code}"
        msg["From"]    = email_from
        msg["To"]      = to_email

        text_body = f"""Bonjour {username},

Votre code de vérification SafetyMonitor est :

    {code}

Ce code expire dans 15 minutes.

Si vous n'avez pas demandé ce compte, ignorez ce message.
"""
        html_body = f"""
<html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:40px;">
<div style="max-width:480px;margin:0 auto;background:#1e293b;border-radius:12px;padding:32px;">
  <h1 style="color:#F5C518;font-size:24px;margin:0 0 16px;">SafetyMonitor</h1>
  <p>Bonjour <strong>{username}</strong>,</p>
  <p>Voici votre code de vérification :</p>
  <div style="font-size:36px;font-weight:700;letter-spacing:12px;text-align:center;
              background:#0f172a;border-radius:8px;padding:20px;margin:24px 0;
              color:#F5C518;font-family:monospace;">{code}</div>
  <p style="color:#94a3b8;font-size:13px;">Ce code expire dans <strong>15 minutes</strong>.</p>
  <hr style="border-color:#334155;margin:24px 0;">
  <p style="color:#64748b;font-size:11px;">Si vous n'avez pas créé ce compte, ignorez ce message.</p>
</div>
</body></html>
"""
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_user, smtp_password)
            server.sendmail(email_from, [to_email], msg.as_string())
        return True
    except Exception as e:
        audit_log.error(f"send_verification_email error: {e}")
        return False

def hash_password(password: str) -> str:
    salt = "safetymonitor_salt_v1"  # In prod: use bcrypt or argon2
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def log_event(event: str, details: str = "", user_id=None, username=None):
    try:
        db = get_db()
        ip = request.remote_addr if request else "system"
        u_id = user_id or (current_user.id if current_user and current_user.is_authenticated else None)
        u_name = username or (current_user.username if current_user and current_user.is_authenticated else "anonymous")
        db.execute(
            "INSERT INTO audit_events (user_id, username, event, ip, details) VALUES (?,?,?,?,?)",
            (u_id, u_name, event, ip, details)
        )
        db.commit()
        audit_log.info(f"[{event}] user={u_name} ip={ip} {details}")
    except Exception as e:
        audit_log.error(f"log_event error: {e}")

# ─────────────────────────────────────────────────────────────
# USER MODEL (Flask-Login)
# ─────────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id       = id
        self.username = username
        self.role     = role

    def is_admin(self):
        return self.role == "admin"

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row:
        return User(row["id"], row["username"], row["role"])
    return None

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────────────────
# MODEL LOADING
# ─────────────────────────────────────────────────────────────
MODEL_VEW_PATH       = str(BASE_DIR / "vew.pt")
MODEL_SCAFANDRI_PATH = str(BASE_DIR / "scafandri.pt")
OUTPUT_DIR = BASE_DIR / "pipeline_outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

CONF_VEW       = 0.25
CONF_SCAFANDRI = 0.25
MAX_PERSONS    = 9

_model_vew  = None
_model_scaf = None
VEW_NAMES   = {}
SCAF_NAMES  = {}

def load_models():
    global _model_vew, _model_scaf, VEW_NAMES, SCAF_NAMES
    if not YOLO_AVAILABLE:
        raise RuntimeError("ultralytics not installed")
    if _model_vew is None:
        print("⏳ Loading models...")
        _model_vew  = YOLO(MODEL_VEW_PATH)
        _model_scaf = YOLO(MODEL_SCAFANDRI_PATH)
        VEW_NAMES   = _model_vew.names
        SCAF_NAMES  = _model_scaf.names
        print(f"✅ vew.pt — {_model_vew.model.nc} classes")
        print(f"✅ scafandri.pt — {_model_scaf.model.nc} classes")
    return _model_vew, _model_scaf

# ─────────────────────────────────────────────────────────────
# CLASS TAXONOMY (unchanged from v10)
# ─────────────────────────────────────────────────────────────
PERSON_CLASSES = {"person","worker","Worker","Person","Human","worker_with_helmet","worker_without_helmet"}
MISSING_PPE_CLASSES = {"No-Helmet","No-Vest","no helmet","no vest","no_helmet","no_vest","NoHelmet","NoVest","without_helmet","without_vest"}
WORN_PPE_CLASSES = {"helmet","Helmet","vest","Vest","safety_vest","hard_hat","HardHat","safety_helmet","worker_with_helmet"}
SCAFFOLD_HIGH_RISK = {"High_Risk_Scaffolding","High_Risk_Suspended_Scaffolding","high_risk","HighRisk"}
SCAFFOLD_MEDIUM_RISK = {"Medium_Risk_Scaffolding","medium_risk","MediumRisk","Scaffolding","scaffolding"}
SCAFFOLD_LOW_RISK = {"Low_Risk_Scaffolding","low_risk","LowRisk","Ground_Level_Scaffolding"}
ALL_SCAFFOLD_CLASSES = SCAFFOLD_HIGH_RISK | SCAFFOLD_MEDIUM_RISK | SCAFFOLD_LOW_RISK
DANGER_ZONE_CLASSES = {"Danger_Zone","danger_zone","DangerZone","warning_sign","WarningSign","warning_zone"}
BARRIER_CLASSES = {"barrier","Barrier","safety_barrier","road_barrier","caution_tape","fence","Fence"}
CONE_CLASSES = {"cone","Cone","safety_cone","traffic_cone"}
ALL_INFRA_CLASSES = DANGER_ZONE_CLASSES | BARRIER_CLASSES | CONE_CLASSES | {"hand","Hand"}
NEUTRAL_CLASSES = ALL_INFRA_CLASSES

RISK_WEIGHT = {
    "helm_miss_ground":15,"vest_miss_ground":10,"helm_miss_scaffold":25,"vest_miss_scaffold":20,
    "scaffold_low":5,"scaffold_high":20,"scaffold_suspended":35,"scaffold_worker_bonus":10,
    "crowd_bonus_per_person":5,"crowd_max":15,"scaffold_env_ppe_ok":10,
    "cap_ppe":50,"cap_scaf":35,"cap_crowd":15,"max_person_score":45,
}

# ─────────────────────────────────────────────────────────────
# UTILITY (unchanged from v10)
# ─────────────────────────────────────────────────────────────
def score_to_level(s):
    if s <= 0:  return "SAFE"
    if s <= 20: return "LOW"
    if s <= 50: return "MEDIUM"
    if s <= 80: return "HIGH"
    return "CRITICAL"

def pil_to_cv2(img):
    return cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2BGR)

def cv2_to_b64(img_bgr):
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    pil = Image.fromarray(img_rgb)
    buf = io.BytesIO()
    pil.save(buf, format="JPEG", quality=88)
    return base64.b64encode(buf.getvalue()).decode()

def results_to_list(results, names):
    out = []
    for box in results.boxes:
        cls_id = int(box.cls); conf = float(box.conf); name = names.get(cls_id, str(cls_id))
        x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())
        if name in SCAFFOLD_HIGH_RISK or name in MISSING_PPE_CLASSES: risk = "HIGH"
        elif name in SCAFFOLD_MEDIUM_RISK: risk = "MEDIUM"
        elif name in NEUTRAL_CLASSES: risk = "NEUTRAL"
        else: risk = "LOW"
        out.append({"class": name, "confidence": round(conf, 3), "risk": risk, "bbox": [x1,y1,x2,y2]})
    return out

def iou(A, B):
    xA,yA = max(A[0],B[0]),max(A[1],B[1]); xB,yB = min(A[2],B[2]),min(A[3],B[3])
    inter = max(0,xB-xA)*max(0,yB-yA)
    if inter == 0: return 0.0
    return inter/((A[2]-A[0])*(A[3]-A[1])+(B[2]-B[0])*(B[3]-B[1])-inter)

def overlap_ratio(inner, outer):
    xA,yA = max(inner[0],outer[0]),max(inner[1],outer[1]); xB,yB = min(inner[2],outer[2]),min(inner[3],outer[3])
    inter = max(0,xB-xA)*max(0,yB-yA)
    area  = max(1,(inner[2]-inner[0])*(inner[3]-inner[1]))
    return inter/area

def crop_person_b64(image_bgr, bbox, pad=0.05):
    h,w = image_bgr.shape[:2]; x1,y1,x2,y2 = bbox; bw,bh = x2-x1,y2-y1
    px,py = int(bw*pad),int(bh*pad)
    x1c,y1c = max(0,x1-px),max(0,y1-py); x2c,y2c = min(w,x2+px),min(h,y2+py)
    crop_bgr = image_bgr[y1c:y2c,x1c:x2c]
    if crop_bgr.size == 0: return ""
    pil_crop = Image.fromarray(cv2.cvtColor(crop_bgr, cv2.COLOR_BGR2RGB))
    target_h = 120; ratio = target_h/max(1,pil_crop.height)
    pil_crop = pil_crop.resize((max(60,int(pil_crop.width*ratio)),target_h), Image.LANCZOS)
    buf = io.BytesIO(); pil_crop.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def analyze_person_ppe(person_bbox, idx, all_dets, on_scaffold=False):
    helmet_worn=helmet_missing=vest_worn=vest_missing=False; reasons=[]
    for det in all_dets:
        cls,bbox = det["class"],det["bbox"]
        if overlap_ratio(bbox,person_bbox)<0.2 and iou(bbox,person_bbox)<0.1: continue
        if cls in WORN_PPE_CLASSES:
            if any(k in cls.lower() for k in ("helmet","helm","hard_hat","hardhat")): helmet_worn=True
            if "vest" in cls.lower(): vest_worn=True
        elif cls in MISSING_PPE_CLASSES:
            if any(k in cls.lower() for k in ("helmet","helm")): helmet_missing=True; reasons.append("❌ Casque absent")
            if "vest" in cls.lower(): vest_missing=True; reasons.append("❌ Gilet absent")
    person_score=0
    if helmet_missing:
        pen=RISK_WEIGHT["helm_miss_scaffold"] if on_scaffold else RISK_WEIGHT["helm_miss_ground"]; person_score+=pen; reasons.append(f"→ Casque absent: +{pen}pts")
    elif not helmet_worn:
        pen=max(4,(RISK_WEIGHT["helm_miss_scaffold"]//2) if on_scaffold else (RISK_WEIGHT["helm_miss_ground"]//2)); person_score+=pen; reasons.append(f"→ Casque inconnu: +{pen}pts")
    if vest_missing:
        pen=RISK_WEIGHT["vest_miss_scaffold"] if on_scaffold else RISK_WEIGHT["vest_miss_ground"]; person_score+=pen; reasons.append(f"→ Gilet absent: +{pen}pts")
    elif not vest_worn:
        pen=max(3,(RISK_WEIGHT["vest_miss_scaffold"]//2) if on_scaffold else (RISK_WEIGHT["vest_miss_ground"]//2)); person_score+=pen; reasons.append(f"→ Gilet inconnu: +{pen}pts")
    if helmet_missing or vest_missing: status="VIOLATION"
    elif helmet_worn and vest_worn:
        if on_scaffold: env_pen=RISK_WEIGHT.get("scaffold_env_ppe_ok",10); person_score=env_pen; reasons+=["✅ Casque OK","✅ Gilet OK",f"⚠️ Risque échafaud: +{env_pen}pts"]; status="PARTIAL"
        else: person_score=0; reasons+=["✅ Casque OK","✅ Gilet OK"]; status="SAFE"
    elif helmet_worn or vest_worn: status="PARTIAL"; (reasons.append("✅ Casque OK") if helmet_worn else None); (reasons.append("✅ Gilet OK") if vest_worn else None)
    else: status="UNKNOWN"; reasons.append("⚠️ PPE non évalué")
    return {"index":idx,"helmet_status":helmet_worn,"vest_status":vest_worn,"helmet_missing":helmet_missing,"vest_missing":vest_missing,"on_scaffold":on_scaffold,"status":status,"score":min(45,person_score),"reasons":reasons,"bbox":person_bbox,"crop_b64":""}

def compute_scaffolding_risk(scaf_dets, all_person_boxes):
    raw_score=0; reasons=[]
    for det in scaf_dets:
        cls,bbox=det["class"],det["bbox"]
        has_worker=any(overlap_ratio(pb,bbox)>0.3 or iou(pb,bbox)>0.1 for pb in all_person_boxes)
        bonus=RISK_WEIGHT["scaffold_worker_bonus"] if has_worker else 0
        wt=" (travailleur détecté)" if has_worker else ""
        if cls in SCAFFOLD_HIGH_RISK:
            if "suspended" in cls.lower(): pts=RISK_WEIGHT["scaffold_suspended"]+bonus; reasons.append(f"🔴 Échafaud suspendu{wt} +{pts}pts")
            else: pts=RISK_WEIGHT["scaffold_high"]+bonus; reasons.append(f"🟠 Échafaud haute risque{wt} +{pts}pts")
            raw_score+=pts
        elif cls in SCAFFOLD_MEDIUM_RISK: pts=RISK_WEIGHT["scaffold_high"]; raw_score+=pts; reasons.append(f"🟡 Échafaud moyen ({cls}) +{pts}pts")
        elif cls in SCAFFOLD_LOW_RISK: pts=RISK_WEIGHT["scaffold_low"]; raw_score+=pts; reasons.append(f"🟢 Échafaud bas risque ({cls}) +{pts}pts")
    return min(RISK_WEIGHT["cap_scaf"], raw_score), reasons

def compute_global_risk(vew_dets, scaf_dets, image_bgr):
    all_dets=vew_dets+scaf_dets
    infra_dets=[d for d in vew_dets if d["class"] in ALL_INFRA_CLASSES]
    scaf_raw=scaf_dets+[d for d in vew_dets if d["class"] in ALL_SCAFFOLD_CLASSES]
    seen=set(); merged_scaf=[]
    for d in scaf_raw:
        k=tuple(d["bbox"])
        if k not in seen: seen.add(k); merged_scaf.append(d)
    persons_raw=[d for d in all_dets if d["class"] in PERSON_CLASSES]
    seen=set(); persons=[]
    for p in persons_raw:
        k=tuple(p["bbox"])
        if k not in seen: seen.add(k); persons.append(p)
    all_person_boxes=[p["bbox"] for p in persons]; n=len(persons)
    scaf_score,scaf_reasons=compute_scaffolding_risk(merged_scaf,all_person_boxes)
    person_results=[]; max_pp=RISK_WEIGHT["max_person_score"]
    for idx,p in enumerate(persons):
        on_scaf=any(overlap_ratio(p["bbox"],det["bbox"])>0.3 or iou(p["bbox"],det["bbox"])>0.1 for det in merged_scaf if det["class"] in (SCAFFOLD_HIGH_RISK|SCAFFOLD_MEDIUM_RISK))
        res=analyze_person_ppe(p["bbox"],idx+1,all_dets,on_scaffold=on_scaf)
        res["bbox"]=p["bbox"]; res["score_pct"]=min(100,round(res["score"]*100/max_pp)); res["crop_b64"]=crop_person_b64(image_bgr,p["bbox"]); person_results.append(res)
    if n>0:
        mean_pp=sum(pr["score"] for pr in person_results)/n; ppe_risk=min(RISK_WEIGHT["cap_ppe"],round(mean_pp*(50/45)))
        missing_helm=sum(1 for pr in person_results if pr["helmet_missing"]); missing_vest=sum(1 for pr in person_results if pr["vest_missing"]); total_missing=missing_helm+missing_vest
        score_ppe=round(100*(1-total_missing/(2*n)),2) if n else 100.0
    else: ppe_risk=missing_helm=missing_vest=total_missing=0; score_ppe=100.0
    n_violators=sum(1 for pr in person_results if pr["status"]=="VIOLATION")
    crowd_raw=max(0,n_violators-1)*RISK_WEIGHT["crowd_bonus_per_person"]; crowd_bonus=min(RISK_WEIGHT["cap_crowd"],crowd_raw)
    crowd_reason=f"👥 {n_violators} violations simultanées → +{crowd_bonus}pts" if crowd_bonus>0 else None
    total_score=min(100,int(ppe_risk+scaf_score+crowd_bonus)); level=score_to_level(total_score)
    return {"score":total_score,"level":level,"ppe_risk":ppe_risk,"scaf_score":scaf_score,"crowd_bonus":crowd_bonus,"scaf_reasons":scaf_reasons,"crowd_reason":crowd_reason,"person_results":person_results,"n_persons":n,"n_violators":n_violators,"missing_helm":missing_helm,"missing_vest":missing_vest,"merged_scaf":merged_scaf,"score_ppe":score_ppe,"infra_dets":infra_dets,"n_infra":len(infra_dets)}

COLOR_DANGER=(0,0,255); COLOR_SAFE=(0,220,0); COLOR_WARN=(0,165,255); COLOR_NEUTRAL=(160,160,160)

def draw_annotated(image_bgr, risk):
    img=image_bgr.copy(); h,w=img.shape[:2]
    for det in risk.get("infra_dets",[]):
        x1,y1,x2,y2=det["bbox"]; cls=det["class"]
        color=(0,50,220) if cls in DANGER_ZONE_CLASSES else (255,180,0) if cls in BARRIER_CLASSES else (0,220,220)
        cv2.rectangle(img,(x1,y1),(x2,y2),color,1); cv2.putText(img,f"{cls} {det['confidence']:.0%}",(x1+2,y1-4),cv2.FONT_HERSHEY_SIMPLEX,0.38,color,1,cv2.LINE_AA)
    for det in risk["merged_scaf"]:
        x1,y1,x2,y2=det["bbox"]; color=COLOR_DANGER if det["class"] in SCAFFOLD_HIGH_RISK else COLOR_WARN if det["class"] in SCAFFOLD_MEDIUM_RISK else COLOR_NEUTRAL
        cv2.rectangle(img,(x1,y1),(x2,y2),color,2); cv2.putText(img,f"SCAF:{det['class']} {det['confidence']:.0%}",(x1+2,y1-4),cv2.FONT_HERSHEY_SIMPLEX,0.45,color,1,cv2.LINE_AA)
    for pr in risk["person_results"]:
        x1,y1,x2,y2=pr["bbox"]; color={"SAFE":COLOR_SAFE,"VIOLATION":COLOR_DANGER,"PARTIAL":COLOR_WARN}.get(pr["status"],(180,100,0))
        cv2.rectangle(img,(x1,y1),(x2,y2),color,3)
        cl=max(10,(x2-x1)//6)
        for (px,py) in [(x1,y1),(x2,y1),(x1,y2),(x2,y2)]:
            dx=cl if px==x1 else -cl; dy=cl if py==y1 else -cl
            cv2.line(img,(px,py),(px+dx,py),color,5); cv2.line(img,(px,py),(px,py+dy),color,5)
        id_text=f" P{pr['index']} "; (tw,th),_=cv2.getTextSize(id_text,cv2.FONT_HERSHEY_SIMPLEX,0.5,1)
        cv2.rectangle(img,(x1,max(0,y1-th-6)),(x1+tw+4,y1),color,-1); cv2.putText(img,id_text,(x1+2,y1-3),cv2.FONT_HERSHEY_SIMPLEX,0.5,(255,255,255),1,cv2.LINE_AA)
        h_icon="H:OK" if pr["helmet_status"] else ("H:XX" if pr["helmet_missing"] else "H: ?")
        v_icon="V:OK" if pr["vest_status"] else ("V:XX" if pr["vest_missing"] else "V: ?")
        badge=f" {h_icon}  {v_icon}  Risk:{pr['score_pct']}% "; (bw,bh2),_=cv2.getTextSize(badge,cv2.FONT_HERSHEY_SIMPLEX,0.44,1)
        by1=min(y2+2,h-bh2-8); overlay=img.copy()
        cv2.rectangle(overlay,(x1,by1),(min(x1+bw+6,w-2),by1+bh2+6),color,-1); cv2.addWeighted(overlay,0.8,img,0.2,0,img)
        cv2.putText(img,badge,(x1+3,by1+bh2+2),cv2.FONT_HERSHEY_SIMPLEX,0.44,(255,255,255),1,cv2.LINE_AA)
    banner_color={"SAFE":(20,160,20),"LOW":(20,180,20),"MEDIUM":(0,150,200),"HIGH":(0,120,230),"CRITICAL":(0,30,200)}.get(risk["level"],(100,100,100))
    overlay=img.copy(); cv2.rectangle(overlay,(0,0),(w,40),banner_color,-1); cv2.addWeighted(overlay,0.85,img,0.15,0,img)
    banner_txt=f"  RISK: {risk['level']}  |  Score: {risk['score']}/100  |  Personnes: {risk['n_persons']}  |  Violations: {risk['n_violators']}  |  PPE: +{risk['ppe_risk']}  Scaffold: +{risk['scaf_score']}  Crowd: +{risk['crowd_bonus']}"
    cv2.putText(img,banner_txt,(6,27),cv2.FONT_HERSHEY_SIMPLEX,0.50,(255,255,255),1,cv2.LINE_AA)
    return img

# ─────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET"])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return send_from_directory("static", "login.html")

@app.route("/register", methods=["GET"])
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return send_from_directory("static", "register.html")

# ── Google OAuth routes ────────────────────────────────────────
@app.route("/auth/google")
def google_auth_start():
    """Start Google OAuth flow. Registers the blueprint on first call."""
    register_google_oauth()
    if "google" not in app.blueprints:
        return jsonify({"error": "Google OAuth non configuré — ajoutez GOOGLE_CLIENT_ID et GOOGLE_CLIENT_SECRET dans .env"}), 503
    from flask_dance.contrib.google import google as google_oauth_local
    if not google_oauth_local.authorized:
        from flask import redirect as _redirect
        return _redirect("/login/google/google")
    return _redirect(url_for("google_login_callback"))

@app.route("/auth/google/callback")
def google_login_callback():
    """Handle Google OAuth callback — create/login user automatically."""
    register_google_oauth()
    if "google" not in app.blueprints:
        return redirect(url_for("login_page"))
    from flask_dance.contrib.google import google as google_oauth_local
    if not google_oauth_local.authorized:
        return redirect(url_for("login_page"))
    resp = google_oauth_local.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return redirect(url_for("login_page"))
    info     = resp.json()
    g_email  = info.get("email", "").lower()
    g_name   = info.get("name", "")
    g_id     = info.get("id", "")
    if not g_email:
        return redirect(url_for("login_page"))

    # Use first part of email as username base
    base_username = g_email.split("@")[0].replace(".", "_")[:20]

    db = get_db()
    # Check if user already exists (by email)
    user_row = db.execute("SELECT * FROM users WHERE email = ?", (g_email,)).fetchone()
    if user_row:
        # Login existing user
        user = User(user_row["id"], user_row["username"], user_row["role"])
        login_user(user)
        db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_row["id"],))
        db.commit()
        log_event("LOGIN_GOOGLE", f"email={g_email}")
        return redirect(url_for("index"))

    # Create new user from Google account
    username = base_username
    # Ensure username is unique
    counter = 1
    while db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
        username = f"{base_username}{counter}"
        counter += 1

    # Generate a random secure password (user can reset later)
    random_pw = secrets.token_urlsafe(24)
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?,?,?,?)",
            (username, hash_password(random_pw), "viewer", g_email)
        )
        db.commit()
    except sqlite3.IntegrityError:
        pass

    user_row = db.execute("SELECT * FROM users WHERE email = ?", (g_email,)).fetchone()
    if user_row:
        user = User(user_row["id"], user_row["username"], user_row["role"])
        login_user(user)
        db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_row["id"],))
        db.commit()
        log_event("REGISTER_GOOGLE", f"email={g_email} username={username}")

    return redirect(url_for("index"))

@app.route("/api/google-oauth-status")
def google_oauth_status():
    """Tell the frontend if Google OAuth is configured."""
    register_google_oauth()
    enabled = (
        GOOGLE_OAUTH_AVAILABLE and
        bool(os.environ.get("GOOGLE_CLIENT_ID")) and
        bool(os.environ.get("GOOGLE_CLIENT_SECRET"))
    )
    return jsonify({"enabled": enabled})

@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Identifiants requis"}), 400

    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not row or row["password_hash"] != hash_password(password):
        log_event("LOGIN_FAILED", f"username={username}")
        return jsonify({"error": "Identifiants incorrects"}), 401

    user = User(row["id"], row["username"], row["role"])
    login_user(user, remember=data.get("remember", False))
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.utcnow(), row["id"]))
    db.commit()
    log_event("LOGIN_SUCCESS", f"username={username}")

    return jsonify({"ok": True, "username": username, "role": row["role"], "redirect": "/"})

@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per minute")
def api_register():
    """Step 1: validate data, store pending registration, send verification email."""
    data       = request.get_json(silent=True) or {}
    username   = data.get("username", "").strip()
    password   = data.get("password", "")
    role       = data.get("role", "viewer")
    email      = data.get("email", "").strip().lower()
    admin_code = data.get("admin_code", "")

    # Basic validation
    if not username or not password or not email:
        return jsonify({"error": "Tous les champs sont requis"}), 400
    if len(username) < 3:
        return jsonify({"error": "Identifiant trop court (min. 3 caractères)"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mot de passe trop court (min. 6 caractères)"}), 400
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Adresse email invalide"}), 400
    if role not in ("admin", "viewer"):
        return jsonify({"error": "Rôle invalide"}), 400

    # Admin role requires secret code
    ADMIN_REGISTRATION_CODE = os.environ.get("ADMIN_REG_CODE", "SAFETYMONITOR_ADMIN_2024")
    if role == "admin" and admin_code != ADMIN_REGISTRATION_CODE:
        log_event("REGISTER_FAILED_ADMIN_CODE", f"username={username}")
        return jsonify({"error": "Code administrateur incorrect"}), 403

    db = get_db()
    # Check username not already taken
    if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
        return jsonify({"error": "Cet identifiant est déjà utilisé"}), 409

    # Clean up old expired verifications for this username/email
    db.execute(
        "DELETE FROM email_verifications WHERE username = ? OR email = ?",
        (username, email)
    )

    # Create verification token + code
    token      = secrets.token_urlsafe(32)
    code       = generate_verification_code(6)
    expires_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    # Use Python datetime arithmetic (add 15 min)
    from datetime import timedelta
    expires_dt = datetime.utcnow() + timedelta(minutes=15)
    expires_at = expires_dt.strftime("%Y-%m-%d %H:%M:%S")

    db.execute(
        "INSERT INTO email_verifications (token, username, password_hash, role, email, code, expires_at) VALUES (?,?,?,?,?,?,?)",
        (token, username, hash_password(password), role, email, code, expires_at)
    )
    db.commit()

    # Send verification email
    ok = send_verification_email(email, username, code)
    if not ok:
        return jsonify({"error": "Impossible d'envoyer l'email de vérification"}), 500

    log_event("REGISTER_PENDING", f"username={username} email={email}")
    return jsonify({"ok": True, "token": token, "message": f"Code envoyé à {email}"}), 200


@app.route("/api/verify-email", methods=["POST"])
@limiter.limit("10 per minute")
def api_verify_email():
    """Step 2: verify the code and create the user account."""
    data  = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    code  = data.get("code", "").strip()

    if not token or not code:
        return jsonify({"error": "Token et code requis"}), 400

    db  = get_db()
    row = db.execute(
        "SELECT * FROM email_verifications WHERE token = ?", (token,)
    ).fetchone()

    if not row:
        return jsonify({"error": "Session invalide ou expirée"}), 400

    # Check expiry
    from datetime import datetime as dt
    expires_at = dt.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if dt.utcnow() > expires_at:
        db.execute("DELETE FROM email_verifications WHERE token = ?", (token,))
        db.commit()
        return jsonify({"error": "Le code a expiré — recommencez l'inscription"}), 400

    if row["code"] != code:
        return jsonify({"error": "Code incorrect"}), 400

    # Create the user
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?,?,?,?)",
            (row["username"], row["password_hash"], row["role"], row["email"])
        )
        db.execute("DELETE FROM email_verifications WHERE token = ?", (token,))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Cet identifiant est déjà utilisé"}), 409

    log_event("REGISTER_SUCCESS", f"username={row['username']} role={row['role']}")
    return jsonify({"ok": True, "username": row["username"], "role": row["role"]}), 201


@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    log_event("LOGOUT")
    logout_user()
    return jsonify({"ok": True, "redirect": "/login"})

@app.route("/api/me")
@login_required
def api_me():
    return jsonify({"username": current_user.username, "role": current_user.role})

# ─────────────────────────────────────────────────────────────
# STATIC ROUTES — protected
# ─────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    return send_from_directory("static", "index.html")

@app.route("/monitor")
@login_required
def monitor():
    return send_from_directory("static", "monitor.html")

# Block direct access to model files
@app.route("/<path:filename>.pt")
def block_model_files(filename):
    return jsonify({"error": "Forbidden"}), 403

# ─────────────────────────────────────────────────────────────
# MAIN API — protected + rate-limited
# ─────────────────────────────────────────────────────────────
@app.route("/api/analyze", methods=["POST"])
@login_required
@limiter.limit("20 per minute; 100 per hour")
def analyze():
    if "image" not in request.files:
        return jsonify({"error": "No image provided"}), 400

    file = request.files["image"]
    conf_vew  = float(request.form.get("conf_vew",  CONF_VEW))
    conf_scaf = float(request.form.get("conf_scaf", CONF_SCAFANDRI))

    pil_img, err = validate_image_upload(file)
    if err:
        log_event("ANALYZE_REJECTED", f"reason={err}")
        return jsonify({"error": err}), 400

    try:
        model_vew, model_scaf = load_models()
    except Exception as e:
        return jsonify({"error": f"Model loading failed: {e}"}), 500

    image_bgr = pil_to_cv2(pil_img)
    res_vew   = model_vew.predict(source=image_bgr, conf=conf_vew, verbose=False)[0]
    res_scaf  = model_scaf.predict(source=image_bgr, conf=conf_scaf, verbose=False)[0]
    vew_dets  = results_to_list(res_vew, VEW_NAMES)
    scaf_dets = results_to_list(res_scaf, SCAF_NAMES)

    risk = compute_global_risk(vew_dets, scaf_dets, image_bgr)
    annotated_bgr = draw_annotated(image_bgr, risk)
    annotated_b64 = cv2_to_b64(annotated_bgr)

    # Save to DB (with annotated image)
    db = get_db()
    db.execute(
        "INSERT INTO analyses (user_id, username, ip, risk_score, risk_level, n_persons, n_violators, image_b64) VALUES (?,?,?,?,?,?,?,?)",
        (current_user.id, current_user.username, request.remote_addr,
         risk["score"], risk["level"], risk["n_persons"], risk["n_violators"], annotated_b64)
    )
    db.commit()
    log_event("ANALYZE_OK", f"score={risk['score']} level={risk['level']} persons={risk['n_persons']}")

    n_viol = risk["n_violators"]
    crowd_share = round(risk["crowd_bonus"] / max(1, n_viol)) if n_viol > 0 else 0
    persons_out = []
    for pr in risk["person_results"]:
        persons_out.append({
            "index": pr["index"], "status": pr["status"], "score": pr["score"], "score_pct": pr["score_pct"],
            "helmet_status": pr["helmet_status"], "helmet_missing": pr["helmet_missing"],
            "vest_status": pr["vest_status"], "vest_missing": pr["vest_missing"],
            "on_scaffold": pr["on_scaffold"], "reasons": pr["reasons"], "crop_b64": pr["crop_b64"],
            "crowd_share": crowd_share if pr["status"] == "VIOLATION" else 0,
        })
    infra_out = []
    for det in risk["infra_dets"]:
        cls = det["class"]
        cat = "danger" if cls in DANGER_ZONE_CLASSES else "barrier" if cls in BARRIER_CLASSES else "cone"
        infra_out.append({"class": cls, "confidence": det["confidence"], "category": cat, "bbox": det["bbox"]})

    return jsonify({
        "annotated_b64": annotated_b64, "score": risk["score"], "level": risk["level"],
        "ppe_risk": risk["ppe_risk"], "scaf_score": risk["scaf_score"], "crowd_bonus": risk["crowd_bonus"],
        "n_persons": risk["n_persons"], "n_violators": risk["n_violators"],
        "missing_helm": risk["missing_helm"], "missing_vest": risk["missing_vest"], "score_ppe": risk["score_ppe"],
        "scaf_reasons": risk["scaf_reasons"], "crowd_reason": risk["crowd_reason"],
        "n_infra": risk["n_infra"], "infra_dets": infra_out, "persons": persons_out,
    })

# ─────────────────────────────────────────────────────────────
# ADMIN ROUTES
# ─────────────────────────────────────────────────────────────
@app.route("/api/admin/users")
@login_required
@admin_required
def admin_users():
    db = get_db()
    rows = db.execute("SELECT id, username, role, created_at, last_login FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/users", methods=["POST"])
@login_required
@admin_required
def admin_create_user():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "viewer")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in ("admin", "viewer"):
        return jsonify({"error": "role must be admin or viewer"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                   (username, hash_password(password), role))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    log_event("USER_CREATED", f"new_user={username} role={role}")
    return jsonify({"ok": True}), 201

@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@login_required
@admin_required
def admin_delete_user(uid):
    if uid == current_user.id:
        return jsonify({"error": "Cannot delete yourself"}), 400
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    log_event("USER_DELETED", f"deleted_id={uid}")
    return jsonify({"ok": True})

@app.route("/api/admin/logs")
@login_required
@admin_required
def admin_logs():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/analyses")
@login_required
@admin_required
def admin_analyses():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM analyses ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/status")
def status():
    models_ok = os.path.exists(MODEL_VEW_PATH) and os.path.exists(MODEL_SCAFANDRI_PATH)
    return jsonify({"status": "ok", "models": {"vew": os.path.exists(MODEL_VEW_PATH), "scafandri": os.path.exists(MODEL_SCAFANDRI_PATH)}, "ready": models_ok})

@app.route("/api/history")
@login_required
def api_history():
    """Return the last 50 analyses for the current user, with image."""
    db = get_db()
    rows = db.execute(
        "SELECT id, risk_score, risk_level, n_persons, n_violators, image_b64, created_at "
        "FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
        (current_user.id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/history/<int:analysis_id>", methods=["DELETE"])
@login_required
def delete_history_item(analysis_id):
    """Delete one history entry (only if owned by current user)."""
    db = get_db()
    db.execute(
        "DELETE FROM analyses WHERE id = ? AND user_id = ?",
        (analysis_id, current_user.id)
    )
    db.commit()
    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()

    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 5000))

    # ── TLS / SSL context ────────────────────────────────────
    SSL_MODE = os.environ.get("SSL_MODE", "").strip()
    SSL_CERT = os.environ.get("SSL_CERT", "").strip()
    SSL_KEY  = os.environ.get("SSL_KEY",  "").strip()

    if SSL_MODE == "adhoc":
        ssl_context = "adhoc"          # pyopenssl auto-signed cert
        ssl_label   = "HTTPS adhoc (auto-signé)"
    elif SSL_CERT and SSL_KEY:
        ssl_context = (SSL_CERT, SSL_KEY)
        ssl_label   = f"HTTPS Let's Encrypt ({SSL_CERT})"
    else:
        ssl_context = None
        ssl_label   = "HTTP local (pas de TLS)"

    print("━" * 55)
    print("🏗️   AI Safety Monitor — Secured Web Server")
    print("━" * 55)
    print(f"   vew.pt       : {'✅' if os.path.exists(MODEL_VEW_PATH) else '❌ MISSING'}")
    print(f"   scafandri.pt : {'✅' if os.path.exists(MODEL_SCAFANDRI_PATH) else '❌ MISSING'}")
    print(f"   Database     : {DB_PATH}")
    print(f"   FORCE_HTTPS  : {'✅ ON' if FORCE_HTTPS else '⚠️  OFF'}")
    print(f"   TLS/SSL      : {ssl_label}")
    proto = "https" if ssl_context else "http"
    print(f"   → {proto}://{host}:{port}/login")
    print("━" * 55)

    app.run(host=host, port=port, debug=False, ssl_context=ssl_context)
