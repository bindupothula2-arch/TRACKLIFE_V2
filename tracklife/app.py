"""TrackLife - symptom tracker, medical history & medication reminders.
Flask + SQLite (free, file based, never expires). See README.md.
"""
import hashlib, hmac, json, os, re, secrets, sqlite3
from datetime import datetime
from functools import wraps

from cryptography.fernet import Fernet
import base64, io
from flask import Flask, Response, g, jsonify, request, session, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", os.path.join(BASE, "instance"))
os.makedirs(DATA, exist_ok=True)
DB_PATH = os.path.join(DATA, "tracklife.db")


DATABASE_URL = os.environ.get("DATABASE_URL")
PG = bool(DATABASE_URL)


def _load_secret(name, env, maker):
    val = os.environ.get(env)
    if val:
        return val.encode()
    if PG:  # hosted disks are temporary: keys must live in env vars or data becomes unreadable
        raise RuntimeError(f"Set the {env} environment variable (see .env.example).")
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(maker())
    return open(path, "rb").read()


FERNET = Fernet(_load_secret("fernet.key", "FERNET_KEY", Fernet.generate_key))
PSEUDO_KEY = _load_secret("pseudo.key", "PSEUDO_KEY", lambda: secrets.token_hex(32).encode())

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = _load_secret("session.key", "SECRET_KEY", lambda: secrets.token_hex(32).encode())
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=6 * 1024 * 1024)  # 5 MB files + form overhead


# ---------------------------------------------------------------- database
# Postgres when DATABASE_URL is set (Neon / Supabase / Render), SQLite otherwise (local use).
if PG:
    import psycopg2, psycopg2.extras
    INTEGRITY_ERRORS = (psycopg2.IntegrityError,)
else:
    INTEGRITY_ERRORS = (sqlite3.IntegrityError,)


class Conn:
    def __init__(self):
        if PG:
            self.c = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            self.c = sqlite3.connect(DB_PATH)
            self.c.row_factory = sqlite3.Row

    def execute(self, sql, params=()):
        cur = self.c.cursor()
        cur.execute(sql.replace("?", "%s") if PG else sql, params)
        return cur

    def commit(self):
        self.c.commit()

    def rollback(self):
        self.c.rollback()

    def close(self):
        self.c.close()


def db():
    if "db" not in g:
        g.db = Conn()
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users(
      id {pk}, role TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      pw_hash TEXT NOT NULL, enc_profile TEXT NOT NULL, specialty TEXT, created TEXT)""",
    """CREATE TABLE IF NOT EXISTS records(
      id {pk}, user_id INTEGER NOT NULL, kind TEXT NOT NULL, enc_data TEXT NOT NULL, created TEXT)""",
    """CREATE TABLE IF NOT EXISTS meds(
      id {pk}, user_id INTEGER NOT NULL, enc_data TEXT NOT NULL, created TEXT)""",
    """CREATE TABLE IF NOT EXISTS reports(
      id {pk}, user_id INTEGER NOT NULL, enc_meta TEXT NOT NULL, enc_blob TEXT NOT NULL, created TEXT)""",
    """CREATE TABLE IF NOT EXISTS access(
      patient_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL, PRIMARY KEY(patient_id, doctor_id))""",
]


def init_db():
    c = Conn()
    for stmt in SCHEMA:
        c.execute(stmt.format(pk="SERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY"))
    c.commit()
    c.close()


init_db()


# ------------------------------------------------------------- encryption
def enc(obj):
    return FERNET.encrypt(json.dumps(obj, ensure_ascii=False).encode()).decode()


def dec(token):
    return json.loads(FERNET.decrypt(token.encode()).decode())


def pseudonym(user_id):
    """Stable anonymous ID - the AI never sees name/email/phone, only this."""
    return "P-" + hmac.new(PSEUDO_KEY, str(user_id).encode(), hashlib.sha256).hexdigest()[:10]


def scrub(text):
    """Remove obvious identifiers (emails, phone numbers, long digit strings) from free text."""
    text = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "[email]", text)
    text = re.sub(r"\+?\d[\d\s-]{7,}\d", "[number]", text)
    return text


# ------------------------------------------------------------------- auth
def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            uid = session.get("uid")
            if not uid:
                return jsonify(error="Please log in."), 401
            u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if not u:
                session.clear()
                return jsonify(error="Please log in."), 401
            if role and u["role"] != role:
                return jsonify(error="Not allowed for your account type."), 403
            g.user = u
            return fn(*a, **kw)
        return wrap
    return deco


def user_json(u):
    p = dec(u["enc_profile"])
    return dict(id=u["id"], role=u["role"], email=u["email"], name=p.get("name"),
                age=p.get("age"), phone=p.get("phone"), specialty=u["specialty"])


@app.post("/api/register")
def register():
    d = request.get_json(force=True)
    role = d.get("role", "patient")
    email = (d.get("email") or "").strip().lower()
    pw = d.get("password") or ""
    name = (d.get("name") or "").strip()
    if role not in ("patient", "doctor") or not name or "@" not in email:
        return jsonify(error="Name, valid email and role are required."), 400
    if len(pw) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    profile = dict(name=name, age=d.get("age"), phone=d.get("phone"))
    try:
        cur = db().execute(
            "INSERT INTO users(role,email,pw_hash,enc_profile,specialty,created) VALUES(?,?,?,?,?,?) RETURNING id",
            (role, email, generate_password_hash(pw), enc(profile),
             d.get("specialty") if role == "doctor" else None, datetime.utcnow().isoformat()))
        new_id = cur.fetchone()["id"]  # read before commit (SQLite requirement)
        db().commit()
    except INTEGRITY_ERRORS:
        db().rollback()
        return jsonify(error="This email is already registered."), 409
    session["uid"] = new_id
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    u = db().execute("SELECT * FROM users WHERE email=?", ((d.get("email") or "").strip().lower(),)).fetchone()
    if not u or not check_password_hash(u["pw_hash"], d.get("password") or ""):
        return jsonify(error="Wrong email or password."), 401
    session["uid"] = u["id"]
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
@login_required()
def me():
    return jsonify(user_json(g.user))


# --------------------------------------------------------------- records
@app.route("/api/records", methods=["GET", "POST"])
@login_required("patient")
def records():
    if request.method == "POST":
        d = request.get_json(force=True)
        kind = d.get("kind")
        if kind not in ("symptom", "condition"):
            return jsonify(error="Invalid record type."), 400
        data = dict(title=(d.get("title") or "").strip(), notes=(d.get("notes") or "").strip(),
                    severity=d.get("severity"), date=d.get("date") or datetime.utcnow().date().isoformat())
        if not data["title"]:
            return jsonify(error="Please enter a title."), 400
        db().execute("INSERT INTO records(user_id,kind,enc_data,created) VALUES(?,?,?,?)",
                     (g.user["id"], kind, enc(data), datetime.utcnow().isoformat()))
        db().commit()
        return jsonify(ok=True)
    return jsonify(load_records(g.user["id"]))


def load_records(uid):
    rows = db().execute("SELECT * FROM records WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    return [dict(id=r["id"], kind=r["kind"], **dec(r["enc_data"])) for r in rows]


@app.delete("/api/records/<int:rid>")
@login_required("patient")
def del_record(rid):
    db().execute("DELETE FROM records WHERE id=? AND user_id=?", (rid, g.user["id"]))
    db().commit()
    return jsonify(ok=True)


# ----------------------------------------------------------------- meds
def load_meds(uid):
    rows = db().execute("SELECT * FROM meds WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    return [dict(id=r["id"], **dec(r["enc_data"])) for r in rows]


@app.route("/api/meds", methods=["GET", "POST"])
@login_required("patient")
def meds():
    if request.method == "POST":
        d = request.get_json(force=True)
        times = [t for t in (d.get("times") or []) if re.fullmatch(r"\d{2}:\d{2}", t)]
        if not (d.get("name") or "").strip() or not times:
            return jsonify(error="Medicine name and at least one time are required."), 400
        data = dict(name=d["name"].strip(), dose=(d.get("dose") or "").strip(), times=times,
                    prescribed_by=(d.get("prescribed_by") or "").strip())
        db().execute("INSERT INTO meds(user_id,enc_data,created) VALUES(?,?,?)",
                     (g.user["id"], enc(data), datetime.utcnow().isoformat()))
        db().commit()
        return jsonify(ok=True)
    return jsonify(load_meds(g.user["id"]))


@app.delete("/api/meds/<int:mid>")
@login_required("patient")
def del_med(mid):
    db().execute("DELETE FROM meds WHERE id=? AND user_id=?", (mid, g.user["id"]))
    db().commit()
    return jsonify(ok=True)


# ---------------------------------------------------- patient <-> doctor
@app.post("/api/grant")
@login_required("patient")
def grant():
    email = (request.get_json(force=True).get("doctor_email") or "").strip().lower()
    doc = db().execute("SELECT id FROM users WHERE email=? AND role='doctor'", (email,)).fetchone()
    if not doc:
        return jsonify(error="No doctor account found with that email."), 404
    db().execute("INSERT INTO access VALUES(?,?) ON CONFLICT DO NOTHING", (g.user["id"], doc["id"]))
    db().commit()
    return jsonify(ok=True)


@app.get("/api/doctors")
@login_required("patient")
def my_doctors():
    rows = db().execute("""SELECT u.id,u.email,u.enc_profile,u.specialty FROM access a
        JOIN users u ON u.id=a.doctor_id WHERE a.patient_id=?""", (g.user["id"],)).fetchall()
    return jsonify([dict(id=r["id"], email=r["email"], name=dec(r["enc_profile"])["name"],
                         specialty=r["specialty"]) for r in rows])


@app.post("/api/revoke/<int:did>")
@login_required("patient")
def revoke(did):
    db().execute("DELETE FROM access WHERE patient_id=? AND doctor_id=?", (g.user["id"], did))
    db().commit()
    return jsonify(ok=True)


@app.get("/api/patients")
@login_required("doctor")
def patients():
    rows = db().execute("""SELECT u.id,u.email,u.enc_profile FROM access a
        JOIN users u ON u.id=a.patient_id WHERE a.doctor_id=?""", (g.user["id"],)).fetchall()
    return jsonify([dict(id=r["id"], email=r["email"], name=dec(r["enc_profile"])["name"],
                         age=dec(r["enc_profile"]).get("age")) for r in rows])


@app.get("/api/patients/<int:pid>")
@login_required("doctor")
def patient_detail(pid):
    ok = db().execute("SELECT 1 FROM access WHERE patient_id=? AND doctor_id=?", (pid, g.user["id"])).fetchone()
    if not ok:
        return jsonify(error="This patient has not shared records with you."), 403
    u = db().execute("SELECT * FROM users WHERE id=?", (pid,)).fetchone()
    return jsonify(patient=user_json(u), records=load_records(pid), meds=load_meds(pid), reports=load_reports(pid))


# --------------------------------------------------------------- reports
CATEGORIES = ("lab", "imaging", "prescription", "discharge", "other")
MAX_FILE = 5 * 1024 * 1024
# extension -> (mime, magic-byte prefixes)
FILE_TYPES = {
    "pdf": ("application/pdf", (b"%PDF",)),
    "png": ("image/png", (b"\x89PNG",)),
    "jpg": ("image/jpeg", (b"\xff\xd8\xff",)),
    "jpeg": ("image/jpeg", (b"\xff\xd8\xff",)),
    "txt": ("text/plain", ()),
}
CAT_WORDS = [
    ("lab", r"hemoglobin|haemoglobin|wbc|rbc|platelet|glucose|cholesterol|creatinine|hba1c|lab|blood test|serum"),
    ("imaging", r"x-?ray|mri|ct scan|ultrasound|sonograph|radiolog|ecg|echo"),
    ("prescription", r"prescription|rx\b|tab\.|cap\.|take .* daily|sig:"),
    ("discharge", r"discharge|admission|admitted|summary of stay"),
]


def extract_text(ext, raw):
    try:
        if ext == "txt":
            return raw.decode("utf-8", "ignore")
        if ext == "pdf":
            from pypdf import PdfReader
            r = PdfReader(io.BytesIO(raw))
            return "\n".join((p.extract_text() or "") for p in r.pages[:15])
    except Exception:
        pass
    return ""


def scrub_report(text, patient_name):
    """De-identify before AI: patient/relative names, emails, phones, ID-like numbers."""
    text = scrub(text)
    for part in re.split(r"\s+", patient_name or ""):
        if len(part) > 2:
            text = re.sub(re.escape(part), "[name]", text, flags=re.I)
    text = re.sub(r"\b(?:[Dd]r|[Mm]rs|[Mm]r|[Mm]s)\.?\s+[A-Z][\w.]+(?:\s+(?!(?:Dr|Mr|Mrs|Ms)\b)[A-Z][\w.]+)?", "[name]", text)
    text = re.sub(r"\b\d{9,}\b", "[id]", text)
    return text[:6000]


def rule_analysis(text):
    cat = "other"
    for c, pat in CAT_WORDS:
        if re.search(pat, text, re.I):
            cat = c
            break
    lines = [l.strip() for l in text.splitlines()
             if re.search(r"[A-Za-z]{3,}.*\d+(\.\d+)?\s*(mg/dl|g/dl|mmol/l|%|/ul|/cumm|mm ?hg|bpm|iu/l|u/l)", l, re.I)]
    return {"category": cat, "summary": "Key values found in this report. Please review them with your doctor.",
            "findings": lines[:12], "source": "rules"}


AN_SYSTEM = """You organise a de-identified medical report for a patient and their doctor.
Return ONLY JSON: {"category":"lab|imaging|prescription|discharge|other","summary":"max 60 words, plain language",
"findings":["up to 10 short items, e.g. 'Hemoglobin 10.2 g/dL (below usual range)'"],"follow_up":"one sentence suggesting which kind of doctor to discuss with"}.
Rules: describe what the report says only. No diagnosis, no drug names to take, no dosage, no treatment advice.
Never repeat names or identifiers. Write summary/findings/follow_up in {lang}."""


def analyze_report(text, patient_name, lang="en"):
    if not text.strip():
        return None
    clean = scrub_report(text, patient_name)
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        import requests
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": os.environ.get("AI_MODEL", "claude-sonnet-5-5"), "max_tokens": 700,
                      "system": AN_SYSTEM.replace("{lang}", "Telugu" if lang == "te" else "English"),
                      "messages": [{"role": "user", "content": clean}]}, timeout=50)
            r.raise_for_status()
            out = "".join(b.get("text", "") for b in r.json()["content"])
            data = json.loads(re.search(r"\{.*\}", out, re.S).group(0))
            if data.get("category") not in CATEGORIES:
                data["category"] = "other"
            data["source"] = "ai"
            return data
        except Exception:
            pass
    return rule_analysis(clean)


def report_row(r, with_user=False):
    m = dec(r["enc_meta"])
    m["id"] = r["id"]
    m["uploaded"] = (r["created"] or "")[:10]
    return m


def load_reports(uid):
    rows = db().execute("SELECT id,enc_meta,created FROM reports WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    return [report_row(r) for r in rows]


@app.route("/api/reports", methods=["GET", "POST"])
@login_required("patient")
def reports():
    if request.method == "GET":
        return jsonify(load_reports(g.user["id"]))
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="Choose a file to upload."), 400
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in FILE_TYPES:
        return jsonify(error="Only PDF, PNG, JPG and TXT files are allowed."), 400
    raw = f.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        return jsonify(error="File is larger than 5 MB."), 413
    if not raw:
        return jsonify(error="The file is empty."), 400
    magic = FILE_TYPES[ext][1]
    if magic and not raw.startswith(magic):
        return jsonify(error="File content does not match its type."), 400
    category = request.form.get("category", "other")
    if category not in CATEGORIES:
        category = "other"
    text = extract_text(ext, raw)
    prof = dec(g.user["enc_profile"])
    analysis = analyze_report(text, prof.get("name"), request.form.get("lang", "en")) if text.strip() else None
    if analysis and request.form.get("category", "auto") in ("", "auto"):
        category = analysis["category"]
    meta = dict(title=(request.form.get("title") or "").strip() or secure_filename(f.filename),
                category=category, date=request.form.get("date") or datetime.utcnow().date().isoformat(),
                notes=(request.form.get("notes") or "").strip(), filename=secure_filename(f.filename) or f"report.{ext}",
                mime=FILE_TYPES[ext][0], size=len(raw), analysis=analysis, has_text=bool(text.strip()))
    cur = db().execute("INSERT INTO reports(user_id,enc_meta,enc_blob,created) VALUES(?,?,?,?) RETURNING id",
                       (g.user["id"], enc(meta), FERNET.encrypt(raw).decode(), datetime.utcnow().isoformat()))
    new_id = cur.fetchone()["id"]
    db().commit()
    return jsonify(ok=True, id=new_id)


def can_view_report(owner_id):
    u = g.user
    if u["role"] == "patient":
        return u["id"] == owner_id
    return bool(db().execute("SELECT 1 FROM access WHERE patient_id=? AND doctor_id=?", (owner_id, u["id"])).fetchone())


@app.get("/api/reports/<int:rid>/file")
@login_required()
def report_file(rid):
    r = db().execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    if not r or not can_view_report(r["user_id"]):
        return jsonify(error="Report not found."), 404
    m = dec(r["enc_meta"])
    raw = FERNET.decrypt(r["enc_blob"].encode())
    return Response(raw, mimetype=m["mime"], headers={
        "Content-Disposition": f'attachment; filename="{m["filename"]}"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"})


@app.post("/api/reports/<int:rid>/analyze")
@login_required("patient")
def reanalyze(rid):
    r = db().execute("SELECT * FROM reports WHERE id=? AND user_id=?", (rid, g.user["id"])).fetchone()
    if not r:
        return jsonify(error="Report not found."), 404
    m = dec(r["enc_meta"])
    ext = m["filename"].rsplit(".", 1)[-1].lower()
    text = extract_text(ext, FERNET.decrypt(r["enc_blob"].encode()))
    if not text.strip():
        return jsonify(error="No readable text in this file (scanned images can't be analysed). It is still stored and organised."), 422
    lang = "te" if (request.get_json(silent=True) or {}).get("lang") == "te" else "en"
    m["analysis"] = analyze_report(text, dec(g.user["enc_profile"]).get("name"), lang)
    db().execute("UPDATE reports SET enc_meta=? WHERE id=?", (enc(m), rid))
    db().commit()
    return jsonify(ok=True)


@app.delete("/api/reports/<int:rid>")
@login_required("patient")
def del_report(rid):
    db().execute("DELETE FROM reports WHERE id=? AND user_id=?", (rid, g.user["id"]))
    db().commit()
    return jsonify(ok=True)


# --------------------------------------------------------------- chatbot
# (keyword -> specialist) in English and Telugu
SPECIALISTS = [
    (r"chest|heart|palpitation|bp|blood pressure|ఛాతి|గుండె", ("Cardiologist", "గుండె వైద్యుడు (Cardiologist)")),
    (r"cough|breath|wheez|asthma|cold|దగ్గు|ఊపిరి|జలుబు", ("Pulmonologist / General Physician", "ఊపిరితిత్తుల వైద్యుడు / జనరల్ ఫిజీషియన్")),
    (r"stomach|vomit|nausea|diarr|acid|abdomen|కడుపు|వాంతి|విరేచన", ("Gastroenterologist", "జీర్ణకోశ వైద్యుడు (Gastroenterologist)")),
    (r"skin|rash|itch|acne|allerg|చర్మ|దురద|దద్దుర", ("Dermatologist", "చర్మ వైద్యుడు (Dermatologist)")),
    (r"headache|migraine|dizz|seizure|numb|తలనొప్పి|తల తిర|మూర్ఛ", ("Neurologist", "నరాల వైద్యుడు (Neurologist)")),
    (r"bone|joint|knee|back pain|fracture|మోకాలు|కీళ్ల|ఎముక|వెన్ను", ("Orthopedic", "ఎముకల వైద్యుడు (Orthopedic)")),
    (r"sugar|diabet|thyroid|weight|షుగర్|మధుమేహ|థైరాయిడ్", ("Endocrinologist / Diabetologist", "హార్మోన్ / మధుమేహ వైద్యుడు")),
    (r"eye|vision|కన్ను|కళ్ళు|చూపు", ("Ophthalmologist", "కంటి వైద్యుడు (Ophthalmologist)")),
    (r"ear|throat|sinus|tonsil|చెవి|గొంతు", ("ENT Specialist", "ENT వైద్యుడు")),
    (r"anxiety|depress|stress|sleep|insomnia|ఆందోళన|నిద్ర|ఒత్తిడి", ("Psychiatrist / Counsellor", "మానసిక వైద్యుడు / కౌన్సిలర్")),
    (r"pregnan|period|menstru|గర్భ|నెలసరి", ("Gynecologist", "స్త్రీ వైద్య నిపుణులు (Gynecologist)")),
    (r"tooth|dental|gum|పంటి", ("Dentist", "దంత వైద్యుడు (Dentist)")),
]
EMERGENCY = r"severe chest pain|can.?t breathe|unconscious|stroke|heavy bleeding|suicid|poison|తీవ్రమైన ఛాతి|స్పృహ|ఆత్మహత్య"
# deep medication / drug questions are NOT answered - show an error + doctor referral
DRUG_DEEP = (r"\b(dose|dosage|dosing|mg|ml|overdose|interaction|interact|contraindicat|side effects?|"
             r"prescri\w*|tablet|capsule|antibiotic|how (much|many) .*(take|pill)|can i (take|mix|combine)|"
             r"drug|medicine for|which medicine|brand|substitute|withdrawal)\b|మోతాదు|మందు|మాత్ర|సైడ్ ఎఫెక్ట్")


def pick_specialist(text, lang):
    for pat, (en, te) in SPECIALISTS:
        if re.search(pat, text, re.I):
            return te if lang == "te" else en
    return "ఫ్యామిలీ డాక్టర్ / జనరల్ ఫిజీషియన్" if lang == "te" else "General Physician"


def build_context(uid):
    """De-identified summary: pseudonym + conditions/symptoms/meds names. No name/email/phone/age/DOB."""
    recs = load_records(uid)[:15]
    meds_ = load_meds(uid)
    return {
        "patient_ref": pseudonym(uid),
        "conditions": [scrub(r["title"]) for r in recs if r["kind"] == "condition"],
        "recent_symptoms": [{"symptom": scrub(r["title"]), "severity": r.get("severity"),
                             "date": r.get("date")} for r in recs if r["kind"] == "symptom"],
        "current_medicines": [m["name"] for m in meds_],
        "report_summaries": [{"type": r["category"], "summary": (r.get("analysis") or {}).get("summary")}
                             for r in load_reports(uid)[:5] if r.get("analysis")],
    }


VOICE_STYLE = ("- This answer will be READ ALOUD to a person with little or no reading ability. Use very simple everyday words, "
               "short sentences, max 60 words, no lists, no symbols, no medical jargon, no English words if replying in Telugu.")
SYSTEM = """You are TrackLife Assistant, a careful symptom-organising helper (not a doctor).
- Give general, non-diagnostic guidance: what the symptoms might relate to, simple self-care, warning signs.
- NEVER give drug names to take, doses, interactions or in-depth medication advice. If asked, say you cannot and refer to a doctor.
- The patient data is de-identified (pseudonym only). Never ask for or repeat names, phone numbers or emails.
- Keep answers under 140 words, warm and clear. If emergency signs appear, tell them to call emergency services (108/112 in India) immediately.
- Reply in {lang}. Do not name a doctor type yourself; the app appends one.
{style}"""


def ask_ai(message, context, lang, voice=False):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    import requests
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": os.environ.get("AI_MODEL", "claude-sonnet-5-5"), "max_tokens": 500,
                  "system": SYSTEM.format(lang="Telugu" if lang == "te" else "English", style=VOICE_STYLE if voice else ""),
                  "messages": [{"role": "user", "content":
                                f"De-identified patient summary (JSON): {json.dumps(context)}\n\nQuestion: {scrub(message)}"}]},
            timeout=40)
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json()["content"])
    except Exception:
        return None


def fallback_reply(message, lang):
    if lang == "te":
        return ("మీ లక్షణాలను నమోదు చేసుకోండి, నీళ్లు ఎక్కువగా తాగండి, విశ్రాంతి తీసుకోండి. "
                "లక్షణాలు 2–3 రోజులకు మించి ఉంటే లేదా తీవ్రమైతే వైద్యుడిని కలవండి.")
    return ("Note your symptoms with times and severity, rest and stay hydrated. "
            "If they last more than 2-3 days or get worse, please see a doctor.")


@app.post("/api/chat")
@login_required("patient")
def chat():
    d = request.get_json(force=True)
    msg = (d.get("message") or "").strip()
    lang = "te" if d.get("lang") == "te" else "en"
    if not msg:
        return jsonify(error="Type a question first."), 400
    spec = pick_specialist(msg, lang)
    if re.search(DRUG_DEEP, msg, re.I):
        text = ("ఈ ప్రశ్నకు నేను సమాధానం ఇవ్వలేను: మందులు, మోతాదులు లేదా ఔషధ వివరాల కోసం డాక్టర్ లేదా ఫార్మసిస్ట్‌ను సంప్రదించండి."
                if lang == "te" else
                "I can't answer in-depth medication or drug questions. Please ask a doctor or pharmacist.")
        return jsonify(error=text, specialist=spec), 422
    if re.search(EMERGENCY, msg, re.I):
        text = ("ఇది అత్యవసరం కావచ్చు. వెంటనే 108 / 112 కి కాల్ చేయండి."
                if lang == "te" else "This may be an emergency. Call 108 / 112 right now.")
        return jsonify(reply=text, specialist=spec, emergency=True)
    reply = ask_ai(msg, build_context(g.user["id"]), lang, bool(d.get("voice"))) or fallback_reply(msg, lang)
    return jsonify(reply=reply, specialist=spec)


# ---------------------------------------------------------------- pages
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(413)
def too_big(_):
    return jsonify(error="File is larger than 5 MB."), 413


@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
