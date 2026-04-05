"""
shadowvault.py — Core Engine
Reversible PII anonymisation via AES-256 token vault.
Builds on PrivGuard's PII detection + PDF/image pipeline,
but replaces destructive redaction with encrypted token substitution.
"""

import os
import re
import io
import json
import uuid
import base64
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime

import pytesseract
import fitz          # PyMuPDF
import spacy
import cv2
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TESSERACT_CONFIG = r"--oem 3 --psm 6"

# ── spaCy ──────────────────────────────────────────────────────────────────────
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    print("[!] spaCy model missing – run: python -m spacy download en_core_web_sm")
    raise

# ── Roles & permissions ────────────────────────────────────────────────────────
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "doctor":     {"NAME", "DOB", "GENDER", "DIAGNOSIS", "MRN", "PHONE", "EMAIL", "PERSON"},
    "auditor":    {"NATIONAL_ID", "SSN", "POLICY_ID", "MEMBER_ID", "ACCOUNT_ID",
                   "PAYER_ID", "TAX_ID", "NPI_ID", "LONG_ID"},
    "legal_team": {"NAME", "DOB", "SSN", "NATIONAL_ID", "PASSPORT", "DRIVER_LICENSE",
                   "TAX_ID", "ADDRESS", "CITY_STATE_ZIP", "ZIP", "EMAIL", "PERSON"},
    "analyst":    {"POLICY_ID", "MEMBER_ID", "ACCOUNT_ID", "GROUP_NUMBER",
                   "INSURANCE_ID", "DATE_NUMERIC"},
    "admin":      None,   # None = all fields
}

ALL_ROLES = list(ROLE_PERMISSIONS.keys())


# ══════════════════════════════════════════════════════════════════════════════
#  KEY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def _derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2 → 32-byte AES-256 key."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)


def _get_master_key(vault_dir: Path) -> bytes:
    """Load or create the master AES-256 key for this vault instance."""
    key_file = vault_dir / "master.key"
    salt_file = vault_dir / "master.salt"
    if key_file.exists() and salt_file.exists():
        return key_file.read_bytes()
    # Generate fresh key
    key = os.urandom(32)
    salt = os.urandom(16)
    key_file.write_bytes(key)
    salt_file.write_bytes(salt)
    return key


def _get_role_key(vault_dir: Path, role: str) -> bytes:
    """One derived 32-byte key per role (stored in keys/)."""
    keys_dir = vault_dir / "keys"
    keys_dir.mkdir(exist_ok=True)
    key_file = keys_dir / f"{role}.key"
    if key_file.exists():
        return key_file.read_bytes()
    # Derive from master + role name
    master = _get_master_key(vault_dir)
    role_key = hashlib.sha256(master + role.encode()).digest()
    key_file.write_bytes(role_key)
    return role_key


# ══════════════════════════════════════════════════════════════════════════════
#  VAULT DATABASE  (SQLite, on-premise)
# ══════════════════════════════════════════════════════════════════════════════

def _open_vault(vault_dir: Path) -> sqlite3.Connection:
    vault_dir.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(vault_dir / "vault.db"))
    db.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token_id      TEXT PRIMARY KEY,
            label         TEXT NOT NULL,
            encrypted_b64 TEXT NOT NULL,
            nonce_b64     TEXT NOT NULL,
            allowed_roles TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id   TEXT NOT NULL,
            role       TEXT NOT NULL,
            action     TEXT NOT NULL,
            timestamp  TEXT NOT NULL
        )
    """)
    db.commit()
    return db


def _encrypt_value(value: str, key: bytes) -> tuple[str, str]:
    """AES-256-GCM encrypt → (ciphertext_b64, nonce_b64)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
    return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()


def _decrypt_value(ct_b64: str, nonce_b64: str, key: bytes) -> str:
    """AES-256-GCM decrypt."""
    ct    = base64.b64decode(ct_b64)
    nonce = base64.b64decode(nonce_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


def store_token(db: sqlite3.Connection, vault_dir: Path,
                label: str, value: str) -> str:
    """Encrypt + store a PII value; return its token string."""
    token_id = f"SV-{uuid.uuid4().hex[:8].upper()}"
    master_key = _get_master_key(vault_dir)
    ct_b64, nonce_b64 = _encrypt_value(value, master_key)

    # Determine which roles may decrypt this label
    allowed = [
        r for r, perms in ROLE_PERMISSIONS.items()
        if perms is None or label in perms
    ]

    db.execute(
        "INSERT INTO tokens VALUES (?,?,?,?,?,?)",
        (token_id, label, ct_b64, nonce_b64,
         json.dumps(allowed), datetime.utcnow().isoformat())
    )
    db.commit()
    return token_id


def decrypt_token(db: sqlite3.Connection, vault_dir: Path,
                  token_id: str, role: str) -> str | None:
    """
    Decrypt a single token for the requesting role.
    Returns the plaintext, or None if role is not permitted.
    """
    row = db.execute(
        "SELECT label, encrypted_b64, nonce_b64, allowed_roles FROM tokens WHERE token_id=?",
        (token_id,)
    ).fetchone()
    if not row:
        return None
    label, ct_b64, nonce_b64, allowed_json = row
    allowed = json.loads(allowed_json)

    # admin always allowed; else check list
    perms = ROLE_PERMISSIONS.get(role)
    if perms is not None and role not in allowed:
        _log_access(db, token_id, role, "DENIED")
        return None

    master_key = _get_master_key(vault_dir)
    try:
        value = _decrypt_value(ct_b64, nonce_b64, master_key)
    except Exception:
        return None

    _log_access(db, token_id, role, "DECRYPTED")
    return value


def _log_access(db: sqlite3.Connection, token_id: str, role: str, action: str):
    db.execute(
        "INSERT INTO access_log (token_id,role,action,timestamp) VALUES (?,?,?,?)",
        (token_id, role, action, datetime.utcnow().isoformat())
    )
    db.commit()


def get_vault_summary(db: sqlite3.Connection) -> dict:
    total = db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
    by_label = db.execute(
        "SELECT label, COUNT(*) FROM tokens GROUP BY label"
    ).fetchall()
    return {"total_tokens": total, "by_label": dict(by_label)}


# ══════════════════════════════════════════════════════════════════════════════
#  PII DETECTION  (inherited + extended from PrivGuard)
# ══════════════════════════════════════════════════════════════════════════════

REGEX_PATTERNS: dict[str, str] = {
    "NAME":            r"(?i)(?<=Name[:\s])([A-Z][a-z]+(?:\s[A-Z]\.)?\s[A-Z][a-z]+)",
    "DOB":             r"(?i)(?:DOB[:\s]*)(?:\d{1,2}[-/\s]\d{1,2}[-/\s]\d{2,4}|[A-Z][a-z]+\s\d{1,2},\s\d{4})",
    "GENDER":          r"(?i)(?<=Gender[:\s])(Male|Female|Other|Non[-\s]?binary|Unknown)",
    "SSN":             r"\b\d{3}-\d{2}-\d{4}\b",
    "EMAIL":           r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "PHONE":           r"(?:\+?\d{1,2}[\s-]?)?(?:\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})",
    "ADDRESS":         r"\d{1,5}\s+[A-Za-z0-9\s]+(Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct|Circle|Way|Place|Trail|Terrace|Parkway|Pkwy|Loop|Highway|Hwy)\b.*",
    "CITY_STATE_ZIP":  r"[A-Z][a-z]+,\s?[A-Z]{2}\s?\d{5}(?:-\d{4})?",
    "MEMBER_ID":       r"(?i)(?<=Member ID[:\s]*)[A-Z0-9-]{6,15}",
    "GROUP_NUMBER":    r"(?i)(?<=Group Number[:\s]*)[A-Z0-9-]{3,15}",
    "POLICY_ID":       r"(?i)(?<=Policy Effective Date[:\s]*)\d{1,2}[-/]\d{1,2}[-/]\d{2,4}",
    "PAYER_ID":        r"(?i)(?<=Payer ID[:\s]*)\d{3,10}",
    "INSURANCE_ID":    r"\b\d{6,15}\b(?=.*(Insurance|Insurer|Provider|ID))",
    "DRIVER_LICENSE":  r"(?i)(?<=License[:\s]*)[A-Z0-9-]{5,15}",
    "PASSPORT":        r"(?i)(?<=Passport[:\s]*)[A-Z0-9-]{6,15}",
    "TAX_ID":          r"\b\d{2}-\d{7}\b(?=.*Tax)",
    "NATIONAL_ID":     r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    "NPI_ID":          r"(?i)NPI[:\s]*\d{8,10}\b",
    "MRN":             r"(?i)MRN[:\s]*[A-Z0-9-]{6,15}\b",
    "ACCOUNT_ID":      r"\b[A-Z]{2,3}\d{6,}\b",
    "LONG_ID":         r"\b[A-Z0-9]{8,}\b",
    "ZIP":             r"\b\d{5}(?:-\d{4})?\b",
    "DATE_NUMERIC":    r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b",
    "AADHAAR":         r"\b\d{4}\s\d{4}\s\d{4}\b",
    "PAN":             r"\b[A-Z]{5}\d{4}[A-Z]\b",
    "IP_ADDRESS":      r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "CREDIT_CARD":     r"\b(?:\d[ -]?){13,16}\b",
}


def detect_pii_entities(text: str) -> list[tuple[str, str]]:
    """Return list of (pii_text, label) found in text."""
    if not text:
        return []
    entities: list[tuple[str, str]] = []

    for label, pattern in REGEX_PATTERNS.items():
        try:
            matches = re.findall(pattern, text)
            for match in set(matches):
                val = match[0] if isinstance(match, tuple) else match
                val = val.strip()
                if val:
                    entities.append((val, label))
        except re.error as e:
            print(f"Skipping pattern for {label} due to regex error: {e}")

    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ in {"PERSON", "GPE", "LOC", "ORG"}:
            et = ent.text.strip()
            if et and len(et.replace(" ", "")) > 3:
                entities.append((et, ent.label_))

    # deduplicate
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for t, l in entities:
        key = (t.lower(), l)
        if key not in seen:
            seen.add(key)
            result.append((t, l))
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  TOKENISATION  (replaces PrivGuard's destructive redact)
# ══════════════════════════════════════════════════════════════════════════════

TOKEN_RE = re.compile(r"<<SV-[A-F0-9]{8}>>")


def tokenise_text(text: str, entities: list[tuple[str, str]],
                  db: sqlite3.Connection, vault_dir: Path) -> tuple[str, dict[str, str]]:
    """
    Replace each PII span with <<SV-TOKEN>>.
    Returns (tokenised_text, {original_value: token_id}).
    """
    value_to_token: dict[str, str] = {}
    result = text

    # Sort longest-first to avoid partial replacements
    sorted_ents = sorted(entities, key=lambda x: len(x[0]), reverse=True)

    for value, label in sorted_ents:
        if not value:
            continue
        if value in value_to_token:
            tok = value_to_token[value]
        else:
            tok = store_token(db, vault_dir, label, value)
            value_to_token[value] = tok

        result = re.sub(re.escape(value), f"<<{tok}>>", result, flags=re.IGNORECASE)

    return result, value_to_token


def detokenise_text(tokenised: str, db: sqlite3.Connection,
                    vault_dir: Path, role: str) -> str:
    """
    Replace each <<SV-TOKEN>> with its decrypted value (for permitted fields)
    or leave the token visible if role is not permitted.
    """
    def replace(m: re.Match) -> str:
        raw = m.group(0)            # <<SV-XXXXXXXX>>
        tok = raw[2:-2]             # SV-XXXXXXXX
        val = decrypt_token(db, vault_dir, tok, role)
        return val if val is not None else raw

    return TOKEN_RE.sub(replace, tokenised)


# ══════════════════════════════════════════════════════════════════════════════
#  PDF PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def extract_text_from_pdf(pdf_path: str) -> str:
    """Extract text; OCR image-only pages."""
    parts: list[str] = []
    try:
        doc = fitz.open(pdf_path)
    except Exception as e:
        print(f"[!] Cannot open PDF: {e}")
        return ""

    for i, page in enumerate(doc):
        try:
            t = page.get_text("text").strip()
        except Exception:
            t = ""
        if t:
            parts.append(t)
        else:
            try:
                pix = page.get_pixmap(dpi=300)
                img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
                t   = pytesseract.image_to_string(img, config=TESSERACT_CONFIG)
            except Exception as e:
                print(f"[!] OCR page {i}: {e}")
                t = ""
            parts.append(t)
    doc.close()
    return "\n\n".join(parts)


def create_tokenised_pdf(original_pdf: str, entities: list[tuple[str, str]],
                         db: sqlite3.Connection, vault_dir: Path,
                         output_pdf: str) -> dict[str, str]:
    """
    Produce a PDF where each PII span is replaced by its <<SV-TOKEN>>.
    The document is NOT blacked out — it looks complete but has no real PII.
    Returns the value_to_token mapping.
    """
    value_to_token: dict[str, str] = {}

    try:
        doc = fitz.open(original_pdf)
    except Exception as e:
        print(f"[!] Cannot open PDF: {e}")
        return value_to_token

    # Pre-assign tokens for all entities
    for value, label in entities:
        if value not in value_to_token:
            value_to_token[value] = store_token(db, vault_dir, label, value)

    sorted_ents = sorted(entities, key=lambda x: len(x[0]), reverse=True)

    for page in doc:
        for value, label in sorted_ents:
            if not value or len(value.replace(" ", "")) < 2:
                continue
            tok_display = f"<<{value_to_token[value]}>>"
            try:
                rects = page.search_for(value)
            except Exception:
                rects = []
            for r in rects:
                # Whiteout the original text
                page.draw_rect(r, color=(1, 1, 1), fill=(1, 1, 1))
                # Write the token in small monospaced-style text
                page.insert_text(
                    (r.x0, r.y0 + r.height * 0.85),
                    tok_display,
                    fontsize=max(5, r.height * 0.75),
                    color=(0.1, 0.4, 0.9),
                )

    try:
        doc.save(output_pdf)
        doc.close()
    except Exception as e:
        print(f"[!] Save failed: {e}")

    return value_to_token


# ══════════════════════════════════════════════════════════════════════════════
#  IMAGE PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def preprocess_for_ocr(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    try:
        _, th = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        return th
    except Exception:
        return gray


def tokenise_image(image_path: str, output_path: str,
                   db: sqlite3.Connection,
                   vault_dir: Path) -> tuple[list[tuple[str, str]], int, dict[str, str]]:
    """
    Tokenise PII in image: replace detected text boxes with <<TOKEN>> overlays.
    Also blurs faces (same as PrivGuard).
    Returns (entities, face_count, value_to_token).
    """
    img = cv2.imread(image_path)
    if img is None:
        return [], 0, {}

    proc    = preprocess_for_ocr(img)
    ocr     = pytesseract.image_to_data(proc, output_type=pytesseract.Output.DICT,
                                        config=TESSERACT_CONFIG)
    words   = [w for w in ocr.get("text", []) if w and w.strip()]
    full_t  = " ".join(words)
    entities = detect_pii_entities(full_t)

    value_to_token: dict[str, str] = {}
    for val, lbl in entities:
        if val not in value_to_token:
            value_to_token[val] = store_token(db, vault_dir, lbl, val)

    pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    draw    = ImageDraw.Draw(pil_img)

    for i, word in enumerate(ocr["text"]):
        if not word.strip():
            continue
        for val, _ in entities:
            if word.lower() in val.lower():
                x = ocr["left"][i];  y = ocr["top"][i]
                w = ocr["width"][i]; h = ocr["height"][i]
                tok = f"<<{value_to_token[val]}>>"
                draw.rectangle([x, y, x + w, y + h], fill=(230, 240, 255))
                draw.text((x + 2, y + 1), tok, fill=(10, 60, 180))
                break

    import numpy as np
    img_cv = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

    # Face blur
    face_cascade = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    )
    gray2  = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    faces  = face_cascade.detectMultiScale(gray2, 1.3, 5)
    for (x, y, w, h) in faces:
        img_cv[y:y+h, x:x+w] = cv2.GaussianBlur(
            img_cv[y:y+h, x:x+w], (99, 99), 30
        )

    cv2.imwrite(output_path, img_cv)
    return entities, len(faces), value_to_token


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def generate_vault_report(report_entries: list[dict],
                          db: sqlite3.Connection,
                          output_path: str):
    summary = get_vault_summary(db)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("═══════════════════════════════════════════\n")
            f.write("        SHADOWVAULT AUDIT REPORT           \n")
            f.write("═══════════════════════════════════════════\n")
            f.write(f"Generated : {datetime.utcnow().isoformat()} UTC\n")
            f.write(f"Vault tokens total : {summary['total_tokens']}\n")
            f.write(f"Token distribution : {json.dumps(summary['by_label'], indent=2)}\n\n")
            f.write("─── Per-File Summary ───────────────────────\n\n")
            for e in report_entries:
                f.write(f"File    : {e['file']}\n")
                f.write(f"Tokens  : {len(e.get('value_to_token', {}))}\n")
                f.write(f"Faces   : {e.get('faces', 0)}\n")
                for val, tok in e.get("value_to_token", {}).items():
                    row = db.execute(
                        "SELECT label, allowed_roles FROM tokens WHERE token_id=?",
                        (tok,)
                    ).fetchone()
                    lbl    = row[0] if row else "?"
                    roles  = json.loads(row[1]) if row else []
                    f.write(f"  {tok}  [{lbl}]  roles={roles}\n")
                f.write("\n")
            f.write("─── Access Log ─────────────────────────────\n\n")
            rows = db.execute(
                "SELECT token_id,role,action,timestamp FROM access_log ORDER BY id DESC LIMIT 100"
            ).fetchall()
            for r in rows:
                f.write(f"  {r[3]}  {r[1]:12s}  {r[2]:10s}  {r[0]}\n")
        print(f"[+] Vault audit report → {output_path}")
    except Exception as e:
        print(f"[!] Report write failed: {e}")
