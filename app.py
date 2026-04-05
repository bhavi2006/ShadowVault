"""
app.py — ShadowVault Flask Application
REST API + vault management + role-based decryption layer.
"""

import os
import uuid
import traceback
import json
from pathlib import Path
from flask import (
    Flask, request, jsonify, send_from_directory,
    render_template, abort, session
)
from werkzeug.utils import secure_filename

from shadowvault import (
    extract_text_from_pdf,
    detect_pii_entities,
    tokenise_text,
    detokenise_text,
    create_tokenised_pdf,
    tokenise_image,
    generate_vault_report,
    decrypt_token,
    get_vault_summary,
    _open_vault,
    ALL_ROLES,
    ROLE_PERMISSIONS,
)

# ── Flask setup ───────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"
VAULT_DIR  = BASE_DIR / "vault"

for d in (UPLOAD_DIR, OUTPUT_DIR, VAULT_DIR):
    d.mkdir(exist_ok=True)

ALLOWED_EXT = {".pdf", ".jpg", ".jpeg", ".png"}

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


# ── helpers ───────────────────────────────────────────────────────────────────
def allowed(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXT


def session_dirs(sid: str):
    up  = UPLOAD_DIR / sid
    out = OUTPUT_DIR / sid
    up.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    return up, out


# ── routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", roles=ALL_ROLES)


# ── Tokenise (anonymise) files ────────────────────────────────────────────────
@app.route("/api/tokenise", methods=["POST"])
def tokenise_files():
    """
    POST multipart/form-data  key=files
    Returns: session_id, per-file results with token maps and download links.
    """
    if "files" not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    files = request.files.getlist("files")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "Empty file list"}), 400

    sid = uuid.uuid4().hex
    up_dir, out_dir = session_dirs(sid)

    # Each session gets its own vault namespace
    session_vault = VAULT_DIR / sid
    db = _open_vault(session_vault)

    report_entries = []
    results        = []

    for f in files:
        if not f.filename:
            continue
        if not allowed(f.filename):
            results.append({"original": f.filename, "status": "skipped",
                             "reason": "Unsupported file type"})
            continue

        safe_name = secure_filename(f.filename)
        stem      = Path(safe_name).stem
        ext       = Path(safe_name).suffix.lower()
        in_path   = up_dir / safe_name
        f.save(str(in_path))

        try:
            result_item = {
                "original": safe_name, "status": "ok",
                "pii": [], "faces": 0, "tokens": {}
            }

            if ext == ".pdf":
                text      = extract_text_from_pdf(str(in_path))
                entities  = detect_pii_entities(text)
                tok_text, v2t = tokenise_text(text, entities, db, session_vault)

                # Save tokenised plain text
                txt_out = out_dir / f"tokenised_{stem}.txt"
                txt_out.write_text(tok_text, encoding="utf-8")

                # Save tokenised PDF
                pdf_out = out_dir / f"tokenised_{stem}.pdf"
                create_tokenised_pdf(str(in_path), entities, db, session_vault, str(pdf_out))

                result_item.update({
                    "pii":    [{"text": t, "label": l} for t, l in entities],
                    "tokens": v2t,
                    "downloads": {
                        "pdf": f"/download/{sid}/tokenised_{stem}.pdf",
                        "txt": f"/download/{sid}/tokenised_{stem}.txt",
                    },
                })
                report_entries.append({"file": safe_name,
                                        "value_to_token": v2t, "faces": 0})

            else:  # image
                img_ext  = ext
                img_out  = out_dir / f"tokenised_{stem}{img_ext}"
                entities, face_count, v2t = tokenise_image(
                    str(in_path), str(img_out), db, session_vault
                )
                result_item.update({
                    "pii":    [{"text": t, "label": l} for t, l in entities],
                    "faces":  face_count,
                    "tokens": v2t,
                    "downloads": {
                        "image": f"/download/{sid}/tokenised_{stem}{img_ext}",
                    },
                })
                report_entries.append({"file": safe_name,
                                        "value_to_token": v2t, "faces": face_count})

            results.append(result_item)

        except Exception:
            results.append({
                "original": safe_name, "status": "error",
                "reason": traceback.format_exc(limit=3),
            })

    # Audit report
    if report_entries:
        report_path = out_dir / "vault_audit.txt"
        generate_vault_report(report_entries, db, str(report_path))

    db.close()

    return jsonify({
        "session_id":  sid,
        "results":     results,
        "report_link": f"/download/{sid}/vault_audit.txt" if report_entries else None,
    })


# ── Decrypt a single token (RBAC) ─────────────────────────────────────────────
@app.route("/api/decrypt", methods=["POST"])
def decrypt_endpoint():
    """
    POST JSON { session_id, token_id, role }
    Returns { value } or { error }.
    """
    data       = request.get_json(force=True) or {}
    sid        = data.get("session_id", "")
    token_id   = data.get("token_id", "")
    role       = data.get("role", "")

    if not sid or not token_id or not role:
        return jsonify({"error": "session_id, token_id and role are required"}), 400
    if role not in ALL_ROLES:
        return jsonify({"error": f"Unknown role '{role}'"}), 400

    session_vault = VAULT_DIR / sid
    if not session_vault.exists():
        return jsonify({"error": "Session vault not found"}), 404

    db    = _open_vault(session_vault)
    value = decrypt_token(db, session_vault, token_id, role)
    db.close()

    if value is None:
        return jsonify({"error": f"Role '{role}' is not permitted to view this token",
                         "denied": True}), 403
    return jsonify({"value": value, "token_id": token_id})


# ── Vault summary ─────────────────────────────────────────────────────────────
@app.route("/api/vault/<sid>")
def vault_summary(sid: str):
    session_vault = VAULT_DIR / sid
    if not session_vault.exists():
        return jsonify({"error": "Not found"}), 404
    db = _open_vault(session_vault)
    summary = get_vault_summary(db)
    db.close()
    return jsonify(summary)


# ── RBAC table ────────────────────────────────────────────────────────────────
@app.route("/api/rbac")
def rbac_table():
    table = {}
    for role, perms in ROLE_PERMISSIONS.items():
        table[role] = list(perms) if perms else ["ALL"]
    return jsonify(table)


# ── Download ──────────────────────────────────────────────────────────────────
@app.route("/download/<sid>/<filename>")
def download(sid: str, filename: str):
    safe   = secure_filename(filename)
    folder = OUTPUT_DIR / sid
    if not folder.exists():
        abort(404)
    return send_from_directory(str(folder), safe, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5050)
