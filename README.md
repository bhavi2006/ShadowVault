# ShadowVault

**Reversible PII Anonymisation** — AES-256 token vault, on-premise, role-based access.

Unlike traditional redaction tools (including PrivGuard) that permanently destroy PII,
ShadowVault *encrypts and tokenises* it. Documents leave the pipeline looking complete
but containing no real sensitive data. Authorised roles can decrypt field-by-field.

---

## Core Difference vs PrivGuard

| Feature           | PrivGuard           | ShadowVault                  |
|-------------------|---------------------|------------------------------|
| PII handling      | Black-box destroy   | AES-256 encrypt + tokenise   |
| Reversible?       | ❌ No               | ✓ Yes                        |
| Role-based access | ❌ No               | ✓ Doctor / Auditor / Legal…  |
| Vault storage     | N/A                 | On-premise SQLite            |
| Air-gap safe      | Yes                 | Yes                          |
| Audit trail       | Basic               | Full access log              |

---

## Setup

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python app.py
```

Open http://localhost:5050

---

## Architecture

```
shadowvault/
├── shadowvault.py    ← Core engine (detection, encryption, tokenisation)
├── app.py            ← Flask REST API
├── templates/
│   └── index.html    ← Single-page UI
├── static/
│   ├── css/style.css
│   └── js/app.js
├── uploads/          ← Session input files
├── outputs/          ← Tokenised output files
└── vault/
    └── <session_id>/
        ├── vault.db      ← Encrypted token→value mapping
        ├── master.key    ← AES-256 master key
        └── keys/
            ├── doctor.key
            ├── auditor.key
            ├── legal_team.key
            ├── analyst.key
            └── admin.key
```

---

## API

### POST /api/tokenise
Multipart form with `files` key. Returns session_id, token maps, download links.

### POST /api/decrypt
```json
{ "session_id": "abc123", "token_id": "SV-A3F9C2E1", "role": "doctor" }
```
Returns `{ "value": "Harini Shankar" }` or `403 ACCESS DENIED`.

### GET /api/vault/<session_id>
Returns vault summary (token count by label).

### GET /api/rbac
Returns role → permitted labels matrix.

---

## Roles & Permissions

| Field         | Doctor | Auditor | Legal | Analyst | Admin |
|---------------|--------|---------|-------|---------|-------|
| NAME          | ✓      | —       | ✓     | —       | ✓     |
| DOB           | ✓      | —       | ✓     | —       | ✓     |
| SSN           | —      | ✓       | ✓     | —       | ✓     |
| NATIONAL_ID   | —      | ✓       | ✓     | —       | ✓     |
| DIAGNOSIS     | ✓      | —       | —     | —       | ✓     |
| POLICY_ID     | —      | ✓       | —     | ✓       | ✓     |
| PASSPORT      | —      | —       | ✓     | —       | ✓     |
| (+ 20 more)   |        |         |       |         |       |

---

## Security

- **AES-256-GCM** with unique nonce per value
- PBKDF2-derived per-role keys (200,000 iterations)
- Vault database is meaningless without the master key
- Brute-force time for AES-256: 2²⁵⁶ combinations
- **Zero data leaves your server**
