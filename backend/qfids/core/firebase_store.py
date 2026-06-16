"""
firebase_store.py — Firebase-backed persistence for customer accounts.

This replaces the volatile in-memory CustomerRegistry with Firestore so that
customer accounts SURVIVE a page refresh and a server restart. Identity is
handled by Firebase Authentication (email + password) on the browser; this
module verifies the Firebase ID token (a signed JWT) on the backend and reads
/ writes the customer's business data (company, plan, channels) in Firestore.

────────────────────────────────────────────────────────────────────────────
GRACEFUL FALLBACK
────────────────────────────────────────────────────────────────────────────
If the Firebase Admin SDK is not installed, OR no service-account credentials
are configured, this module reports `enabled() == False`. The API layer then
falls back to the original in-memory registry, so the project still runs for
anyone who has not set Firebase up yet (e.g. a judge cloning the repo).

────────────────────────────────────────────────────────────────────────────
HOW TO CONFIGURE (see FIREBASE_SETUP.md for the full walkthrough)
────────────────────────────────────────────────────────────────────────────
  1. Create a Firebase project + enable Email/Password auth + create a
     Firestore database (test mode is fine for the demo).
  2. Project settings → Service accounts → "Generate new private key".
     Save the JSON file as:  backend/firebase-service-account.json
  3. pip install firebase-admin
  4. Restart the backend. You should see "[firebase] connected" in the logs.

The path can be overridden with the env var GOOGLE_APPLICATION_CREDENTIALS
or FIREBASE_CREDENTIALS.
"""
from __future__ import annotations

import os
import time
from typing import Optional

# Customers collection name in Firestore
_COLLECTION = "customers"

# Module-level handles (populated lazily by init()).
_db = None            # firestore client
_auth = None          # firebase_admin.auth module
_initialised = False
_enabled = False
_init_error: Optional[str] = None


def _candidate_credential_paths() -> list[str]:
    """Where we look for the service-account JSON, in priority order."""
    here = os.path.dirname(os.path.abspath(__file__))
    backend_root = os.path.normpath(os.path.join(here, "..", ".."))  # .../backend
    paths = []
    env = os.environ.get("FIREBASE_CREDENTIALS") or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if env:
        paths.append(env)
    paths.append(os.path.join(backend_root, "firebase-service-account.json"))
    paths.append(os.path.join(backend_root, "serviceAccountKey.json"))
    return paths


def init() -> bool:
    """
    Initialise Firebase Admin once. Returns True if Firebase is usable.
    Safe to call repeatedly — only the first call does work.
    """
    global _db, _auth, _initialised, _enabled, _init_error
    if _initialised:
        return _enabled
    _initialised = True

    try:
        import firebase_admin
        from firebase_admin import credentials, firestore, auth as fb_auth
    except Exception as e:  # firebase-admin not installed
        _init_error = (
            "firebase-admin not installed — run `pip install firebase-admin`. "
            "Falling back to in-memory accounts."
        )
        _enabled = False
        return False

    cred_path = next((p for p in _candidate_credential_paths() if p and os.path.exists(p)), None)
    if cred_path is None:
        _init_error = (
            "No Firebase service-account JSON found "
            "(expected backend/firebase-service-account.json). "
            "Falling back to in-memory accounts."
        )
        _enabled = False
        return False

    try:
        if not firebase_admin._apps:  # don't double-init under uvicorn reload
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
        _db = firestore.client()
        _auth = fb_auth
        _enabled = True
        _init_error = None
    except Exception as e:
        _init_error = f"Firebase init failed: {e}. Falling back to in-memory accounts."
        _enabled = False
    return _enabled


def enabled() -> bool:
    return _enabled


def status() -> dict:
    return {
        "enabled": _enabled,
        "error": _init_error,
        "collection": _COLLECTION,
    }


# ── Auth ──────────────────────────────────────────────────────────────────
def verify_id_token(id_token: str) -> Optional[dict]:
    """
    Verify a Firebase ID token (JWT from the browser). Returns the decoded
    claims (including 'uid' and 'email') or None if invalid/expired.
    """
    if not _enabled or not _auth:
        return None
    try:
        return _auth.verify_id_token(id_token)
    except Exception:
        return None


# ── Customer documents (Firestore) ──────────────────────────────────────────
def get_customer(uid: str) -> Optional[dict]:
    if not _enabled:
        return None
    snap = _db.collection(_COLLECTION).document(uid).get()
    return snap.to_dict() if snap.exists else None


def get_by_email(email: str) -> Optional[dict]:
    if not _enabled:
        return None
    q = _db.collection(_COLLECTION).where("email", "==", email.lower()).limit(1).stream()
    for doc in q:
        return doc.to_dict()
    return None


def all_customers() -> list[dict]:
    if not _enabled:
        return []
    return [d.to_dict() for d in _db.collection(_COLLECTION).stream()]


def taken_channels(exclude_uid: Optional[str] = None) -> set[str]:
    """All channels already owned by any customer (optionally excluding one)."""
    taken: set[str] = set()
    for c in all_customers():
        if exclude_uid and c.get("uid") == exclude_uid:
            continue
        taken.update(c.get("channels", []))
    return taken


def upsert_customer(uid: str, *, name: str, company: str, email: str,
                    plan: str, channels: list[str]) -> dict:
    """Create or overwrite a customer document keyed by the Firebase UID."""
    doc = {
        "uid": uid,
        "customer_id": uid,           # keep the key name the frontend expects
        "name": name,
        "company": company,
        "email": email.lower(),
        "plan": plan,
        "channels": channels,
        "created_at": time.time(),
    }
    _db.collection(_COLLECTION).document(uid).set(doc)
    return doc


def update_channels(uid: str, channels: list[str]) -> Optional[dict]:
    if not _enabled:
        return None
    ref = _db.collection(_COLLECTION).document(uid)
    if not ref.get().exists:
        return None
    ref.update({"channels": channels})
    return ref.get().to_dict()
