# Connecting QF-IDS Customer Portal to Firebase

This makes customer accounts **persist** — they survive page refreshes *and*
server restarts — using **Firebase Authentication** (email + password) for login
and **Cloud Firestore** for storing each customer's profile (company, plan,
channels).

> If you skip this entirely, the portal still works in **legacy mode**
> (email-only login, accounts kept in memory and lost on restart). The demo
> accounts keep working. You only need the steps below to get persistence.

---

## How it works (architecture)

```
Browser (customer-portal)                 FastAPI backend                 Firebase
─────────────────────────                 ───────────────                 ────────
1. Sign up / sign in  ───────────────────────────────────────────────▶  Firebase Auth
   (email + password)                                                    (verifies password,
                          ◀──────────── returns ID token (JWT) ──────────  returns token)
2. POST /api/portal/register  ──▶  verifies token with Admin SDK
   { id_token, company, plan }       writes profile  ──────────────────▶  Firestore
                                                                          (customers/{uid})
3. GET /api/portal/me  ─────────▶  verifies token, reads profile  ◀─────  Firestore
   Authorization: Bearer <token>
```

Passwords are handled entirely by Firebase — the backend never sees them.
The backend is the source of truth for **which channels** a customer owns.

---

## Part A — Firebase Console (one-time, ~5 minutes)

1. Go to <https://console.firebase.google.com> and **Add project** (any name,
   e.g. `qfids-demo`). Google Analytics is not needed.

2. **Enable Email/Password sign-in**
   Build → **Authentication** → **Get started** → **Sign-in method** tab →
   click **Email/Password** → toggle **Enable** → **Save**.

3. **Create the Firestore database**
   Build → **Firestore Database** → **Create database** →
   choose **Start in test mode** (fine for a demo / hackathon) → pick a region →
   **Enable**.

   > Test mode lets reads/writes through for 30 days. For the backend this is
   > irrelevant (the Admin SDK bypasses rules anyway), but it avoids friction.

---

## Part B — Backend credentials (Admin SDK)

4. In the Console: **⚙ Project settings** → **Service accounts** tab →
   **Generate new private key** → confirm. A `.json` file downloads.

5. Rename that file to **`firebase-service-account.json`** and put it in the
   **`backend/`** folder (next to `run.py`).

   ```
   backend/
     run.py
     firebase-service-account.json   ← here
   ```

   > Alternatively set an env var pointing at it:
   > `export FIREBASE_CREDENTIALS=/path/to/key.json`

6. Install the Admin SDK and start the backend:

   ```
   cd backend
   pip install -r requirements.txt        # now includes firebase-admin
   python run.py
   ```

   On startup you should see:

   ```
   [firebase] connected — customer accounts persist to Firestore
   ```

   If instead you see `[firebase] not active — ...`, read the message: it's
   either the missing JSON file or `firebase-admin` not installed. The portal
   keeps working in legacy mode until fixed.

---

## Part C — Frontend config (Web app keys)

7. In the Console: **⚙ Project settings** → **General** tab → scroll to
   **Your apps** → click the **Web** icon `</>` → register an app (nickname
   `qfids-portal`, no hosting needed). Firebase shows a `firebaseConfig` object.

8. Open **`customer-portal/index.html`**, find the `FIREBASE_CONFIG` block near
   the top (in the `<head>`), and paste your real values:

   ```js
   window.FIREBASE_CONFIG = {
     apiKey: "AIza...your-key...",
     authDomain: "qfids-demo.firebaseapp.com",
     projectId: "qfids-demo",
     appId: "1:1234567890:web:abc123"
   };
   ```

   As long as `apiKey` is not the placeholder, the portal automatically switches
   into Firebase mode: the Register and Sign-in forms now show a **Password**
   field and use Firebase Auth.

That's it. Reload `http://localhost:8000/portal`, register an account with a
password, refresh the page, restart the server — you stay logged in and your
account is still there.

---

## Verifying it persisted

- Firebase Console → **Authentication → Users**: your new email appears.
- Firebase Console → **Firestore → Data → `customers`**: a document keyed by the
  user's UID holds `company`, `plan`, `channels`, etc.

---

## Notes & gotchas

- **Channels still come from the backend.** A new customer starts with whatever
  channels you assign at registration. The four demo channels (`ch-a`..`ch-d`)
  may already be taken by seeded/earlier accounts.
- **"Add customer" while logged in** (Firebase mode) creates the new user on a
  temporary secondary Firebase app, so your own admin session is *not* replaced.
- **Tokens expire after ~1 hour.** The portal refreshes them automatically via
  Firebase's `onAuthStateChanged` / `getIdToken`, so you won't get logged out.
- **Don't commit `firebase-service-account.json`** to a public repo — it's a
  secret. (`.gitignore` already ignores it.)
- **Production rules**: before going live, lock Firestore rules down. For this
  project the backend Admin SDK is the only writer, so you can set client rules
  to deny all and still have the app work.
