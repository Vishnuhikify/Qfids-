# Quantum Fingerprint Intrusion Detection System — How to Run

## Backend

Open a terminal, go into the `backend` folder:

```
cd qfids\backend
```

Activate your virtual environment (if you have one):

```
venv\Scripts\activate        ← Windows
source venv/bin/activate     ← Mac/Linux
```

Install dependencies (first time only):

```
pip install -r requirements.txt
```

Start the server — pick **one** of these:

```
python run.py                            ← easiest, just double-click or run this
uvicorn main:app --reload                ← hot-reload (code changes apply instantly)
uvicorn qfids.api.server:app --reload  ← alternative
```

> ❌ **DO NOT** run `uvicorn app.main:app` — that path does not exist and will crash.

The API will be available at: **http://localhost:8000**

---

## Frontend

Open a second terminal, go into the `frontend` folder:

```
cd qfids\frontend
```

Install dependencies (first time only):

```
npm install
```

Start the dev server:

```
npm run dev
```

Open your browser at: **http://localhost:5173**

---

## Quick check

Once both are running, visit http://localhost:8000 — you should see:

```json
{"service":"QF-IDS","version":"2.0.0","channels":["ch-alpha","ch-beta","ch-gamma","ch-delta"]}
```
