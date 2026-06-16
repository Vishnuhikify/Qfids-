"""
Run the QF-IDS backend server.

HOW TO START (run these commands from inside the 'backend' folder):

    python run.py                          # simplest — no reload
    uvicorn main:app --reload              # hot-reload during development
    uvicorn qfids.api.server:app --reload  # also valid

DO NOT use:  uvicorn app.main:app  (wrong path — will crash)
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "qfids.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
