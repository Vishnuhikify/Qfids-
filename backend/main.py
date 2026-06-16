# main.py — entry point alias for uvicorn
# This lets you run:  uvicorn main:app --reload
# from inside the 'backend' folder.
from qfids.api.server import app  # noqa: F401 — re-exported for uvicorn
