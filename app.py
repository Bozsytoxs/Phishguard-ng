"""
PhishGuard NG web app (FastAPI).

Run locally:   uvicorn app:app --reload
"""
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine import model
from engine.pipeline import analyse_message

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="PhishGuard NG", description="Detect. Understand. Stay Safe.", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class AnalyseRequest(BaseModel):
    text: str = Field(default="", description="The suspicious message text")
    url: Optional[str] = Field(default=None, description="Optional link to check")


@app.post("/api/analyse")
def api_analyse(payload: AnalyseRequest):
    """Analyse a message and optional URL; returns risk level, score, matched rules and advice."""
    try:
        return analyse_message(payload.text, payload.url)
    except ValueError as exc:  # empty / too long input
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/health")
def health():
    return {"status": "ok", "model_loaded": model.is_available()}


# The front-end is one HTML page; the browser switches views by URL path.
@app.get("/", include_in_schema=False)
@app.get("/check", include_in_schema=False)
@app.get("/awareness", include_in_schema=False)
@app.get("/about", include_in_schema=False)
def page():
    return FileResponse(STATIC_DIR / "index.html")
