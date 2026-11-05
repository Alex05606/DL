from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles

from .model import PhishGuardModel

app = FastAPI(title="PhishGuard-Z API", version="1.0.0")
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "phishguardz.joblib"
MODEL_PATH = os.environ.get("PHISHGUARD_MODEL", str(DEFAULT_MODEL_PATH))


class ScoreRequest(BaseModel):
    url: str


@lru_cache(maxsize=1)
def _load_model() -> PhishGuardModel:
    return PhishGuardModel.load(MODEL_PATH)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "model_loaded": os.path.isfile(MODEL_PATH)}


@app.post("/score")
def score(payload: ScoreRequest) -> Dict[str, Any]:
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(
            status_code=503,
            detail=(
                "Model not trained yet. Run `python -m phishguardz.fetch_data`, "
                "`python -m phishguardz.prepare_data`, then "
                "`python -m phishguardz.train`."
            ),
        )
    try:
        return _load_model().score_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


app.mount(
    "/",
    StaticFiles(
        directory=Path(__file__).resolve().parent / "static",
        html=True,
        check_dir=False,
    ),
    name="website",
)
