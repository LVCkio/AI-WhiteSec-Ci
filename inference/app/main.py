from fastapi import FastAPI

from .predictor import SUPPORTED_CWES, build_predictor
from .schemas import (
    BatchPredictionRequest,
    BatchPredictionResponse,
    PredictionRequest,
    PredictionResponse,
)


predictor = build_predictor()
app = FastAPI(
    title="AI WhiteSec Inference API",
    version="0.1.0",
    description="Stable inference boundary for the pilot CodeBERT classifier.",
)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "inference",
        "model_version": predictor.model_version,
        "model_mode": predictor.model_mode,
    }


@app.get("/v1/model")
def model_info() -> dict:
    return {
        "model_version": predictor.model_version,
        "model_mode": predictor.model_mode,
        "supported_cwes": SUPPORTED_CWES,
        "unsupported_cwes": ["CWE-798"],
        "safe_semantics": "SAFE means no supported target CWE was detected; it does not mean globally secure.",
    }


@app.post("/v1/predict", response_model=PredictionResponse)
def predict(payload: PredictionRequest) -> PredictionResponse:
    return predictor.predict(payload)


@app.post("/v1/predict/batch", response_model=BatchPredictionResponse)
def predict_batch(payload: BatchPredictionRequest) -> BatchPredictionResponse:
    return BatchPredictionResponse(
        predictions=[predictor.predict(item) for item in payload.samples],
        model_version=predictor.model_version,
        model_mode=predictor.model_mode,
    )

