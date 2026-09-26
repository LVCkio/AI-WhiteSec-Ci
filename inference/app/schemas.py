from pydantic import BaseModel, Field


class PredictionRequest(BaseModel):
    code: str = Field(min_length=1)
    file_path: str | None = None
    function_name: str | None = None
    start_line: int | None = Field(default=None, ge=1)


class BatchPredictionRequest(BaseModel):
    samples: list[PredictionRequest] = Field(min_length=1, max_length=500)


class PredictionResponse(BaseModel):
    label: str
    cwe: str | None
    confidence: float
    scores: dict[str, float]
    model_version: str
    model_mode: str
    risk_detected: bool
    explanation: str


class BatchPredictionResponse(BaseModel):
    predictions: list[PredictionResponse]
    model_version: str
    model_mode: str

