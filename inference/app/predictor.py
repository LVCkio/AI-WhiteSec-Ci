from __future__ import annotations

from abc import ABC, abstractmethod
import os
import re

from .schemas import PredictionRequest, PredictionResponse


SUPPORTED_CWES = ["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-287"]


class Predictor(ABC):
    model_version: str
    model_mode: str

    @abstractmethod
    def predict(self, sample: PredictionRequest) -> PredictionResponse:
        raise NotImplementedError


class MockPredictor(Predictor):
    """Deterministic contract test; this is not a vulnerability detector."""

    def __init__(self) -> None:
        self.model_version = os.getenv("MODEL_VERSION", "mock-codebert-5cwe-v1")
        self.model_mode = "mock"
        self.rules = [
            (
                "CWE-89",
                re.compile(r"(execute|raw)\s*\([^\n]*(\+|%|\.format\(|f[\"'])", re.I),
                0.93,
                "Mock rule saw dynamic text passed to a SQL-like execution API.",
            ),
            (
                "CWE-78",
                re.compile(r"(os\.system\s*\(|shell\s*=\s*True|subprocess\.[a-z]+\([^\n]*(\+|f[\"']))", re.I),
                0.91,
                "Mock rule saw shell execution with dynamic command construction.",
            ),
            (
                "CWE-79",
                re.compile(r"(render_template_string|mark_safe|safe\s*\}\}|innerHTML)", re.I),
                0.84,
                "Mock rule saw an API that can bypass normal output escaping.",
            ),
            (
                "CWE-22",
                re.compile(r"open\s*\([^\n]*(request|input|filename|path)|send_file\s*\(", re.I),
                0.79,
                "Mock rule saw a path-sensitive API near an input-like value.",
            ),
            (
                "CWE-287",
                re.compile(r"(verify\s*=\s*False|is_authenticated\s*=\s*True|skip_auth)", re.I),
                0.82,
                "Mock rule saw an authentication control that appears disabled or bypassed.",
            ),
        ]

    def predict(self, sample: PredictionRequest) -> PredictionResponse:
        matched = [rule for rule in self.rules if rule[1].search(sample.code)]
        scores = {label: 0.02 for label in SUPPORTED_CWES}
        scores["SAFE"] = 0.82
        if matched:
            label, _, confidence, explanation = max(matched, key=lambda rule: rule[2])
            scores[label] = confidence
            scores["SAFE"] = round(1 - confidence, 4)
            return PredictionResponse(
                label=label,
                cwe=label,
                confidence=confidence,
                scores=scores,
                model_version=self.model_version,
                model_mode=self.model_mode,
                risk_detected=True,
                explanation=explanation,
            )
        return PredictionResponse(
            label="SAFE",
            cwe=None,
            confidence=0.82,
            scores=scores,
            model_version=self.model_version,
            model_mode=self.model_mode,
            risk_detected=False,
            explanation="No supported CWE pattern was detected by the mock. This is not proof that the code is safe.",
        )


class CodeBertPredictor(Predictor):
    """Production CodeBERT classifier.

    Environment variables
    ---------------------
    CHECKPOINT_DIR  : Path to the fine-tuned checkpoint directory that must
                      contain:
                        - config.json / pytorch_model.bin (or model.safetensors)
                        - tokenizer_config.json + vocab.json / merges.txt
                        - label_map.json  {"0": "SAFE", "1": "CWE-89", ...}
                        - thresholds.json {"CWE-89": 0.72, "CWE-79": 0.68, ...}
                        - model_meta.json {"model_version": "codebert-5cwe-v2"}
    MODEL_VERSION   : Override model_version string (optional).

    The implementation intentionally imports torch and transformers lazily so
    that the inference container can start without GPU drivers when running in
    mock mode.
    """

    def __init__(self) -> None:
        import json
        from pathlib import Path

        checkpoint_dir_env = os.getenv("CHECKPOINT_DIR", "")
        if not checkpoint_dir_env:
            raise RuntimeError(
                "MODEL_MODE=codebert requires CHECKPOINT_DIR to point to the "
                "fine-tuned checkpoint directory. See inference/app/predictor.py "
                "for the expected directory layout."
            )
        checkpoint_dir = Path(checkpoint_dir_env)
        if not checkpoint_dir.is_dir():
            raise RuntimeError(
                f"CHECKPOINT_DIR={checkpoint_dir} does not exist or is not a directory."
            )

        # ── Lazy imports ─────────────────────────────────────────────────────
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "torch and transformers must be installed to use MODEL_MODE=codebert. "
                "Add them to inference/requirements.txt."
            ) from exc

        # ── Tokenizer ────────────────────────────────────────────────────────
        self._tokenizer = AutoTokenizer.from_pretrained(str(checkpoint_dir))

        # ── Model ────────────────────────────────────────────────────────────
        self._model = AutoModelForSequenceClassification.from_pretrained(str(checkpoint_dir))
        self._model.eval()
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._model.to(self._device)
        self._torch = torch

        # ── Label map  {int_id: label_string} ────────────────────────────────
        label_map_path = checkpoint_dir / "label_map.json"
        if not label_map_path.exists():
            raise RuntimeError(f"label_map.json not found in {checkpoint_dir}")
        raw_map: dict[str, str] = json.loads(label_map_path.read_text(encoding="utf-8"))
        self._id2label: dict[int, str] = {int(k): v for k, v in raw_map.items()}

        # ── Per-CWE decision thresholds ───────────────────────────────────────
        thresholds_path = checkpoint_dir / "thresholds.json"
        self._thresholds: dict[str, float] = (
            json.loads(thresholds_path.read_text(encoding="utf-8"))
            if thresholds_path.exists()
            else {}
        )
        self._default_threshold = float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.70"))

        # ── Model metadata ───────────────────────────────────────────────────
        meta_path = checkpoint_dir / "model_meta.json"
        meta: dict = (
            json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        )
        self.model_version = os.getenv(
            "MODEL_VERSION", meta.get("model_version", "codebert-unknown")
        )
        self.model_mode = "codebert"

        self._max_length: int = int(os.getenv("CODEBERT_MAX_LENGTH", "512"))

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, sample: PredictionRequest) -> PredictionResponse:
        import torch

        inputs = self._tokenizer(
            sample.code,
            truncation=True,
            max_length=self._max_length,
            return_tensors="pt",
        )
        inputs = {k: v.to(self._device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self._model(**inputs).logits  # shape: (1, num_labels)

        probs = torch.softmax(logits, dim=-1).squeeze(0).tolist()

        scores: dict[str, float] = {
            self._id2label[i]: round(float(p), 6) for i, p in enumerate(probs)
        }

        # Find the highest-scoring non-SAFE label.
        cwe_scores = {label: score for label, score in scores.items() if label != "SAFE"}
        best_label = max(cwe_scores, key=lambda l: cwe_scores[l]) if cwe_scores else None
        best_confidence = cwe_scores[best_label] if best_label else 0.0
        threshold = self._thresholds.get(best_label or "", self._default_threshold)

        risk_detected = best_label in SUPPORTED_CWES and best_confidence >= threshold

        if risk_detected:
            return PredictionResponse(
                label=best_label,
                cwe=best_label,
                confidence=round(best_confidence, 6),
                scores=scores,
                model_version=self.model_version,
                model_mode=self.model_mode,
                risk_detected=True,
                explanation=(
                    f"CodeBERT predicted {best_label} with confidence "
                    f"{best_confidence:.2%} (threshold {threshold:.2%})."
                ),
            )

        safe_conf = scores.get("SAFE", round(1 - best_confidence, 4))
        return PredictionResponse(
            label="SAFE",
            cwe=None,
            confidence=round(safe_conf, 6),
            scores=scores,
            model_version=self.model_version,
            model_mode=self.model_mode,
            risk_detected=False,
            explanation=(
                "No supported CWE met the decision threshold. "
                "SAFE does not mean globally secure."
            ),
        )


def build_predictor() -> Predictor:
    mode = os.getenv("MODEL_MODE", "mock").strip().lower()
    if mode == "mock":
        return MockPredictor()
    if mode == "codebert":
        return CodeBertPredictor()
    raise RuntimeError(f"Unsupported MODEL_MODE: {mode}")


