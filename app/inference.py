"""Local six-label inference; a reviewed checkpoint is required in real mode.

This module never downloads a model or initializes an untrained replacement
classification head. Long inputs raise a coverage exception before inference.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.contracts import GROUPS, CodeUnit, Prediction


class EngineUnavailable(RuntimeError):
    """The approved model cannot produce trustworthy probabilities."""


class ContextTooLong(ValueError):
    def __init__(self, token_count: int, max_tokens: int):
        self.token_count = token_count
        self.max_tokens = max_tokens
        super().__init__(f"Context has {token_count} tokens; limit is {max_tokens}")


def _nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonblank string")
    return value.strip()


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    return float(value)


@dataclass(frozen=True)
class Policy:
    version: str
    release_approved: bool
    block_checkmarx_severities: frozenset[str]
    review_score_margin: float


def load_policy(path: Path | str) -> Policy:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Policy must be an object")
    version = _nonblank(data.get("version"), "version")
    if type(data.get("release_approved")) is not bool:
        raise ValueError("release_approved must be a boolean")
    severities = data.get("block_checkmarx_severities")
    allowed = {"critical", "high", "medium", "low", "info", "unknown"}
    if not isinstance(severities, list) or any(
        not isinstance(item, str) or item not in allowed for item in severities
    ):
        raise ValueError("block_checkmarx_severities contains an invalid severity")
    margin = _number(data.get("review_score_margin"), "review_score_margin")
    if not 0 <= margin <= 1:
        raise ValueError("review_score_margin must be in [0, 1]")
    # A policy can make the gate stricter; it cannot permit high-risk evidence.
    return Policy(version, data["release_approved"],
                  frozenset(severities) | {"critical", "high"}, margin)


@dataclass(frozen=True)
class Manifest:
    model_version: str
    tokenizer_version: str
    dataset_version: str
    validation_report: str
    max_tokens: int
    thresholds: dict[str, float]


def load_manifest(model_dir: Path | str) -> Manifest:
    data = json.loads((Path(model_dir) / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Manifest must be an object")
    if data.get("approved_for_inference") is not True:
        raise ValueError("The checkpoint is not approved for inference")
    if data.get("task") != "multi_label_classification":
        raise ValueError("The checkpoint must be trained for multi-label classification")
    versions = {field: _nonblank(data.get(field), field) for field in (
        "model_version", "tokenizer_version", "dataset_version", "validation_report"
    )}
    expected = {label: index for index, label in enumerate(GROUPS)}
    mapping = data.get("label_mapping")
    if mapping != expected or any(type(index) is not int for index in mapping.values()):
        raise ValueError("Manifest labels must use the six canonical indices")
    maximum = data.get("max_tokens")
    if type(maximum) is not int or not 1 <= maximum <= 512:
        raise ValueError("max_tokens must be an integer in [1, 512]")
    raw_thresholds = data.get("thresholds")
    if not isinstance(raw_thresholds, dict) or set(raw_thresholds) != set(GROUPS):
        raise ValueError("Exactly six calibrated thresholds are required")
    thresholds = {label: _number(value, f"thresholds.{label}")
                  for label, value in raw_thresholds.items()}
    if any(not 0 < value < 1 for value in thresholds.values()):
        raise ValueError("Thresholds must be in (0, 1)")
    return Manifest(**versions, max_tokens=maximum, thresholds=thresholds)


def validate_checkpoint_config(config: dict[str, Any]) -> None:
    """Reject base CodeBERT config and incompatible/random label heads."""
    label2id = {label: index for index, label in enumerate(GROUPS)}
    id2label = {str(index): label for index, label in enumerate(GROUPS)}
    if config.get("model_type") != "roberta":
        raise ValueError("Checkpoint must use the CodeBERT RoBERTa architecture")
    if config.get("architectures") != ["RobertaForSequenceClassification"]:
        raise ValueError("Checkpoint must contain a trained sequence classification head")
    if config.get("problem_type") != "multi_label_classification":
        raise ValueError("Checkpoint problem_type must be multi_label_classification")
    if config.get("label2id") != label2id or config.get("id2label") != id2label:
        raise ValueError("Checkpoint label indices do not match the reviewed manifest")
    if any(type(index) is not int for index in config["label2id"].values()):
        raise ValueError("Checkpoint label indices must be integers")
    if "num_labels" in config and (type(config["num_labels"]) is not int or config["num_labels"] != 6):
        raise ValueError("Checkpoint must have six labels")


def validate_loading_info(info: dict[str, Any]) -> None:
    """HF can otherwise silently initialize a missing classification head."""
    for field in ("missing_keys", "mismatched_keys", "unexpected_keys", "error_msgs"):
        if info.get(field):
            raise EngineUnavailable(f"Checkpoint loading reported {field}")


class RealEngine:
    mode = "real"

    def __init__(self, model_dir: Path | str):
        directory = Path(model_dir)
        self.manifest = load_manifest(directory)
        config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
        validate_checkpoint_config(config)
        if not (directory / "model.safetensors").is_file() and not (
            directory / "model.safetensors.index.json"
        ).is_file():
            raise EngineUnavailable("Local safetensors checkpoint weights are required")
        # Heavy dependencies are intentionally optional in the gateway/demo stack.
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(
            str(directory), local_files_only=True, trust_remote_code=False
        )
        self.model, loading_info = AutoModelForSequenceClassification.from_pretrained(
            str(directory), local_files_only=True, trust_remote_code=False,
            use_safetensors=True, output_loading_info=True,
        )
        validate_loading_info(loading_info)
        runtime_config = self.model.config.to_dict()
        runtime_config["id2label"] = {str(key): value for key, value in runtime_config["id2label"].items()}
        validate_checkpoint_config(runtime_config)
        if self.model.config.num_labels != len(GROUPS):
            raise EngineUnavailable("Loaded classifier does not have six labels")
        self.model.eval()
        self.model_version = self.manifest.model_version
        self.max_tokens = self.manifest.max_tokens
        self.thresholds = self.manifest.thresholds

    def predict(self, unit: CodeUnit) -> Prediction:
        encoded = self.tokenizer(unit.code, add_special_tokens=True, truncation=False,
                                 return_attention_mask=True)
        token_count = len(encoded["input_ids"])
        if token_count > self.max_tokens:
            raise ContextTooLong(token_count, self.max_tokens)
        inputs = {key: self.torch.tensor([value]) for key, value in encoded.items()
                  if key in self.tokenizer.model_input_names}
        with self.torch.inference_mode():
            logits = self.model(**inputs).logits
            if tuple(logits.shape) != (1, len(GROUPS)) or not self.torch.isfinite(logits).all().item():
                raise EngineUnavailable("Classifier produced an invalid output")
            probabilities = self.torch.sigmoid(logits)[0].tolist()
        return Prediction(unit_id=unit.unit_id, token_count=token_count,
                          scores=dict(zip(GROUPS, probabilities)))


class DemoEngine:
    """Deterministic wiring fixture; this engine can never authorize deployment."""
    mode = "demo"
    model_version = "demo-fixture-v1"
    max_tokens = 512
    thresholds = {label: 0.8 for label in GROUPS}

    def predict(self, unit: CodeUnit) -> Prediction:
        # This count only exercises coverage handling in demo, not model accuracy.
        token_count = len(re.findall(r"\w+|[^\w\s]", unit.code)) + 2
        if token_count > self.max_tokens:
            raise ContextTooLong(token_count, self.max_tokens)
        marked = set()
        for match in re.finditer(r"(?m)^\s*#\s*demo:\s*([^\r\n]+)", unit.code):
            marked.update(re.findall(r"[A-Z_]+", match.group(1)))
        return Prediction(unit_id=unit.unit_id, token_count=token_count,
                          scores={label: 0.95 if label in marked else 0.02 for label in GROUPS})


def build_engine(mode: str, model_dir: Path | str):
    if mode == "demo":
        return DemoEngine()
    if mode != "real":
        raise ValueError("MODEL_MODE must be real or demo")
    return RealEngine(model_dir)
