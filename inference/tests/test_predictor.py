from app.predictor import MockPredictor
from app.schemas import PredictionRequest


def test_mock_detects_dynamic_sql():
    result = MockPredictor().predict(
        PredictionRequest(code="cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")")
    )
    assert result.cwe == "CWE-89"
    assert result.risk_detected is True


def test_safe_is_scoped_not_absolute():
    result = MockPredictor().predict(PredictionRequest(code="def add(a, b):\n    return a + b"))
    assert result.label == "SAFE"
    assert "not proof" in result.explanation

