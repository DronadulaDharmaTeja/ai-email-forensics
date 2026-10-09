"""Phishing detection using the validated Linear SVM model."""

from pathlib import Path
import joblib

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "models" / "tfidf_svm_grouped_validated.pkl"
VECTORIZER_PATH = PROJECT_ROOT / "models" / "tfidf_vectorizer_grouped_validated.pkl"

_model = None
_vectorizer = None


def _load_artifacts():
    global _model, _vectorizer

    if _model is None or _vectorizer is None:
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)

    return _model, _vectorizer


def predict_email(text: str) -> dict:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Email text must be a non-empty string.")

    model, vectorizer = _load_artifacts()
    features = vectorizer.transform([text])
    score = float(model.decision_function(features)[0])
    prediction = int(score >= 0.0)

    return {
        "label": "PHISHING" if prediction == 1 else "LEGITIMATE",
        "prediction": prediction,
        "decision_score": round(score, 4),
        "threshold": 0.0,
        "model": "LinearSVC",
        "score_type": "decision_function_not_probability",
    }
