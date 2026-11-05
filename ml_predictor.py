from functools import lru_cache
import joblib
import pandas as pd
from django.conf import settings
from .features import extract_url_features, FEATURE_NAMES, FEATURE_VERSION

@lru_cache(maxsize=1)
def load_model(path, modified):
    # Only load the local artifact produced by our own training script.
    bundle = joblib.load(path)
    if bundle.get("feature_names") != FEATURE_NAMES or bundle.get("feature_version") != FEATURE_VERSION:
        raise ValueError("The saved model feature schema is incompatible. Retrain it.")
    # One URL per request: avoid worker-pool overhead and Windows pipe permissions.
    bundle["model"].set_params(n_jobs=1)
    return bundle

def predict_phishing(url):
    path = settings.BASE_DIR / "ml" / "saved_models" / "phishing_model.joblib"
    if not path.is_file():
        raise FileNotFoundError("The URL model has not been trained yet.")
    bundle = load_model(str(path), path.stat().st_mtime_ns)
    model = bundle["model"]
    frame = pd.DataFrame([extract_url_features(url)], columns=FEATURE_NAMES)
    index = list(model.classes_).index(1)
    probability = float(model.predict_proba(frame)[0][index]) * 100
    return round(probability, 2), bundle["model_version"]
