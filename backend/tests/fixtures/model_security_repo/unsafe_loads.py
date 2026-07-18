import joblib
import pickle
import torch


def load_artifacts(uploaded_path: str, safe_path: str, payload: bytes) -> None:
    pickle.load(open(uploaded_path, "rb"))
    pickle.loads(payload)
    torch.load(uploaded_path)
    joblib.load("models/recommender.joblib")
    torch.load(safe_path, weights_only=True)
