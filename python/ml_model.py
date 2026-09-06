import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


FEATURES = [
    "request_rate",
    "bad_request_rate",
    "temperature",
    "humidity",
]


def create_model():
    return IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )


def train_model(normal_data):
    model = create_model()

    X = np.array([
        [
            row["request_rate"],
            row["bad_request_rate"],
            row["temperature"],
            row["humidity"],
        ]
        for row in normal_data
    ])

    model.fit(X)
    return model


def save_model(model, filename="intrusion_model.pkl"):
    joblib.dump(model, filename)


def load_model(filename="intrusion_model.pkl"):
    if not os.path.exists(filename):
        return None
    return joblib.load(filename)


def predict(model, data):
    if model is None:
        return {
            "prediction": "UNKNOWN",
            "score": 0.0,
        }

    X = np.array([[
        float(data.get("request_rate", 0)),
        float(data.get("bad_request_rate", 0)),
        float(data.get("temperature", 25)),
        float(data.get("humidity", 50)),
    ]])

    prediction = model.predict(X)[0]
    score = model.decision_function(X)[0]

    return {
        "prediction": "NORMAL" if prediction == 1 else "ANOMALY",
        "score": float(score),
    }
