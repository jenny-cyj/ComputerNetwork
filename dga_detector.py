from dataclasses import dataclass
from typing import Optional


@dataclass
class DGAResult:
    domain: str
    is_malicious: bool
    score: float


class DGAClassifier:
    def __init__(self, model_path: str, threshold: float = 0.5) -> None:
        from joblib import load

        self.model_path = model_path
        self.threshold = threshold
        self.model = load(model_path)

    def predict(self, domain: str) -> DGAResult:
        score = self._score(domain)
        return DGAResult(domain=domain, is_malicious=score >= self.threshold, score=score)

    def _score(self, domain: str) -> float:
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba([domain])[0]
            classes = list(self.model.classes_)
            malicious_index = classes.index(1) if 1 in classes else len(classes) - 1
            return float(probabilities[malicious_index])

        if hasattr(self.model, "decision_function"):
            decision = float(self.model.decision_function([domain])[0])
            return 1.0 / (1.0 + pow(2.718281828, -decision))

        prediction = int(self.model.predict([domain])[0])
        return 1.0 if prediction == 1 else 0.0


def load_detector(model_path: Optional[str], threshold: float) -> Optional[DGAClassifier]:
    if not model_path:
        return None
    return DGAClassifier(model_path=model_path, threshold=threshold)
