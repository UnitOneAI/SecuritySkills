"""Vulnerable fixture: high-resolution confidence output over sensitive data."""


class RiskRequest:
    def __init__(self, text):
        self.text = text


class TicketRiskModel:
    def predict_proba(self, features):
        # Trained on real support tickets that may contain personal data.
        return [[0.02, 0.03, 0.95]]


labels = ["low", "medium", "high"]
model = TicketRiskModel()


def vectorize(text):
    return [text]


def predict_risk(req):
    probs = model.predict_proba(vectorize(req.text))[0]
    ranked = sorted(zip(labels, probs), key=lambda item: item[1], reverse=True)

    return {
        "label": ranked[0][0],
        "confidence": float(ranked[0][1]),
        "top_k": [{"label": label, "probability": prob} for label, prob in ranked],
    }


# Expected review outcome: High if this endpoint handles sensitive personal
# training data and lacks membership-inference evaluation plus query controls.
