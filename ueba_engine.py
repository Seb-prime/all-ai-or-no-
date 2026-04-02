import numpy as np
from sklearn.ensemble import IsolationForest


class UEBAEngine:
    """
    Two-tier anomaly detection:
      Tier 1 — Rule-based: deterministic catches (clearance breach, brute force, bad IP)
      Tier 2 — ML-based:  Isolation Forest on numeric features for subtle patterns
    """

    SUSPICIOUS_IPS = {"185.220.101.47", "91.108.4.200", "77.88.55.60", "198.54.117.212"}
    BUSINESS_HOURS = range(7, 19) 

    def __init__(self):
        self._model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        self._fitted = False
        self._history = [] 
        self._event_store = [] 
        self._threat_store = [] 

    def analyse(self, event: dict) -> dict:
        """Analyse a single event. Returns the event enriched with threat metadata."""
        rule_hit, rule_reasons = self._rule_check(event)
        ml_score = self._ml_score(event)

        is_threat = rule_hit or ml_score < 0
        final_risk = self._combine_risk(event.get("risk_score", 0.5), rule_hit, ml_score)

        enriched = {
            **event,
            "rule_triggered": rule_hit,
            "ml_anomaly": ml_score < 0,
            "ml_raw_score": round(float(ml_score), 4),
            "final_risk": round(final_risk, 3),
            "is_threat": is_threat,
            "threat_reasons": event.get("reasons", []) + rule_reasons,
        }

        self._event_store.append(enriched)
        self._update_model(event)

        if is_threat:
            self._threat_store.append(enriched)

        return enriched

    def get_all_events(self, limit=100):
        return list(reversed(self._event_store))[:limit]

    def get_threats(self, limit=50):
        return list(reversed(self._threat_store))[:limit]

    def stats(self):
        total = len(self._event_store)
        threats = len(self._threat_store)
        by_type = {}
        for e in self._event_store:
            t = e.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "total_events": total,
            "total_threats": threats,
            "threat_rate": round(threats / total, 3) if total else 0,
            "events_by_type": by_type,
            "model_fitted": self._fitted,
        }

    def _rule_check(self, event):
        reasons = []
        hit = False

        etype = event.get("type")

        if etype == "login":
            if event.get("ip_address") in self.SUSPICIOUS_IPS:
                reasons.append("IP on threat intelligence blocklist")
                hit = True
            if event.get("failed_attempts", 0) >= 5:
                reasons.append("brute-force threshold exceeded ({} attempts)".format(event["failed_attempts"]))
                hit = True
            if event.get("hour_utc") not in self.BUSINESS_HOURS:
                reasons.append("access outside permitted hours ({}:00 UTC)".format(event.get("hour_utc")))
                hit = True

        elif etype == "file_access":
            uc = event.get("user_clearance", 0)
            fc = event.get("file_clearance", 0)
            if uc < fc:
                reasons.append("clearance violation: {} attempted {} resource".format(
                    event.get("user_clearance_label"), event.get("file_clearance_label")))
                hit = True

        elif etype == "network":
            if event.get("dst_ip") in self.SUSPICIOUS_IPS:
                reasons.append("traffic to known malicious IP {}".format(event.get("dst_ip")))
                hit = True
            if event.get("bytes_sent", 0) > 200_000:
                reasons.append("large data transfer: {} KB exfiltration pattern".format(event.get("bytes_kb")))
                hit = True

        return hit, reasons

    def _ml_score(self, event):
        """Returns IsolationForest decision score. Negative = anomaly."""
        vec = self._featurise(event)
        if not self._fitted or len(self._history) < 20:
            return 1  # not enough data yet, don't flag
        return self._model.decision_function([vec])[0]

    def _featurise(self, event):
        etype = event.get("type", "")
        return [
            1 if etype == "login" else 0,
            1 if etype == "file_access" else 0,
            1 if etype == "network" else 0,
            event.get("failed_attempts", 0),
            event.get("hour_utc", 12),
            1 if event.get("ip_address") in self.SUSPICIOUS_IPS else 0,
            1 if event.get("dst_ip") in self.SUSPICIOUS_IPS else 0,
            max(0, event.get("file_clearance", 0) - event.get("user_clearance", 0)),
            event.get("bytes_sent", 0) / 1_000_000,
            event.get("risk_score", 0.0),
        ]

    def _update_model(self, event):
        self._history.append(self._featurise(event))
        if len(self._history) >= 20 and len(self._history) % 10 == 0:
            X = np.array(self._history)
            self._model.fit(X)
            self._fitted = True

    def _combine_risk(self, base_score, rule_hit, ml_score):
        score = base_score
        if rule_hit:
            score = max(score, 0.75)
        if ml_score < 0:
            score = max(score, 0.6)
        if rule_hit and ml_score < 0:
            score = min(score + 0.15, 0.99)
        return score
