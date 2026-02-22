from typing import Dict


class GradingService:
    """
    Calculates security posture and migration priority.
    """

    RISK_SCORES = {
        "RSA_1024": 9,
        "RSA_2048": 7,
        "SHA1": 8,
    }

    def assess(self, finding: Dict) -> Dict:
        algorithm = finding.get("algorithm")
        key_size = finding.get("key_size")

        template_key = f"{algorithm}_{key_size}"

        risk_score = self.RISK_SCORES.get(template_key, 5)

        quantum_safe = algorithm in ["Kyber", "ML-KEM"]

        return {
            "overall_security_posture": {
                "classical_compliance": self._classical_status(algorithm, key_size),
                "quantum_readiness": "READY" if quantum_safe else "NOT_READY",
                "harvest_now_decrypt_later_risk": not quantum_safe,
                "migration_priority": self._priority(risk_score),
                "overall_cvss_score": risk_score,
                "compliance_badge": self._badge(risk_score),
            },
            "details": [
                {
                    "algorithm": template_key,
                    "classification": {
                        "classical_status": self._classical_status(algorithm, key_size),
                        "quantum_status": "QUANTUM_SAFE" if quantum_safe else "NOT_QUANTUM_SAFE",
                        "nist_reference": "SP 800-131A Rev2 + NIST PQC 2023",
                        "nist_800_53_controls": ["SC-12"],
                    },
                    "cvss_score": risk_score,
                }
            ],
        }

    def _classical_status(self, algorithm: str, key_size: str) -> str:
        if algorithm == "RSA" and int(key_size) >= 2048:
            return "APPROVED"
        if algorithm == "RSA":
            return "DEPRECATED"
        return "APPROVED"

    def _priority(self, score: int) -> str:
        if score >= 8:
            return "CRITICAL"
        if score >= 6:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW"

    def _badge(self, score: int) -> str:
        if score >= 8:
            return "CRITICAL_RISK"
        if score >= 6:
            return "HIGH_RISK"
        if score >= 4:
            return "MODERATE_RISK"
        return "LOW_RISK"