def grade_findings(findings):
    score = 100

    for f in findings:
        if f["severity"] == "CRITICAL":
            score -= 40
        elif f["severity"] == "HIGH":
            score -= 25
        elif f["severity"] == "MEDIUM":
            score -= 10

    score = max(score, 0)

    return {
        "security_score": score,
        "risk_level": (
            "CRITICAL" if score < 40 else
            "HIGH" if score < 60 else
            "MODERATE" if score < 80 else
            "SAFE"
        )
    }