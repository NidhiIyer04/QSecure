def normalize_algorithm(finding):
    algo = finding.get("algorithm")
    key_size = finding.get("key_size")

    if algo == "RSA" and key_size:
        return f"RSA_{key_size}"

    return algo


def detect_hybrid_crypto(findings):
    algorithms = set()

    for f in findings:
        normalized = normalize_algorithm(f)
        algorithms.add(normalized)

    # Hybrid detection logic
    has_classical_rsa = any(a.startswith("RSA_") for a in algorithms)
    has_mlkem = any("ML-KEM" in a or "KYBER" in a.upper() for a in algorithms)

    return {
        "hybrid_detected": has_classical_rsa and has_mlkem,
        "algorithms_detected": list(algorithms)
    }