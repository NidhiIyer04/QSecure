def scan_code_for_crypto(code: str):
    findings = []

    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        if "KeyPairGenerator.getInstance(\"RSA\")" in line:
            findings.append({
                "algorithm": "RSA",
                "key_size": "2048",
                "line": idx,
                "original_line": line.strip(),
                "severity": "HIGH",
            })

    return findings