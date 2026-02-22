WEAK_ALGORITHMS = {
    "MD5": "Use SHA-256 or SHA-3",
    "SHA1": "Use SHA-256 or SHA-3",
    "DES": "Use AES-256",
    "RSA": "Use CRYSTALS-Kyber for key exchange"
}

def detect_crypto(code: str, tree):
    findings = []

    root = tree.root_node

    def walk(node):
        if node.type == "identifier":
            text = code[node.start_byte:node.end_byte]

            if text in WEAK_ALGORITHMS:
                findings.append({
                    "algorithm": text,
                    "line": node.start_point[0] + 1,
                    "severity": "HIGH",
                    "recommendation": WEAK_ALGORITHMS[text]
                })

        # crude key size detection
        if node.type == "decimal_integer_literal":
            value = code[node.start_byte:node.end_byte]
            if value in ["1024", "2048"]:
                findings.append({
                    "algorithm": "RSA",
                    "line": node.start_point[0] + 1,
                    "severity": "CRITICAL" if value == "1024" else "MEDIUM",
                    "key_size": value,
                    "recommendation": "Use Kyber (post-quantum safe)"
                })

        for child in node.children:
            walk(child)

    walk(root)

    return findings