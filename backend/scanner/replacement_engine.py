from typing import Dict, List


class ReplacementEngine:
    """
    Deterministic secure migration engine.
    No AI is used for cryptographic replacement.
    """

    TEMPLATES = {
        "RSA_2048": [
            'KeyEncapsulation kem = new KeyEncapsulation("Kyber512");',
            "byte[] publicKey = kem.generateKeyPair().getPublic();"
        ],
        "RSA_1024": [
            'KeyEncapsulation kem = new KeyEncapsulation("Kyber512");',
            "byte[] publicKey = kem.generateKeyPair().getPublic();"
        ],
    }

    def generate_fix(self, finding: Dict, original_line: str) -> Dict:
        """
        Generates deterministic replacement diff.
        """

        algorithm = finding.get("algorithm")
        key_size = finding.get("key_size")

        template_key = f"{algorithm}_{key_size}"

        if template_key not in self.TEMPLATES:
            return {}

        replacement_lines = self.TEMPLATES[template_key]

        diff = self._build_diff(original_line, replacement_lines)

        return {
            "line": finding.get("line"),
            "diff": diff
        }

    def _build_diff(self, original_line: str, replacement_lines: List[str]) -> str:
        """
        Creates minimal unified diff.
        """

        diff_lines = [
            "--- original",
            "+++ migrated",
            "@@ -1 +1,{} @@".format(len(replacement_lines))
        ]

        diff_lines.append(f"-{original_line.strip()}")

        for line in replacement_lines:
            diff_lines.append(f"+{line}")

        return "\n".join(diff_lines)