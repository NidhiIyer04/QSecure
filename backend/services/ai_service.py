from typing import Dict, Any


class AIService:
    """
    AI Service is strictly used for contextual explanations.
    It does NOT generate cryptographic code.
    """

    FORBIDDEN_PATTERNS = [
        "```",
        "class ",
        "public static void main",
        "System.out",
        "import ",
        "KeyPairGenerator",
        "Cipher",
    ]

    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def _sanitize(self, output: str) -> str:
        """
        Prevent unsafe or structured code generation.
        """
        for pattern in self.FORBIDDEN_PATTERNS:
            if pattern in output:
                raise ValueError("LLM output contains forbidden content")

        return output.strip()

    def generate_explanation(self, finding: Dict[str, Any]) -> str:
        """
        Generates a short security explanation for a detected issue.
        """

        if not self.llm_client:
            return self._fallback_explanation(finding)

        prompt = f"""
Explain why the following cryptographic algorithm is not quantum-safe.

Algorithm: {finding.get("algorithm")}
Key Size: {finding.get("key_size")}
Severity: {finding.get("severity")}

Rules:
- 2-3 sentences maximum
- No code
- No markdown
- No imports
- No examples
- No formatting symbols
"""

        raw_output = self.llm_client.generate(prompt)
        return self._sanitize(raw_output)

    def _fallback_explanation(self, finding: Dict[str, Any]) -> str:
        """
        Deterministic fallback explanation if LLM unavailable.
        """

        if finding.get("algorithm") == "RSA":
            return (
                "RSA relies on integer factorization, which is vulnerable "
                "to Shor’s algorithm on sufficiently powerful quantum computers. "
                "Migration to post-quantum cryptography is recommended."
            )

        return "The detected algorithm is not considered quantum-safe and should be migrated."