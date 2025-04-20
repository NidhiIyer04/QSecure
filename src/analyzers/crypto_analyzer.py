import sys
import os
import re
import ast
import logging
import json
import pandas as pd
from collections import defaultdict
import networkx as nx
from tqdm import tqdm

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import CRYPTO_CONFIG, STATIC_ANALYSIS_CONFIG

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ✅ Expanded Java Crypto API regex triggers
java_triggers = [
    r'Cipher\.getInstance\(\".*\"',
    r'KeyPairGenerator\.getInstance\(\".*\"',
    r'MessageDigest\.getInstance\(\".*\"',
    r'Mac\.getInstance\(\".*\"',
    r'KeyGenerator\.getInstance\(\".*\"',
    r'KeyFactory\.getInstance\(\".*\"'
]

# ✅ Expanded JavaScript (Node.js Crypto module) regex triggers
javascript_triggers = [
    r'crypto\.createCipheriv\(\"[a-zA-Z0-9\-]+\"',
    r'crypto\.createCipher\(\"[a-zA-Z0-9\-]+\"',
    r'crypto\.createDecipher\(\"[a-zA-Z0-9\-]+\"',
    r'crypto\.createDecipheriv\(\"[a-zA-Z0-9\-]+\"',
    r'crypto\.createHmac\(\"[a-zA-Z0-9\-]+\"',
    r'crypto\.createSign\(\"[a-zA-Z0-9\-]+\"',
    r'crypto\.createVerify\(\"[a-zA-Z0-9\-]+\"',
    r'crypto\.publicEncrypt\(',
    r'crypto\.privateDecrypt\(',
    r'crypto\.generateKeyPair\(',
    r'crypto\.generateKeyPairSync\('
]

class CryptoStaticAnalyzer:
    """Static analyzer for cryptographic code."""

    def __init__(self):
        self.quantum_vulnerable = set(CRYPTO_CONFIG.get("quantum_vulnerable", []))
        self.symmetric_affected = CRYPTO_CONFIG.get("symmetric_affected", [])
        self.quantum_resistant = CRYPTO_CONFIG.get("quantum_resistant", [])
        self.minimum_key_lengths = CRYPTO_CONFIG.get("minimum_key_lengths", {})
        self.recommended_key_lengths = CRYPTO_CONFIG.get("recommended_key_lengths", {})

        # Base crypto patterns from config
        self.crypto_patterns = STATIC_ANALYSIS_CONFIG.get("crypto_patterns", {})

        # Inject updated regex patterns dynamically
        self.crypto_patterns["java"] = {"crypto_api_usage": java_triggers}
        self.crypto_patterns["javascript"] = {"crypto_api_usage": javascript_triggers}

    def analyze_file(self, file_path):
        vulnerabilities = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                logger.info(f"Analyzing {file_path}")

                for lang, patterns in self.crypto_patterns.items():
                    if not file_path.endswith(self.get_extension(lang)):
                        continue

                    for pattern_type, regex_list in patterns.items():
                        for regex in regex_list:
                            logger.debug(f"Using regex: {regex}")
                            matches = list(re.finditer(regex, content))
                            logger.info(f"Found {len(matches)} matches for {lang}")

                            for match in matches:
                                vulnerabilities.append({
                                    "file": file_path,
                                    "language": lang,
                                    "type": pattern_type,
                                    "match": match.group(),
                                    "line": content[:match.start()].count('\n') + 1
                                })

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
        return vulnerabilities

    def get_extension(self, language):
        """Map language to file extension."""
        return {
            "python": ".py",
            "java": ".java",
            "javascript": ".js"
        }.get(language, "")

    def analyze_directory(self, directory):
        """Analyze all files in a directory."""
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.py', '.java', '.js')):
                    file_path = os.path.join(root, file)
                    results.extend(self.analyze_file(file_path))
        return results


class FeatureExtractor:
    """Extract features from cryptographic code for ML analysis."""

    def __init__(self):
        self.features = []

    def extract_features(self, vulnerabilities):
        """Extract relevant features from vulnerabilities."""
        extracted_features = []
        for vuln in vulnerabilities:
            quantum_vuln_flag = self.check_quantum_vulnerable(vuln["match"])
            feature = {
                "file": vuln["file"],
                "language": vuln["language"],
                "type": vuln["type"],
                "match": vuln["match"],
                "line": vuln["line"],
                "severity": self.assign_severity(vuln["match"]),
                "quantum_vulnerable": quantum_vuln_flag
            }
            extracted_features.append(feature)
        return extracted_features

    def assign_severity(self, match):
        """Assign severity score based on cryptographic weakness."""
        if any(qv in match for qv in CRYPTO_CONFIG.get("quantum_vulnerable", [])):
            return "High"
        elif any(qr in match for qr in CRYPTO_CONFIG.get("quantum_resistant", [])):
            return "Low"
        return "Medium"

    def check_quantum_vulnerable(self, match):
        """Check if the matched string involves a quantum-vulnerable algorithm."""
        return int(any(qv in match for qv in CRYPTO_CONFIG.get("quantum_vulnerable", [])))



if __name__ == "__main__":
    analyzer = CryptoStaticAnalyzer()
    feature_extractor = FeatureExtractor()

    # Analyze code files in a given directory
    analysis_results = analyzer.analyze_directory("src")
    features = feature_extractor.extract_features(analysis_results)

    # Convert results to DataFrame and handle missing columns
    df = pd.DataFrame(features)
    if "quantum_vulnerable" not in df.columns:
        df["quantum_vulnerable"] = 0  # Default value

    # Save results to a JSON file
    output_file = "analysis_results.json"
    try:
        df.to_json(output_file, orient="records", indent=4)
        logger.info(f"Analysis complete. Results saved to {output_file}.")
    except Exception as e:
        logger.error(f"Error saving results: {e}")
