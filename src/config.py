# src/config.py
import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")
SYNTHETIC_DATA_DIR = os.path.join(DATA_DIR, "synthetic")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")

# Machine learning configuration
ML_CONFIG = {
    "test_size": 0.2,
    "random_state": 42,
    "n_estimators": 100,
    "max_depth": 10,
    "cv_folds": 5
}

# Cryptographic algorithms configuration
CRYPTO_CONFIG = {
    "quantum_vulnerable": [
        "RSA", "DSA", "ECDSA", "ECDH", "DH",
        "ElGamal"
    ],
    "symmetric_affected": [
        "AES", "3DES", "DES", "Blowfish", "RC4",
        "ChaCha20"
    ],
    "quantum_resistant": [
        "Kyber", "Dilithium", "Falcon", "SPHINCS+",
        "NTRU", "McEliece", "SIKE"
    ],
    "minimum_key_lengths": {
        "RSA": 2048,
        "DSA": 2048,
        "ECDSA": 256,
        "AES": 128,
        "3DES": 168
    },
    "recommended_key_lengths": {
        "RSA": 3072,
        "DSA": 3072,
        "ECDSA": 384,
        "AES": 256,
        "3DES": 168
    },
    "quantum_safe_recommendations": {
        "RSA": "Kyber",
        "DSA": "Dilithium",
        "ECDSA": "Dilithium",
        "ECDH": "Kyber",
        "DH": "Kyber"
    }
}

# Vulnerability severity levels
SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

# API endpoints for data collection
VULNERABILITY_DATABASES = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cve": "https://cve.circl.lu/api/"
}

# Static analysis configuration
STATIC_ANALYSIS_CONFIG = {
    "max_file_size_mb": 10,
    "supported_languages": ["python", "c", "cpp", "java", "javascript"],
    "ignore_patterns": ["*test*", "*.min.js", "node_modules/*", "venv/*"],
    "depth_limit": 5
}
