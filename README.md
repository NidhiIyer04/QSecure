
# QSecure: Quantum-Safe Cryptographic Vulnerability Detector
A machine learning-based tool to detect vulnerabilities in cryptographic libraries with a focus on quantum computing threats.

## Features

- **Static Code Analysis**  
  Scans source files to detect cryptographic API usage (e.g., PyCryptodome, OpenSSL) and flags weak configurations.

- **Machine Learning-Based Classification**  
  Trained on real-world and synthetic examples to classify cryptographic patterns by severity.

- **Quantum Resistance Assessment**  
  Evaluates if cryptographic algorithms are safe against known quantum attacks.

- **Detailed Reporting**  
  Generates vulnerability reports in JSON format for integration with CI/CD pipelines.

- **Recommendations Engine** *(Coming Soon)*  
  Suggests NIST-approved quantum-resistant alternatives for insecure code.

---

## Project Structure

```
QSecure
├── src/
│   ├── analyzers/                # Static analysis engine
│   │   └── crypto_analyzer.py
│   ├── static_analyzer/          # Pattern definitions
│   │   └── __init__.py
│   ├── feature_extractor/        # Feature engineering module
│   │   └── __init__.py
│   ├── ml_model/                 # ML model scripts (TBD)
│   │   └── __init__.py
│   ├── recommendation_engine/    # Quantum-safe recommendations (TBD)
│   │   └── __init__.py
│   ├── config.py                 # Analysis configuration
│   ├── data_collection.py        # Scripts for gathering CVE data
│   ├── data_generation.py        # Synthetic data generator
│   ├── app.py                    # CLI entrypoint (WIP)
├── tests/                        # Unit tests
├── docs/                         # Technical documentation
├── analysis_results.json         # Sample output
└── requirements.txt              # Project dependencies
```

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/qcsa.git
cd qcsa
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Static Analyzer

```bash
python src/analyzers/crypto_analyzer.py
```

### 5. View Output

Check `analysis_results.json` for the vulnerability report.

---

## Configuration

Update `src/config.py` to customize:

- Cryptographic patterns and regex rules
- List of quantum-vulnerable and quantum-resistant algorithms
- Key length thresholds

---

## Roadmap

- [x] Static analysis engine for Python/JS/Java
- [x] Feature extraction and severity scoring
- [ ] ML classification model training
- [ ] Quantum-resistant recommendations
- [ ] CI/CD integration plugin
- [ ] VS Code extension (Nice-to-Have)

---

## References

- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/)
- [OpenSSL Cryptographic APIs](https://www.openssl.org/docs/man3.0/)

