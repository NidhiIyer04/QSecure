# Quantum Vulnerability Detector – QSecure

## Overview

QSecure is a Post-Quantum Cryptography (PQC) vulnerability scanner designed to detect cryptographic algorithms that are vulnerable to quantum attacks. It identifies insecure or non-quantum-safe primitives such as RSA and SHA-1 and provides deterministic, production-safe migration guidance toward post-quantum alternatives like ML-KEM (Kyber).

The system is built with a FastAPI backend and a lightweight frontend for uploading source files and reviewing findings.

## Features

* Detects quantum-vulnerable algorithms:
  * RSA (1024, 2048, etc.)
  * SHA-1
  * Other legacy crypto primitives (extendable)
* Classical vs Quantum security classification
* Harvest-Now-Decrypt-Later (HNDL) risk indicator
* CVSS-style risk scoring
* NIST SP 800-131A + NIST PQC aligned classification
* Deterministic post-quantum migration suggestions (no AI-generated crypto)
* Unified diff output for secure patching
* Minimal web UI for uploading and reviewing findings
* REST API support for CI/CD integration


## Technologies Used

### Backend

* FastAPI
* Uvicorn
* Python 3.10+
* Deterministic secure template engine

### Frontend

* Vanilla HTML + JavaScript
* Simple HTTP server

## Project Structure

```
QSecure/
│
├── backend/
│   ├── api/
│   │   └── routes_scan.py
│   ├── scanner/
│   │   ├── static_scanner.py
│   │   └── replacement_engine.py
│   ├── services/
│   │   ├── scan_service.py
│   │   ├── grading_service.py
│   │   └── ai_service.py
│   └── main.py
│
├── frontend/
│   └── index.html
│
└── requirements.txt
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/NidhiIyer04/QSecure.git
cd QSecure
```
### 2. Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

# Start Backend (FastAPI)

From project root:

```bash
uvicorn backend.main:app --reload
```

Backend will run at:

```
http://127.0.0.1:8000
```

Verify it is running:

```
http://127.0.0.1:8000/docs
```

You should see the Swagger UI.

# Start Frontend

Open a new terminal:

```bash
cd frontend
python3 -m http.server 5500
```

Open browser:

```
http://localhost:5500
```

Make sure backend is already running.

## Usage

1. Open `http://localhost:5500`
2. Upload a `.java` file
3. Click **Scan**
4. View:

   * Algorithm detected
   * Line number
   * Classical compliance
   * Quantum readiness
   * CVSS score
   * Migration priority
   * Deterministic secure patch (diff format)

## API Usage (Direct)

You can also call the API directly:

```bash
curl -X POST "http://127.0.0.1:8000/scan" \
  -F "file=@TestCrypto.java"
```

Response will be JSON:

```json
[
  {
    "finding": {...},
    "grading": {...},
    "fix": {...},
    "explanation": "..."
  }
]
```

## Expected Output

* Algorithm: RSA
* Classical Compliance: APPROVED
* Quantum Readiness: NOT_READY
* Harvest-Now-Decrypt-Later Risk: true
* CVSS Score: 7
* Suggested Migration: ML-KEM (Kyber512)

## Security Design Principles

* No AI-generated cryptographic code
* Deterministic migration templates
* NIST-aligned classification
* Production-safe patch generation
* Modular service architecture
* Extensible for future PQC standards

## Future Enhancements (Roadmap)

* Hybrid RSA + ML-KEM transition mode
* AST-based Java parsing
* GitHub PR patch generation
* CI/CD integration
* Multi-language scanning
* Enterprise compliance reporting (PDF export)