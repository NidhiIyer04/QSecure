# QSecure

### Built by Team Spectra for AMD Slingshot Hackathon

## What is QSecure?

QSecure is a Post-Quantum Cryptography security scanner.

It checks source code and detects cryptographic algorithms that are not safe against future quantum computers. For example, it identifies algorithms like RSA and SHA-1 that may become vulnerable when large-scale quantum machines become practical.

The tool helps developers understand the risk and guides them toward safer, post-quantum alternatives.

## Why This Matters

Quantum computers will be able to break many currently used cryptographic systems.

Organizations need to prepare early.
QSecure helps teams become **quantum-ready** before real attacks become possible.

## What QSecure Does

* Detects quantum-vulnerable algorithms (RSA, SHA-1, etc.)
* Identifies weak key sizes
* Classifies classical vs quantum security
* Shows quantum risk severity
* Flags Harvest-Now-Decrypt-Later risk
* Suggests safe post-quantum replacements
* Generates structured JSON reports
* Provides a simple web interface for file uploads

## Technologies Used

* Python
* FastAPI
* Uvicorn
* Tree-Sitter
* PyCryptodome
* HTML / CSS / JavaScript
* Render (Deployment)

## Project Structure

```
QSecure/
│
├── backend/
│   ├── api/
│   ├── scanner/
│   ├── services/
│   └── main.py
│
├── frontend/
│   └── index.html
│
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/NidhiIyer04/QSecure.git
cd QSecure
```

### 2. (Optional) Create Virtual Environment

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

From the project root directory, run:

```bash
python3 -m uvicorn backend.main:app --reload
```

The backend will start at:

```
http://127.0.0.1:8000
```

You can verify it is running by visiting:

```
http://127.0.0.1:8000/docs
```

This opens the automatic API documentation.

## How to Use

1. Open the deployed website or local server.
2. Upload a `.java` file.
3. Click Scan.
4. View detected algorithms, risk level, and suggested migration guidance.

The API also supports direct integration for automation and CI/CD pipelines.

## Security Design Principles

* No AI-generated cryptographic code
* Deterministic migration suggestions
* NIST-aligned classification logic
* Modular and extensible architecture
* Production-safe design

## Future Improvements

* Multi-language support
* VS Code extension
* CLI tool
* CI/CD integration
* Enterprise compliance reporting
* Post-quantum benchmarking
