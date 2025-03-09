# Directory structure creation script
import os

def create_project_structure():
    """Create the directory structure for the project."""
    directories = [
        "src/static_analyzer",
        "src/feature_extractor",
        "src/ml_model",
        "src/recommendation_engine",
        "src/dashboard",
        "data/raw",
        "data/processed",
        "data/synthetic",
        "models",
        "tests/static_analyzer",
        "tests/feature_extractor",
        "tests/ml_model",
        "tests/recommendation_engine",
        "docs"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        # Create __init__.py files for Python packages
        if directory.startswith("src") or directory.startswith("tests"):
            with open(os.path.join(directory, "__init__.py"), "w") as f:
                f.write("# Initialize package\n")
    
    # Create main app file
    with open("src/app.py", "w") as f:
        f.write("# Main application entry point\n")
    
    # Create README
    with open("README.md", "w") as f:
        f.write("# Quantum-Safe Cryptographic Vulnerability Detector\n\n")
        f.write("A machine learning-based tool to detect vulnerabilities in cryptographic libraries with a focus on quantum computing threats.\n")
    
    # Create requirements.txt
    with open("requirements.txt", "w") as f:
        f.write("# Core dependencies\n")
        f.write("numpy>=1.20.0\n")
        f.write("pandas>=1.3.0\n")
        f.write("scikit-learn>=1.0.0\n")
        f.write("tensorflow>=2.8.0\n")
        f.write("pycryptodome>=3.15.0\n")
        f.write("cryptography>=37.0.0\n")
        f.write("bandit>=1.7.4\n")
        f.write("ast-comments>=1.0.1\n")
        f.write("networkx>=2.8.0\n")
        f.write("streamlit>=1.12.0\n")
        f.write("matplotlib>=3.5.0\n")
        f.write("seaborn>=0.12.0\n")
        f.write("pytest>=7.0.0\n")
        f.write("sphinx>=5.0.0\n")
        f.write("requests>=2.28.0\n")
        f.write("tqdm>=4.64.0\n")

if __name__ == "__main__":
    create_project_structure()
    print("Project structure created successfully!")
