import os
import json
import random
import pandas as pd
from tqdm import tqdm
import logging
import numpy as np
from config import CRYPTO_CONFIG, SYNTHETIC_DATA_DIR

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CryptoCodeGenerator:
    """Generate synthetic cryptographic code samples for training the ML model."""
    
    def __init__(self):
        self.output_dir = SYNTHETIC_DATA_DIR
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.quantum_vulnerable = CRYPTO_CONFIG["quantum_vulnerable"]
        self.symmetric_affected = CRYPTO_CONFIG["symmetric_affected"]
        self.quantum_resistant = CRYPTO_CONFIG["quantum_resistant"]
        self.minimum_key_lengths = CRYPTO_CONFIG["minimum_key_lengths"]
        self.recommended_key_lengths = CRYPTO_CONFIG["recommended_key_lengths"]
        
        self.libraries = {
            "python": ["cryptography", "pycryptodome", "pyca/cryptography", "PyNaCl", "hashlib", "ssl"],
            "java": ["javax.crypto", "java.security", "org.bouncycastle", "java.util.Base64"],
            "c": ["openssl", "libgcrypt", "mbedtls", "wolfssl", "sodium"],
            "cpp": ["crypto++", "botan", "openssl", "libsodium"],
            "javascript": ["crypto", "node:crypto", "crypto-js", "sjcl", "noble-crypto"]
        }

    def generate_samples(self, num_samples=500):
        """Generate cryptographic code samples in multiple languages."""
        logger.info(f"Generating {num_samples} cryptographic code samples")
        
        languages = list(self.libraries.keys())
        samples = []
        
        for _ in tqdm(range(num_samples)):
            language = random.choice(languages)
            vuln_type = random.choice([
                "weak_key", "quantum_vulnerable", "insecure_random", 
                "secure_implementation", "quantum_safe"
            ])
            
            if vuln_type == "weak_key":
                code, label, metadata = self._generate_weak_key_sample(language)
            elif vuln_type == "quantum_vulnerable":
                code, label, metadata = self._generate_quantum_vulnerable_sample(language)
            elif vuln_type == "insecure_random":
                code, label, metadata = self._generate_insecure_random_sample(language)
            elif vuln_type == "secure_implementation":
                code, label, metadata = self._generate_secure_sample(language)
            else:
                code, label, metadata = self._generate_quantum_safe_sample(language)
            
            samples.append({
                "code": code,
                "label": label,
                "metadata": metadata,
                "language": language
            })
        
        output_file = os.path.join(self.output_dir, "crypto_samples.json")
        with open(output_file, "w") as f:
            json.dump(samples, f, indent=2)
        
        df = pd.DataFrame([{ "language": s["language"], "label": s["label"] } for s in samples])
        df.to_csv(os.path.join(self.output_dir, "crypto_samples.csv"), index=False)
        
        logger.info(f"Saved {len(samples)} cryptographic samples")
        return samples

    def _generate_weak_key_sample(self, language):
        """Generate a weak key cryptographic code sample."""
        algorithm = random.choice(list(self.minimum_key_lengths.keys()))
        key_length = random.choice([512, 768, 1024]) if algorithm in ["RSA", "DSA"] else 128
        code = f"// {algorithm} implementation with weak key length {key_length}"
        return code, "Vulnerable", { "algorithm": algorithm, "key_length": key_length }
    
    def _generate_quantum_vulnerable_sample(self, language):
        """Generate a quantum-vulnerable cryptographic code sample."""
        algorithm = random.choice(self.quantum_vulnerable)
        code = f"// {algorithm} implementation vulnerable to quantum attacks"
        return code, "Vulnerable", { "algorithm": algorithm }
    
    def _generate_insecure_random_sample(self, language):
        """Generate a cryptographic code sample using insecure random number generation."""
        code = f"// Insecure random number generation example in {language}"
        return code, "Vulnerable", { "random": "insecure" }
    
    def _generate_secure_sample(self, language):
        """Generate a secure cryptographic code sample."""
        algorithm = random.choice(self.quantum_resistant)
        code = f"// Secure {algorithm} cryptographic implementation"
        return code, "Secure", { "algorithm": algorithm }
    
    def _generate_quantum_safe_sample(self, language):
        """Generate a quantum-safe cryptographic code sample."""
        algorithm = random.choice(self.quantum_resistant)
        code = f"// Quantum-safe cryptographic implementation using {algorithm}"
        return code, "Quantum-Safe", { "algorithm": algorithm }

if __name__ == "__main__":
    generator = CryptoCodeGenerator()
    generator.generate_samples(500)
