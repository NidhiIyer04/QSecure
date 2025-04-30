import streamlit as st
import re
import pandas as pd

# Expanded function to detect more vulnerabilities in the code
def detect_vulnerabilities(file_content, language):
    vulnerabilities = [
        {"match": "rsa", "severity": "High", "quantum_vulnerable": True, "explanation": "RSA is vulnerable to Shor's algorithm.", "fix": "Consider using post-quantum algorithms like NTRU or Kyber."},
        {"match": "RSA", "severity": "High", "quantum_vulnerable": True, "explanation": "RSA is vulnerable to Shor's algorithm.", "fix": "Consider using post-quantum algorithms like NTRU or Kyber."},
        {"match": "SHA-1", "severity": "Medium", "quantum_vulnerable": False, "explanation": "SHA-1 is weak due to collision vulnerabilities.", "fix": "Replace SHA-1 with SHA-256 or SHA-3."},
        {"match": "DES", "severity": "High", "quantum_vulnerable": False, "explanation": "DES is considered insecure due to its short key size.", "fix": "Switch to AES with at least 128-bit key size."},
        {"match": "MD5", "severity": "Medium", "quantum_vulnerable": False, "explanation": "MD5 is susceptible to collision attacks.", "fix": "Replace MD5 with SHA-256 or SHA-3."},
        {"match": "RC4", "severity": "High", "quantum_vulnerable": False, "explanation": "RC4 has been deprecated due to multiple vulnerabilities.", "fix": "Switch to AES for encryption."},
        {"match": "AES", "severity": "Low", "quantum_vulnerable": False, "explanation": "AES can be vulnerable if key sizes or modes are not properly used.", "fix": "Ensure you are using AES with a 256-bit key and an authenticated encryption mode (e.g., AES-GCM)."},
        {"match": "Crypto.PublicKey.RSA", "severity": "High", "quantum_vulnerable": True, "explanation": "RSA is vulnerable to Shor's algorithm.", "fix": "Consider using post-quantum algorithms like NTRU or Kyber."}
    ]
    
    findings = []
    for vuln in vulnerabilities:
        # Use regex with case-insensitive flag to catch all variations
        pattern = re.compile(r'\b' + re.escape(vuln["match"]) + r'\b', re.IGNORECASE)
        matches = pattern.finditer(file_content)
        
        for match in matches:
            # Find the line number where the vulnerability is found
            line_number = file_content[:match.start()].count('\n') + 1
            
            findings.append({
                "file_name": f"sample_code.{language.lower()}",  # Use lowercase language extension
                "language": language,
                "match": vuln["match"],
                "line": line_number,  # Line numbers are 1-based
                "severity": vuln["severity"],
                "quantum_vulnerable": vuln["quantum_vulnerable"],
                "explanation": vuln["explanation"],
                "fix": vuln["fix"]
            })
    
    return findings

def get_recommendation(vulnerability, language):
    recommendations = {
        "rsa": {
            "general": "RSA is vulnerable to Shor's algorithm. Replace it with quantum-resistant algorithms like Kyber or NTRU.",
            "code_changes": {
                "python": """
from ntru import NTRUEncrypt
ntru = NTRUEncrypt()
encrypted = ntru.encrypt(data)
""",
                "javascript": """
// Using a mock Post-Quantum library (for demonstration)
import { kyberEncrypt, kyberDecrypt } from 'post-quantum-crypto-lib';

const keyPair = generateKyberKeyPair();
const encrypted = kyberEncrypt(keyPair.publicKey, "Hello World");
const decrypted = kyberDecrypt(keyPair.privateKey, encrypted);
""",
                "java": """
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import org.openquantumsafe.kyber.KyberCiphertext;
import org.openquantumsafe.kyber.KyberPrivateKey;
import org.openquantumsafe.kyber.KyberPublicKey;
import org.openquantumsafe.kyber.KyberKeyPair;
import org.openquantumsafe.kyber.KyberCipher;

public class PostQuantumCryptoExample {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            KyberKeyPair keyPair = KyberKeyPair.generateKeyPair();
            KyberPublicKey publicKey = keyPair.getPublicKey();
            KyberPrivateKey privateKey = keyPair.getPrivateKey();

            String data = "Hello, Quantum World!";
            KyberCiphertext ciphertext = KyberCipher.encrypt(publicKey, data.getBytes());
            byte[] decryptedData = KyberCipher.decrypt(privateKey, ciphertext);

            System.out.println("Original Data: " + data);
            System.out.println("Decrypted Data: " + new String(decryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
""",
                "cpp": """
#include <oqs/oqs.h>
#include <stdio.h>

int main() {
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_512)) {
        printf("Kyber is not enabled in liboqs\\n");
        return -1;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    uint8_t public_key[OQS_KEM_kyber_512_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_512_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    uint8_t shared_secret_enc[OQS_KEM_kyber_512_length_shared_secret];
    uint8_t shared_secret_dec[OQS_KEM_kyber_512_length_shared_secret];

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key);
    OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key);

    OQS_KEM_free(kem);
    return 0;
}
"""
            }
        },
        
        "RSA": {
            "general": "RSA is vulnerable to Shor's algorithm. Replace it with quantum-resistant algorithms like Kyber or NTRU.",
            "code_changes": {
                "python": """
from ntru import NTRUEncrypt
ntru = NTRUEncrypt()
encrypted = ntru.encrypt(data)
""",
                "javascript": """
// Using a mock Post-Quantum library (for demonstration)
import { kyberEncrypt, kyberDecrypt } from 'post-quantum-crypto-lib';

const keyPair = generateKyberKeyPair();
const encrypted = kyberEncrypt(keyPair.publicKey, "Hello World");
const decrypted = kyberDecrypt(keyPair.privateKey, encrypted);
""",
                "java": """
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import org.openquantumsafe.kyber.KyberCiphertext;
import org.openquantumsafe.kyber.KyberPrivateKey;
import org.openquantumsafe.kyber.KyberPublicKey;
import org.openquantumsafe.kyber.KyberKeyPair;
import org.openquantumsafe.kyber.KyberCipher;

public class PostQuantumCryptoExample {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            KyberKeyPair keyPair = KyberKeyPair.generateKeyPair();
            KyberPublicKey publicKey = keyPair.getPublicKey();
            KyberPrivateKey privateKey = keyPair.getPrivateKey();

            String data = "Hello, Quantum World!";
            KyberCiphertext ciphertext = KyberCipher.encrypt(publicKey, data.getBytes());
            byte[] decryptedData = KyberCipher.decrypt(privateKey, ciphertext);

            System.out.println("Original Data: " + data);
            System.out.println("Decrypted Data: " + new String(decryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
""",
                "cpp": """
#include <oqs/oqs.h>
#include <stdio.h>

int main() {
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_512)) {
        printf("Kyber is not enabled in liboqs\\n");
        return -1;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    uint8_t public_key[OQS_KEM_kyber_512_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_512_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    uint8_t shared_secret_enc[OQS_KEM_kyber_512_length_shared_secret];
    uint8_t shared_secret_dec[OQS_KEM_kyber_512_length_shared_secret];

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key);
    OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key);

    OQS_KEM_free(kem);
    return 0;
}
"""
            }
        },

        "Crypto.PublicKey.RSA": {
            "general": "RSA is vulnerable to Shor's algorithm. Replace it with quantum-resistant algorithms like Kyber or NTRU.",
            "code_changes": {
                "python": """
# Using a post-quantum cryptography library
from pqcrypto.kem import kyber
from pqcrypto.sign import dilithium

# Generate key pairs
public_key, private_key = kyber.generate_keypair()

# Encrypt a message
ciphertext, shared_secret = kyber.encrypt(public_key)

# Decrypt a message
decrypted_secret = kyber.decrypt(ciphertext, private_key)
"""
            }
        },

        "AES": {
            "general": "Ensure AES is used with a 256-bit key and in an authenticated mode like AES-GCM.",
            "code_changes": {
                "python": """
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # 256-bit key
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(b"Secret message")
""",
                "javascript": """
const crypto = require('crypto');
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);

const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update('Secret message', 'utf8', 'hex');
encrypted += cipher.final('hex');
const tag = cipher.getAuthTag();
""",
                "java": """
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256);
SecretKey key = keyGen.generateKey();

byte[] iv = new byte[12];
SecureRandom random = new SecureRandom();
random.nextBytes(iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);
byte[] ciphertext = cipher.doFinal("Secret message".getBytes());
""",
                "cpp": """
#include <openssl/evp.h>

EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

unsigned char key[32]; // 256-bit key
unsigned char iv[12];  // 96-bit IV
unsigned char outbuf[1024];
int outlen;

EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
EVP_EncryptUpdate(ctx, outbuf, &outlen, (unsigned char *)"Secret message", strlen("Secret message"));
"""
            }
        },

        "MD5": {
            "general": "MD5 is insecure and should be replaced with SHA3-256 or BLAKE3.",
            "code_changes": {
                "python": """
import hashlib
hash_value = hashlib.sha3_256("input".encode()).hexdigest()
""",
                "javascript": """
const crypto = require('crypto');
const hash = crypto.createHash('sha3-256').update("input").digest('hex');
""",
                "java": """
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

MessageDigest digest = MessageDigest.getInstance("SHA3-256");
byte[] hash = digest.digest("input".getBytes(StandardCharsets.UTF_8));
"""
            }
        },

        "DES": {
            "general": "DES is insecure. Replace it with AES-256 in GCM mode.",
            "code_changes": {
                "python": """
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # AES-256
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(b"Sensitive data")
""",
                "javascript": """
const crypto = require('crypto');
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);

const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update('Sensitive data', 'utf8', 'hex');
encrypted += cipher.final('hex');
const tag = cipher.getAuthTag();
""",
                "java": """
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256);
SecretKey key = keyGen.generateKey();

byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
"""
            }
        }
    }

    # Case-insensitive lookup by normalizing keys and input to lowercase
    lookup_key = vulnerability.lower()
    for key in recommendations:
        if key.lower() == lookup_key:
            rec = recommendations[key]
            code_snippet = rec["code_changes"].get(language.lower(), "No code example available for this language.")
            return {
                "general": rec["general"],
                "code_change": code_snippet
            }
    
    return {
        "general": "No predefined recommendation available.",
        "code_change": ""
    }

# Function to guess language based on file extension
def guess_language(file_extension):
    extension_map = {
        "py": "Python",
        "js": "JavaScript", 
        "java": "Java",
        "cpp": "C++",
        "c": "C",
        "ts": "TypeScript",
        "rb": "Ruby",
        "go": "Go",
        "php": "PHP",
        "cs": "C#"
    }
    return extension_map.get(file_extension.lower(), "Unknown")

# Centering the title and subheader
st.markdown("""
    <h1 style="text-align: center; color: white;">Q Secure</h1>
    <h2 style="text-align: center; color: white;">Quantum Vulnerability Detector</h2>
""", unsafe_allow_html=True)

# Step 1: File upload or example selection
st.write("You can either upload a file or try with an example:")

# Create tabs for "Upload File" and "Try Examples"
tab1, tab2 = st.tabs(["Upload File", "Try Examples"])

with tab1:
    # Original file upload functionality
    uploaded_file = st.file_uploader("Upload your code file", type=["py", "cpp", "js", "java", "c", "ts", "rb", "go", "php", "cs"])

with tab2:
    # Example selection
    example_options = [
        "Python file with RSA", 
        "JavaScript file with AES", 
        "Clean code (no crypto)",
        "Mixed RSA and MD5"
    ]
    selected_example = st.selectbox("Select an example:", example_options)
    
    # Dictionary with example code
    example_code = {
        "Python file with RSA": {
            "content": """import rsa

def generate_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return public_key, private_key

def encrypt_message(message, public_key):
    return rsa.encrypt(message.encode(), public_key)

def decrypt_message(ciphertext, private_key):
    return rsa.decrypt(ciphertext, private_key).decode()

# Generate new keys
pub_key, priv_key = generate_keys()

# Encrypt a message
message = "This is a secret message"
encrypted = encrypt_message(message, pub_key)
print(f"Encrypted message: {encrypted}")

# Decrypt the message
decrypted = decrypt_message(encrypted, priv_key)
print(f"Decrypted message: {decrypted}")
""",
            "language": "Python"
        },
        "JavaScript file with AES": {
            "content": """const crypto = require('crypto');

function encryptData(data, key) {
    // Use AES for encryption
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decryptData(encryptedData, key) {
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Example usage
const secretKey = 'my-secret-key-for-encryption';
const sensitiveData = 'This is sensitive information';

const encrypted = encryptData(sensitiveData, secretKey);
console.log('Encrypted:', encrypted);

const decrypted = decryptData(encrypted, secretKey);
console.log('Decrypted:', decrypted);
""",
            "language": "JavaScript"
        },
        "Clean code (no crypto)": {
            "content": """def calculate_fibonacci(n):
    if n <= 0:
        return []
    elif n == 1:
        return [0]
    elif n == 2:
        return [0, 1]
    
    fib_sequence = [0, 1]
    for i in range(2, n):
        fib_sequence.append(fib_sequence[i-1] + fib_sequence[i-2])
    
    return fib_sequence

def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    
    return True

# Generate the first 10 Fibonacci numbers
fibonacci_numbers = calculate_fibonacci(10)
print("First 10 Fibonacci numbers:", fibonacci_numbers)

# Check if numbers from 1 to 20 are prime
for number in range(1, 21):
    if is_prime(number):
        print(f"{number} is prime")
    else:
        print(f"{number} is not prime")
""",
            "language": "Python"
        },
        "Mixed RSA and MD5": {
            "content": """import hashlib
import Crypto.PublicKey.RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys():
    # Generate RSA key pair
    key = Crypto.PublicKey.RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_rsa(message, public_key):
    key = Crypto.PublicKey.RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted = cipher.encrypt(message.encode())
    return encrypted

def decrypt_with_rsa(encrypted_message, private_key):
    key = Crypto.PublicKey.RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted = cipher.decrypt(encrypted_message)
    return decrypted.decode()

def hash_with_md5(message):
    # Create MD5 hash of message
    md5_hash = hashlib.md5()
    md5_hash.update(message.encode())
    return md5_hash.hexdigest()

# Example usage
message = "This is a top secret message"

# Generate RSA keys
private_key, public_key = generate_rsa_keys()

# Encrypt the message with RSA
encrypted = encrypt_with_rsa(message, public_key)
print(f"Encrypted message: {encrypted}")

# Decrypt the message
decrypted = decrypt_with_rsa(encrypted, private_key)
print(f"Decrypted message: {decrypted}")

# Create MD5 hash
md5_hash = hash_with_md5(message)
print(f"MD5 hash of the message: {md5_hash}")
""",
            "language": "Python"
        }
    }
    
    # Run example button
    if st.button("Run Example"):
        file_content = example_code[selected_example]["content"]
        language = example_code[selected_example]["language"]
        st.success(f"Running analysis on {selected_example} example...")
    else:
        file_content = None
        language = None

# Process the file or example
process_content = False
if 'tab1' in locals() and uploaded_file is not None:
    # Read file content as string
    file_content = uploaded_file.read().decode("utf-8")
    file_extension = uploaded_file.name.split(".")[-1]
    language = guess_language(file_extension)
    process_content = True
elif 'tab2' in locals() and 'file_content' in locals() and file_content is not None:
    # Example content is already set
    process_content = True

if process_content:
    # Step 2: Detect vulnerabilities
    findings = detect_vulnerabilities(file_content, language)

    if findings:
        st.subheader("Code with Highlighted Vulnerabilities:")

        # Split the file content into lines
        lines = file_content.split("\n")

        # Create a map of vulnerabilities by line
        vulnerabilities_by_line = {}
        for finding in findings:
            line_num = finding["line"]
            if line_num not in vulnerabilities_by_line:
                vulnerabilities_by_line[line_num] = []
            vulnerabilities_by_line[line_num].append(finding["match"])

        # Build the editor-style display with preserved indentation and highlights
        styled_lines = ""
        for i, line in enumerate(lines):
            line_number = i + 1
            line_str = f"{str(line_number).rjust(4)}"
            styled_line = line.replace(" ", "&nbsp;")

            # If this line has vulnerabilities, highlight them
            if line_number in vulnerabilities_by_line:
                for vuln in vulnerabilities_by_line[line_number]:
                    styled_line = re.sub(
                        f"\\b{re.escape(vuln)}\\b",
                        f"<span style='background-color: #facc15; color: black; font-weight: bold; padding: 1px 2px; border-radius: 3px;'>{vuln}</span>",
                        styled_line,
                        flags=re.IGNORECASE  # Add case-insensitive flag here
                    )
            
            background = "#0f172a" if i % 2 == 0 else "#1e293b"
            styled_lines += f"<div style='background-color: {background};'><span style='color: #64748b;'>{line_str}</span>&nbsp;{styled_line}</div>"

        st.markdown(f"""
        <div style='
            background-color: #0f172a;
            color: #f1f5f9;
            padding: 12px;
            border-radius: 6px;
            font-family: "Fira Code", monospace;
            overflow-x: auto;
            font-size: 13px;
            line-height: 1.35;
            white-space: pre;
            border: 1px solid #334155;
        '>
            <pre style="margin: 0;">{styled_lines}</pre>
        </div>
        """, unsafe_allow_html=True)
            
        # Step 3: Display findings summary
        st.write(f"**Found {len(findings)} potential vulnerabilities in this {language} code.**")

        # Display summary badges
        col1, col2, col3, col4 = st.columns(4)
        
        # Count vulnerabilities by severity
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        quantum_vulnerable_count = 0
        
        for finding in findings:
            if finding["severity"] in severity_counts:
                severity_counts[finding["severity"]] += 1
            if finding["quantum_vulnerable"]:
                quantum_vulnerable_count += 1
        
        with col1:
            st.markdown(f"""
            <div style='background-color: #dc2626; color: white; padding: 10px; border-radius: 5px; text-align: center;'>
                <h3 style='margin: 0;'>{severity_counts["High"]}</h3>
                <p style='margin: 0;'>High Severity</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div style='background-color: #f59e0b; color: white; padding: 10px; border-radius: 5px; text-align: center;'>
                <h3 style='margin: 0;'>{severity_counts["Medium"]}</h3>
                <p style='margin: 0;'>Medium Severity</p>
            </div>
            """, unsafe_allow_html=True)
            
        with col3:
            st.markdown(f"""
            <div style='background-color: #10b981; color: white; padding: 10px; border-radius: 5px; text-align: center;'>
                <h3 style='margin: 0;'>{severity_counts["Low"]}</h3>
                <p style='margin: 0;'>Low Severity</p>
            </div>
            """, unsafe_allow_html=True)
            
        with col4:
            st.markdown(f"""
            <div style='background-color: #6366f1; color: white; padding: 10px; border-radius: 5px; text-align: center;'>
                <h3 style='margin: 0;'>{quantum_vulnerable_count}</h3>
                <p style='margin: 0;'>Quantum Vulnerable</p>
            </div>
            """, unsafe_allow_html=True)

        # Step 4: Display table of findings in a cleaner format
        st.subheader("Detailed Vulnerability Findings")
        table_data = []
        for finding in findings:
            table_data.append([
                finding["file_name"],
                finding["language"],
                finding["match"],
                finding["line"],
                finding["severity"],
                "Yes" if finding["quantum_vulnerable"] else "No",
                finding["explanation"]
            ])
        findings_df = pd.DataFrame(table_data, columns=["File", "Language", "Vulnerability", "Line", "Severity", "Quantum Vulnerable", "Explanation"])
        st.dataframe(findings_df)

        # Step 5: Chatbot-style recommendation interface
        st.sidebar.title("Quantum-Safe Solutions")
        unique_vulnerabilities = list(dict.fromkeys([finding["match"] for finding in findings]))
        
        if unique_vulnerabilities:
            selected_vulnerability = st.sidebar.selectbox(
                "Select a vulnerability to get recommendations",
                unique_vulnerabilities
            )

            recommendation = get_recommendation(selected_vulnerability, language)

            st.sidebar.subheader("General Recommendations:")
            st.sidebar.write(recommendation["general"])

            st.sidebar.subheader("Suggested Code Change:")
            st.sidebar.code(recommendation["code_change"], language=language.lower())
            
            # Create a mapping of language names to their file extensions
            language_to_extension = {
                "python": "py",
                "javascript": "js",
                "java": "java",
                "csharp": "cs",
                "cpp": "cpp",
                "php": "php",
                "ruby": "rb",
                "go": "go",
                # Add more languages as needed
            }

            # Get the appropriate extension for the language
            file_extension = language_to_extension.get(language.lower(), language.lower())

            # Add download button for the recommended fix
            st.sidebar.download_button(
                label="Download Fix",
                data=recommendation["code_change"],
                file_name=f"fix_{selected_vulnerability.lower()}_{language.lower()}.{file_extension}",
                mime="text/plain"
            )
    else:
        st.success("No vulnerabilities detected in this code! Your code appears to be secure.")
        st.balloons()

else:
    st.info("Upload a code file or select an example to begin analysis.")

