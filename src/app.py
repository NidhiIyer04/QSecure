import streamlit as st
import re
import pandas as pd

# Expanded function to detect more vulnerabilities in the code
def detect_vulnerabilities(file_content, language):
    vulnerabilities = [
        {"match": "RSA", "severity": "High", "quantum_vulnerable": True, "explanation": "RSA is vulnerable to Shor's algorithm.", "fix": "Consider using post-quantum algorithms like NTRU or Kyber."},
        {"match": "SHA-1", "severity": "Medium", "quantum_vulnerable": False, "explanation": "SHA-1 is weak due to collision vulnerabilities.", "fix": "Replace SHA-1 with SHA-256 or SHA-3."},
        {"match": "DES", "severity": "High", "quantum_vulnerable": False, "explanation": "DES is considered insecure due to its short key size.", "fix": "Switch to AES with at least 128-bit key size."},
        {"match": "MD5", "severity": "Medium", "quantum_vulnerable": False, "explanation": "MD5 is susceptible to collision attacks.", "fix": "Replace MD5 with SHA-256 or SHA-3."},
        {"match": "RC4", "severity": "High", "quantum_vulnerable": False, "explanation": "RC4 has been deprecated due to multiple vulnerabilities.", "fix": "Switch to AES for encryption."},
        {"match": "AES", "severity": "Low", "quantum_vulnerable": False, "explanation": "AES can be vulnerable if key sizes or modes are not properly used.", "fix": "Ensure you are using AES with a 256-bit key and an authenticated encryption mode (e.g., AES-GCM)."}
    ]
    
    findings = []
    for vuln in vulnerabilities:
        if vuln["match"] in file_content:
            # Find the line numbers where the vulnerability is found
            lines = file_content.split("\n")
            for i, line in enumerate(lines):
                if vuln["match"] in line:
                    findings.append({
                        "file_name": "sample_code." + language,  # Hardcoded file name for simplicity
                        "language": language,
                        "match": vuln["match"],
                        "line": i + 1,  # Line numbers are 1-based
                        "severity": vuln["severity"],
                        "quantum_vulnerable": vuln["quantum_vulnerable"],
                        "explanation": vuln["explanation"],
                        "fix": vuln["fix"]  # Including the recommended fix
                    })
    return findings

def get_recommendation(vulnerability, language):
    
    recommendations = {
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
        printf("Kyber is not enabled in liboqs\n");
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


    rec = recommendations.get(vulnerability)
    if rec:
        code_snippet = rec["code_changes"].get(language.lower(), "No code example available for this language.")
        return {
            "general": rec["general"],
            "code_change": code_snippet
        }
    else:
        return {
            "general": "No predefined recommendation available.",
            "code_change": ""
        }


# Centering the title and subheader
st.markdown("""
    <h1 style="text-align: center; color: white;">Q Secure</h1>
    <h2 style="text-align: center; color: white;">Quantum Vulnerability Detector</h2>
""", unsafe_allow_html=True)


# Step 1: File upload
uploaded_file = st.file_uploader("Upload your code file", type=["py", "cpp", "js", "java", "c"])

if uploaded_file is not None:
    # Read file content as string
    file_content = uploaded_file.read().decode("utf-8")
    language = uploaded_file.name.split(".")[-1]

    # Step 2: Detect vulnerabilities
    findings = detect_vulnerabilities(file_content, language)

    if findings:
        st.subheader("Code with Highlighted Vulnerabilities:")

        # Split the file content into lines
        lines = file_content.split("\n")

        # Build the editor-style display with preserved indentation and highlights
        styled_lines = ""
        for i, line in enumerate(lines):
            line_number = f"{str(i+1).rjust(4)}"
            styled_line = line.replace(" ", "&nbsp;")

            for finding in findings:
                if finding["line"] == i + 1:
                    styled_line = re.sub(
                        f"({finding['match']})",
                        r"<span style='background-color: #facc15; color: black; font-weight: bold; padding: 1px 2px; border-radius: 3px;'>\1</span>",
                        styled_line
                    )
            background = "#0f172a" if i % 2 == 0 else "#1e293b"
            styled_lines += f"<div style='background-color: {background};'><span style='color: #64748b;'>{line_number}</span>&nbsp;{styled_line}</div>"


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
            

        # Step 4: Display table of findings in a cleaner format
        st.subheader("Vulnerability Findings")
        table_data = []
        for finding in findings:
            table_data.append([
                finding["file_name"],
                finding["language"],
                finding["match"],
                finding["line"],
                finding["severity"],
                finding["quantum_vulnerable"],
                finding["explanation"]
            ])
        findings_df = pd.DataFrame(table_data, columns=["File Name", "Language", "Match", "Line", "Severity", "Quantum Vulnerable", "Explanation"])
        st.dataframe(findings_df)

        # Step 5: Chatbot-style recommendation interface
        st.sidebar.title("Quantum-Safe Solution")
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
            st.sidebar.code(recommendation["code_change"], language=language)
        else:
            st.sidebar.write("No vulnerabilities detected.")


else:
    st.info("Upload a code file to begin analysis.")