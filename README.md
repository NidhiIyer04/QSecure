# Quantum Vulnerability Detector - QSecure

## Overview
Q Secure is a tool designed to detect vulnerabilities related to quantum-safe cryptography in codebases. It identifies cryptographic algorithms that are vulnerable to quantum attacks (e.g., RSA, AES) and provides recommendations for more secure alternatives. This tool is useful for developers working on cryptographic applications to ensure their code is future-proof against quantum computing threats.

## Features
- Detects quantum-vulnerable cryptographic algorithms such as RSA, SHA-1, DES, MD5, RC4, and others.
- Highlights vulnerable code in a code editor-style interface for easy review.
- Provides context-sensitive recommendations for replacing vulnerable algorithms with quantum-resistant alternatives.
- Displays a table of findings, including severity and explanation of each vulnerability.
- Provides a Quantum-Safe Solution with recommendations and code changes.
- TCP/IP Packet Simulation with cryptographic overhead, latency, and loss.
- Real-time metrics dashboard: packets sent/received, quantum security level.

## Technologies Used
- Frontend: Streamlit
- Backend: Python
- Simulation: NetworkX, Matplotlib, NumPy
- Visualization: PIL, base64
- Data Processing: Pandas
- Crypto Simulation: Custom ruleset

## Installation
To run the Quantum Vulnerability Detector locally, follow the steps below:

### 1. Clone the repository
```bash
git clone https://github.com/NidhiIyer04/QSecure.git
```

### 2. Install the required dependencies
Navigate to the project directory and install the dependencies using pip:

```bash
cd QSecure
pip install -r requirements.txt
```

### 3. Run the Streamlit app
Once the dependencies are installed, run the Streamlit app with the following command:

```bash
cd src
streamlit run app.py
```

This will start a local web server, and you can access the tool at `http://localhost:8501`.

## Usage
1. Go to Upload File or Try Examples tab.
2. Upload a .py, .java, .js, .cpp, or .c file.
3. View vulnerabilities, highlighted code, severity, and recommended fixes.
4. Use the sidebar chatbot to view language-specific recommendations.
5. Download a ready-to-use fixed snippet.
6. Open the Quantum Network Simulation tab.
7. Select number of nodes and percentage of quantum-capable nodes.
8. Choose a cryptographic algorithm to simulate.
9. View network diagram.
10. Run: Key Distribution Simulation, Attack Simulation, TCP/IP Simulation
11. Analyze packet metrics and vulnerabilities.

## Sample Input
Save the below code in a .java file and upload it into the application.
```
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.Mac;

public class TestCrypto {

    public static void main(String[] args) {
        try {
            // AES Encryption Example
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal("Hello, World!".getBytes());
            System.out.println("Encrypted data: " + new String(encryptedData));

            // RSA KeyPair Example
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            PublicKey publicKey = keyPairGenerator.genKeyPair().getPublic();
            PrivateKey privateKey = keyPairGenerator.genKeyPair().getPrivate();
            System.out.println("Public Key: " + publicKey);
            System.out.println("Private Key: " + privateKey);

            // MessageDigest (Hashing) Example
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest("Hello, World!".getBytes());
            System.out.println("SHA-256 hash: " + new String(hash));

            // HMAC Example
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] hmacData = mac.doFinal("Hello, World!".getBytes());
            System.out.println("HMAC: " + new String(hmacData));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

