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

# Extending the rule-based chatbot recommendation function with context-sensitive fixes
def get_recommendation(vulnerability):
    recommendations = {
        "RSA": {
            "general": "RSA is vulnerable to Shor's algorithm. You can replace it with quantum-resistant algorithms.",
            "code_change": """
                # Example of switching from RSA to NTRU
                from ntru import NTRUEncrypt
                ntru = NTRUEncrypt()
                encrypted = ntru.encrypt(data)
                """
        },
        "SHA-1": {
            "general": "SHA-1 is weak due to collision vulnerabilities. It is recommended to use SHA-256 or SHA-3.",
            "code_change": """
                # Replace SHA-1 with SHA-256
                import hashlib
                hash_object = hashlib.sha256(b'input')
                hex_dig = hash_object.hexdigest()
                """
        },
        "DES": {
            "general": "DES is insecure because of its short key size. Switch to AES.",
            "code_change": """
                # Switch from DES to AES
                from Crypto.Cipher import AES
                cipher = AES.new('your_key_256_bits', AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(data)
                """
        },
        "MD5": {
            "general": "MD5 is vulnerable to collision attacks. It is recommended to use SHA-256 or SHA-3.",
            "code_change": """
                # Replace MD5 with SHA-256
                import hashlib
                hash_object = hashlib.sha256(b'input')
                hex_dig = hash_object.hexdigest()
                """
        },
        "RC4": {
            "general": "RC4 is deprecated due to vulnerabilities. You should switch to AES for encryption.",
            "code_change": """
                # Example of switching from RC4 to AES
                from Crypto.Cipher import AES
                cipher = AES.new('your_key_256_bits', AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(data)
                """
        },
        "AES": {
            "general": "Ensure you are using AES with proper key sizes and modes like AES-GCM.",
            "code_change": """
                # Example of using AES with 256-bit key in GCM mode
                from Crypto.Cipher import AES
                cipher = AES.new('your_key_256_bits', AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(data)
                """
        }
    }

    return recommendations.get(vulnerability, {"general": "No predefined recommendation available.", "code_change": ""})

st.title("Quantum-Safe Code Vulnerability Analyzer")

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
        selected_vulnerability = st.sidebar.selectbox(
            "Select a vulnerability to get recommendations",
            unique_vulnerabilities
        )

        if selected_vulnerability:
            recommendation = get_recommendation(selected_vulnerability)
            st.sidebar.subheader("General Recommendations:")
            st.sidebar.write(recommendation["general"])

            st.sidebar.subheader("Suggested Code Change:")
            st.sidebar.code(recommendation["code_change"])

    else:
        st.success("✅ No vulnerabilities detected in the uploaded file.")

else:
    st.info("Upload a code file to begin analysis.")