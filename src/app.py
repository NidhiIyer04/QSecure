import sys
import os
from flask import Flask, request, jsonify
from crypto_analyzer import CryptoStaticAnalyzer, FeatureExtractor

# Add the 'analyzers' directory to the sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), 'analyzers'))

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # Ensure a file was uploaded
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    # Save the file temporarily
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)

    # Run the analysis
    analyzer = CryptoStaticAnalyzer()
    feature_extractor = FeatureExtractor()

    vulnerabilities = analyzer.analyze_file(file_path)
    features = feature_extractor.extract_features(vulnerabilities)
    
    # Format the response data for frontend usage
    results = []
    for vulnerability in features:
        results.append({
            'file': vulnerability.get('file'),
            'language': vulnerability.get('language'),
            'match': vulnerability.get('match'),
            'line': vulnerability.get('line'),
            'severity': vulnerability.get('severity'),
            'quantum_vulnerable': vulnerability.get('quantum_vulnerable'),
            'explanation': vulnerability.get('explanation')  # Assuming explanation is part of the output
        })
    
    return jsonify({'results': results})


if __name__ == "__main__":
    # Ensure uploads folder exists
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
