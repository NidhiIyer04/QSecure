import json

def convert_to_sarif(filename, findings):

    sarif_results = []

    for f in findings:
        sarif_results.append({
            "ruleId": f["algorithm"],
            "level": "error" if f.get("severity") == "HIGH" else "warning",
            "message": {
                "text": f.get("recommendation", "")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": filename
                    },
                    "region": {
                        "startLine": f.get("line", 1)
                    }
                }
            }]
        })

    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "QuantumCryptoAnalyzer",
                    "rules": []
                }
            },
            "results": sarif_results
        }]
    }