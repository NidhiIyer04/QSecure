from backend.services.grading_service import GradingService
from backend.scanner.replacement_engine import ReplacementEngine
from backend.services.ai_service import AIService


grading_service = GradingService()
replacement_engine = ReplacementEngine()
ai_service = AIService()


def run_scan(findings):
    results = []

    for finding in findings:
        grading = grading_service.assess(finding)

        fix = replacement_engine.generate_fix(
            finding,
            finding.get("original_line", "")
        )

        explanation = ai_service.generate_explanation(finding)

        results.append({
            "finding": finding,
            "grading": grading,
            "fix": fix,
            "explanation": explanation,
        })

    return results