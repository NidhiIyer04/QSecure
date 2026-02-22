def detect_language(filename: str) -> str:
    extension = filename.split(".")[-1].lower()

    mapping = {
        "py": "python",
        "java": "java",
        "js": "javascript",
        "c": "c",
        "cpp": "c",
    }

    return mapping.get(extension, "python")