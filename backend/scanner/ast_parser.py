from tree_sitter import Language, Parser
import os

LIB_PATH = "backend/scanner/build/my-languages.so"

def build_language_library():
    if not os.path.exists(LIB_PATH):
        os.makedirs("backend/scanner/build", exist_ok=True)

        Language.build_library(
            LIB_PATH,
            [
                "third_party/tree-sitter-python",
                "third_party/tree-sitter-java",
                "third_party/tree-sitter-javascript",
                "third_party/tree-sitter-c",
            ],
        )

def get_parser(language: str):
    build_language_library()

    LANGUAGE = Language(LIB_PATH, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    return parser