from backend.scanner.ast_parser import get_parser

def parse_code(code: str, language: str):
    parser = get_parser(language)
    tree = parser.parse(bytes(code, "utf8"))
    return tree