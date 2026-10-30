"""Launch the scanner's stdio MCP transport."""
from bypass_scanner.transports.mcp import serve


def main() -> None:
    serve()


if __name__ == "__main__":
    main()
