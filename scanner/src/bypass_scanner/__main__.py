"""Launch the scanner's stdio MCP transport."""
from bypass_scanner.transports.mcp import serve
from bypass_scanner.service import close


def main() -> None:
    try:
        serve()
    finally:
        close()


if __name__ == "__main__":
    main()
