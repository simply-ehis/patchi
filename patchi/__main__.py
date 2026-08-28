"""Allow running patchi as a module: python -m patchi"""

import sys


def main():
    from patchi.cli.main import main as cli_main

    return cli_main()


if __name__ == "__main__":
    sys.exit(main() or 0)
