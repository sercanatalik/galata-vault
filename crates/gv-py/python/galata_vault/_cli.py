"""The ``gv`` console script: the native galata-vault CLI, run in-process."""

import sys

from . import _native


def main() -> None:
    sys.exit(_native.run_cli(["gv", *sys.argv[1:]]))


if __name__ == "__main__":
    main()
