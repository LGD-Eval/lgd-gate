import sys

from .skillgate import main as _main


def run():
    sys.exit(_main() or 0)
