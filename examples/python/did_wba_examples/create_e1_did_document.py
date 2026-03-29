"""Create an explicit e1 DID document example."""

from __future__ import annotations

from create_did_document import main as _main
import sys


if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--profile", "e1"] + sys.argv[1:]
    _main()
