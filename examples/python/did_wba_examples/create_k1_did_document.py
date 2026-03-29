"""Create an explicit k1 DID document example for compatibility scenarios."""

from __future__ import annotations

import sys

from create_did_document import main as _main


if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--profile", "k1"] + sys.argv[1:]
    _main()
