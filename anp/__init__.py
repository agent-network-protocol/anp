"""Top-level ANP Python SDK exports.

[INPUT]: Package consumers importing the ANP Python SDK and its shared version
metadata.
[OUTPUT]: Public Python SDK entry points, direct E2EE helpers, and the package
version string.
[POS]: This module is the Python package root for the ANP SDK distribution.

[PROTOCOL]:
1. Keep exported symbols aligned with the packaged SDK surface.
2. Update the package version here when cutting a new coordinated SDK release.
3. Avoid importing optional-heavy modules unless they are part of the public API.
"""

# ANP Crawler
from .anp_crawler.anp_client import ANPClient

# Legacy E2EE modules remain importable but are not wire-compatible with
# anp.direct.e2ee.v1.
# from .e2e_encryption.wss_message_sdk import WssMessageSDK

from .direct_e2ee import (
    DirectE2eeSession,
    FileSessionStore,
    FileSignedPrekeyStore,
    MessageServiceDirectE2eeClient,
    PrekeyManager,
)

__version__ = "0.8.7"

# interfaces
# from .authentication import didallclient

# simple node
# from .simple_node import simple_node

# Define what should be exported when using "from anp import *"
__all__ = [
    '__version__',
    'ANPClient',
    'DirectE2eeSession',
    'FileSessionStore',
    'FileSignedPrekeyStore',
    'MessageServiceDirectE2eeClient',
    'PrekeyManager',
    'simple_node',
    'didallclient',
]
