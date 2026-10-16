"""Legacy LLM-driven meta-protocol negotiation.

This module implements the earlier ANP-06 design, where negotiation ran inside
message payloads with a binary protocol-type header. It is kept for existing
users. New code should use ``anp.meta_negotiation``, which follows the current
ANP-06 draft (``anp.meta.negotiation.v1`` / ``anp.negotiate``).
"""

from .meta_protocol import MetaProtocol, ProtocolType

__all__ = ['MetaProtocol', 'ProtocolType']














