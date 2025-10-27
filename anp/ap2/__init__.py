"""AP2 Protocol Support Module.

This module implements the AP2 (Agent Payment Protocol v2) for ANP,
providing CartMandate and PaymentMandate construction and verification.

Core Components:
    - models: Pydantic data models for AP2 protocol entities
    - cart_mandate: CartMandate builder and verifier
    - payment_mandate: PaymentMandate builder and verifier
    - utils: Common utilities (JCS canonicalization, hash computation)
"""

from anp.ap2.cart_mandate import CartMandateBuilder, CartMandateVerifier
from anp.ap2.payment_mandate import PaymentMandateBuilder, PaymentMandateVerifier
from anp.ap2.client import (
    AP2Client,
    create_cart_mandate,
    send_payment_mandate,
)
from anp.ap2.models import (
    CartMandate,
    PaymentMandate,
    CartContents,
    PaymentMandateContents,
    PaymentRequest,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentResponse,
    MoneyAmount,
    DisplayItem,
    ShippingAddress,
    PaymentMethodData,
    QRCodePaymentData,
    PaymentRequestOptions,
    PaymentTotal,
)

__all__ = [
    # Builders and Verifiers
    "CartMandateBuilder",
    "CartMandateVerifier",
    "PaymentMandateBuilder",
    "PaymentMandateVerifier",
    # HTTP Client
    "AP2Client",
    "create_cart_mandate",
    "send_payment_mandate",
    # Models
    "CartMandate",
    "PaymentMandate",
    "CartContents",
    "PaymentMandateContents",
    "PaymentRequest",
    "PaymentDetails",
    "PaymentDetailsTotal",
    "PaymentResponse",
    "MoneyAmount",
    "DisplayItem",
    "ShippingAddress",
    "PaymentMethodData",
    "QRCodePaymentData",
    "PaymentRequestOptions",
    "PaymentTotal",
]
