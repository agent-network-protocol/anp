"""AP2 Protocol Support Module.

This module provides a collection of orthogonal tools for building and
verifying AP2 protocol data structures.

The primary API surface is flat, providing direct access to key builders,
validators, and commonly used Pydantic models so callers can simply import
`from anp.ap2 import CartMandate` without digging into subpackages.
"""

from .models import (
    ANPMessage,
    CartContents,
    CartMandate,
    CartMandateRequestData,
    DisplayItem,
    FulfillmentReceipt,
    FulfillmentReceiptContents,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandate,
    PaymentMandateContents,
    PaymentMethodData,
    PaymentProvider,
    PaymentReceipt,
    PaymentReceiptContents,
    PaymentRequest,
    PaymentRequestOptions,
    PaymentResponse,
    PaymentResponseDetails,
    PaymentStatus,
    QRCodePaymentData,
    ShippingAddress,
    ShippingInfo,
)
from .mandate import (
    b64url_no_pad,
    build_mandate,
    compute_hash,
    jcs_canonicalize,
    validate_mandate,
)

__all__ = [
    # Data Models
    "ANPMessage",
    "CartContents",
    "CartMandate",
    "CartMandateRequestData",
    "DisplayItem",
    "MoneyAmount",
    "PaymentDetails",
    "PaymentDetailsTotal",
    "PaymentMandate",
    "PaymentMandateContents",
    "PaymentMethodData",
    "PaymentReceipt",
    "PaymentReceiptContents",
    "PaymentProvider",
    "PaymentRequest",
    "PaymentRequestOptions",
    "PaymentResponse",
    "PaymentResponseDetails",
    "PaymentStatus",
    "QRCodePaymentData",
    "ShippingAddress",
    "ShippingInfo",
    "FulfillmentReceipt",
    "FulfillmentReceiptContents",
    # Utilities
    "compute_hash",
    "b64url_no_pad",
    "jcs_canonicalize",
    # Functional Mandate API
    "build_mandate",
    "validate_mandate",
]
