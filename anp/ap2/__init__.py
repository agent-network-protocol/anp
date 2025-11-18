"""AP2 Protocol Support Module.

Core Components:
    - MandateVerifier: Unified verifier for all mandate types
    - cart_mandate: CartMandate request/response utilities
    - payment_mandate: PaymentMandate request/response utilities
    - credential_mandate: Credential building/verification utilities
    - AP2Client: High-level client API for Travel Agents
"""

# Agents
from anp.ap2.shopper_agent import ShopperAgent
from anp.ap2.merchant_agent import MerchantAgent

# Models
from anp.ap2.models import (
    # Mandates
    CartMandate,
    PaymentMandate,
    PaymentReceipt,
    FulfillmentReceipt,

    # Content models
    CartContents,
    PaymentMandateContents,
    PaymentReceiptContents,
    FulfillmentReceiptContents,

    # Request/Response models
    CartMandateRequest,
    CartMandateRequestData,
    PaymentMandateRequest,

    # Payment models
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
    FulfillmentItem,
    ShippingInfo,
    WebhookResponse,
    CartRequestItem,

    # Enums
    PaymentProvider,
    PaymentStatus,
)

# Convenience function modules (for explicit import)
from anp.ap2 import cart_mandate
from anp.ap2 import payment_mandate
from anp.ap2 import credential_mandate

__all__ = [
    # Agents
    "ShopperAgent",
    "MerchantAgent",

    # Models
    "CartMandate",
    "PaymentMandate",
    "PaymentReceipt",
    "FulfillmentReceipt",

    # Content models
    "CartContents",
    "PaymentMandateContents",
    "PaymentReceiptContents",
    "FulfillmentReceiptContents",

    # Request/Response models
    "CartMandateRequest",
    "CartMandateRequestData",
    "PaymentMandateRequest",

    # Payment models
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
    "FulfillmentItem",
    "ShippingInfo",
    "WebhookResponse",
    "CartRequestItem",

    # Enums
    "PaymentProvider",
    "PaymentStatus",

    # Convenience function modules
    "cart_mandate",
    "payment_mandate",
    "credential_mandate",
]
