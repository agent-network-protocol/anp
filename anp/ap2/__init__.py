"""AP2 Protocol Support Module.

Core Components:
    - MandateVerifier: Unified verifier for all mandate types
    - cart_mandate: CartMandate request/response utilities
    - payment_mandate: PaymentMandate request/response utilities
    - credential_mandate: Credential building/verification utilities
    - AP2Client: High-level client API for Travel Agents
"""

# Agents (Stateless - no session management, no HTTP client)
# These agents provide protocol-level operations only.
# State management and HTTP requests are YOUR responsibility.
# Convenience function modules (for explicit import)
from anp.ap2 import cart_mandate, credential_mandate, payment_mandate
from anp.ap2.merchant_agent import MerchantAgent

# Models
from anp.ap2.models import (
    # Content models
    CartContents,
    # Mandates
    CartMandate,
    # Request/Response models
    CartMandateRequest,
    CartMandateRequestData,
    CartRequestItem,
    DisplayItem,
    FulfillmentItem,
    FulfillmentReceipt,
    FulfillmentReceiptContents,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandate,
    PaymentMandateContents,
    PaymentMandateRequest,
    PaymentMethodData,
    # Enums
    PaymentProvider,
    PaymentReceipt,
    PaymentReceiptContents,
    # Payment models
    PaymentRequest,
    PaymentRequestOptions,
    PaymentResponse,
    PaymentResponseDetails,
    PaymentStatus,
    QRCodePaymentData,
    ShippingAddress,
    ShippingInfo,
    WebhookResponse,
)
from anp.ap2.shopper_agent import ShopperAgent

# Utility functions
from anp.ap2.utils import compute_hash

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
    "CartMandateResponse",
    "PaymentMandateRequest",
    "PaymentMandateResponse",
    # Payment models
    "PaymentRequest",
    "PaymentDetails",
    "PaymentDetailsTotal",
    "PaymentResponse",
    "PaymentResponseDetails",
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
    # Utility functions
    "compute_hash",
    
    # Optional modules
    "fastapi_router",  # Optional FastAPI integration
]
