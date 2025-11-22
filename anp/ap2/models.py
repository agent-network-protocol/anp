"""AP2 Protocol Data Models.

This module defines Pydantic models for AP2 protocol entities,
including CartMandate, PaymentMandate, and related structures.
"""

from datetime import datetime, timedelta, timezone
from enum import Enum, StrEnum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class MoneyAmount(BaseModel):
    """Money amount model."""

    currency: str = Field(..., description="Currency code, e.g., CNY, USD")
    value: float = Field(..., description="Amount value")


class DisplayItem(BaseModel):
    """Display item model."""

    id: str = Field(..., description="Item unique identifier")
    sku: str = Field(..., description="Item SKU")
    label: str = Field(..., description="Item display name")
    quantity: int = Field(..., description="Item quantity")
    options: Optional[Dict[str, Any]] = Field(
        None, description="Item options, e.g., color, size"
    )
    amount: MoneyAmount = Field(..., description="Item amount")
    pending: Optional[bool] = Field(None, description="Whether pending")
    remark: Optional[str] = Field(None, description="Remark")


class ShippingAddress(BaseModel):
    """Shipping address model."""

    recipient_name: str = Field(..., description="Recipient name")
    phone: str = Field(..., description="Contact phone")
    region: str | None = Field(None, description="Province/Region")
    city: str | None = Field(None, description="City")
    address_line: str | None = Field(None, description="Detailed address")
    postal_code: str | None = Field(None, description="Postal code")


class PaymentDetailsTotal(BaseModel):
    """Payment details total model."""

    label: str = Field(..., description="Label")
    amount: MoneyAmount = Field(..., description="Amount")
    pending: Optional[bool] = Field(None, description="Whether pending")
    refund_period: Optional[int] = Field(None, description="Refund period (days)")


class PaymentDetails(BaseModel):
    """Payment details model."""

    id: str = Field(..., description="Order unique identifier")
    displayItems: List[DisplayItem] = Field(..., description="Display items list")
    shipping_address: Optional[ShippingAddress] = Field(
        None, description="Shipping address"
    )
    shipping_options: Optional[Any] = Field(None, description="Shipping options")
    modifiers: Optional[Any] = Field(None, description="Modifiers")
    total: PaymentDetailsTotal = Field(..., description="Payment total")


class QRCodePaymentData(BaseModel):
    """QR code payment data model."""

    channel: str = Field(..., description="Payment channel, e.g., ALIPAY, WECHAT")
    qr_url: str = Field(..., description="QR code URL")
    out_trade_no: str = Field(..., description="External trade number")
    expires_at: str = Field(
        default_factory=lambda: (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
        description="Expiration time in ISO 8601 format",
    )


class PaymentMethodData(BaseModel):
    """Payment method data model."""

    supported_methods: str = Field(
        ..., description="Supported payment methods, e.g., QR_CODE"
    )
    data: QRCodePaymentData = Field(..., description="Payment method data")


class PaymentRequestOptions(BaseModel):
    """Payment request options model."""

    requestPayerName: bool = Field(False, description="Whether to request payer name")
    requestPayerEmail: bool = Field(False, description="Whether to request payer email")
    requestPayerPhone: bool = Field(False, description="Whether to request payer phone")
    requestShipping: bool = Field(
        True, description="Whether to request shipping information"
    )
    shippingType: Optional[str] = Field(None, description="Shipping type")


class PaymentRequest(BaseModel):
    """Payment request model."""

    method_data: List[PaymentMethodData] = Field(
        ..., description="Payment method data list"
    )
    details: PaymentDetails = Field(..., description="Payment details")
    options: PaymentRequestOptions = Field(..., description="Payment request options")


class CartContents(BaseModel):
    """Cart contents model."""

    id: str = Field(..., description="Cart unique identifier")
    user_signature_required: bool = Field(
        ..., description="Whether user signature is required"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp in ISO 8601 format",
    )
    payment_request: PaymentRequest = Field(..., description="Payment request")


class CartMandate(BaseModel):
    """Cart mandate model (CartMandate)."""

    contents: CartContents = Field(..., description="Cart contents")
    merchant_authorization: str = Field(
        ..., description="Merchant authorization signature (JWS format)"
    )


class PaymentResponseDetails(BaseModel):
    """Payment response detail payload."""

    model_config = ConfigDict(extra="allow")

    channel: str = Field(..., description="Payment channel identifier")
    out_trade_no: str = Field(..., description="External trade number")


class PaymentResponse(BaseModel):
    """Payment response model."""

    request_id: str = Field(
        ..., description="Request ID, corresponding to PaymentDetails.id"
    )
    method_name: str = Field(..., description="Payment method name, e.g., QR_CODE")
    details: PaymentResponseDetails = Field(
        ..., description="Provider-specific payment response details"
    )
    shipping_address: Optional[ShippingAddress] = Field(
        None, description="Shipping address"
    )
    shipping_option: Optional[str] = Field(None, description="Shipping option")
    payer_name: Optional[str] = Field(None, description="Payer name")
    payer_email: Optional[str] = Field(None, description="Payer email")
    payer_phone: Optional[str] = Field(None, description="Payer phone")


class PaymentMandateContents(BaseModel):
    """Payment mandate contents model."""

    payment_mandate_id: str = Field(
        ..., description="Payment mandate unique identifier"
    )
    payment_details_id: str = Field(
        ...,
        description="Payment details ID, corresponding to details.id in CartMandate",
    )
    payment_details_total: PaymentDetailsTotal = Field(
        ..., description="Payment details total"
    )
    payment_response: PaymentResponse = Field(..., description="Payment response")
    merchant_agent: str = Field(..., description="Merchant agent identifier")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp in ISO 8601 format",
    )
    prev_hash: Optional[str] = Field(
        None, description="Previous hash pointer (cart_hash for chaining)"
    )


class PaymentMandate(BaseModel):
    """Payment mandate model (PaymentMandate)."""

    payment_mandate_contents: PaymentMandateContents = Field(
        ..., description="Payment mandate contents"
    )
    user_authorization: str = Field(
        ..., description="User authorization signature (JWS format)"
    )


class ANPMessage(BaseModel):
    """Generic ANP message structure for requests."""

    model_config = ConfigDict(populate_by_name=True)

    messageId: str = Field(..., description="Unique message identifier")
    from_: str = Field(..., alias="from", description="Sender's DID")
    to: str = Field(..., description="Recipient's DID")
    credential_webhook_url: Optional[str] = Field(
        None, description="Webhook URL for credentials"
    )
    data: Optional[Dict[str, Any]] = Field(
        None, description="Protocol-specific payload for the message"
    )


class CartRequestItem(BaseModel):
    """Simplified item model for an initial cart request."""

    id: str = Field(..., description="Item unique identifier (e.g., SKU)")
    quantity: int = Field(..., ge=1, description="Item quantity")
    amount: MoneyAmount = Field(..., description="Price per item")
    label: Optional[str] = Field(None, description="Item display name")


class CartMandateRequestData(BaseModel):
    """Data for initiating a CartMandate request from TA to MA."""

    cart_mandate_id: str = Field(
        ..., description="Unique identifier for the cart mandate"
    )
    items: List[CartRequestItem] = Field(..., description="List of items in the cart")
    shipping_address: Optional[ShippingAddress] = Field(
        None, description="Optional shipping address for the cart"
    )
    remark: Optional[str] = Field(None, description="Optional remark for the order")
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Business-specific metadata for fulfillment (e.g., hotel booking info)",
    )


class CartMandateRequest(ANPMessage):
    """Full ANP message for a CartMandate request."""

    data: CartMandateRequestData = Field(..., description="Cart mandate request data")


class CartMandateResponse(ANPMessage):
    """Full ANP message for a CartMandate response."""

    data: CartMandate = Field(..., description="Cart mandate response data")


class PaymentMandateRequest(ANPMessage):
    """Full ANP message for a PaymentMandate request."""

    data: PaymentMandate = Field(..., description="Payment mandate request data")


class PaymentMandateResponse(ANPMessage):
    """Full ANP message for a PaymentMandate response."""

    data: Dict[str, Any] = Field(..., description="Payment mandate response data")


# ==============================================================================
# Webhook Credential Models
# ==============================================================================


class PaymentProvider(StrEnum):
    """Payment provider enum."""

    ALIPAY = "ALIPAY"
    WECHAT = "WECHAT"


class PaymentStatus(str, Enum):
    """Payment status enum."""

    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PENDING = "PENDING"
    TIMEOUT = "TIMEOUT"


class PaymentReceiptContents(BaseModel):
    """Payment receipt contents model."""

    payment_mandate_id: str = Field(..., description="Payment mandate ID")
    provider: PaymentProvider = Field(..., description="Payment provider")
    status: PaymentStatus = Field(..., description="Payment status")
    transaction_id: str = Field(..., description="Provider transaction ID")
    out_trade_no: str = Field(..., description="External trade number")
    paid_at: str = Field(..., description="Payment time in ISO-8601 format")
    amount: MoneyAmount = Field(..., description="Payment amount")
    timestamp: Optional[str] = Field(
        None, description="Credential issuance time in ISO-8601 format"
    )
    prev_hash: Optional[str] = Field(
        None, description="Previous hash pointer (pmt_hash)"
    )


class PaymentReceipt(BaseModel):
    """Payment receipt credential model."""

    credential_type: Literal["PaymentReceipt"] = Field(
        default="PaymentReceipt", description="Credential type"
    )
    version: int = Field(default=1, description="Credential version")
    id: str = Field(..., description="Credential unique ID")
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    contents: PaymentReceiptContents = Field(..., description="Receipt contents")
    merchant_authorization: str = Field(
        ..., description="Merchant authorization signature (JWS)"
    )


class FulfillmentItem(BaseModel):
    """Fulfillment item model."""

    id: str = Field(..., description="Item ID")
    quantity: int = Field(..., description="Fulfilled quantity")


class ShippingInfo(BaseModel):
    """Shipping information model."""

    carrier: str = Field(..., description="Shipping carrier")
    tracking_number: str = Field(..., description="Tracking number")
    delivered_eta: str = Field(
        ..., description="Expected delivery time in ISO-8601 format"
    )


class FulfillmentReceiptContents(BaseModel):
    """Fulfillment receipt contents model."""

    order_id: str = Field(..., description="Order ID")
    items: List[FulfillmentItem] = Field(..., description="Fulfilled items")
    fulfilled_at: str = Field(..., description="Fulfillment time in ISO-8601 format")
    shipping: Optional[ShippingInfo] = Field(None, description="Shipping information")
    timestamp: Optional[str] = Field(
        None, description="Credential issuance time in ISO-8601 format"
    )
    prev_hash: Optional[str] = Field(
        None, description="Previous hash pointer (pmt_hash)"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Business-specific fulfillment data (e.g., hotel order number, booking confirmation)",
    )


class FulfillmentReceipt(BaseModel):
    """Fulfillment receipt credential model."""

    credential_type: Literal["FulfillmentReceipt"] = Field(
        default="FulfillmentReceipt", description="Credential type"
    )
    version: int = Field(default=1, description="Credential version")
    id: str = Field(..., description="Credential unique ID")
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    contents: FulfillmentReceiptContents = Field(..., description="Receipt contents")
    merchant_authorization: str = Field(
        ..., description="Merchant authorization signature (JWS)"
    )  # Union type for credentials


Credential = PaymentReceipt | FulfillmentReceipt


class WebhookResponse(BaseModel):
    """Webhook response model (TA → MA)."""

    status: Literal["received", "already_received", "error"] = Field(
        ..., description="Response status"
    )
    credential_id: str = Field(..., description="Credential ID")
    received_at: Optional[str] = Field(None, description="ISO-8601 timestamp")
    first_received_at: Optional[str] = Field(
        None, description="First received time (for already_received)"
    )
    error_code: Optional[str] = Field(None, description="Error code if status is error")
    message: Optional[str] = Field(None, description="Error message if status is error")
