"""AP2 Protocol Data Models.

This module defines Pydantic models for AP2 protocol entities,
including CartMandate, PaymentMandate, and related structures.
"""

import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum, StrEnum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class PaymentProvider(StrEnum):
    """Payment provider enum."""

    ALIPAY = "ALIPAY"
    WECHAT = "WECHAT"


class MoneyAmount(BaseModel):
    """Money amount model."""

    currency: str = Field(..., description="Currency code, e.g., CNY, USD")
    value: float = Field(..., description="Amount value")


class DisplayItem(BaseModel):
    """Display item model.

    This model serves as both DisplayItem (for cart display) and CartRequestItem
    (for initial cart requests). The optional fields (options, pending, remark) are
    only used in display contexts.
    """

    id: str = Field(..., description="Item unique identifier (e.g., SKU)")
    label: str = Field(..., description="Item display name")
    quantity: int = Field(..., ge=1, description="Item quantity")
    amount: MoneyAmount = Field(..., description="Price per item")
    options: Optional[Dict[str, Any]] = Field(
        None, description="Item options, e.g., color, size"
    )
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

    channel: PaymentProvider = Field(..., description="Payment channel")
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
    cart_hash: str = Field(
        ...,
        description="Hash pointer to the previously verified CartMandate contents",
    )


class PaymentMandate(BaseModel):
    """Payment mandate model (PaymentMandate)."""

    payment_mandate_contents: PaymentMandateContents = Field(
        ..., description="Payment mandate contents"
    )
    user_authorization: str = Field(
        ..., description="User authorization signature (JWS format)"
    )

    @property
    def id(self) -> str:
        """Returns the payment mandate's unique identifier."""
        return self.payment_mandate_contents.payment_mandate_id


class VerifiedCartMandate(BaseModel):
    """Result returned by CartMandateValidator."""

    cart_mandate: CartMandate = Field(..., description="Original CartMandate object")
    merchant_payload: Dict[str, Any] = Field(..., description="Decoded merchant JWT payload")
    cart_hash: str = Field(..., description="Hash of CartMandate contents")


class VerifiedPaymentMandate(BaseModel):
    """Result returned by PaymentMandateValidator."""

    payment_mandate: PaymentMandate = Field(..., description="Original PaymentMandate object")
    shopper_payload: Dict[str, Any] = Field(..., description="Decoded shopper JWT payload")
    pmt_hash: str = Field(..., description="Hash of PaymentMandate contents")


class CartMandateRequestData(BaseModel):
    """Data for initiating a CartMandate request from TA to MA."""

    cart_mandate_id: str = Field(
        ..., description="Unique identifier for the cart mandate"
    )
    items: List[DisplayItem] = Field(..., description="List of items in the cart")
    shipping_address: Optional[ShippingAddress] = Field(
        None, description="Optional shipping address for the cart"
    )
    remark: Optional[str] = Field(None, description="Optional remark for the order")
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Business-specific metadata for fulfillment (e.g., hotel booking info)",
    )


class PaymentStatus(str, Enum):
    """Payment status enum."""

    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PENDING = "PENDING"
    TIMEOUT = "TIMEOUT"


class PaymentReceiptContents(BaseModel):
    """Payment receipt contents model."""

    credential_type: Literal["PaymentReceipt"] = Field(
        default="PaymentReceipt", description="Credential type"
    )
    version: int = Field(default=1, description="Credential version")
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Credential unique ID"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Credential issuance time in ISO-8601 format",
    )
    payment_mandate_id: str = Field(..., description="Payment mandate ID")
    provider: PaymentProvider = Field(..., description="Payment provider")
    status: PaymentStatus = Field(..., description="Payment status")
    transaction_id: str = Field(..., description="Provider transaction ID")
    out_trade_no: str = Field(..., description="External trade number")
    paid_at: str = Field(..., description="Payment time in ISO-8601 format")
    amount: MoneyAmount = Field(..., description="Payment amount")
    pmt_hash: str = Field(
        ..., description="Hash pointer to PaymentMandate contents (set when issued)"
    )


class PaymentReceipt(BaseModel):
    """Payment receipt credential model."""

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

    credential_type: Literal["FulfillmentReceipt"] = Field(
        default="FulfillmentReceipt", description="Credential type"
    )
    version: int = Field(default=1, description="Credential version")
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Credential unique ID"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Credential issuance time in ISO-8601 format",
    )
    order_id: str = Field(..., description="Order ID")
    items: List[FulfillmentItem] = Field(..., description="Fulfilled items")
    fulfilled_at: str = Field(..., description="Fulfillment time in ISO-8601 format")
    shipping: Optional[ShippingInfo] = Field(None, description="Shipping information")
    pmt_hash: str = Field(
        ..., description="Hash pointer to PaymentMandate contents (set when issued)"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Business-specific fulfillment data (e.g., hotel order number, booking confirmation)",
    )


class FulfillmentReceipt(BaseModel):
    """Fulfillment receipt credential model."""

    contents: FulfillmentReceiptContents = Field(..., description="Receipt contents")
    merchant_authorization: str = Field(
        ..., description="Merchant authorization signature (JWS)"
    )


Credential = PaymentReceipt | FulfillmentReceipt

# Union of all possible ANP message data payloads for composition.
# Note: Credential types are defined later in the file
ANPMessageData = (
    CartMandateRequestData
    | CartMandate
    | PaymentMandate
    | PaymentReceipt
    | FulfillmentReceipt
)


class ANPMessage(BaseModel):
    """Generic ANP message structure using composition.

    This structure acts as an envelope, holding common metadata, and a 'data'
    field that contains the specific message payload as a composed object.
    This approach is favored over inheritance for flexibility.
    """

    model_config = ConfigDict(populate_by_name=True)

    messageId: str = Field(..., description="Unique message identifier")
    from_: str = Field(..., alias="from", description="Sender's DID")
    to: str = Field(..., description="Recipient's DID")
    data: ANPMessageData = Field(
        ..., description="Protocol-specific payload (composed object)"
    )
    credential_webhook_url: Optional[str] = Field(
        None, description="Webhook URL for credentials"
    )
