"""AP2 Protocol Data Models.

This module defines Pydantic models for AP2 protocol entities,
including CartMandate, PaymentMandate, and related structures.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


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
    options: Optional[Dict[str, Any]] = Field(None, description="Item options, e.g., color, size")
    amount: MoneyAmount = Field(..., description="Item amount")
    pending: Optional[bool] = Field(None, description="Whether pending")
    remark: Optional[str] = Field(None, description="Remark")


class PaymentTotal(BaseModel):
    """Payment total model."""

    label: str = Field(..., description="Label, e.g., Total")
    amount: MoneyAmount = Field(..., description="Total amount")
    pending: Optional[bool] = Field(None, description="Whether pending")


class ShippingAddress(BaseModel):
    """Shipping address model."""

    recipient_name: str = Field(..., description="Recipient name")
    phone: str = Field(..., description="Contact phone")
    region: str = Field(..., description="Province/Region")
    city: str = Field(..., description="City")
    address_line: str = Field(..., description="Detailed address")
    postal_code: str = Field(..., description="Postal code")


class PaymentDetails(BaseModel):
    """Payment details model."""

    id: str = Field(..., description="Order unique identifier")
    displayItems: List[DisplayItem] = Field(..., description="Display items list")
    shipping_address: Optional[ShippingAddress] = Field(None, description="Shipping address")
    shipping_options: Optional[Any] = Field(None, description="Shipping options")
    modifiers: Optional[Any] = Field(None, description="Modifiers")
    total: PaymentTotal = Field(..., description="Payment total")


class QRCodePaymentData(BaseModel):
    """QR code payment data model."""

    channel: str = Field(..., description="Payment channel, e.g., ALIPAY, WECHAT")
    qr_url: str = Field(..., description="QR code URL")
    out_trade_no: str = Field(..., description="External trade number")
    expires_at: str = Field(..., description="Expiration time in ISO 8601 format")


class PaymentMethodData(BaseModel):
    """Payment method data model."""

    supported_methods: str = Field(..., description="Supported payment methods, e.g., QR_CODE")
    data: QRCodePaymentData = Field(..., description="Payment method data")


class PaymentRequestOptions(BaseModel):
    """Payment request options model."""

    requestPayerName: bool = Field(False, description="Whether to request payer name")
    requestPayerEmail: bool = Field(False, description="Whether to request payer email")
    requestPayerPhone: bool = Field(False, description="Whether to request payer phone")
    requestShipping: bool = Field(True, description="Whether to request shipping information")
    shippingType: Optional[str] = Field(None, description="Shipping type")


class PaymentRequest(BaseModel):
    """Payment request model."""

    method_data: List[PaymentMethodData] = Field(..., description="Payment method data list")
    details: PaymentDetails = Field(..., description="Payment details")
    options: PaymentRequestOptions = Field(..., description="Payment request options")


class CartContents(BaseModel):
    """Cart contents model."""

    id: str = Field(..., description="Cart unique identifier")
    user_signature_required: bool = Field(..., description="Whether user signature is required")
    payment_request: PaymentRequest = Field(..., description="Payment request")


class CartMandate(BaseModel):
    """Cart mandate model (CartMandate)."""

    contents: CartContents = Field(..., description="Cart contents")
    merchant_authorization: str = Field(..., description="Merchant authorization signature (JWS format)")
    timestamp: str = Field(..., description="Timestamp in ISO 8601 format")


class PaymentResponse(BaseModel):
    """Payment response model."""

    request_id: str = Field(..., description="Request ID, corresponding to PaymentDetails.id")
    method_name: str = Field(..., description="Payment method name, e.g., QR_CODE")
    details: Dict[str, Any] = Field(..., description="Payment details")
    shipping_address: Optional[ShippingAddress] = Field(None, description="Shipping address")
    shipping_option: Optional[str] = Field(None, description="Shipping option")
    payer_name: Optional[str] = Field(None, description="Payer name")
    payer_email: Optional[str] = Field(None, description="Payer email")
    payer_phone: Optional[str] = Field(None, description="Payer phone")


class PaymentDetailsTotal(BaseModel):
    """Payment details total model (for PaymentMandate)."""

    label: str = Field(..., description="Label")
    amount: MoneyAmount = Field(..., description="Amount")
    pending: Optional[bool] = Field(None, description="Whether pending")
    refund_period: int = Field(..., description="Refund period (days)")


class PaymentMandateContents(BaseModel):
    """Payment mandate contents model."""

    payment_mandate_id: str = Field(..., description="Payment mandate unique identifier")
    payment_details_id: str = Field(..., description="Payment details ID, corresponding to details.id in CartMandate")
    payment_details_total: PaymentDetailsTotal = Field(..., description="Payment details total")
    payment_response: PaymentResponse = Field(..., description="Payment response")
    merchant_agent: str = Field(..., description="Merchant agent identifier")
    timestamp: str = Field(..., description="Timestamp in ISO 8601 format")


class PaymentMandate(BaseModel):
    """Payment mandate model (PaymentMandate)."""

    payment_mandate_contents: PaymentMandateContents = Field(..., description="Payment mandate contents")
    user_authorization: str = Field(..., description="User authorization signature (JWS format)")
