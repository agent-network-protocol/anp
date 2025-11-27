# AP2 Protocol Tools

This module provides a collection of orthogonal tools for building and verifying AP2 protocol data structures, such as `CartMandate`, `PaymentMandate`, and receipt credentials.

## Core Principles

The library is designed with the following principles in mind:

- **Solid Foundation**: Prioritizes reliability and correctness over cleverness. It's built on `pydantic` for robust data validation.
- **Extensible Architecture**: The data models and functions are designed to be composed, allowing developers to easily build complex workflows.
- **API Orthogonality**: Each component has a clear and distinct responsibility. `cart_mandate` tools handle cart logic, `payment_mandate` handles payment authorization, and `credential_mandate` handles issuing receipts.
- **Clear Documentation**: All major functions and models are clearly documented.

## Usage

The primary workflow involves two parties: a "shopper" and a "merchant". The process generally follows these steps:
1. The shopper requests a `CartMandate` from the merchant.
2. The merchant creates and signs a `CartMandate` and sends it back.
3. The shopper verifies the `CartMandate`, then creates and signs a `PaymentMandate` that includes a hash of the original cart.
4. The merchant receives and verifies the `PaymentMandate`, confirming the payment authorization.
5. The merchant issues a signed `PaymentReceipt` credential to the shopper.
6. The shopper verifies the `PaymentReceipt` to ensure its authenticity.

### Core Components

The module provides three main types of components:
- **Data Models**: `pydantic` models representing the core data structures (e.g., `CartMandate`, `PaymentMandateContents`, `PaymentReceipt`).
- **Builders**: Functions to construct and sign mandates and credentials (e.g., `build_cart_mandate`, `build_payment_receipt`).
- **Validators**: Functions to verify the integrity and signature of mandates and credentials (e.g., `validate_payment_mandate`, `validate_credential`).

### Example: Creating and Verifying a Full Flow

This example demonstrates a complete interaction from cart creation to receipt issuance.

```python
import json
from datetime import datetime, timezone

# Helper for loading keys (in a real app, manage these securely)
from anp.utils.crypto_tool import load_private_key_from_string
# Import models, builders, and validators
from anp.ap2.models import (
    CartContents,
    CartMandate,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandateContents,
    PaymentReceiptContents,
    PaymentRequest,
    PaymentResponse,
    PaymentResponseDetails,
    PaymentStatus,
)
from anp.ap2.cart_mandate import build_cart_mandate, validate_cart_mandate
from anp.ap2.credential_mandate import build_payment_receipt, validate_credential
from anp.ap2.payment_mandate import build_payment_mandate, validate_payment_mandate
from anp.ap2.mandate import compute_hash

# --- 0. Setup: DIDs and Keys ---
# In a real system, these would be unique to each party.
# For this example, we reuse the same keys for simplicity.
private_key_pem = ""
public_key_pem = ""

shopper_did = "did:wba:example:shopper"
merchant_did = "did:wba:example:merchant"
shopper_kid = "shopper-key-1"
merchant_kid = "merchant-key-1"
algorithm = "ES256K"
# Use RS256 for credentials as per credential_mandate.py
credential_algorithm = "RS256"


# --- 1. Merchant: Create a Cart Mandate ---
# The merchant defines the contents of the cart.
cart_contents = CartContents(
    id="cart-123",
    payment_request=PaymentRequest(
        details=PaymentDetails(
            id="order-456",
            total=PaymentDetailsTotal(
                label="Total",
                amount=MoneyAmount(currency="CNY", value=100.00),
            ),
        )
    ),
)

# The merchant signs the cart contents to create a secure CartMandate.
cart_mandate = build_cart_mandate(
    contents=cart_contents,
    merchant_private_key=private_key_pem,
    merchant_did=merchant_did,
    merchant_kid=merchant_kid,
    shopper_did=shopper_did,
    algorithm=algorithm,
)

print("[Merchant] CartMandate created.")

# --- 2. Shopper: Verify the Cart Mandate ---
# The shopper receives the CartMandate and verifies its authenticity.
validate_cart_mandate(
    cart_mandate=cart_mandate,
    merchant_public_key=public_key_pem,
    merchant_algorithm=algorithm,
    expected_shopper_did=shopper_did,
)
print("[Shopper] CartMandate verified successfully.")

# The shopper computes the hash of the cart contents for the next step.
cart_hash = compute_hash(cart_mandate.contents.model_dump(exclude_none=True))
print(f"[Shopper] Cart hash: {cart_hash[:32]}...")


# --- 3. Shopper: Create a Payment Mandate ---
# The shopper creates a payment mandate, linking it to the cart via the hash.
payment_mandate_contents = PaymentMandateContents(
    payment_mandate_id="pm-789",
    payment_details_id=cart_mandate.contents.payment_request.details.id,
    payment_details_total=cart_mandate.contents.payment_request.details.total,
    payment_response=PaymentResponse(
        request_id=cart_mandate.contents.payment_request.details.id,
        method_name="EXAMPLE_PAY",
        details=PaymentResponseDetails(channel="mock_channel"),
    ),
    cart_hash=cart_hash, # This links the payment to the cart
)

# The shopper signs the payment mandate.
payment_mandate = build_payment_mandate(
    contents=payment_mandate_contents,
    user_private_key=private_key_pem,
    user_did=shopper_did,
    user_kid=shopper_kid,
    merchant_did=merchant_did,
    algorithm=algorithm,
)
print("[Shopper] PaymentMandate created.")


# --- 4. Merchant: Verify the Payment Mandate ---
# This check ensures the payment is for the correct, unmodified cart.
if not validate_payment_mandate(
    payment_mandate=payment_mandate,
    shopper_public_key=public_key_pem,
    shopper_algorithm=algorithm,
    expected_merchant_did=merchant_did,
    expected_cart_hash=cart_hash,
):
    raise ValueError("PaymentMandate validation failed")
print("[Merchant] PaymentMandate verified successfully.")
# The hash of the payment mandate is needed for the next step in the chain.
pmt_hash = compute_hash(payment_mandate.payment_mandate_contents.model_dump(exclude_none=True))
print(f"[Merchant] PaymentMandate hash: {pmt_hash[:32]}...")


# --- 5. Merchant: Issue a Payment Receipt Credential ---
receipt_contents = PaymentReceiptContents(
    id="receipt-888",
    payment_mandate_id=payment_mandate.payment_mandate_contents.payment_mandate_id,
    status=PaymentStatus.SUCCESS,
    timestamp=datetime.now(timezone.utc).isoformat(),
)

# The merchant signs the receipt, linking it to the payment mandate via pmt_hash.
payment_receipt = build_payment_receipt(
    contents=receipt_contents,
    pmt_hash=pmt_hash,
    merchant_private_key=private_key_pem, # Using same key for simplicity
    merchant_did=merchant_did,
    merchant_kid=merchant_kid,
    algorithm=credential_algorithm,
    shopper_did=shopper_did,
)
print("[Merchant] PaymentReceipt credential issued.")


# --- 6. Shopper: Verify the Payment Receipt ---
# The shopper receives the receipt and verifies its authenticity and its link to the payment.
cred_payload = validate_credential(
    credential=payment_receipt,
    merchant_public_key=public_key_pem,
    merchant_algorithm=credential_algorithm,
    expected_shopper_did=shopper_did,
    expected_pmt_hash=pmt_hash,
)
print("[Shopper] PaymentReceipt verified successfully.")
print(f"[Shopper] Receipt issuer: {cred_payload['iss']}")
print(f\"[Shopper] Credential hash: {cred_payload.get('cred_hash', '')[:32]}...\")

```
