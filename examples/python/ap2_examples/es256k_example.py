"""Example: Using ES256K algorithm with AP2 CartMandate and PaymentMandate.

This example demonstrates how to use ES256K (ECDSA with secp256k1 curve)
for signing CartMandate and PaymentMandate, which is particularly useful
for blockchain and cryptocurrency applications.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from anp.ap2.cart_mandate import CartMandateBuilder, CartMandateVerifier
from anp.ap2.models import (
    CartContents,
    DisplayItem,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandateContents,
    PaymentMethodData,
    PaymentRequest,
    PaymentRequestOptions,
    PaymentResponse,
    PaymentTotal,
)
from anp.ap2.payment_mandate import PaymentMandateBuilder, PaymentMandateVerifier


def generate_es256k_keypair():
    """Generate ES256K (secp256k1) key pair.
    
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    # Generate private key using secp256k1 curve (same as Bitcoin/Ethereum)
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    
    # Serialize to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


def main():
    """Run ES256K example."""
    print("=" * 70)
    print("AP2 Protocol with ES256K Algorithm Example")
    print("=" * 70)
    
    # Step 1: Generate merchant's ES256K key pair
    print("\n[Step 1] Generating merchant's ES256K key pair...")
    merchant_private_key, merchant_public_key = generate_es256k_keypair()
    print("✓ Merchant key pair generated (secp256k1 curve)")
    
    # Step 2: Build CartMandate with ES256K
    print("\n[Step 2] Building CartMandate with ES256K...")
    
    cart_builder = CartMandateBuilder(
        merchant_private_key=merchant_private_key,
        merchant_did="did:wba:didhost.cc:merchant",
        merchant_kid="merchant-es256k-key-001",
        algorithm="ES256K",  # Use ES256K algorithm
        shopper_did="did:wba:didhost.cc:shopper"
    )
    
    # Create cart contents
    cart_contents = CartContents(
        id="cart_crypto_payment_001",
        user_signature_required=False,
        payment_request=PaymentRequest(
            method_data=[
                PaymentMethodData(
                    supported_methods="QR_CODE",
                    data={
                        "channel": "CRYPTO",
                        "qr_url": "https://crypto.example.com/pay/abc123",
                        "out_trade_no": "crypto_order_20250126_001",
                        "expires_at": "2025-01-26T12:00:00Z"
                    }
                )
            ],
            details=PaymentDetails(
                id="order_crypto_001",
                displayItems=[
                    DisplayItem(
                        id="item-001",
                        sku="CRYPTO-TOKEN-001",
                        label="Crypto Token Purchase",
                        quantity=100,
                        amount=MoneyAmount(currency="USDT", value=1000.0)
                    )
                ],
                total=PaymentTotal(
                    label="Total",
                    amount=MoneyAmount(currency="USDT", value=1000.0)
                )
            ),
            options=PaymentRequestOptions()
        )
    )
    
    # Build CartMandate
    cart_mandate = cart_builder.build(
        cart_contents=cart_contents,
        extensions=["anp.ap2.crypto.v1", "anp.blockchain.v1"]
    )
    
    print("✓ CartMandate built successfully")
    print("  Algorithm: ES256K")
    print(f"  Authorization: {cart_mandate.merchant_authorization[:60]}...")
    
    # Step 3: Verify CartMandate
    print("\n[Step 3] Verifying CartMandate with ES256K...")
    
    cart_verifier = CartMandateVerifier(
        merchant_public_key=merchant_public_key,
        algorithm="ES256K"  # Use ES256K algorithm
    )
    
    cart_payload = cart_verifier.verify(
        cart_mandate=cart_mandate,
        expected_aud="did:wba:didhost.cc:shopper"
    )
    
    print("✓ CartMandate verified successfully")
    print(f"  Issuer: {cart_payload['iss']}")
    print(f"  Audience: {cart_payload['aud']}")
    print(f"  Cart Hash: {cart_payload['cart_hash'][:40]}...")
    print(f"  Extensions: {cart_payload.get('extensions', [])}")
    
    # Step 4: Generate user's ES256K key pair
    print("\n[Step 4] Generating user's ES256K key pair...")
    user_private_key, user_public_key = generate_es256k_keypair()
    print("✓ User key pair generated (secp256k1 curve)")
    
    # Step 5: Build PaymentMandate with ES256K
    print("\n[Step 5] Building PaymentMandate with ES256K...")
    
    payment_builder = PaymentMandateBuilder(
        user_private_key=user_private_key,
        user_did="did:wba:didhost.cc:shopper",
        user_kid="shopper-es256k-key-001",
        algorithm="ES256K",  # Use ES256K algorithm
        merchant_did="did:wba:didhost.cc:merchant"
    )
    
    # Create payment mandate contents
    payment_contents = PaymentMandateContents(
        payment_mandate_id="pm_crypto_001",
        payment_details_id="order_crypto_001",
        payment_details_total=PaymentDetailsTotal(
            label="Total",
            amount=MoneyAmount(currency="USDT", value=1000.0),
            refund_period=7
        ),
        payment_response=PaymentResponse(
            request_id="order_crypto_001",
            method_name="QR_CODE",
            details={
                "channel": "CRYPTO",
                "out_trade_no": "crypto_order_20250126_001",
                "tx_hash": "0x1234567890abcdef..."
            }
        ),
        merchant_agent="CryptoMerchantAgent",
        timestamp="2025-01-26T10:30:00Z"
    )
    
    # Build PaymentMandate
    payment_mandate = payment_builder.build(
        payment_mandate_contents=payment_contents,
        cart_hash=cart_payload["cart_hash"],
        extensions=["anp.ap2.crypto.v1", "anp.blockchain.v1"]
    )
    
    print("✓ PaymentMandate built successfully")
    print("  Algorithm: ES256K")
    print(f"  Authorization: {payment_mandate.user_authorization[:60]}...")
    
    # Step 6: Verify PaymentMandate
    print("\n[Step 6] Verifying PaymentMandate with ES256K...")
    
    payment_verifier = PaymentMandateVerifier(
        user_public_key=user_public_key,
        algorithm="ES256K"  # Use ES256K algorithm
    )
    
    payment_payload = payment_verifier.verify(
        payment_mandate=payment_mandate,
        expected_cart_hash=cart_payload["cart_hash"],
        expected_aud="did:wba:didhost.cc:merchant"
    )
    
    print("✓ PaymentMandate verified successfully")
    print(f"  Issuer: {payment_payload['iss']}")
    print(f"  Audience: {payment_payload['aud']}")
    print("  Transaction Data:")
    print(f"    - Cart Hash: {payment_payload['transaction_data'][0][:40]}...")
    print(f"    - PMT Hash: {payment_payload['transaction_data'][1][:40]}...")
    print(f"  Extensions: {payment_payload.get('extensions', [])}")
    
    print("\n" + "=" * 70)
    print("✅ ES256K example completed successfully!")
    print("=" * 70)
    print("\nKey Benefits of ES256K:")
    print("  • Smaller signatures (~70 bytes vs ~256 bytes for RS256)")
    print("  • Compatible with blockchain ecosystems (Bitcoin, Ethereum)")
    print("  • Efficient verification")
    print("  • Same security level as ES256 but with secp256k1 curve")


if __name__ == "__main__":
    main()

