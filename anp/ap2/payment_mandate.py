"""PaymentMandate Builder and Verifier.

This module provides tools to build and verify PaymentMandate with
user_authorization signatures using JWT.

Supported algorithms:
- RS256: RSASSA-PKCS1-v1_5 using SHA-256 (default)
- ES256K: ECDSA using secp256k1 curve and SHA-256 (for blockchain/crypto apps)
"""

import time
import uuid
from typing import Dict, List, Optional

import jwt

from anp.ap2.models import PaymentMandate, PaymentMandateContents
from anp.ap2.utils import compute_pmt_hash


class PaymentMandateBuilder:
    """PaymentMandate builder.

    Used to build PaymentMandate with user_authorization signature.
    """

    def __init__(
        self,
        user_private_key: str,
        user_did: str,
        user_kid: str,
        algorithm: str = "RS256",
        merchant_did: Optional[str] = None,
    ):
        """Initialize PaymentMandate builder.

        Args:
            user_private_key: User private key (PEM format)
            user_did: User DID (e.g., did:wba:didhost.cc:shopper)
            user_kid: User key identifier
            algorithm: JWT signing algorithm, supports "RS256" or "ES256K", defaults to "RS256"
            merchant_did: Merchant DID (optional, used for aud field)
        """
        self.user_private_key = user_private_key
        self.user_did = user_did
        self.user_kid = user_kid
        self.algorithm = algorithm
        self.merchant_did = merchant_did

    def build(
        self,
        payment_mandate_contents: PaymentMandateContents,
        cart_hash: str,
        cnf: Optional[Dict] = None,
        sd_hash: Optional[str] = None,
        ttl_seconds: int = 15552000,  # 180 days
        extensions: Optional[List[str]] = None,
    ) -> PaymentMandate:
        """Build PaymentMandate.

        Args:
            payment_mandate_contents: Payment mandate contents
            cart_hash: Cart hash (from CartMandate)
            cnf: Holder binding information (optional)
            sd_hash: SD-JWT/VC hash pointer (optional)
            ttl_seconds: Time to live in seconds, defaults to 15552000 seconds (180 days)
            extensions: Extension list (optional)

        Returns:
            Built PaymentMandate object

        Example:
            >>> builder = PaymentMandateBuilder(private_key, "did:wba:didhost.cc:shopper", "key-001")
            >>> contents = PaymentMandateContents(...)
            >>> mandate = builder.build(contents, cart_hash="abc123...")
        """
        # Calculate pmt_hash
        contents_dict = payment_mandate_contents.model_dump(exclude_none=True)
        pmt_hash = compute_pmt_hash(contents_dict)

        # Build transaction_data
        transaction_data = [cart_hash, pmt_hash]

        # Build JWT payload
        now = int(time.time())
        payload = {
            "iss": self.user_did,
            "sub": self.user_did,
            "aud": self.merchant_did or "did:wba:MA",
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": str(uuid.uuid4()),
            "transaction_data": transaction_data,
        }

        # Add optional fields
        if cnf:
            payload["cnf"] = cnf
        if sd_hash:
            payload["sd_hash"] = sd_hash
        if extensions:
            payload["extensions"] = extensions

        # Build JWT header
        headers = {
            "alg": self.algorithm,
            "kid": self.user_kid,
            "typ": "JWT",
        }

        # Generate signature
        user_authorization = self._encode_jwt(payload, headers)

        # Build PaymentMandate
        return PaymentMandate(
            payment_mandate_contents=payment_mandate_contents,
            user_authorization=user_authorization,
        )

    def _encode_jwt(self, payload: Dict, headers: Dict) -> str:
        """Encode JWT using PyJWT library.

        Args:
            payload: JWT payload
            headers: JWT headers

        Returns:
            Encoded JWT string
        """
        
        return jwt.encode(
            payload,
            self.user_private_key,
            algorithm=self.algorithm,
            headers=headers,
        )


class PaymentMandateVerifier:
    """PaymentMandate verifier.

    Used to verify user_authorization signature of PaymentMandate.
    """

    def __init__(self, user_public_key: str, algorithm: str = "RS256"):
        """Initialize PaymentMandate verifier.

        Args:
            user_public_key: User public key (PEM format)
            algorithm: JWT signing algorithm, supports "RS256" or "ES256K", defaults to "RS256"
        """
        self.user_public_key = user_public_key
        self.algorithm = algorithm

    def verify(
        self,
        payment_mandate: PaymentMandate,
        expected_cart_hash: str,
        expected_aud: Optional[str] = None,
        verify_time: bool = True,
    ) -> Dict:
        """Verify PaymentMandate.

        Args:
            payment_mandate: PaymentMandate to verify
            expected_cart_hash: Expected cart_hash (from CartMandate)
            expected_aud: Expected aud value (optional)
            verify_time: Whether to verify time validity (defaults to True)

        Returns:
            Decoded JWT payload

        Raises:
            jwt.InvalidSignatureError: Invalid signature
            jwt.ExpiredSignatureError: JWT expired
            jwt.InvalidTokenError: Invalid JWT format
            ValueError: transaction_data mismatch or cart_hash inconsistency

        Example:
            >>> verifier = PaymentMandateVerifier(public_key)
            >>> payload = verifier.verify(payment_mandate, cart_hash="abc123...")
            >>> print(f"Verified payment from {payload['iss']}")
        """
        # Decode and verify JWT
        payload = self._decode_jwt(
            payment_mandate.user_authorization,
            expected_aud=expected_aud,
            verify_time=verify_time,
        )

        # aud is already verified in _decode_jwt, no need to verify again here

        # Recalculate pmt_hash and verify
        contents_dict = payment_mandate.payment_mandate_contents.model_dump(
            exclude_none=True
        )
        computed_pmt_hash = compute_pmt_hash(contents_dict)

        # Verify transaction_data
        transaction_data = payload.get("transaction_data", [])
        if len(transaction_data) != 2:
            raise ValueError(
                f"Invalid transaction_data length: expected 2, got {len(transaction_data)}"
            )

        cart_hash_in_token = transaction_data[0]
        pmt_hash_in_token = transaction_data[1]

        # Verify cart_hash
        if cart_hash_in_token != expected_cart_hash:
            raise ValueError(
                f"cart_hash mismatch: expected {expected_cart_hash}, "
                f"got {cart_hash_in_token}"
            )

        # Verify pmt_hash
        if pmt_hash_in_token != computed_pmt_hash:
            raise ValueError(
                f"pmt_hash mismatch: expected {computed_pmt_hash}, "
                f"got {pmt_hash_in_token}"
            )

        # Verify time window (if enabled)
        if verify_time:
            now = int(time.time())
            iat = payload.get("iat", 0)
            exp = payload.get("exp", 0)

            if not (iat <= now <= exp):
                raise ValueError(
                    f"Token not valid at current time: iat={iat}, now={now}, exp={exp}"
                )

        return payload

    def _decode_jwt(
        self, token: str, expected_aud: Optional[str] = None, verify_time: bool = True
    ) -> Dict:
        """Decode JWT using PyJWT library.

        Args:
            token: JWT token string
            expected_aud: Expected aud value
            verify_time: Whether to verify time

        Returns:
            Decoded payload
        """
        
        options = {"verify_exp": verify_time}
        decode_kwargs = {"algorithms": [self.algorithm], "options": options}
        
        if expected_aud:
            decode_kwargs["audience"] = expected_aud
        else:
            options["verify_aud"] = False

        return jwt.decode(
            token, self.user_public_key, **decode_kwargs
        )
