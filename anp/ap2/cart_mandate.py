"""CartMandate Builder and Verifier.

This module provides tools to build and verify CartMandate with
merchant_authorization signatures using JWT.

Supported algorithms:
- RS256: RSASSA-PKCS1-v1_5 using SHA-256 (default)
- ES256K: ECDSA using secp256k1 curve and SHA-256 (for blockchain/crypto apps)
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

import jwt

from anp.ap2.models import CartContents, CartMandate
from anp.ap2.utils import compute_cart_hash


class CartMandateBuilder:
    """CartMandate builder.

    Used to build CartMandate with merchant_authorization signature.
    """

    def __init__(
        self,
        merchant_private_key: str,
        merchant_did: str,
        merchant_kid: str,
        algorithm: str = "RS256",
        shopper_did: Optional[str] = None,
    ):
        """Initialize CartMandate builder.

        Args:
            merchant_private_key: Merchant private key (PEM format)
            merchant_did: Merchant DID (e.g., did:wba:didhost.cc:merchant)
            merchant_kid: Merchant key identifier
            algorithm: JWT signing algorithm, supports "RS256" or "ES256K", defaults to "RS256"
            shopper_did: Shopper DID (optional, used for aud field)
        """
        self.merchant_private_key = merchant_private_key
        self.merchant_did = merchant_did
        self.merchant_kid = merchant_kid
        self.algorithm = algorithm
        self.shopper_did = shopper_did

    def build(
        self,
        cart_contents: CartContents,
        cnf: Optional[Dict] = None,
        sd_hash: Optional[str] = None,
        ttl_seconds: int = 900,
        extensions: Optional[List[str]] = None,
    ) -> CartMandate:
        """Build CartMandate.

        Args:
            cart_contents: Cart contents
            cnf: Holder binding information (optional)
            sd_hash: SD-JWT/VC hash pointer (optional)
            ttl_seconds: Time to live in seconds, defaults to 900 seconds (15 minutes)
            extensions: Extension list (optional)

        Returns:
            Built CartMandate object

        Example:
            >>> builder = CartMandateBuilder(private_key, "did:anp:MA", "MA-key-001")
            >>> contents = CartContents(...)
            >>> mandate = builder.build(contents)
        """
        # Calculate cart_hash
        contents_dict = cart_contents.model_dump(exclude_none=True)
        cart_hash = compute_cart_hash(contents_dict)

        # Build JWT payload
        now = int(time.time())
        payload = {
            "iss": self.merchant_did,
            "sub": self.merchant_did,
            "aud": self.shopper_did,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": str(uuid.uuid4()),
            "cart_hash": cart_hash,
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
            "kid": self.merchant_kid,
            "typ": "JWT",
        }

        # Generate signature
        merchant_authorization = self._encode_jwt(payload, headers)

        # Generate timestamp
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build CartMandate
        return CartMandate(
            contents=cart_contents,
            merchant_authorization=merchant_authorization,
            timestamp=timestamp,
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
            self.merchant_private_key,
            algorithm=self.algorithm,
            headers=headers,
        )


class CartMandateVerifier:
    """CartMandate verifier.

    Used to verify merchant_authorization signature of CartMandate.
    """

    def __init__(self, merchant_public_key: str, algorithm: str = "RS256"):
        """Initialize CartMandate verifier.

        Args:
            merchant_public_key: Merchant public key (PEM format)
            algorithm: JWT signing algorithm, supports "RS256" or "ES256K", defaults to "RS256"
        """
        self.merchant_public_key = merchant_public_key
        self.algorithm = algorithm

    def verify(
        self,
        cart_mandate: CartMandate,
        expected_aud: Optional[str] = None,
        verify_time: bool = True,
    ) -> Dict:
        """Verify CartMandate.

        Args:
            cart_mandate: CartMandate to verify
            expected_aud: Expected aud value (optional)
            verify_time: Whether to verify time validity (defaults to True)

        Returns:
            Decoded JWT payload

        Raises:
            jwt.InvalidSignatureError: Invalid signature
            jwt.ExpiredSignatureError: JWT expired
            jwt.InvalidTokenError: Invalid JWT format
            ValueError: cart_hash mismatch

        Example:
            >>> verifier = CartMandateVerifier(public_key)
            >>> payload = verifier.verify(cart_mandate)
            >>> print(f"Verified cart from {payload['iss']}")
        """
        # Decode and verify JWT
        payload = self._decode_jwt(
            cart_mandate.merchant_authorization,
            expected_aud=expected_aud,
            verify_time=verify_time,
        )

        # aud is already verified in _decode_jwt, no need to verify again here

        # Recalculate cart_hash and verify
        contents_dict = cart_mandate.contents.model_dump(exclude_none=True)
        computed_cart_hash = compute_cart_hash(contents_dict)

        if payload.get("cart_hash") != computed_cart_hash:
            raise ValueError(
                f"cart_hash mismatch: expected {computed_cart_hash}, "
                f"got {payload.get('cart_hash')}"
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
            token, self.merchant_public_key, **decode_kwargs
        )
