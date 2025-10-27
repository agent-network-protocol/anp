"""AP2 Protocol HTTP Client.

This module provides HTTP client functions for sending AP2 protocol requests
with DID WBA authentication headers.
"""

from typing import Any, Dict, List, Optional

import aiohttp

from anp.ap2.models import (
    CartContents,
    CartMandate,
    PaymentMandate,
)
from anp.authentication import DIDWbaAuthHeader


class AP2Client:
    """AP2 Protocol HTTP Client.

    Used to send create_cart_mandate and send_payment_mandate requests,
    automatically adding DID WBA authentication headers.
    """

    def __init__(
        self,
        did_document_path: str,
        private_key_path: str,
        client_did: str,
    ):
        """Initialize the AP2 client.

        Args:
            did_document_path: Path to the DID document
            private_key_path: Path to the DID private key
            client_did: Client DID
        """
        self.auth_header = DIDWbaAuthHeader(
            did_document_path=did_document_path,
            private_key_path=private_key_path,
        )
        self.client_did = client_did

    async def create_cart_mandate(
        self,
        merchant_url: str,
        merchant_did: str,
        cart_mandate_id: str,
        items: List[Dict[str, Any]],
        shipping_address: Dict[str, str],
        remark: Optional[str] = None,
    ) -> CartMandate:
        """Send a create_cart_mandate request to the merchant.

        Args:
            merchant_url: Merchant API base URL (e.g., https://merchant.example.com)
            merchant_did: Merchant DID
            cart_mandate_id: Cart mandate ID
            items: List of items, each containing id, sku, quantity, options, remark, etc.
            shipping_address: Shipping address containing recipient_name, phone, region, city, address_line, postal_code
            remark: Optional remark

        Returns:
            CartMandate: Cart mandate returned by the merchant

        Raises:
            Exception: HTTP request failed or response error

        Example:
            >>> client = AP2Client(did_doc_path, key_path, "did:wba:didhost.cc:shopper")
            >>> items = [{
            ...     "id": "sku-001",
            ...     "sku": "Nike-Air-Max-90",
            ...     "quantity": 1,
            ...     "options": {"color": "red", "size": "42"},
            ...     "remark": "Please ship as soon as possible"
            ... }]
            >>> address = {
            ...     "recipient_name": "John Doe",
            ...     "phone": "13800138000",
            ...     "region": "Beijing",
            ...     "city": "Beijing",
            ...     "address_line": "123 Some Street, Chaoyang District",
            ...     "postal_code": "100000"
            ... }
            >>> cart = await client.create_cart_mandate(
            ...     merchant_url="https://merchant.example.com",
            ...     merchant_did="did:wba:merchant.example.com:merchant",
            ...     cart_mandate_id="cart-123",
            ...     items=items,
            ...     shipping_address=address
            ... )
        """
        # Build request URL
        endpoint = f"{merchant_url.rstrip('/')}/ap2/merchant/create_cart_mandate"

        # Build request data
        request_data = {
            "messageId": f"cart-request-{cart_mandate_id}",
            "from": self.client_did,
            "to": merchant_did,
            "data": {
                "cart_mandate_id": cart_mandate_id,
                "items": items,
                "shipping_address": shipping_address,
            },
        }

        if remark:
            request_data["data"]["remark"] = remark

        # Get DID WBA authentication header
        auth_headers = self.auth_header.get_auth_header(endpoint, force_new=True)

        # Send HTTP POST request
        async with aiohttp.ClientSession() as session:
            async with session.post(
                endpoint,
                json=request_data,
                headers={
                    **auth_headers,
                    "Content-Type": "application/json",
                },
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(
                        f"Failed to create cart mandate: HTTP {response.status}, {error_text}"
                    )

                result = await response.json()

                # Parse response into CartMandate object
                data = result.get("data", {})
                return CartMandate(
                    contents=CartContents(**data["contents"]),
                    merchant_authorization=data["merchant_authorization"],
                    timestamp=data["timestamp"],
                )

    async def send_payment_mandate(
        self,
        merchant_url: str,
        merchant_did: str,
        payment_mandate: PaymentMandate,
    ) -> Dict[str, Any]:
        """Send a PaymentMandate to the merchant.

        Args:
            merchant_url: Merchant API base URL (e.g., https://merchant.example.com)
            merchant_did: Merchant DID
            payment_mandate: Payment mandate object

        Returns:
            Dict: Response data from the merchant

        Raises:
            Exception: HTTP request failed or response error

        Example:
            >>> # First create a PaymentMandate
            >>> from anp.ap2 import PaymentMandateBuilder
            >>> builder = PaymentMandateBuilder(
            ...     user_private_key=private_key,
            ...     user_did="did:wba:didhost.cc:shopper",
            ...     user_kid="shopper-key-001",
            ...     algorithm="RS256",
            ...     merchant_did=merchant_did
            ... )
            >>> payment_mandate = builder.build(pmt_contents, cart_hash)
            >>>
            >>> # Send the PaymentMandate
            >>> response = await client.send_payment_mandate(
            ...     merchant_url="https://merchant.example.com",
            ...     merchant_did="did:wba:merchant.example.com:merchant",
            ...     payment_mandate=payment_mandate
            ... )
        """
        # Build request URL
        endpoint = f"{merchant_url.rstrip('/')}/ap2/merchant/send_payment_mandate"

        # Build request data
        request_data = {
            "messageId": f"payment-mandate-{payment_mandate.payment_mandate_contents.payment_mandate_id}",
            "from": self.client_did,
            "to": merchant_did,
            "data": {
                "payment_mandate_contents": payment_mandate.payment_mandate_contents.model_dump(
                    exclude_none=True
                ),
                "user_authorization": payment_mandate.user_authorization,
            },
        }

        # Get DID WBA authentication header
        # Note: Use force_new=True to generate a new nonce for each request
        auth_headers = self.auth_header.get_auth_header(endpoint, force_new=True)

        # Send HTTP POST request
        async with aiohttp.ClientSession() as session:
            async with session.post(
                endpoint,
                json=request_data,
                headers={
                    **auth_headers,
                    "Content-Type": "application/json",
                },
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(
                        f"Failed to send payment mandate: HTTP {response.status}, {error_text}"
                    )

                result = await response.json()
                return result


# Convenience functions

async def create_cart_mandate(
    merchant_url: str,
    merchant_did: str,
    cart_mandate_id: str,
    items: List[Dict[str, Any]],
    shipping_address: Dict[str, str],
    did_document_path: str,
    private_key_path: str,
    client_did: str,
    remark: Optional[str] = None,
) -> CartMandate:
    """Send a create_cart_mandate request (convenience function).

    Args:
        merchant_url: Merchant API base URL
        merchant_did: Merchant DID
        cart_mandate_id: Cart mandate ID
        items: List of items
        shipping_address: Shipping address
        did_document_path: Path to DID document
        private_key_path: Path to DID private key
        client_did: Client DID
        remark: Optional remark

    Returns:
        CartMandate: Cart mandate returned by the merchant

    Example:
        >>> cart = await create_cart_mandate(
        ...     merchant_url="https://merchant.example.com",
        ...     merchant_did="did:wba:merchant.example.com:merchant",
        ...     cart_mandate_id="cart-123",
        ...     items=[{...}],
        ...     shipping_address={...},
        ...     did_document_path="path/to/did-doc.json",
        ...     private_key_path="path/to/private-key.pem",
        ...     client_did="did:wba:didhost.cc:shopper"
        ... )
    """
    client = AP2Client(did_document_path, private_key_path, client_did)
    return await client.create_cart_mandate(
        merchant_url=merchant_url,
        merchant_did=merchant_did,
        cart_mandate_id=cart_mandate_id,
        items=items,
        shipping_address=shipping_address,
        remark=remark,
    )


async def send_payment_mandate(
    merchant_url: str,
    merchant_did: str,
    payment_mandate: PaymentMandate,
    did_document_path: str,
    private_key_path: str,
    client_did: str,
) -> Dict[str, Any]:
    """Send a PaymentMandate request (convenience function).

    Args:
        merchant_url: Merchant API base URL
        merchant_did: Merchant DID
        payment_mandate: Payment mandate object
        did_document_path: Path to DID document
        private_key_path: Path to DID private key
        client_did: Client DID

    Returns:
        Dict: Response data from the merchant

    Example:
        >>> response = await send_payment_mandate(
        ...     merchant_url="https://merchant.example.com",
        ...     merchant_did="did:wba:merchant.example.com:merchant",
        ...     payment_mandate=payment_mandate,
        ...     did_document_path="path/to/did-doc.json",
        ...     private_key_path="path/to/private-key.pem",
        ...     client_did="did:wba:didhost.cc:shopper"
        ... )
    """
    client = AP2Client(did_document_path, private_key_path, client_did)
    return await client.send_payment_mandate(
        merchant_url=merchant_url,
        merchant_did=merchant_did,
        payment_mandate=payment_mandate,
    )
