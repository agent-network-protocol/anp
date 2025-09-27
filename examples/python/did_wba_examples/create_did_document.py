"""Minimal example showing how to create a DID WBA document."""

from __future__ import annotations

import json
from pathlib import Path

from agent_connect.authentication import create_did_wba_document


def main() -> None:
    """Create a DID document and persist the generated artifacts."""
    hostname = "demo.agent-network"
    did_document, keys = create_did_wba_document(
        hostname=hostname,
        path_segments=["agents", "demo"],
        agent_description_url="https://demo.agent-network/agents/demo",
    )

    output_dir = Path(__file__).resolve().parent / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)

    did_path = output_dir / "did.json"
    did_path.write_text(json.dumps(did_document, indent=2), encoding="utf-8")
    print(f"DID document saved to {did_path}")

    for fragment, (private_bytes, public_bytes) in keys.items():
        private_path = output_dir / f"{fragment}_private.pem"
        public_path = output_dir / f"{fragment}_public.pem"
        private_path.write_bytes(private_bytes)
        public_path.write_bytes(public_bytes)
        print(
            "Registered verification method",
            fragment,
            "→ private key:",
            private_path.name,
            "public key:",
            public_path.name,
        )

    print(f"Generated DID identifier: {did_document['id']}")


if __name__ == "__main__":
    main()
