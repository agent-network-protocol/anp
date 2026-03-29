"""Minimal example showing how to create a DID WBA document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from anp.authentication import create_did_wba_document


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Create a DID WBA document and save generated artifacts.",
    )
    parser.add_argument(
        "--profile",
        choices=("e1", "k1", "plain_legacy"),
        default="e1",
        help="DID profile to generate.",
    )
    parser.add_argument(
        "--hostname",
        default="demo.agent-network",
        help="Hostname used in the DID.",
    )
    return parser.parse_args()


def main() -> None:
    """Create a DID document and persist the generated artifacts."""
    args = parse_args()
    did_document, keys = create_did_wba_document(
        hostname=args.hostname,
        path_segments=["agents", "demo"],
        agent_description_url=f"https://{args.hostname}/agents/demo",
        did_profile=args.profile,
    )

    output_dir = Path(__file__).resolve().parent / "generated" / args.profile
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
    proof = did_document.get("proof", {})
    if proof:
        print(
            "Generated proof profile:",
            proof.get("type"),
            proof.get("cryptosuite", "<legacy>"),
        )


if __name__ == "__main__":
    main()
