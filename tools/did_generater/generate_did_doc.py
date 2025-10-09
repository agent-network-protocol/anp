#!/usr/bin/env python3
# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# This script generates DID document and private key document based on input DID

import argparse
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from anp.authentication.did_wba import create_did_wba_document
from anp.utils.log_base import set_log_color_level


def parse_did(did: str) -> Tuple[str, List[str], str]:
    """
    Parse DID string and extract hostname and path segments

    Args:
        did: DID string, e.g. did:wba:service.agent-network-protocol.com:wba:user:lkcoffe

    Returns:
        Tuple[str, list, str]: A tuple containing:
            - hostname: The hostname part of the DID
            - path_segments: List of path segments
            - unique_id: The last segment of the path (user identifier)

    Raises:
        ValueError: If DID format is invalid
    """
    if not did.startswith("did:wba:"):
        raise ValueError("Invalid DID format: must start with 'did:wba:'")

    # Split the DID into parts
    parts = did.split(":", 3)
    if len(parts) < 4:
        raise ValueError("Invalid DID format: missing domain or path segments")

    hostname = parts[2]

    # Validate hostname
    if not hostname or re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname):
        raise ValueError("Invalid hostname: cannot be empty or an IP address")

    path_segments_str = parts[3]
    path_segments = path_segments_str.split(":")

    if not path_segments:
        raise ValueError("Invalid DID format: missing path segments")

    # Get the unique ID (last segment)
    unique_id = path_segments[-1]

    if not unique_id:
        raise ValueError("Invalid DID format: empty unique ID")

    return hostname, path_segments, unique_id

def validate_agent_description_url(url: Optional[str]) -> Optional[str]:
    """
    Validate agent description URL

    Args:
        url: URL to validate

    Returns:
        Optional[str]: Validated URL or None

    Raises:
        ValueError: If URL is invalid
    """
    if not url:
        return None

    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL format")
        if result.scheme not in ['http', 'https']:
            raise ValueError("URL scheme must be http or https")
        return url
    except Exception as e:
        raise ValueError(f"Invalid URL: {e}")

def save_documents(unique_id: str, did_document: Dict[str, Any], keys: Dict[str, Tuple[bytes, bytes]]) -> str:
    """
    Save DID document and private keys to files

    Args:
        unique_id: Unique identifier for the user
        did_document: DID document dictionary
        keys: Dictionary of private and public keys

    Returns:
        str: Path to the directory where documents were saved

    Raises:
        IOError: If files cannot be written
    """
    # Get current directory
    current_dir = Path.cwd()

    # Create user directory
    user_dir = current_dir / f"user_{unique_id}"
    try:
        user_dir.mkdir(exist_ok=True)
    except Exception as e:
        raise IOError(f"Failed to create directory {user_dir}: {e}")

    # Save DID document
    did_path = user_dir / "did.json"
    try:
        with open(did_path, 'w', encoding='utf-8') as f:
            json.dump(did_document, f, indent=2)
        logging.info(f"Saved DID document to {did_path}")
    except Exception as e:
        raise IOError(f"Failed to save DID document to {did_path}: {e}")

    # Save private keys
    for method_fragment, (private_key_bytes, _) in keys.items():
        private_key_path = user_dir / f"{method_fragment}_private.pem"
        try:
            with open(private_key_path, 'wb') as f:
                f.write(private_key_bytes)
            logging.info(f"Saved private key '{method_fragment}' to {private_key_path}")
        except Exception as e:
            raise IOError(f"Failed to save private key to {private_key_path}: {e}")

    # Create a private key document (JSON) with paths to the keys
    private_key_doc = {
        "did": did_document["id"],
        "created_at": datetime.now().isoformat(),
        "keys": {}
    }

    for method_fragment in keys:
        private_key_doc["keys"][method_fragment] = {
            "path": f"{method_fragment}_private.pem",
            "type": "EcdsaSecp256k1"
        }

    # Save private key document
    private_key_doc_path = user_dir / "private_keys.json"
    try:
        with open(private_key_doc_path, 'w', encoding='utf-8') as f:
            json.dump(private_key_doc, f, indent=2)
        logging.info(f"Saved private key document to {private_key_doc_path}")
    except Exception as e:
        raise IOError(f"Failed to save private key document to {private_key_doc_path}: {e}")

    return str(user_dir)

def print_colored(text: str, color: str = "green") -> None:
    """Print colored text to console"""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m"
    }

    print(f"{colors.get(color, colors['white'])}{text}{colors['reset']}")

def main():
    """Main function to generate DID document and private keys"""
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Generate DID document and private keys from DID")
    parser.add_argument("did", help="DID string, e.g. did:wba:service.agent-network-protocol.com:wba:user:lkcoffe")
    parser.add_argument("--agent-description-url", help="Optional URL for agent description")
    parser.add_argument("--output-dir", "-o", help="Optional custom output directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress all output except errors")

    # Parse arguments
    args = parser.parse_args()

    # Set logging level
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.ERROR
    set_log_color_level(log_level)

    try:
        # Parse DID
        hostname, path_segments, unique_id = parse_did(args.did)
        logging.info(f"Parsed DID: hostname={hostname}, path_segments={path_segments}, unique_id={unique_id}")

        # Validate agent description URL if provided
        agent_description_url = None
        if args.agent_description_url:
            agent_description_url = validate_agent_description_url(args.agent_description_url)
            logging.info(f"Using agent description URL: {agent_description_url}")

        # Create DID document and keys
        did_document, keys = create_did_wba_document(
            hostname=hostname,
            path_segments=path_segments,
            agent_description_url=agent_description_url
        )

        # Save documents
        output_dir = save_documents(unique_id, did_document, keys)

        # Print success message
        if not args.quiet:
            print_colored("\n✅ Success! Documents generated successfully.", "green")
            print_colored(f"📁 Documents saved to: {output_dir}", "cyan")
            print_colored(f"📄 DID document: {output_dir}/did.json", "cyan")
            print_colored(f"🔑 Private key document: {output_dir}/private_keys.json", "cyan")
            print_colored(f"🔒 Private key file(s): {output_dir}/key-1_private.pem", "cyan")

            print_colored("\n⚠️  Important Security Notice:", "yellow")
            print_colored("   The private key files contain sensitive cryptographic material.", "yellow")
            print_colored("   Keep these files secure and do not share them.", "yellow")

    except ValueError as e:
        logging.error(f"Validation error: {e}")
        print_colored(f"\n❌ Error: {e}", "red")
        sys.exit(1)
    except IOError as e:
        logging.error(f"I/O error: {e}")
        print_colored(f"\n❌ I/O Error: {e}", "red")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print_colored(f"\n❌ Unexpected error: {e}", "red")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
