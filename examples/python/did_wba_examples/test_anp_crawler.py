#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Example: Test ANPCrawler with local DID doc and keys.

Requirements:
- DID document: docs/did_public/public-did-doc.json
- DID private key: docs/did_public/public-private-key.pem

This script:
1) Initializes ANPCrawler using local DID credentials
2) Fetches content from an Agent Description or interface URL
3) Prints the extracted OpenAI Tools formatted interfaces
"""

import asyncio
import json
import logging
from pathlib import Path

from agent_connect.anp_crawler import ANPCrawler
from agent_connect.utils.log_base import set_log_color_level

# Example Agent Description URL (you can replace it with your own):
AGENT_DESCRIPTION_URL = "https://agent-weather.xyz/ad.json"


async def main() -> None:
    set_log_color_level(logging.INFO)

    current_dir = Path(__file__).parent.absolute()
    project_root = current_dir.parent.parent.parent

    did_doc_path = project_root / "docs" / "did_public" / "public-did-doc.json"
    did_private_key_path = project_root / "docs" / "did_public" / "public-private-key.pem"

    if not did_doc_path.exists() or not did_private_key_path.exists():
        raise FileNotFoundError("DID doc or private key not found under docs/did_public/")

    # Initialize crawler
    crawler = ANPCrawler(
        did_document_path=str(did_doc_path),
        private_key_path=str(did_private_key_path),
        cache_enabled=True,
    )

    # Fetch text content and interfaces
    content_json, interfaces_list = await crawler.fetch_text(AGENT_DESCRIPTION_URL)

    print("\n=== Content JSON ===")
    print(json.dumps(content_json, ensure_ascii=False, indent=2))

    print("\n=== Extracted Interfaces (OpenAI Tools format) ===")
    if not interfaces_list:
        print("No interfaces found.")
    else:
        for i, tool in enumerate(interfaces_list, start=1):
            func = tool.get("function", {})
            print(f"{i}. {func.get('name')} - {func.get('description')}")


if __name__ == "__main__":
    asyncio.run(main())
