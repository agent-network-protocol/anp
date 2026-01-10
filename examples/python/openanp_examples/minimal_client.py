#!/usr/bin/env python3
"""OpenANP 极简客户端示例。

用最少的代码调用远程 ANP 代理。

前提条件：
    先启动 minimal_server.py：
    uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

运行命令：
    uv run python examples/python/openanp_examples/minimal_client.py
"""

import asyncio
from pathlib import Path

from anp.authentication import DIDWbaAuthHeader
from anp.openanp import RemoteAgent


# DID 文档和私钥路径
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DID_DOC = PROJECT_ROOT / "docs/did_public/public-did-doc.json"
PRIVATE_KEY = PROJECT_ROOT / "docs/did_public/public-private-key.pem"


async def main() -> None:
    """极简客户端演示。"""
    # 1. 创建认证
    auth = DIDWbaAuthHeader(
        did_document_path=str(DID_DOC),
        private_key_path=str(PRIVATE_KEY),
    )

    # 2. 发现代理
    print("发现代理...")
    try:
        agent = await RemoteAgent.discover(
            "http://localhost:8000/agent/ad.json",
            auth,
        )
    except Exception as e:
        print(f"连接失败: {e}")
        print("\n请先启动服务端:")
        print("  uvicorn examples.python.openanp_examples.minimal_server:app --port 8000")
        return

    print(f"已连接: {agent.name}")

    # 3. 调用方法
    result = await agent.add(a=10, b=20)
    print(f"10 + 20 = {result}")

    result = await agent.multiply(a=6, b=7)
    print(f"6 × 7 = {result}")

    print("\n演示完成!")


if __name__ == "__main__":
    asyncio.run(main())
