#!/usr/bin/env python3
"""OpenANP 极简服务端示例。

用最少的代码搭建一个完整的 ANP Server。

运行命令：
    uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

生成的端点：
    GET  /agent/ad.json           - Agent Description
    GET  /agent/interface.json    - OpenRPC 接口文档
    POST /agent/rpc               - JSON-RPC 端点

测试调用：
    curl -X POST http://localhost:8000/agent/rpc \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"add","params":{"a":10,"b":20},"id":1}'
"""

from fastapi import FastAPI

from anp.openanp import AgentConfig, anp_agent, interface


@anp_agent(
    AgentConfig(
        name="Calculator",
        did="did:wba:example.com:calculator",
        prefix="/agent",
        description="一个简单的计算器代理",
    )
)
class CalculatorAgent:
    """极简计算器代理。"""

    @interface
    async def add(self, a: int, b: int) -> int:
        """计算两数之和。

        Args:
            a: 第一个数
            b: 第二个数

        Returns:
            两数之和
        """
        return a + b

    @interface
    async def multiply(self, a: int, b: int) -> int:
        """计算两数之积。

        Args:
            a: 第一个数
            b: 第二个数

        Returns:
            两数之积
        """
        return a * b


app = FastAPI(title="Calculator Agent")
app.include_router(CalculatorAgent.router())


if __name__ == "__main__":
    import uvicorn

    print("启动极简 ANP Server...")
    print("  Agent Description: http://localhost:8000/agent/ad.json")
    print("  OpenRPC 文档:      http://localhost:8000/agent/interface.json")
    print("  JSON-RPC 端点:     http://localhost:8000/agent/rpc")
    uvicorn.run(app, host="0.0.0.0", port=8000)
