<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# AgentConnect

## AgentConnect是什么

AgentConnect是[Agent Network Protocol(ANP)](https://github.com/agent-network-protocol/AgentNetworkProtocol)的开源SDK实现。

AgentNetworkProtocol(ANP)的目标是成为**智能体互联网时代的HTTP**，为数十亿智能体构建一个开放、安全、高效的协作网络。

<p align="center">
  <img src="/images/agentic-web.png" width="50%" alt="Agentic Web"/>
</p>

## 核心模块

### Authentication（身份认证）
基于DID-WBA（Decentralized Identifier - Web-Based Authentication）的智能体身份认证系统：
- **身份管理**：创建和管理智能体DID文档
- **身份验证**：提供端到端的身份认证和授权
- **安全通信**：确保智能体间通信的安全性和可信度

### ANP Crawler（智能体发现与交互）
智能体网络的发现和交互工具：
- **智能体发现**：自动发现和解析智能体描述文档
- **接口解析**：解析JSON-RPC接口并转换为可调用的工具
- **协议交互**：支持与符合ANP协议的智能体进行通信
- **直接JSON-RPC**：无需接口发现，直接执行JSON-RPC请求

### FastANP（快速开发框架）
基于FastAPI构建ANP智能体的插件化框架：
- **插件架构**：FastAPI作为主框架，FastANP作为辅助插件
- **自动OpenRPC**：从Python函数自动生成OpenRPC文档
- **Context 注入**：自动会话和 Request 对象注入
- **DID WBA 认证**：内置认证中间件，支持通配符路径排除
- **灵活路由**：完全控制所有路由包括 ad.json
- **会话管理**：基于 DID 的内置会话管理

完整文档请参考 [FastANP README](anp/fastanp/README.md)

### AP2（智能体支付协议 v2）
安全的智能体交易支付授权协议：
- **CartMandate（购物车授权）**：带商户签名的购物车授权
- **PaymentMandate（支付授权）**：带用户签名的支付授权
- **ES256K 签名**：支持 ECDSA secp256k1 签名
- **哈希完整性**：购物车和支付数据完整性验证
- **DID WBA 集成**：与基于 DID 的身份认证无缝集成

**规范文档**：[AP2 协议规范](docs/ap2/ap2-flow.md)

## 使用方式

### 方式一：通过pip安装
```bash
pip install anp
```

### 方式二：源码安装（推荐开发者使用）
```bash
# 下载源码
git clone https://github.com/agent-network-protocol/AgentConnect.git
cd AgentConnect

# 使用UV配置环境
uv sync

# 运行示例
uv run python examples/python/did_wba_examples/create_did_document.py
```

## 示例演示

### DID-WBA身份认证示例
位置：`examples/python/did_wba_examples/`

#### 主要示例
- **创建DID文档** (`create_did_document.py`)  
  演示如何生成智能体的DID身份文档和密钥对
  
- **身份认证验证** (`authenticate_and_verify.py`)  
  展示完整的DID-WBA身份认证和验证流程

#### 运行示例
```bash
# 创建DID文档
uv run python examples/python/did_wba_examples/create_did_document.py

# 身份认证演示
uv run python examples/python/did_wba_examples/authenticate_and_verify.py
```

**详细文档**： [DID-WBA示例说明](examples/python/did_wba_examples/README.cn.md)

### ANP Crawler智能体交互示例
位置：`examples/python/anp_crawler_examples/`

#### 主要示例
- **简单示例** (`simple_amap_example.py`)  
  快速入门：连接AMAP服务并调用地图搜索接口
  
- **完整示例** (`amap_crawler_example.py`)  
  完整演示：智能体发现、接口解析、工具调用的全流程

#### 运行示例
```bash
# 快速体验
uv run python examples/python/anp_crawler_examples/simple_amap_example.py

# 完整功能演示
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py
```

**详细文档**：[ANP Crawler示例说明](examples/python/anp_crawler_examples/README.cn.md)

### FastANP智能体开发示例
位置：`examples/python/fastanp_examples/`

#### 主要示例
- **简单智能体** (`simple_agent.py`)
  最小化FastANP设置，包含单个接口方法

- **酒店预订智能体** (`hotel_booking_agent.py`)
  完整示例，包含多个接口、Pydantic模型和会话管理

#### 运行示例
```bash
# 简单智能体
uv run python examples/python/fastanp_examples/simple_agent.py

# 酒店预订智能体
uv run python examples/python/fastanp_examples/hotel_booking_agent.py
```

#### 测试示例
```bash
# 使用Python客户端测试
uv run python examples/python/fastanp_examples/test_hotel_booking_client.py

# 或使用curl手动测试
# 获取智能体描述
curl http://localhost:8000/ad.json | jq

# 调用JSON-RPC方法
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "search_rooms", "params": {"query": {"check_in_date": "2025-01-01", "check_out_date": "2025-01-05", "guest_count": 2, "room_type": "deluxe"}}}'
```

**详细文档**：[FastANP示例说明](examples/python/fastanp_examples/README.md)

### AP2 支付协议示例
位置：`examples/python/ap2_examples/`

#### 主要示例
- **完整流程** (`ap2_complete_flow.py`)
  完整演示 AP2 支付协议，包括商户和购物者智能体

#### 功能特性
- **商户智能体**：处理购物车创建和支付验证
- **购物者智能体**：创建购物车并授权支付
- **Mandate 验证**：CartMandate 和 PaymentMandate 双重验证
- **本地 IP 通信**：两个智能体在本地网络上通信
- **ES256K 签名**：所有 mandate 使用 ECDSA secp256k1 签名

#### 运行示例
```bash
# 运行完整的 AP2 流程
uv run python examples/python/ap2_examples/ap2_complete_flow.py
```

#### 流程概览
1. 商户智能体在本地 IP 上启动
2. 购物者发送 `create_cart_mandate` 请求
3. 商户验证 DID WBA 认证，创建并签名 CartMandate
4. 购物者验证 CartMandate 签名
5. 购物者创建并签名 PaymentMandate
6. 购物者发送 PaymentMandate 给商户
7. 商户验证 PaymentMandate 并确认支付

详细的协议规范请参阅 [AP2 协议文档](docs/ap2/ap2-flow.md)

## 工具推荐

### ANP网络探索工具
通过网页界面使用自然语言探索智能体网络：[ANP 网络探索工具](https://service.agent-network-protocol.com/anp-explorer/)

### DID文档生成工具
命令行工具快速生成DID文档：
```bash
uv run python tools/did_generater/generate_did_doc.py <did> [--agent-description-url URL]
```

## 联系我们

- **作者**：常高伟  
- **邮箱**：chgaowei@gmail.com  
- **官网**：[https://agent-network-protocol.com/](https://agent-network-protocol.com/)  
- **Discord**：[https://discord.gg/sFjBKTY7sB](https://discord.gg/sFjBKTY7sB)  
- **GitHub**：[https://github.com/agent-network-protocol/AgentNetworkProtocol](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- **微信**：flow10240

## 许可证

本项目基于MIT许可证开源。详细信息请参阅[LICENSE](LICENSE)文件。

---

**Copyright (c) 2024 GaoWei Chang**
