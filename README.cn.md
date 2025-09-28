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

## 使用方式

### 方式一：通过pip安装
```bash
pip install agent-connect
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
