---
name: anp-agent
description: ANP 协议跨 Agent 调用技能。通过 did:wba 去中心化身份，调用 ANP 网络中的任意 Agent（如高德地图、酒店预订、快递查询等）。当用户提到 ANP、调用 Agent、订酒店、查快递、查地图、路线规划时触发此技能。
---

# ANP Agent Skill

通过 ANP (Agent Network Protocol) 协议，使用去中心化身份 (did:wba) 调用远程 Agent。

## 使用场景

当用户需要：
- 调用 ANP 网络中的 Agent（高德地图、酒店、快递等）
- 搜索地点、规划路线、查询天气
- 预订酒店、查询快递
- 发现新的 ANP Agent

## 调用流程

### 1. 连接 Agent（查看能力）

给定 AD URL，获取 Agent 的可用方法：

```bash
python scripts/anp_cli.py connect "<AD_URL>"
```

示例：
```bash
python scripts/anp_cli.py connect "https://agent-connect.ai/mcp/agents/amap/ad.json"
```

### 2. 调用方法

使用已注册 ID 或 AD URL 调用：

```bash
python scripts/anp_cli.py call <id|ad_url> <method> '<json_params>'
```

示例：
```bash
# 搜索北京咖啡厅
python scripts/anp_cli.py call amap maps_text_search '{"keywords":"咖啡厅","city":"北京"}'

# 查询天气
python scripts/anp_cli.py call amap maps_weather '{"city":"上海"}'
```

### 3. 管理 Agent

```bash
# 列出已注册
python scripts/anp_cli.py list

# 添加新 Agent
python scripts/anp_cli.py add <id> "<ad_url>"

# 移除
python scripts/anp_cli.py remove <id>
```

## 已注册 Agent

| ID | 名称 | AD URL |
|----|------|--------|
| amap | 高德地图 | https://agent-connect.ai/mcp/agents/amap/ad.json |
| kuaidi | 快递查询 | https://agent-connect.ai/mcp/agents/kuaidi/ad.json |
| hotel | 酒店预订 | https://agent-connect.ai/agents/hotel-assistant/ad.json |
| juhe | 聚合查询 | https://agent-connect.ai/mcp/agents/juhe/ad.json |
| navigation | Agent导航 | https://agent-search.ai/agents/navigation/ad.json |

## 高德地图常用方法

| 方法 | 功能 | 参数示例 |
|------|------|----------|
| maps_text_search | 搜索地点 | `{"keywords":"咖啡厅","city":"北京"}` |
| maps_weather | 查询天气 | `{"city":"上海"}` |
| maps_direction_driving | 驾车路线 | `{"origin":"经度,纬度","destination":"经度,纬度"}` |
| maps_around_search | 周边搜索 | `{"location":"经度,纬度","keywords":"美食"}` |

## 目录结构

```
anp-agent/
├── SKILL.md              # 本文件
├── config/
│   ├── did.json          # DID 文档（公钥）
│   ├── private-key.pem   # 私钥（签名用）
│   ├── agents.json       # 已注册的 Agent 列表
│   └── .gitignore        # 防止私钥泄露
└── scripts/
    └── anp_cli.py        # 主程序
```

## 依赖

```bash
pip install anp aiohttp
```
