# ANP Agent Skill

通过 ANP 协议调用远程 Agent（高德地图、快递查询、酒店预订等）。

## 一键部署

```bash
# 1. 克隆/下载本目录

# 2. 运行安装脚本
./setup.sh

# 3. 开始使用
python scripts/anp_cli.py list
```

## 使用方式

### 查看已注册的 Agent

```bash
python scripts/anp_cli.py list
```

### 调用 Agent

```bash
# 搜索地点
python scripts/anp_cli.py call amap maps_text_search '{"keywords":"咖啡厅","city":"北京"}'

# 查询天气
python scripts/anp_cli.py call amap maps_weather '{"city":"上海"}'

# 驾车路线规划
python scripts/anp_cli.py call amap maps_direction_driving '{"origin":"116.481028,39.989643","destination":"116.434446,39.90816"}'

# 周边搜索
python scripts/anp_cli.py call amap maps_around_search '{"location":"116.396652,40.003128","keywords":"酒店","radius":"3000"}'
```

### 连接新 Agent

```bash
# 查看 Agent 能力
python scripts/anp_cli.py connect "https://agent-connect.ai/mcp/agents/amap/ad.json"

# 添加到本地
python scripts/anp_cli.py add myagent "https://example.com/ad.json"

# 移除
python scripts/anp_cli.py remove myagent
```

## 已内置的 Agent

| ID | 名称 | 功能 |
|----|------|------|
| amap | 高德地图 | 地点搜索、路线规划、天气查询、周边搜索 |
| kuaidi | 快递查询 | 快递单号追踪 |
| hotel | 酒店预订 | 搜索酒店、查询房价 |
| juhe | 聚合查询 | 多种生活服务查询 |
| navigation | Agent导航 | 发现更多 Agent |

## 高德地图常用方法

| 方法 | 功能 | 参数 |
|------|------|------|
| maps_text_search | 搜索地点 | keywords, city |
| maps_weather | 查询天气 | city |
| maps_direction_driving | 驾车路线 | origin, destination |
| maps_around_search | 周边搜索 | location, keywords, radius |

## 身份配置（可选）

### 情况一：已有 DID 身份

如果你已有 ANP 网络的 DID 身份，将文件放到 `config/` 目录：

```
config/
├── did.json          # 你的 DID 文档
└── private-key.pem   # 你的私钥
```

### 情况二：没有 DID

运行 `setup.sh` 会自动生成本地临时身份，可以正常调用大部分 Agent。

如需注册正式 DID，访问：https://didhost.cc 或其他 DID 托管服务。

## 目录结构

```
anp-agent/
├── README.md           # 本文件
├── SKILL.md            # AI 助手技能描述
├── setup.sh            # 一键安装脚本
├── requirements.txt    # Python 依赖
├── config/
│   ├── agents.json     # 已注册的 Agent 列表
│   ├── did.json        # DID 身份文档
│   ├── private-key.pem # 私钥（自动生成或自己放）
│   └── .gitignore      # 防止私钥泄露
└── scripts/
    └── anp_cli.py      # 主程序
```

## 常见问题

### Q: 什么是 ANP？
ANP (Agent Network Protocol) 是 Agent 互联协议，让不同的 AI Agent 可以相互调用。

### Q: 什么是 DID？
DID (Decentralized Identifier) 是去中心化身份，用于 Agent 之间的身份验证。

### Q: 没有 DID 能用吗？
可以。setup.sh 会生成本地身份，大部分公开 Agent 都能调用。

### Q: 如何获取正式 DID？
访问 https://didhost.cc 注册，获得托管的 DID 身份。

## License

MIT
