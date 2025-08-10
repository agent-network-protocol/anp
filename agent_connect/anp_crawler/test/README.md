# ANP Crawler 测试

此目录包含了 ANP Crawler 模块的完整测试套件。

## 文件说明

- `test_anp_crawler.py` - 主要测试文件，包含所有测试用例
- `run_tests.py` - 测试运行脚本
- `test_data_agent_description.json` - Agent Description 测试数据
- `test_data_openrpc.json` - OpenRPC 接口测试数据
- `test_data_embedded_openrpc.json` - 嵌入式 OpenRPC 测试数据

## 测试覆盖范围

### ANPCrawler 类测试
- ✅ 初始化和组件配置
- ✅ `fetch_text()` - 文本内容获取
- ✅ Agent Description 文档解析
- ✅ OpenRPC 文档解析和 $ref 引用解析
- ✅ **嵌入式 OpenRPC 内容解析** - Agent Description 中包含 OpenRPC content
- ✅ 错误处理机制
- ✅ `fetch_image()`, `fetch_video()`, `fetch_audio()` - 多媒体接口（pass 实现）
- ✅ `fetch_auto()` - 自动检测接口（pass 实现）
- ✅ 缓存功能测试
- ✅ 会话管理（访问历史、URL 参数清理）

### ANPDocumentParser 类测试
- ✅ Agent Description 文档解析
- ✅ OpenRPC 文档解析
- ✅ **嵌入式 OpenRPC 文档解析** - StructuredInterface + openrpc + content
- ✅ 无效 JSON 处理

### ANPInterface 类测试
- ✅ OpenRPC 方法转换为 OpenAI Tools 格式
- ✅ $ref 引用解析
- ✅ 函数名称规范化
- ✅ 不支持接口类型处理

## 运行测试

### 方法1：使用测试运行脚本
```bash
cd octopus/anp_sdk/anp_crawler/test
python run_tests.py
```

### 方法2：直接运行测试文件
```bash
cd octopus/anp_sdk/anp_crawler/test
python test_anp_crawler.py
```

### 方法3：使用 unittest 模块
```bash
cd octopus/anp_sdk/anp_crawler/test
python -m unittest test_anp_crawler -v
```

## 测试数据

### Agent Description 测试数据
`test_data_agent_description.json` 包含一个完整的 Grand Hotel Assistant 智能体描述文档，包括：
- 智能体基本信息
- 产品和信息资源
- 多种协议的接口定义
- DID 认证信息

### OpenRPC 测试数据
`test_data_openrpc.json` 包含 Grand Hotel Services API 的 OpenRPC 规范，包括：
- 房间搜索接口 (`searchRooms`)
- 预订创建接口 (`makeReservation`)
- 完整的 components/schemas 定义
- $ref 引用示例

### 嵌入式 OpenRPC 测试数据
`test_data_embedded_openrpc.json` 包含带有嵌入式 OpenRPC 内容的 Agent Description，包括：
- Hotel Booking Assistant 智能体描述
- 嵌入在 `interfaces.StructuredInterface.content` 中的完整 OpenRPC 规范
- 房间可用性检查接口 (`checkAvailability`)
- 预订创建接口 (`createBooking`)
- 复杂的 $ref 引用链（Address、GuestInfo、PaymentInfo 等）
- 测试 `StructuredInterface` + `openrpc` + `content` 组合模式

## 依赖要求

测试需要以下模块正常工作：
- `octopus.utils.log_base` - 日志系统
- `agent_connect.authentication` - DID 认证（测试中会被 mock）
- `aiohttp` - HTTP 客户端
- `unittest.mock` - 测试 mock 功能

## 测试结果

成功运行测试后，你将看到：
- 每个测试用例的执行状态
- 测试覆盖的功能点
- 最终的成功率统计

例如：
```
Tests run: 21
Failures: 0
Errors: 0
Success rate: 100.0%
✅ All tests passed!
```

## 注意事项

1. 测试使用 mock 来模拟 DID 认证和 HTTP 请求，无需真实的网络连接
2. 多媒体接口（`fetch_image`, `fetch_video`, `fetch_audio`, `fetch_auto`）目前是 pass 实现，测试验证它们返回 None
3. 所有测试都是异步的，使用 `unittest.IsolatedAsyncioTestCase` 基类

## 🆕 新功能：嵌入式 OpenRPC 支持

### 功能概述
ANP Crawler 现在支持解析 Agent Description 中嵌入的 OpenRPC 内容，支持两种 OpenRPC 处理模式：

1. **独立 OpenRPC 文档** - 整个文档是一个 OpenRPC 规范（原有功能）
2. **嵌入式 OpenRPC 内容** - Agent Description 的 interfaces 中包含 OpenRPC 内容（新功能）

### 嵌入式格式支持
系统现在能够识别和解析以下格式的接口定义：

```json
{
  "interfaces": [
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "description": "OpenRPC interface for accessing hotel services.",
      "content": {
        "openrpc": "1.3.2",
        "info": { ... },
        "methods": [ ... ],
        "components": { ... }
      }
    }
  ]
}
```

### 处理逻辑
1. **检测条件**：`type` 为 `StructuredInterface`，`protocol` 为 `openrpc`，且包含 `content` 字段
2. **内容验证**：验证 `content` 是有效的 OpenRPC 文档结构
3. **接口提取**：从嵌入的 OpenRPC 内容中提取 methods 和 components
4. **$ref 解析**：支持完整的 $ref 引用解析，包括复杂的嵌套引用
5. **格式转换**：将提取的接口转换为统一的 OpenAI Tools 格式

### 测试覆盖
- ✅ 嵌入式 OpenRPC 文档识别和解析
- ✅ 复杂 $ref 引用链解析（Address → GuestInfo → PaymentInfo）
- ✅ 方法提取和 OpenAI Tools 格式转换
- ✅ 错误处理（无效 OpenRPC 内容）
- ✅ 与传统 URL 引用接口的混合处理

### 使用场景
这种嵌入式支持特别适用于：
- 自包含的 Agent Description 文档
- 减少外部依赖的接口定义
- 简化部署和分发的场景
- 需要在单一文档中包含完整接口定义的情况

### 演示示例
运行以下命令查看完整的嵌入式 OpenRPC 功能演示：
```bash
uv run python octopus/anp_sdk/anp_crawler/test/example_embedded_openrpc.py
```

演示脚本将展示：
- Agent Description 文档结构分析
- ANPDocumentParser 直接解析功能
- ANPInterface 转换为 OpenAI Tools 格式
- ANPCrawler 完整流程演示
- $ref 引用解析效果展示