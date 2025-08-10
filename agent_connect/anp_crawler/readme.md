ANP Crawler 重构方案

## 当前的问题

在模块 anp_crawler 中，存在以下问题：
- 使用了LLM。好的做法是在外部使用模型，因为模型的使用比较复杂，anp_crawler定位为一个sdk，不适合包含模型的处理。
- anp_crawler要处理的是类似json-ld的数据，比如下面的数据，一个入口文件，可以连接到下面的很多文件，当我收到一个入口文件URL的时候，我应重新生成一个实例，在这个实例中，记录我爬取的内容，并且这个文件底层的URL，都要通过这个实例来获取才是。如果输入一个URL，应该要返回这个URL对应的文本，以及这段文本中的Interface（Interface返回字典格式，这个格式与json rpc、llm的tools非常的像）：

## URL的示例数据格式
```json
{
  "protocolType": "ANP",
  "protocolVersion": "1.0.0",
  "type": "AgentDescription",
  "url": "https://grand-hotel.com/agents/hotel-assistant",
  "name": "Grand Hotel Assistant",
  "did": "did:wba:grand-hotel.com:service:hotel-assistant",
  "owner": {
    "type": "Organization",
    "name": "Grand Hotel Management Group",
    "url": "https://grand-hotel.com"
  },
  "description": "Grand Hotel Assistant is an intelligent hospitality agent providing comprehensive hotel services including room booking, concierge services, guest assistance, and real-time communication capabilities.",
  "created": "2024-12-31T12:00:00Z",
  "securityDefinitions": {
    "didwba_sc": {
      "scheme": "didwba",
      "in": "header",
      "name": "Authorization"
    }
  },
  "security": "didwba_sc",
  "Infomations": [
    {
      "type": "Product",
      "description": "Luxury hotel rooms with premium amenities and personalized services.",
      "url": "https://grand-hotel.com/products/luxury-rooms.json"
    },
    {
      "type": "Product", 
      "description": "Comprehensive concierge and guest services including dining, spa, and local attractions.",
      "url": "https://grand-hotel.com/products/concierge-services.json"
    }
  ],
  "interfaces": [
    {
      "type": "NaturalLanguageInterface",
      "protocol": "YAML",
      "version": "1.2.2",
      "url": "https://grand-hotel.com/api/nl-interface.yaml",
      "description": "Natural language interface for conversational hotel services and guest assistance."
    },
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": "https://grand-hotel.com/api/services-interface.json",
      "description": "openrpc interface for accessing hotel services and amenities."
    }
  ],
  "proof": {
    "type": "EcdsaSecp256r1Signature2019",
    "created": "2024-12-31T15:00:00Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:wba:grand-hotel.com:service:hotel-assistant#keys-1",
    "challenge": "1235abcd6789",
    "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
  }
}

```

## 输出格式设计

函数返回两个独立的字典：

### 第一个字典：内容信息
```json
{
    "agentDescriptionURI":"https://abc.com/ad.json",
    "contentURI":"https://abc.com/ad.json", 
    "content":"原始文件内容"
}
```

**字段说明：**
- `agentDescriptionURI`: 智能体描述文档的URI（第一个访问文件的URL，去掉参数）
- `contentURI`: 当前读取内容的URI（去掉URL参数）
- `content`: 文件的原始内容

### 第二个字典：工具列表
返回OpenAI API Tools格式的接口列表，从文档中提取的所有可调用接口。

## Tools提取规则

当远端JSON文件包含接口定义时，按以下规则提取：

### JSON-RPC/OpenRPC格式
如果文件包含OpenRPC格式的接口定义（如包含 `methods` 字段），则：
1. 遍历 `methods` 数组中的每个方法
2. 提取方法的 `name`、`description`、`params` 等信息
3. 将 `params` 中的 `schema` 转换为OpenAI Tools的 `parameters` 格式
4. 生成符合OpenAI API Tools规范的接口定义

### Agent Description格式
如果文件是Agent Description格式（包含 `interfaces` 字段），则：
1. 遍历 `interfaces` 数组
2. 根据每个interface的 `protocol` 类型进行相应处理
3. 如果是JSON-RPC协议，进一步处理其URL指向的接口文件

### 转换目标格式
所有提取的接口都转换为统一的OpenAI API Tools格式：
```json
{
    "type": "function",
    "function": {
        "name": "方法名",
        "description": "方法描述", 
        "parameters": {
            "type": "object",
            "properties": {...},
            "required": [...]
        }
    }
}
```

## 重构设计方案

### 核心设计理念
将 anp_crawler 重构为纯粹的数据获取和解析 SDK，完全移除 LLM 依赖，专注于：
1. 单个 URL 的内容获取和解析
2. Interface 信息提取和格式转换  
3. 统一输出为 OpenAI Tools 格式

### 新文件结构

**保留原文件**：
- `anp_tool.py` - 保留不变，但是不在新的模块中使用
- `anp_crawler.py` - 保留不变，但是不在新的模块中使用

**新增文件**：
- `anp_client.py` - 新的HTTP客户端类
- `anp_parser.py` - 文档解析类
- `anp_interface.py` - 接口转换类  
- `anp_session.py` - 会话管理类

### 类设计架构

```
ANPSession (会话管理类) - anp_session.py
├── 管理单次爬取会话
├── 记录已访问的 URL
├── 缓存获取结果
└── 提供统一的接口入口

ANPClient (HTTP客户端类) - anp_client.py  
├── 复用 ANPTool 的 DID 认证能力
├── 执行 HTTP 请求
├── 处理响应格式（JSON/YAML/文本）
└── 错误处理和重试机制

ANPDocumentParser (文档解析类) - anp_parser.py
├── 解析 JSON-LD 结构
├── 提取 agents description 信息
├── 识别和提取 interfaces 字段
├── 解析 Infomations 中的链接
└── 递归处理嵌套 URL

ANPInterface (接口转换类) - anp_interface.py
├── JSON-RPC 格式转换
├── YAML 接口格式转换  
├── MCP 格式转换
├── REST API 格式转换
└── 统一输出为 OpenAI Tools JSON 格式
```

### 主要接口设计

#### ANPSession 核心接口
- `fetch_text()` - 获取文本内容（JSON、YAML、普通文本等）
- `fetch_image()` - 获取图片信息
- `fetch_video()` - 获取视频信息
- `fetch_audio()` - 获取音频信息
- `fetch_auto()` - 自动检测内容类型

所有接口均返回两个字典：内容信息 + 工具列表

### 输入输出设计

**输入参数**：
- 单个 URL（Agent Description 文件或 Interface 文件）
- DID 认证配置（文档路径和私钥路径）

**输出格式**：
每个接口返回两个独立的字典：
1. **内容信息字典** - 包含agentDescriptionURI、contentURI、content三个字段
2. **工具列表字典** - OpenAI API Tools格式的接口列表

### 处理场景

#### 场景1：文本内容处理
- **支持格式**：Agent Description、JSON-RPC/OpenRPC文件、YAML接口文件等
- **处理逻辑**：解析JSON内容，提取interfaces字段或methods字段，转换为OpenAI Tools格式

#### 场景2：多媒体内容处理  
- **支持格式**：图片（JPG、PNG、GIF）、视频（MP4、AVI、MOV）、音频（MP3、WAV、AAC）
- **处理逻辑**：获取文件元数据信息，通常不包含接口定义

#### 场景3：自动类型检测
- **处理逻辑**：根据HTTP响应的Content-Type自动识别文件类型，调用相应的处理方法

### 接口转换规范

当前版本专注于JSON-RPC格式的接口转换：
- **openrpc / OpenRPC** → OpenAI Tools

### 关键设计原则

1. **简化优先**：专注于核心JSON处理，避免过度复杂化
2. **格式统一**：所有接口输出统一为OpenAI API Tools格式
3. **会话管理**：通过session实例管理URL访问历史和缓存
4. **认证集成**：保持与现有DID认证体系的兼容性
5. **错误容错**：URL访问失败时返回错误信息但保持接口一致性
