# anp的ap2导入设想

## 1. anp的ap2兼容性方案

### 1.1 总体框架

#### 1.1.1 交易与交付的隔离
交易智能体代表用户与商户智能体交互，执行交易过程；
凭证智能体代表用户与交易智能体、商户智能体、商户支付智能体交互，执行支付过程。
- 用户--交易智能体 vs 商户智能体
- 用户--凭证智能体 vs 商户支付智能体

每个智能体通过DID身份标识自身 通过ad.json声明自身角色和角色接口（当前anp没有extension机制，可以通过角色+角色接口来简单模拟）

#### 1.1.2 智能体交易的场景抽象

1. 用户在场交易过程
   1. 场景举例：用户与购物助手交互中购买
   2. 核心凭证：用户签署商户智能体提供的购物车凭证+支付凭证
   3. 流程举例：
      1. 设置：用户登录交易智能体，指定连接的凭证智能体，并在连接界面(可能来自凭证智能体的UI)验证身份，确保两个智能体识别验证了同一用户，并建立互信关系。
      2. 发现与协商：用户向交易智能体发出购买需求，交易智能体与一个或多个商户智能体交互,在交易智能体中最终组装满足用户需求的购物车
         1. 购物车中可能包含商家提供的忠诚度、优惠、交叉销售和追加销售信息
         2. 用户授权 SKU 或一组 SKU 用于 购买。由交易智能体代理传达给商户智能体，以启动订单创建
         3. 商家签署购物车：商户智能体在商户创建的购物车上签名，表示他们将履行此购物车。
      3. 提供付款方式：交易智能体根据商户购物车声明的支付方式向凭证智能体请求适用的付款方式，以及任何忠诚度/折扣 可能与付款方式选择相关的信息（例如，商户购物车对应的交易订单可兑换的积分）
      4. 展示购物车：商户智能体出示最终购物车和适用的支付方式，在可信的界面中呈现给可信的用户（例如手机的系统级安全UI+必要的用户识别）。
      5. 签名和支付：用户签署“购物车凭证”+"支付凭证"（可以视为一对凭证）。购物车凭证包含明确的商品购买和购买确认。它与商家共享这样他们就可以在发生争议时将其用作证据。支付凭证（包含智能体参与程度和人类介入程度的说明）可能会与网络和发行者共享以进行支付授权。
      6. 付款执行：根据实际场景可能有多种方式（推送模式/拉取模式）：
         1. 交易智能体通知凭证智能体对指定一对凭证发起支付（例如手机上直接拉起支付/web上拉起浏览器插件web3钱包）
         2. 交易智能体将一对凭证提交给商户智能体，由商户智能体调用商户支付智能体去执行具体支付流程，例如
            1. 商户支付智能体向凭证智能体提交支付凭证请求付款，
            2. 向支付网络提交支付凭证从支付网络向凭证智能体触发付款
          支付凭证中可以包含AI智能体参与交易的标识和附加信息，确保支付网络/发卡机构了解智能体交易。
      7. 质询：支付过程中，任何一方（支付网络、凭证智能体、商户智能体）都可以选择 通过 3DS2 等现有机制请求用户对支付进行确认,质询确认可能通过不同的流程发起，但是一定要在安全可信的用户交互界面中进行呈现，确认结果的传输以质询方认可的方式和安全性进行。
      8. 质询确认：用户通过可信的交互界面（例如，银行应用程序、网站等）进行确认
      9. 授权交易：支付网络批准付款并确认成功返回，并传达给用户和商家，支付收据要在凭证智能体和商户支付智能体间完成同步分别保存，以便作为后续争议解决的证据。

2. 用户离场交易过程
   如果将一个需要支付的任务（例如购物）委托给 AI 代理，并希望 AI 在自己不在场的情况下完成支付时，会涉及以下关键变化：
   1. 场景举例：
      1. 用户对 SA 说：“从 \<this 购买 2 张 \<this 音乐会的门票>商家>一旦它们可用于 7 月的拉斯维加斯演出。您的预算是 1000 美元，我们希望尽可能靠近主舞台可能”
      2. 用户将此签名为意向授权，允许 SA 在 用户缺席下代为交易。
      3. 商家收到此意向授权，不确定是否用户满意时：
         1. 他们可以说“我有3个符合此标准的座位变化，我不知道是哪一种 用户想要。意向授权不足以让我实现这一点，商家可以回复 SA 并说我想向用户展示 最后 3 个选项。
         2. SA 通知用户需要他们的在场确认才能生成txn(交易订单)。
         3. 用户看到 3 个选项，选择一个签署“购物车 授权“，这为商家提供了用户确切知道什么的证据 他们正在得到。
      4. 商家确信用户意向与提供服务匹配，直接签发购物车交易智能体，交易智能体在不让用户返回的情况下生成支付凭证。
   2. 核心凭证：用户签署的意向凭证和支付凭证；商户签署的购物车凭证；以及必要时用户签署购物车凭证
   3. 流程变化：
      1. 无需“购物车确认提示”：AI 代理必须向用户重复他们理解的购买意图。例如：“您希望我在这双鞋价格低于 $100 时为您购买。”  
      2. 用户必须确认这个意图，并通过会话中的身份验证（如生物识别）来授权 AI 在其不在场时进行购买。
      3. 完成用户离线认证：使用“意图授权”代替“购物车授权”：
         1. 在“人类不在场”的场景中，用户签署的是“意图授权”而非“购物车授权”。  
         2. “意图授权”包含 AI 代理所理解的用户自然语言描述的购买意图。用户签署后，该授权将被共享给商家，由商家决定是否能够满足用户的需求。
      4. 商家可以强制用户确认
         1. 如果商家对是否能满足用户需求感到不确定，他们可以要求用户重新进入会话进行确认。商家可以要求：
            1. 用户从一组商品（SKU）中进行选择 → 这将生成“人类在场”的购物车授权。
            2. 用户回答商家提出的额外问题 → 这将更新“意图授权”，提供更明确的信息。
          这种机制确保商家在不确定时能获得更高的用户意图确认度，从而在交易转化率与退货/用户不满之间取得平衡。



#### 1.1.3 支付场景抽象
两种交易过程均以支付凭证签发提交启动支付过程，支付过程要解决商户智能体和交易智能体之间支付方式的协商，以及支付网络各个主体根据交易凭证的风险披露追加质询，需要考虑如下三个问题
1. 添加付款方式
根据商家的风险偏好，如果要接受代理交易，商家应有权要求所使用的支付方式达到最低安全级别。支付网络也可能会针对代理交易设定安全性或令牌化的要求，而这些要求应在交易发起前由商家强制执行。
如果用户在其凭证提供商处没有任何符合条件的支付方式的情况下，通过购物代理发起购买请求，则凭证提供商（CP）应能够通过购物代理向用户提供设置支付方式的指导，并使其具备执行代理交易的条件。这可能需要一个令牌化流程，用户可能需要在由凭证提供商或支付网络/发卡机构拥有的受信任支付界面上完成该流程。

2. 付款方式选择

商家可以声明他们已经存储了用户支付方式 “存档”，这种情况一般是交易智能体和商户智能体已经通过用户的身份认证和登录建立可信连接，并且商户与用户有过非智能体交易过程，此时商户智能体签发的购物车凭证中可以直接声明存储的支付方式供用户选择，在用户签署支付凭证后，商户智能体直接引用支付凭证发起支付。
凭据智能体知道用户可以使用哪些付款方式。交易智能体可以查询用户的付款方式，以确保用户的付款方式与商家接受的付款方式兼容付款方式。

3. 交易质询
生态系统中的任何参与方都可以在支付流程中要求用户进行身份验证挑战。对于 v0.1 版本，这种挑战将以重定向的方式传回购物代理，由其呈现给用户。用户将被重定向至受信任的界面以完成该挑战。这使得当前常见的用户验证机制，如 3DS2 或一次性密码（OTP），可以作为代理交易中的挑战手段使用。

凭证智能体应在挑战执行时保持知情，以便将成功完成的挑战类型信息传递给相关实体（商家和发卡机构），从而确保在发卡机构或商家已信任该挑战的情况下，用户不会被重复验证。对于“用户离场交易”的场景，交易挑战将强制用户重新进入会话了解交易细节。商家、支付网络和发卡机构所建立的所有现有风险系统仍应能够对接收到的数据进行推理，识别何时需要发起挑战，从而确保与现有系统的兼容性。


4. 交易方式兼容性路线图
   - 初始规范侧重于建立核心架构并启用最常见的用例。主要功能包括： 支持“拉式”支付方式（例如信用卡/借记卡） 定义明确的数据有效负载，支持基于 VDC 框架的透明问责制 支持人类存在的场景 支持用户和商家发起的升级挑战 使用 A2A 协议的详细序列图和参考实现
   - 最初的0.1版本支持常见的“拉动”支付方式，如信用卡/借记卡，未来的路线图计划支持包括实时银行转账和数字货币钱包等“推送”的新一代支付系统
   - 通过支付无关的交易层保证可以兼容未来支付






## 2. ap2现状

### 2.1 官网与demo的总体状态
1. ap2的官网规范比较简略，主要阐明交易的主体和交易层支付层的分离，声明了着眼现有支付生态的业务描述和网络兼容，并展望了对web2/3支付统一支持和a2a/mcp等多种协议的支持
2. ap2的demo分为两个，python和android
   1. python完整呈现了shop-merchant的交易交互和cp-mpp的支付交互，由于现实支付网络复杂，demo使用了虚拟的支付网络来演示
   2. android主要呈现android购物智能体与andorid的credentials manager API的调用交互，主要是DPC的生成验证，可以认为是对android的CM的一种推荐和推广
3. 总体来说，ap2的场景和3种mandate的设计比较清晰全面给出了智能体交易与用户交易/简单的自动续费类程序化交易的差异，并给出了合理的交易层解决框架，并通过cp/mpp的设计隔离了支付过程的细节。
4. 路线图
   1. v0.1 初始规范旨在建立核心架构，并支持最常见的使用场景。主要特性包括：
     - 支持“拉式”支付方式（例如信用卡/借记卡）
     - 定义明确的数据载荷，以支持基于 VDC(Verifiable Digital Contract) 框架的透明问责机制
     - 支持“人类在场”场景
     - 支持用户和商家发起的增强验证挑战（Step-up Challenges）
     - 提供使用 A2A 协议的详细序列图和参考实现
     - spec基本完成，正在进行中的：
       - AP2 A2A extension v0.1
       - AP2 MCP server v0.1
       - AP2 python SDK v0.1
       - AP2 android SDK v0.1

   2. 后续版本将根据社区反馈和不断变化的需求，扩展协议的功能。潜在的重点领域包括：
     - 全面支持“推送式”支付及所有支付方式（例如实时银行转账、电子钱包等）
     - 定期付款和订阅的标准化流程
     - 支持“人类不在场”场景
     - 基于 MCP 的实现的详细序列图
  1. 从长远来看，计划将该协议纳入更多智能性和灵活性，包括：
     - 对复杂的多商家交易拓扑结构的原生支持
     - 支持买方与卖方代理之间的实时协商
     - 积极通过 GitHub 仓库中的 issue 和讨论板块，寻求反馈与批评意见
     - 协作式的方法打造一个稳健、安全且能够满足整个生态系统多样化需求的协议


###  2.2 python系统

一个adk开发的shopping_agent 
加三个a2a agentcard声明的agent
1. merchant_agent
2. credentials_provider_agent 
3. merchant_payment_processor_agent

#### 2.2.1 shopping_agent的结构

shopping_agent 采用分层架构设计，包含一个根代理和三个专门的子代理，每个负责购物流程的不同阶段。

##### 1. 根代理 (root_agent)
- 根代理是整个购物流程的主要协调者，根代理管理三种主要场景：
    - 场景1: 用户购买商品的完整流程
    - 场景2: 用户要求描述数据传递过程
    - 场景3: 其他请求的默认响应 


##### 2. 子代理系统
- Shopper 子代理，负责产品搜索和意图收集，是购物流程的第一步。
该子代理的核心功能包括：
   - 收集用户购买意图
   - 创建 IntentMandate 对象
   - 与商家代理通信获取产品选项
   - 处理用户的购物车选择
- Shipping Address Collector 子代理，专门处理用户配送地址收集。
  - 支持两种地址收集方式：
      - 通过数字钱包自动获取
      - 用户手动输入 
- Payment Method Collector 子代理，负责支付方式的选择和处理。 
    - 从凭证提供商获取可用支付方式
    - 向用户展示支付选项
    - 获取支付凭证令牌


##### 3.  工具系统
- 根代理配备了六个核心工具来处理支付流程：
    - update_cart: 更新购物车信息
    - create_payment_mandate: 创建支付授权
    - initiate_payment: 在payment_mandate完成向cp的最终更新后，商户将把payment_mandate发送给merchart，正式启动支付
    - initiate_payment_with_otp : 使用 OTP（一次性密码）进行支付，模拟了现实中支付服务商的二次确认，发生在第一次init从sa到ma到mpp，mpp发起质询任务递归返回到sa后，重新发起，这是一种模拟，现实不是这个通道
    - sign_mandates_on_user_device : 在用户设备上模拟对交易详情进行签名，他会让用户同时签署 CartMandate 和 PaymentMandate。它从工具上下文状态中检索这两种授权类型，为每种类型生成加密哈希，并创建一个模拟的用户授权签名，将两个授权绑定在一起
    - send_signed_payment_mandate_to_credentials_provider : 将签名后的支付授权书发送给凭证提供方，cp会将其中包含的mandate-id和token的绑定存储下来。

- 子代理（Subagents）的工具
  - Shopper 子代理工具
    - create_intent_mandate - 创建用户购物意图授权书
    - find_products - 调用商家代理查找符合用户意图的产品
    - update_chosen_cart_mandate - 更新用户选择的购物车
  - Payment Method Collector 子代理工具 
    - get_payment_methods - 从凭证提供商获取用户的支付方式
    - get_payment_credential_token - 通过发送包含用户电子邮件和付款方式别名的 A2A 消息，向凭证提供商代理请求支付凭据令牌，例如seanzhang9999@gmail.com的支付宝支付，cp将返回一个token，这个token不泄露支付宝支付的账号等细节，在后续各方提请支付的时候，cp在自己程序内查找token对应的细节，并执行支付。
  - Shipping Address Collector 子代理工具
    - get_shipping_address - 从凭证提供商获取用户的配送地址

##### 4. 通过a2a client调用外部agent

购物代理通过预定义的客户端配置与远程代理建立通信。
- 为 http://localhost:8002/a2a/credentials_provider 凭据提供商创建一个 PaymentRemoteA2aClient，
- 为 http://localhost:8001/a2a/merchant_agent 商家代理创建另一个 PaymentRemoteA2aClient。


#### 2.2.2 其他三个通过a2a声明ap2协议能力的agent

##### merchant_agent  
a2a地址： http://localhost:8001/a2a/merchant_agent
agent card： samples/python/src/roles/merchant_agent/agent.json
```
{
  "name": "MerchantAgent",
  "description": "A sales assistant agent for a merchant.",
  "url": "http://localhost:8001/a2a/merchant_agent",
  "preferredTransport": "JSONRPC",
  "protocolVersion": "0.3.0",
  "version": "1.0.0",
  "defaultInputModes": ["json"],
  "defaultOutputModes": ["json"],
  "capabilities": {
      "extensions": [
        {
          "uri": "https://github.com/google-agentic-commerce/ap2/v1",
          "description": "Supports the Agent Payments Protocol.",
          "required": true
        },
        {
          "uri": "https://sample-card-network.github.io/paymentmethod/types/v1",
          "description": "Supports the Sample Card Network payment method extension",
          "required": true
        }
      ]
  },
    "skills": [
    {
      "id": "search_catalog",
      "name": "Search Catalog",
      "description": "Searches the merchant's catalog based on a shopping intent & returns a cart containing the top results.",
      "parameters": {
        "type": "object",
        "properties": {
          "shopping_intent": {
            "type": "string",
            "description": "A JSON string representing the user's shopping intent."
          }
        },
        "required": ["shopping_intent"]
      },
      "tags": ["merchant", "search", "catalog"]
    }
  ]
```
- 其中的关键部分：
  - 商家代理定义为“商家的销售助理代理”
  - extensions声明了两个能力，都通过uri作为能力标识
    - 第一个是AP2协议，用于处理支付："uri": "https://github.com/google-agentic-commerce/ap2/v1",
    - 第二个是支付方法扩展： "uri": "https://sample-card-network.github.io/paymentmethod/types/v1",
  - 代理声明一项关键技能：search_catalog 根据购物意图搜索商家目录

##### credentials_provider_agent
- 凭据提供程序代理被描述为“持有用户付款凭据的代理”
- a2a地址：http://localhost:8002/a2a/credentials_provider
- agent card声明：  samples/python/src/roles/credentials_provider_agent/agent.json
```
{
  "name": "CredentialsProvider",
  "description": "An agent that holds a user's payment credentials.",
  "capabilities": {
      "extensions": [
        {
          "uri": "https://github.com/google-agentic-commerce/ap2/v1",
          "description": "Supports the Agent Payments Protocol.",
          "required": true
        },
        {
          "uri": "https://sample-card-network.github.io/paymentmethod/types/v1",
          "description": "Supports the Sample Card Network payment method extension",
          "required": true
        }
      ]
  },
  "skills": [
    {
      "id": "initiate_payment",
      "name": "Initiate Payment",
      "description": "Initiates a payment with the correct payment processor.",
      "tags": ["payments"]
    },
    {
      "id": "get_eligible_payment_methods",
      "name": "Get Eligible Payment Methods",
      "description": "Provides a list of eligible payment methods for a particular purchase.",
      "parameters": {
        "type": "object",
        "properties": {
          "email_address": {
            "type": "string",
            "description": "The email address associated with the user's account."
          }
        },
        "required": ["email_address"]
      },
      "tags": ["eligible", "payment", "methods"]
    },
    {
      "id": "get_account_shipping_address",
      "name": "Get Shipping Address",
      "description": "Fetches the shipping address from a user's wallet.",
      "parameters": {
        "type": "object",
        "properties": {
          "email_address": {
            "type": "string",
            "description": "The email address associated with the user's account."
          }
        },
        "required": ["email_address"]
      },
      "tags": ["account", "shipping"]
    }
  ],
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["application/json"],
  "url": "http://localhost:8002/a2a/credentials_provider",
  "version": "1.0.0"
}
```
 - 关键信息
   - 同样支持 ap2协议和指定的支付网络
   - 声明了三个供shopping_agent及其子agent调用的接口
     - initiate_payment
     - get_eligible_payment_methods
     - get_account_shipping_address
   - 
##### merchant_payment_processor_agent



凭证提供商客户端: 处理支付方式和地址信息
商家代理客户端: 处理产品搜索和购物车管理




### 2.3 python系统的运行流程


#### 1 .产品发现 ： 
- 购物者子代理创建一个 IntentMandate，并将其发送给商家代理以查找匹配的产品 

#### 2. 付款方式收集：
- payment_method_collector 子代理从凭证提供程序，检索符合条件的付款方式，并获取每个付款方式的支付凭证令牌

#### 3. 购物车更新 ：
购物代理通过商家代理更新购物车的交付信息。

#### 4. 付款处理 ：
购物代理向凭证提供商发送签名的付款授权，由商家代理发起付款。

#### 5. 商户侧支付处理发起 ：
商家代理根据付款方式类型将付款请求动态路由到相应的付款处理器。对于演示中的卡支付，它会在路由到http://localhost:8003/a2a/merchant_payment_processor_agent 

### 2.4 python 安全体系

- 商家代理通过验证请求是否来自已知的购物代理来实现安全性
- 支付处理器模拟了用otp支付环路中对用户进行质询-响应身份验证
 

### 2.5 委托样例

#### 意愿委托样例

意向授权可能包含以下绑定信息（不是某些 它可能会因人类存在和人类不存在的情况而异）：

付款人和收款人信息：用户的可验证身份，即 商家及其各自的凭证提供商。
收费付款方式：用户支付方式的列表或类别 已授权交易。
风险有效载荷：商家所需的风险相关信号的容器， 支付处理商和发卡机构
购物意图：定义购买的参数，例如产品 类别或特定 SKU 和相关的购买决策标准，例如 可退款性。
提示回放：代理对用户提示的理解自然 语言。
生存时间 （TTL）：授权有效性的到期时间。
```
{
  "messageId": "e0b84c60-3f5f-4234-adc6-91f2b73b19e5",
  "contextId": "sample-payment-context",
  "taskId": "sample-payment-task",
  "role": "user",
  "parts": [
    {
      "kind": "data",
      "data": {
        "ap2.mandates.IntentMandate": {
          "user_cart_confirmation_required": false,
          "natural_language_description": "I'd like some cool red shoes in my size",
          "merchants": null,
          "skus": null,
          "required_refundability": true,
          "intent_expiry": "2025-09-16T15:00:00Z"
        }
      }
    }
  ]
}
```
#### 购物委托样例

购物车授权包含以下绑定信息：

付款人和收款人信息：用户的可验证身份，即 商家及其各自的凭证提供商。
付款方式：单个特定支付的代币化表示 由凭据提供商选择并确认的收费方法 由用户。
风险有效载荷：商家所需的风险相关信号的容器， 支付处理商和发卡机构
交易详情：最终、确切的交易产品、目的地 （电子邮件或实际地址）、金额和货币。
如果适用，购买的退款条件

```
{
  "contents": {
    "id": "cart_shoes_123",
    "user_signature_required": false,
    "payment_request": {
      "method_data": [
        {
          "supported_methods": "CARD",
          "data": {
            "payment_processor_url": "http://example.com/pay"
          }
        }
      ],
      "details": {
        "id": "order_shoes_123",
        "displayItems": [
          {
            "label": "Nike Air Max 90",
            "amount": {
              "currency": "USD",
              "value": 120.0
            },
            "pending": null
          }
        ],
        "shipping_options": null,
        "modifiers": null,
        "total": {
          "label": "Total",
          "amount": {
            "currency": "USD",
            "value": 120.0
          },
          "pending": null
        }
      },
      "options": {
        "requestPayerName": false,
        "requestPayerEmail": false,
        "requestPayerPhone": false,
        "requestShipping": true,
        "shippingType": null
      }
    }
  },
  "merchant_signature": "sig_merchant_shoes_abc1",
  "timestamp": "2025-08-26T19:36:36.377022Z"
}
```

#### 支付样例

协议单独提供了对代理的额外可见性 交易到支付生态系统。为此，可验证的数字凭证 “PaymentMandate”（绑定到购物车/意图授权，但包含单独的 信息）可以与标准一起与网络/发行人共享 交易授权消息。PaymentMandate 的目标是帮助 network/issuer 将信任构建到代理交易中，它包含 以下信息。

AI 代理存在和交易模式（人类在场与不在场） 必须始终共享信号
在用户同意的情况下，发行人和/或网络可以通过合同执行规则 需要共享购物车中存在的其他信息和/或 用于预防欺诈等目的的意向授权。
发生争议时，商家可以使用完整的购物车和/或意图授权 作为在网络/发行人处代表期间的证据，如 网络规则。
这种架构代表了传统架构的重大演变， 命令式 API 调用（例如，）对“合同 对话。协议消息不仅仅是命令;他们是一步 正式的、可审计的谈判，最终形成具有约束力的数字合同。 这种声明性、共识驱动的模型本质上更加安全和健壮 对于将定义代理时代的复杂多方互动， 为信任和争议解决提供了比任何 客户端-服务器 API 模型可以提供并为未来的安全性铺平道路 数字支付凭证和其他加密等增强功能 方法

```
{
  "payment_details": {
    "cart_mandate": "<user-signed hash of the cart mandate>"
    "payment_request_id": "order_shoes_123",
    "merchant_agent_card": {
      "name": "MerchantAgent"
    },
    "payment_method": {
      "supported_methods": "CARD",
      "data": {
        "token": "xyz789"
      },
    },
    "amount": {
      "currency": "USD",
      "value": 120.0,
    },
    "risk_info": {
      "device_imei": "abc123"
    },
    "display_info": "<image bytes>"
  },
  "creation_time": "2025-08-26T19:36:36.377022Z"
}
```



## 3. extension机制问题


客户端 ：当客户端发送 A2A 消息时，它会使用所需的扩展 URI（逗号分隔）设置 X-A2A-Extensions HTTP 标头。
服务器端解析 ：A2A 框架的 SimpleRequestContextBuilder（不是 AP2 示例代码的一部分，而是底层 A2A SDK 的一部分）解析此 HTTP 标头并填充字段 RequestContext.requested_extensions 。

扩展激活 ：该 BaseServerExecutor._handle_extensions() 方法读取 context.requested_extensions 并将其与代理的 _supported_extension_uris 进行比较，以确定要激活哪些扩展。

X-A2A-Extensions 标头的实际解析 RequestContext.requested_extensions 由 A2A SDK 基础结构处理，这是一个依赖项，未显示在 AP2 示例代码中。

扩展要求 ：但是，该代码确实要求必须为对这些代理的所有请求激活 AP2 付款扩展 （EXTENSION_URI），如果未激活，则会引发 ValueError。

```
    if EXTENSION_URI in context.call_context.activated_extensions:
      payment_mandate = message_utils.find_data_part(
          PAYMENT_MANDATE_DATA_KEY, data_parts
      )
      if payment_mandate is not None:
        validate_payment_mandate_signature(
            PaymentMandate.model_validate(payment_mandate)
        )
    else:
      raise ValueError(
          "Payment extension not activated."
          f" {context.call_context.activated_extensions}"
      )
```


BaseServerExecutor 由始终在 AP2 支付生态系统中工作的特定于支付的代理（MerchantAgent、CredentialsProviderAgent、PaymentProcessorAgent）使用。即使特定消息不包含支付授权，代理仍然需要激活 AP2 扩展来处理与支付相关的作。


扩展激活的本质
"激活扩展"（activate extension）在 _handle_extensions() 方法中确实没有加载任何实际代码或动态加载模块。 base_server_executor.py:182-191

这个过程只是：

协商匹配：计算客户端请求的扩展和服务端支持的扩展的交集
标记状态：将匹配的扩展 URI 添加到 context.call_context.activated_extensions 集合中 base_server_executor.py:188-190
实际作用
这个"激活"标记的作用是：

协议协商：确认客户端和服务端都同意使用某个扩展协议
后续验证：在后续的代码中检查扩展是否已激活，决定是否执行特定的验证逻辑
例如，在 execute() 方法中检查 AP2 扩展是否激活，如果激活了才会验证 PaymentMandate： base_server_executor.py:94-105

Notes   笔记
这是一种声明式的协议协商机制，而不是动态代码加载。所有的业务逻辑代码（如 PaymentMandate 验证）都已经静态地存在于 BaseServerExecutor 中，"激活"只是决定是否执行这些已有的代码路径。这种设计符合 A2A 协议的扩展机制，允许客户端和服务端在运行时协商使用哪些协议特性。




## 4. DPC的核心逻辑

DPC支付流程分析
1. 数字支付凭证的获取不等于完成支付
在Android的DPC实现中，通过Credential Manager获取的数字支付凭证并不意味着支付已经完成。这个token只是用户授权的凭证，实际的支付处理仍需要后续步骤。 ShoppingTools.kt:210-222

从代码可以看出，invokeCredentialManager方法返回的是dpcCredential.credentialJson，这是一个包含用户授权信息的token，而不是支付完成的确认。

2. 支付验证步骤是关键
获取token后，还需要将其发送给merchant进行验证才能完成支付： ShoppingTools.kt:166-187

只有当merchant返回"SUCCESS"状态时，支付才真正完成。

3. Android scenarios与AP2协议的关系
3. Android 场景与 AP2 协议的关系
您提到的关于"将CP生成的token绑定到payment mandate"的问题很有洞察力。确实，Android scenarios采用了简化的实现方式：

直接使用CartMandate: Android实现直接将CartMandate传递给Credential Manager，而不是先生成PaymentMandate DpcHelper.kt:38-123

跳过了标准AP2流程: 根据AP2协议规范，标准流程应该包括PaymentMandate的生成和绑定 specification.md:330-359

4. 实现差异的原因
Android scenarios作为演示实现，简化了某些步骤以专注于DPC的核心功能展示。在生产环境中，完整的AP2协议实现会包含更复杂的mandate管理和绑定流程。

Notes   笔记
Android scenarios展示了DPC技术的实际应用，但为了演示目的简化了完整的AP2协议流程。实际的支付完成需要经过token验证步骤，而不仅仅是获取凭证。这种简化有助于理解DPC的核心概念，但在生产实现中需要遵循完整的AP2协议规范。

Wiki pages you might want to explore:
您可能想要探索的 Wiki 页面：







## 5. andorid的代码逻辑

Android Scenarios 代码逻辑分析
这个Android scenarios是一个完整的购物助手应用，演示了使用数字支付凭证(DPC)进行安全支付的购物流程。以下是主要的代码逻辑分析：

应用架构概览
该Android应用采用MVVM架构，主要包含以下核心组件：

1. 主Activity和导航
MainActivity是应用的入口点，使用Jetpack Compose进行UI构建，实现了聊天界面和设置界面之间的导航 MainActivity.kt:37-76

2. 聊天状态管理
ChatViewModel负责管理整个聊天会话的状态，包括消息列表、加载状态和与后端服务的连接 ChatViewModel.kt:46-111

聊天消息使用ChatMessage数据类表示，支持不同的发送者角色(用户、Gemini、代理) ChatMessage.kt:16-29

3. 核心业务逻辑
ChatRepository是核心业务逻辑层，集成了Gemini AI模型并定义了购物工具函数，包括产品搜索、产品选择、地址获取、购物车更新和DPC支付 ChatRepository.kt:81-130

购物流程实现
4. 购物工具集成
ShoppingTools类实现了具体的购物功能，通过A2A协议与merchant agent通信：

产品搜索: 根据自然语言描述查找产品 ShoppingTools.kt:76-110
购物车更新: 更新购物车信息包括配送地址 ShoppingTools.kt:112-146
5. 数字支付凭证(DPC)支付流程
应用实现了完整的DPC支付流程，这是该scenarios的核心特性：

DPC请求构建: 构建OpenID4VP请求，包含交易数据和凭证查询 DpcHelper.kt:38-123
凭证管理器集成: 使用Android Credential Manager API获取数字支付凭证 ShoppingTools.kt:149-188
支付验证: 将获得的token发送给merchant进行验证 ShoppingTools.kt:166-187
A2A协议通信
6. 代理通信
A2aClient负责与merchant agent的通信，实现A2A协议的消息发送和接收 A2AClient.kt:62-86

7. 数据模型
应用定义了完整的数据模型来支持购物流程，包括购物车mandate、支付请求详情等 ShoppingAgentTypes.kt:43-57

DPC相关的数据类型支持OpenID4VP协议的完整实现 DpcTypes.kt:19-30

工具执行流程
应用通过工具函数执行模式处理用户请求，支持产品查找、选择、地址管理和支付等操作 ChatRepository.kt:184-271

Notes   笔记
这个Android scenarios展示了一个完整的现代购物应用架构，特别突出了数字支付凭证(DPC)的使用，这是一种安全的支付方式，允许用户在可信界面上确认购买意图。应用使用Jetpack Compose构建现代UI，集成Gemini AI提供自然语言交互，并通过A2A协议实现与后端服务的标准化通信。整个架构展现了Android平台上安全支付和智能购物助手的最佳实践。


DPC的构造
```
    @OptIn(ExperimentalEncodingApi::class)
    fun constructDPCRequest(cartMandate: CartMandate, merchantName: String): String {
    val totalValue = cartMandate.contents.paymentRequest.details.total.amount.value

    val credId = "cred1"
    val mdocIdentifier = "mso_mdoc"
    // This nonce should ideally be generated securely for each transaction.
    val nonce = UUID.randomUUID().toString()

    val totalValueString = String.format("%.2f", totalValue)

    val tableRows =
        cartMandate.contents.paymentRequest.details.displayItems.map { item ->
        listOf(item.label, "1", item.amount.value.toString(), item.amount.value.toString())
        }

    for (row in tableRows) {
        Log.d("reemademo", "Row: $row")
    }

    val footerText = "Your total is $totalValueString"

    val additionalInfo =
        AdditionalInfo(
        title = "Please confirm your purchase details...",
        tableHeader = listOf("Name", "Qty", "Price", "Total"),
        tableRows = tableRows,
        footer = footerText,
        )

    // Build transaction_data payload.
    val transactionData =
        TransactionData(
        type = "payment_card",
        credentialIds = listOf(credId),
        transactionDataHashesAlg = listOf("sha-256"),
        merchantName = merchantName,
        amount = "US ${String.format("%.2f", totalValue)}",
        additionalInfo = json.encodeToString(additionalInfo), // Serialize the inner object
        )

    // Build the DCQL query to request specific credential claims.
    val claims =
        listOf(
        Claim(path = listOf("com.emvco.payment_card.1", "card_number")),
        Claim(path = listOf("com.emvco.payment_card.1", "holder_name")),
        )

    val credentialQuery =
        CredentialQuery(
        id = credId,
        format = mdocIdentifier,
        meta = Meta(doctypeValue = "com.emvco.payment_card"),
        claims = claims,
        )

    val dcqlQuery = DcqlQuery(credentials = listOf(credentialQuery))

    // Build client_metadata to specify supported formats.
    val mdocFormatsSupported =
        MdocFormatsSupported(
        issuerauthAlgValues = listOf(-7), // ES256
        deviceauthAlgValues = listOf(-7),
        )
    val clientMetadata =
        ClientMetadata(vpFormatsSupported = VpFormatsSupported(msoMdoc = mdocFormatsSupported))

    // Base64URL-encode the transaction_data JSON string.
    val transactionDataJsonString = json.encodeToString(transactionData)
    val encodedTransactionData =
        Base64.UrlSafe.encode(transactionDataJsonString.toByteArray(Charsets.UTF_8))

    // Build the final request object.
    val dcRequest =
        Request(
        responseType = "vp_token",
        responseMode = "dc_api",
        nonce = nonce,
        dcqlQuery = dcqlQuery,
        transactionData = listOf(encodedTransactionData),
        clientMetadata = clientMetadata,
        )

    val dpcRequest = DpcRequest(protocol = "openid4vp-v1-unsigned", request = dcRequest)

    // Serialize the final object to a string and return.
    return json.encodeToString(dpcRequest)
```


```
# CM的调用返回代码
  private suspend fun invokeCredentialManager(dpcRequestJson: String, activity: Activity): String? {
    Log.d(TAG, "Invoking Credential Manager")
    val jsonFromMerchant = JSONObject(dpcRequestJson)

    val protocol = jsonFromMerchant.getString("protocol")
    val data = jsonFromMerchant.getJSONObject("request")

    val request =
      JSONObject().apply {
        put("protocol", protocol)
        put("data", data)
      }

    val requests = JSONObject().apply { put("requests", JSONArray().apply { put(request) }) }

    val reqStr = requests.toString()
    Log.d(TAG, "Invoking DPC with request: $reqStr")

    val digitalCredentialOption = GetDigitalCredentialOption(reqStr)
    return try {
      val credential =
        credentialManager.getCredential(
          activity,
          GetCredentialRequest(listOf(digitalCredentialOption)),
        )
      val dpcCredential = credential.credential as DigitalCredential
      Log.i(TAG, "Credential Manager returned a token.")
      dpcCredential.credentialJson
    } catch (e: Exception) {
      Log.e(TAG, "Credential Manager failed or was cancelled", e)
      null
    }
  }
```

