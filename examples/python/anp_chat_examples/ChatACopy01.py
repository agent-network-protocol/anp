import asyncio
import time
import random
from openai import OpenAI
import os
from datetime import datetime
from anp.openanp import anp_agent, interface, AgentConfig, RemoteAgent
from anp.authentication import DIDWbaAuthHeader
from fastapi import FastAPI
import uvicorn
import requests

AGENT_A_DID = "did:wba:example.com:chata"
AGENT_B_DID = "did:wba:example.com:chatb"
AGENT_B_URL = "http://localhost:8001/b/ad.json"

API_KEY = os.getenv("OPENAI_KEY")
BASE_URL = os.getenv("OPENAI_API_BASE")
MODEL_NAME = "deepseek-chat"

client = OpenAI(
    base_url=BASE_URL,
    api_key=API_KEY
)

auth = DIDWbaAuthHeader(
    did_document_path="./did_a.json",
    private_key_path="./private_a.pem"
)

@anp_agent(AgentConfig(
    name="Chat Agent A",
    did=AGENT_A_DID,
    prefix="/a",
))
class ChatAgentA:
    def __init__(self, auth: DIDWbaAuthHeader):
        self.auth = auth
        self.chat_b = None
        self.conversation_active = False
        self.conversation_count = 0
        print("Intialized ChatAgentA")

    async def ensure_chat_b_connection(self):
        """确保 ChatB 连接"""
        if self.chat_b is None:
            try:
                self.chat_b = await RemoteAgent.discover(
                    AGENT_B_URL,
                    self.auth
                )
                print(f"ChatA: 成功连接 {self.chat_b.name}")
                return True
            except Exception as e:
                print(f"ChatA: 连接失败: {str(e)}")
                return False
        return True

    async def check_if_chatb_is_alive(self) -> bool:
        """检查 ChatB 是否存活"""
        try:
            response = requests.get("http://localhost:8001/health", timeout=2)
            if response.status_code == 200:
                return True
            response = requests.get(AGENT_B_URL, timeout=2)
            if response.status_code == 200:
                return True
            return False
        except Exception as e:
            print(f"ChatA: 未检测到服务: {str(e)}")
            return False

    async def start_autonomous_conversation(self):
        """启动自主对话 - 仅当 ChatB 存活且没有活跃对话时"""
        if self.conversation_active:
            print(" ChatA: 对话已在进行中，跳过新对话请求")
            return
            
        if await self.check_if_chatb_is_alive():
            if await self.ensure_chat_b_connection():
                print("\n" + "="*60)
                print(f"ChatA: 检测到 ChatB，准备开始自主对话! (第 {self.conversation_count + 1} 次)")
                print("="*60)
                
                self.conversation_active = True
                self.conversation_count += 1
                
                try:
                    # 准备初始消息
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    initial_message = f"你好 ChatB! 我是 ChatA。现在是 {timestamp}，让我们开始一段自主对话吧!"
                    remaining_turns = 5  # 最大对话轮数
                    
                    print(f"ChatA 向 ChatB 发送: '{initial_message}'")
                    
                    # 启动对话
                    response = await self.chat_b.receive_message(
                        message=initial_message,
                        remaining_turns=remaining_turns
                    )
                    
                    print(f"ChatA 收到 ChatB 最终响应: {response}")
                    
                except Exception as e:
                    print(f"ChatA 自主对话失败: {str(e)}")
                finally:
                    self.conversation_active = False
                    # 计划下一次对话（随机间隔，避免与 ChatB 冲突）
                    next_delay = random.randint(30, 60)  # 30-60秒后再次尝试
                    print(f"ChatA: 将在 {next_delay} 秒后再次检查 ChatB 并可能开始新对话")
                    asyncio.create_task(self.schedule_next_conversation(next_delay))
        else:
            # 未检测到 ChatB，稍后重试
            next_delay = random.randint(10, 20)
            print(f"⏳ ChatA: 未检测到 ChatB，将在 {next_delay} 秒后重试")
            asyncio.create_task(self.schedule_next_conversation(next_delay))

    async def schedule_next_conversation(self, delay_seconds: int):
        """安排下一次对话检查"""
        await asyncio.sleep(delay_seconds)
        await self.start_autonomous_conversation()

    @interface
    async def receive_message(self, message: str, remaining_turns: int) -> dict:
        """接收消息并回复"""
        # 生成回复
        reply = f"A收到: '{message}'. 很高兴和你聊天! [剩余轮数: {remaining_turns}]"
        print(f"\n ChatA 收到 ({remaining_turns}轮): '{message}'")
        print(f" ChatA 回复: {reply}")
        
        # 检查是否继续对话
        if remaining_turns > 0:
            try:
                if not await self.ensure_chat_b_connection():
                    return {
                        "error": "ChatB connection failed",
                        "agent": "ChatA",
                        "last_message": reply,
                        "status": "failed"
                    }
                
                print(f" ChatA 调用 ChatB (剩余 {remaining_turns-1} 轮)...")
                
                # 调用 ChatB
                response = await self.chat_b.receive_message(
                    message=reply,
                    remaining_turns=remaining_turns - 1
                )
                print(f" ChatA 收到 ChatB 响应: {response}")
                return response
                
            except Exception as e:
                error_msg = str(e)
                print(f"❌ ChatA 调用 ChatB 时出错: {error_msg}")
                return {
                    "error": error_msg,
                    "agent": "ChatA",
                    "last_message": reply,
                    "status": "failed"
                }
        else:
            print(f"\n ChatA 终止对话，达到最大轮数")
            return {
                "final_message": reply,
                "agent": "ChatA",
                "remaining_turns": remaining_turns
            }

# 创建应用
app = FastAPI(title="ChatAgentA", description="Chat Agent A - 端口 8000")

chat_agent_a = ChatAgentA(auth)
app.include_router(chat_agent_a.router())

@app.get("/")
async def root():
    return {
        "name": "Chat Agent A",
        "did": AGENT_A_DID,
        "endpoint": "/a",
        "status": "running",
        "conversations_started": chat_agent_a.conversation_count
    }

@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {
        "status": "healthy",
        "agent": "ChatA",
        "timestamp": time.time(),
        "uptime": time.time() - getattr(app.state, 'start_time', time.time())
    }

@app.on_event("startup")
async def startup_event():
    """应用启动时的初始化"""
    app.state.start_time = time.time()
    print("\n" + "="*60)
    print("启动 Chat Agent A (端口 8000)")
    print("   • 访问 http://localhost:8000 查看状态")
    print("   • 访问 http://localhost:8000/a/ad.json 查看广告")
    print("   • 访问 http://localhost:8000/health 进行健康检查")
    print("="*60 + "\n")
    
    # 启动自主对话系统（添加随机延迟避免与 ChatB 冲突）
    delay = random.randint(5, 15)  # 5-15秒随机延迟
    print(f" ChatA: 将在 {delay} 秒后开始自主对话系统...")
    await asyncio.sleep(delay)
    
    # 启动自主对话循环
    asyncio.create_task(chat_agent_a.start_autonomous_conversation())

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)