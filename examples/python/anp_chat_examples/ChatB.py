import asyncio
import time
from openai import OpenAI
import os
from anp.openanp import anp_agent, interface, AgentConfig, RemoteAgent
from anp.authentication import DIDWbaAuthHeader
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fastapi import FastAPI
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

AGENT_B_DID = "did:wba:example.com:chatb"
AGENT_A_DID = "did:wba:example.com:chata"
AGENT_A_URL = "http://localhost:8000/a/ad.json"

API_KEY = os.getenv("OPENAI_KEY")
BASE_URL = os.getenv("OPENAI_API_BASE")
MODEL_NAME = "deepseek-chat"

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    if not API_KEY:
        raise RuntimeError("missing OPENAI_KEY")
    if BASE_URL:
        _client = OpenAI(base_url=BASE_URL, api_key=API_KEY)
    else:
        _client = OpenAI(api_key=API_KEY)
    return _client

# 修复 anp 内置 DIDWbaAuthHeader：支持 Ed25519（RemoteAgent.discover / ANPClient 会用到）。
try:
    from anp.authentication.did_wba_authenticator import DIDWbaAuthHeader as _LibDIDWbaAuthHeader

    def _sign_callback_compat(self, content: bytes, method_fragment: str) -> bytes:
        private_key = self._load_private_key()
        if isinstance(private_key, Ed25519PrivateKey):
            return private_key.sign(content)
        return private_key.sign(content, ec.ECDSA(hashes.SHA256()))

    _LibDIDWbaAuthHeader._sign_callback = _sign_callback_compat
except Exception:
    pass


auth = DIDWbaAuthHeader(
    did_document_path="./did_b.json",
    private_key_path="./private_b.pem"
)

@anp_agent(AgentConfig(
    name="Chat Agent B",
    did=AGENT_B_DID,
    prefix="/b",
))
class ChatAgentB:
    def __init__(self, auth: DIDWbaAuthHeader):
        self.auth = auth
        self.chat_a = None
        self.sent_count = 0
        print("Intialized ChatAgentB")

    def _llm_generate(self, prompt: str) -> str:
        if not API_KEY:
            return "（ChatB 未配置 OPENAI_KEY，无法调用模型）"

        system_prompt = (
            "你是智能体 ChatB。你的任务是与 ChatA 进行简短对话。"
            "每次只输出一句要发给 ChatA 的中文消息，简洁自然。"
            "不要输出解释、不要带前缀。"
        )

        resp = _get_client().chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            temperature=0.8,
        )
        content = resp.choices[0].message.content
        return (content or "").strip() or "（空消息）"

    async def ensure_chat_a_connection(self):
        """确保 ChatA 连接"""
        if self.chat_a is None:
            try:
                self.chat_a = await RemoteAgent.discover(
                    AGENT_A_URL,
                    self.auth
                )
                print(f" ChatB: 成功连接: {self.chat_a.name}")
                return True
            except Exception as e:
                print(f" ChatB: 连接失败: {str(e)}")
                return False
        return True

    async def start_model_driven_chat(self, turns: int = 4):
        """discover ChatA 后，用模型驱动生成消息并发送"""
        for attempt in range(10):
            if await self.ensure_chat_a_connection():
                break
            await asyncio.sleep(1)
        else:
            print("ChatB: 多次尝试后仍无法 discover ChatA")
            return

        remaining_turns = int(turns)
        prompt = "请你主动和 ChatA 打个招呼并开启对话。"
        next_message = self._llm_generate(prompt)

        while remaining_turns > 0:
            print(f"\nChatB -> ChatA: {next_message}")
            self.sent_count += 1

            try:
                response = await self.chat_a.receive_message(
                    message=next_message,
                    remaining_turns=remaining_turns,
                )
            except Exception as e:
                print(f"ChatB: 调用 ChatA 失败: {str(e)}")
                return

            chat_a_reply = (response or {}).get("reply", "")
            if chat_a_reply:
                print(f"ChatA -> ChatB: {chat_a_reply}")
            else:
                print(f"ChatB: 未收到 ChatA.reply，原始响应: {response}")
            remaining_turns = int((response or {}).get("remaining_turns", 0))
            if remaining_turns <= 0:
                print("\nChatB: 对话结束")
                return

            next_message = self._llm_generate(f"ChatA 说：{chat_a_reply}\n你回复 ChatA 一句话。")

    @interface
    async def status(self) -> dict:
        """给广告/健康检查提供一个简单可调用的 interface"""
        return {
            "agent": "ChatB",
            "did": AGENT_B_DID,
            "sent_count": self.sent_count,
        }

# 创建应用
app = FastAPI(title="ChatAgentB", description="Chat Agent B - 端口 8001")

chat_agent_b = ChatAgentB(auth)
app.include_router(chat_agent_b.router())

@app.get("/")
async def root():
    return {
        "name": "Chat Agent B",
        "did": AGENT_B_DID,
        "endpoint": "/b",
        "status": "running",
        "messages_sent": chat_agent_b.sent_count
    }

@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {
        "status": "healthy",
        "agent": "ChatB",
        "timestamp": time.time(),
        "uptime": time.time() - getattr(app.state, 'start_time', time.time())
    }

@app.on_event("startup")
async def startup_event():
    """应用启动时的初始化"""
    app.state.start_time = time.time()
    print("\n" + "="*60)
    print("启动 Chat Agent B (端口 8001)")
    print("   • 访问 http://localhost:8001 查看状态")
    print("   • 访问 http://localhost:8001/b/ad.json 查看广告")
    print("   • 访问 http://localhost:8001/health 进行健康检查")
    print("="*60 + "\n")

    # ChatB 作为发起方：等 ChatA 启动后 discover 并发起一段短对话
    await asyncio.sleep(2)
    asyncio.create_task(chat_agent_b.start_model_driven_chat(turns=4))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)