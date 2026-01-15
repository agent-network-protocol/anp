import time
from openai import OpenAI
import os
from anp.openanp import anp_agent, interface, AgentConfig
from anp.authentication import DIDWbaAuthHeader
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
import uvicorn

AGENT_A_DID = "did:wba:example.com:chata"

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
        self.message_count = 0
        print("Intialized ChatAgentA")

    def _llm_reply(self, user_message: str) -> str:
        if not API_KEY:
            return "（ChatA 未配置 OPENAI_KEY，无法调用模型）"

        system_prompt = (
            "你是一个通过 ANP 接口对话的智能体 ChatA。"
            "你需要用中文、简洁、自然地回复对方的消息。"
            "不要输出多余的元信息。"
        )

        resp = _get_client().chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=0.7,
        )
        content = resp.choices[0].message.content
        return (content or "").strip() or "（空回复）"

    @interface
    async def receive_message(self, message: str, remaining_turns: int) -> dict:
        """ANP Interface: 接收消息并用模型回复"""
        self.message_count += 1
        print(f"\nChatB -> ChatA: {message}")

        try:
            reply = self._llm_reply(message)
        except Exception as e:
            reply = f"（ChatA 调用模型失败：{str(e)}）"

        print(f"ChatA -> ChatB: {reply}")

        return {
            "agent": "ChatA",
            "reply": reply,
            "remaining_turns": max(0, int(remaining_turns) - 1),
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
        "messages_received": chat_agent_a.message_count
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False)