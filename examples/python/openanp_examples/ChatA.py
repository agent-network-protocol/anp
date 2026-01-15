import time
import asyncio
import uuid
from openai import OpenAI
import os
from typing import Optional, Any
from contextlib import asynccontextmanager
from anp.openanp import anp_agent, interface, AgentConfig, RemoteAgent
from anp.authentication import DIDWbaAuthHeader
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Body
import uvicorn

AGENT_A_DID = "did:wba:example.com:chata"
AGENT_A_NAME = "ChatA"

PEER_AD_URL = os.getenv("CHAT_PEER_AD_URL", "http://localhost:8001/b/ad.json")

AUTO_DISCOVER = (os.getenv("CHAT_AUTO_DISCOVER", "1").strip().lower() not in {"0", "false", "no"})
AUTO_DISCOVER_MAX_TRIES = int(os.getenv("CHAT_AUTO_DISCOVER_MAX_TRIES", "30").strip() or "30")
AUTO_DISCOVER_INTERVAL_SEC = float(os.getenv("CHAT_AUTO_DISCOVER_INTERVAL_SEC", "1").strip() or "1")

AUTO_START_CHAT = (os.getenv("CHAT_AUTO_START", "1").strip().lower() not in {"0", "false", "no"})
AUTO_CHAT_TURNS = int(os.getenv("CHAT_AUTO_TURNS", "4").strip() or "4")

DISCOVER_TIE_TOLERANCE_SEC = float(os.getenv("CHAT_DISCOVER_TIE_TOLERANCE_SEC", "0.5").strip() or "0.5")

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

    def _load_private_key_compat(self):
        key_path = self.private_key_path
        with open(key_path, 'rb') as f:
            private_key_data = f.read()

        try:
            return serialization.load_pem_private_key(private_key_data, password=None)
        except Exception:
            return serialization.load_ssh_private_key(private_key_data, password=None)

    def _sign_callback_compat(self, content: bytes, method_fragment: str) -> bytes:
        private_key = self._load_private_key()
        if isinstance(private_key, Ed25519PrivateKey):
            return private_key.sign(content)
        return private_key.sign(content, ec.ECDSA(hashes.SHA256()))

    _LibDIDWbaAuthHeader._load_private_key = _load_private_key_compat
    _LibDIDWbaAuthHeader._sign_callback = _sign_callback_compat
except Exception:
    pass


auth = DIDWbaAuthHeader(
    did_document_path="./did_a.json",
    private_key_path="./private_a.pem"
)

@anp_agent(AgentConfig(
    name=AGENT_A_NAME,
    did=AGENT_A_DID,
    prefix="/a",
))
class ChatAgentA:
    def __init__(self, auth: DIDWbaAuthHeader):
        self.auth = auth
        self.message_count = 0
        self.sent_count = 0
        self.connected_agents = set()
        self.peer: Any = None
        self.peer_name: Optional[str] = None
        self.first_discover_ts: Optional[float] = None
        self._chat_lock = asyncio.Lock()
        self._active_session_id: Optional[str] = None
        self._chat_task: Optional[asyncio.Task] = None
        self._auto_start_attempted = False
        print("Intialized ChatAgentA")

    def _log_connected_once(self, agent_name: str) -> None:
        name = (agent_name or "").strip() or "Unknown"
        if name == "Unknown":
            return
        if name in self.connected_agents:
            return
        self.connected_agents.add(name)
        print(f"\nChatA: 成功连接 {name}")

    @interface
    async def notify_connected(self, agent: str) -> dict:
        """ANP Interface: 由对端在 discover/连接后主动通知，用于日志展示"""
        agent_name = (agent or "").strip() or "Unknown"
        self._log_connected_once(agent_name)
        if agent_name and agent_name != "Unknown":
            self.peer_name = agent_name
        return {"ok": True, "agent": "ChatA", "connected": agent_name}

    def _llm_generate(self, prompt: str) -> str:
        if not API_KEY:
            return "你好，我们开始聊天吧。"

        system_prompt = (
            "你是智能体 ChatA。你的任务是与对端智能体进行简短对话。"
            "每次只输出一句要发给对端的中文消息，简洁自然。"
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

    async def _run_chat_as_initiator(self, turns: int):
        if self.peer is None:
            return
        peer_label = self.peer_name or getattr(self.peer, "name", None) or "Peer"
        remaining_turns = int(turns)
        next_message = self._llm_generate("请你主动向对端打个招呼并开启对话。")

        while remaining_turns > 0:
            print(f"\nChatA -> {peer_label}: {next_message}")
            self.sent_count += 1

            try:
                response = await self.peer.receive_message(message=next_message, remaining_turns=remaining_turns)
            except Exception as e:
                print(f"ChatA: 调用对端失败: {str(e)}")
                return

            peer_reply = (response or {}).get("reply", "")
            if peer_reply:
                print(f"{peer_label} -> ChatA: {peer_reply}")
            else:
                print(f"ChatA: 未收到对端 reply，原始响应: {response}")

            remaining_turns = int((response or {}).get("remaining_turns", 0))
            if remaining_turns <= 0:
                print("\nChatA: 对话结束")
                return

            next_message = self._llm_generate(f"对端说：{peer_reply}\n你回复对端一句话。")

    @interface
    async def propose_chat(self, initiator_did: str, initiator_discover_ts: float, session_id: str, turns: int = 4) -> dict:
        """ANP Interface: 对端请求由其发起聊天。"""
        initiator = (initiator_did or "").strip()
        sid = (session_id or "").strip()
        if not initiator or not sid:
            return {"accepted": False, "reason": "missing_params"}

        async with self._chat_lock:
            if self._active_session_id is not None:
                return {"accepted": False, "reason": "already_active", "session_id": self._active_session_id}

            local_ts = self.first_discover_ts
            if local_ts is not None:
                diff = float(initiator_discover_ts) - float(local_ts)
                if diff > DISCOVER_TIE_TOLERANCE_SEC:
                    # 我方明显更早 discover：拒绝，让我方发起
                    return {"accepted": False, "reason": "i_discovered_first", "winner": AGENT_A_DID}
                if abs(diff) <= DISCOVER_TIE_TOLERANCE_SEC:
                    # 近似同时：用 DID 做确定性裁决
                    if AGENT_A_DID < initiator:
                        return {"accepted": False, "reason": "tie_break", "winner": AGENT_A_DID}

            self._active_session_id = sid
            return {"accepted": True, "session_id": sid, "turns": int(turns)}

    async def maybe_start_chat_if_discovered_first(self, turns: int) -> None:
        if not AUTO_START_CHAT:
            return
        if self.peer is None or self.first_discover_ts is None:
            return

        async with self._chat_lock:
            if self._active_session_id is not None:
                return
            if self._chat_task is not None and not self._chat_task.done():
                return

        sid = str(uuid.uuid4())
        peer_label = self.peer_name or getattr(self.peer, "name", None) or "Peer"
        try:
            resp = await self.peer.propose_chat(
                initiator_did=AGENT_A_DID,
                initiator_discover_ts=float(self.first_discover_ts),
                session_id=sid,
                turns=int(turns),
            )
        except Exception as e:
            print(f"ChatA: 向 {peer_label} 发起聊天失败: {str(e)}")
            return

        if not (resp or {}).get("accepted"):
            return

        async with self._chat_lock:
            if self._active_session_id is None:
                self._active_session_id = sid
            if self._chat_task is None or self._chat_task.done():
                self._chat_task = asyncio.create_task(self._run_chat_as_initiator(turns=int(turns)))

    async def ensure_peer_connection(self, peer_ad_url: Optional[str] = None) -> bool:
        """discover 对端（ChatB）并缓存 RemoteAgent"""
        if self.peer is not None:
            return True

        url = (peer_ad_url or "").strip() or PEER_AD_URL
        try:
            self.peer = await RemoteAgent.discover(url, self.auth)
            self.peer_name = getattr(self.peer, "name", None) or self.peer_name
            if self.first_discover_ts is None:
                self.first_discover_ts = time.time()
            self._log_connected_once(self.peer_name or "Unknown")
            try:
                await self.peer.notify_connected(agent=AGENT_A_NAME)
            except Exception as e:
                print(f" ChatA: 已连接但通知对端失败: {str(e)}")
            return True
        except Exception as e:
            print(f" ChatA: discover 对端失败: {str(e)}")
            self.peer = None
            return False

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
    async def status(self) -> dict:
        return {
            "agent": "ChatA",
            "did": AGENT_A_DID,
            "messages_received": self.message_count,
            "messages_sent": self.sent_count,
            "peer_connected": self.peer is not None,
            "peer_name": self.peer_name,
        }

    @interface
    async def receive_message(self, message: str, remaining_turns: int) -> dict:
        """ANP Interface: 接收消息并用模型回复"""
        self.message_count += 1
        sender = self.peer_name or getattr(self.peer, "name", None) or "Peer"
        print(f"\n{sender} -> ChatA: {message}")

        try:
            reply = self._llm_reply(message)
        except Exception as e:
            reply = f"（ChatA 调用模型失败：{str(e)}）"

        print(f"ChatA -> ChatB: {reply}")

        new_remaining_turns = max(0, int(remaining_turns) - 1)
        if new_remaining_turns <= 0:
            print("\nChatA: 对话结束")

        return {
            "agent": "ChatA",
            "reply": reply,
            "remaining_turns": new_remaining_turns,
        }

    async def send_message(self, message: str, remaining_turns: int = 4, peer_ad_url: Optional[str] = None) -> dict:
        """主动向对端发送消息"""
        ok = await self.ensure_peer_connection(peer_ad_url=peer_ad_url)
        if not ok or self.peer is None:
            return {"ok": False, "error": "peer_not_connected"}

        self.sent_count += 1
        try:
            return await self.peer.receive_message(message=message, remaining_turns=int(remaining_turns))
        except Exception as e:
            return {"ok": False, "error": f"call_peer_failed: {str(e)}"}

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.start_time = time.time()
    print("\n" + "=" * 60)
    print("启动 Chat Agent A (端口 8000)")
    print("   • 访问 http://localhost:8000 查看状态")
    print("   • 访问 http://localhost:8000/a/ad.json 查看广告")
    print("   • 访问 http://localhost:8000/health 进行健康检查")
    print("   • 访问 http://localhost:8000/p2p/discover 进行 P2P discover")
    print("   • 访问 http://localhost:8000/p2p/send 主动发送消息")
    print("=" * 60 + "\n")

    if AUTO_DISCOVER:
        async def _auto_discover_loop():
            for _ in range(max(1, AUTO_DISCOVER_MAX_TRIES)):
                if await chat_agent_a.ensure_peer_connection():
                    if not chat_agent_a._auto_start_attempted:
                        chat_agent_a._auto_start_attempted = True
                        await chat_agent_a.maybe_start_chat_if_discovered_first(turns=AUTO_CHAT_TURNS)
                    return
                await asyncio.sleep(max(0.1, AUTO_DISCOVER_INTERVAL_SEC))

        asyncio.create_task(_auto_discover_loop())

    yield


app = FastAPI(title="ChatAgentA", description="Chat Agent A - 端口 8000", lifespan=lifespan)

chat_agent_a = ChatAgentA(auth)
app.include_router(chat_agent_a.router())

@app.get("/")
async def root():
    return {
        "name": "Chat Agent A",
        "did": AGENT_A_DID,
        "endpoint": "/a",
        "status": "running",
        "messages_received": chat_agent_a.message_count,
        "messages_sent": chat_agent_a.sent_count,
        "peer_connected": chat_agent_a.peer is not None,
        "peer_name": chat_agent_a.peer_name,
        "peer_ad_url": PEER_AD_URL,
    }


@app.post("/p2p/discover")
async def p2p_discover(payload: dict = Body(default={})):  
    peer_ad_url = (payload or {}).get("peer_ad_url")
    ok = await chat_agent_a.ensure_peer_connection(peer_ad_url=peer_ad_url)
    if ok:
        await chat_agent_a.maybe_start_chat_if_discovered_first(turns=AUTO_CHAT_TURNS)
    return {
        "ok": ok,
        "peer_ad_url": (peer_ad_url or "").strip() or PEER_AD_URL,
        "peer_name": getattr(chat_agent_a.peer, "name", None),
    }


@app.post("/p2p/send")
async def p2p_send(payload: dict = Body(default={})):  
    message = (payload or {}).get("message", "")
    remaining_turns = (payload or {}).get("remaining_turns", 4)
    peer_ad_url = (payload or {}).get("peer_ad_url")
    if not str(message).strip():
        return {"ok": False, "error": "missing_message"}
    resp = await chat_agent_a.send_message(
        message=str(message),
        remaining_turns=int(remaining_turns),
        peer_ad_url=peer_ad_url,
    )
    return {"ok": True, "response": resp}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "agent": "ChatA",
        "timestamp": time.time(),
        "uptime": time.time() - getattr(app.state, 'start_time', time.time())
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False)