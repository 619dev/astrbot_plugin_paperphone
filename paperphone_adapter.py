"""
PaperPhone Platform Adapter for AstrBot

Connects AstrBot to a PaperPhone server as a regular user account.
Handles login/registration, WebSocket messaging, and E2E encryption/decryption.
"""

import asyncio
import base64
import json
import os
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from astrbot.api.platform import (
    Platform,
    AstrBotMessage,
    MessageMember,
    PlatformMetadata,
    MessageType,
    register_platform_adapter,
)
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Plain, Image
from astrbot.core.platform.astr_message_event import MessageSesion
from astrbot import logger

from .paperphone_crypto import PaperPhoneCrypto, b64encode
from .paperphone_event import PaperPhoneEvent

DEFAULT_CONFIG_TMPL = {
    "server_url": "http://localhost:3000",
    "username": "",
    "password": "",
    "auto_register": True,
    "bot_nickname": "AstrBot",
}


@register_platform_adapter(
    "paperphone", "PaperPhone 适配器", default_config_tmpl=DEFAULT_CONFIG_TMPL
)
class PaperPhoneAdapter(Platform):
    """
    AstrBot platform adapter for PaperPhone.

    Connects as a regular PaperPhone user via WebSocket,
    with full E2E encryption support implemented in Python.
    """

    def __init__(
        self,
        platform_config: dict,
        platform_settings: dict,
        event_queue: asyncio.Queue,
    ) -> None:
        super().__init__(platform_config, event_queue)
        self.config = platform_config
        self.settings = platform_settings

        self.server_url = self.config.get("server_url", "").rstrip("/")
        self.username = self.config.get("username", "")
        self.password = self.config.get("password", "")
        self.auto_register = self.config.get("auto_register", True)
        self.bot_nickname = self.config.get("bot_nickname", "AstrBot")

        # Platform instance ID
        platform_instance_id = self.config.get("id")
        if not platform_instance_id:
            platform_instance_id = f"paperphone_{self.username}"
            logger.warning(
                f"PaperPhoneAdapter: 未找到平台实例ID，使用: {platform_instance_id}"
            )

        self.metadata = PlatformMetadata(
            name="paperphone",
            description="PaperPhone 平台适配器",
            id=platform_instance_id,
        )

        # Runtime state
        self._jwt_token: Optional[str] = None
        self._user_id: Optional[str] = None
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._stop_event = asyncio.Event()
        self._crypto = PaperPhoneCrypto()
        self._ik_pub_cache: Dict[str, str] = {}  # user_id -> ik_pub (base64)
        self._dm_notified_users: set = set()  # users already notified about DM limitation

        if not self.server_url:
            logger.error(
                f"PaperPhoneAdapter '{self.metadata.id}': server_url 不能为空!"
            )
        if not self.username or not self.password:
            logger.error(
                f"PaperPhoneAdapter '{self.metadata.id}': username 和 password 不能为空!"
            )

    def meta(self) -> PlatformMetadata:
        return self.metadata

    # ── HTTP Session ─────────────────────────────────────────────────────

    async def _get_http_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession()
        return self._http_session

    async def _api_request(
        self,
        method: str,
        path: str,
        json_data: Optional[dict] = None,
        auth: bool = True,
    ) -> dict:
        """Make an HTTP request to the PaperPhone API."""
        url = f"{self.server_url}{path}"
        headers = {"Content-Type": "application/json"}
        if auth and self._jwt_token:
            headers["Authorization"] = f"Bearer {self._jwt_token}"

        http = await self._get_http_session()
        timeout = aiohttp.ClientTimeout(total=15)

        async with http.request(
            method, url, json=json_data, headers=headers, timeout=timeout
        ) as resp:
            response_text = await resp.text()
            if resp.status >= 400:
                logger.error(
                    f"PaperPhoneAdapter API 请求失败: {method} {path} -> "
                    f"{resp.status}: {response_text[:300]}"
                )
                raise RuntimeError(
                    f"API error {resp.status}: {response_text[:200]}"
                )
            try:
                return json.loads(response_text)
            except json.JSONDecodeError:
                return {"_raw": response_text}

    # ── Auth: Register & Login ───────────────────────────────────────────

    async def _register(self) -> dict:
        """
        Register a new PaperPhone account for the bot.

        Generates all required cryptographic keys (IK, SPK, OPK, KEM)
        and uploads them during registration.
        """
        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 注册新账户 '{self.username}'..."
        )

        # Generate identity keypair
        ik_pub_b64, _ik_priv_b64 = self._crypto.generate_identity_keypair()

        # Generate signed pre-key
        spk_pub_b64, _spk_priv_b64, spk_sig_b64 = (
            self._crypto.generate_signed_prekey()
        )

        # Generate one-time pre-keys
        prekeys = self._crypto.generate_one_time_prekeys(10)

        # Generate KEM public key
        kem_pub_b64 = self._crypto.generate_kem_keypair()

        result = await self._api_request(
            "POST",
            "/api/auth/register",
            json_data={
                "username": self.username,
                "password": self.password,
                "nickname": self.bot_nickname,
                "ik_pub": ik_pub_b64,
                "spk_pub": spk_pub_b64,
                "spk_sig": spk_sig_b64,
                "kem_pub": kem_pub_b64,
                "prekeys": prekeys,
            },
            auth=False,
        )

        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 注册成功，用户ID: {result.get('user', {}).get('id')}"
        )
        return result

    async def _login(self) -> dict:
        """
        Login to PaperPhone with username/password.
        Returns the JWT token and user info.
        """
        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 登录 '{self.username}'..."
        )

        result = await self._api_request(
            "POST",
            "/api/auth/login",
            json_data={
                "username": self.username,
                "password": self.password,
            },
            auth=False,
        )

        if result.get("requires_2fa"):
            raise RuntimeError(
                "Bot 账户启用了 2FA，请关闭 2FA 后重试。"
            )

        self._jwt_token = result.get("token")
        user_info = result.get("user", {})
        self._user_id = user_info.get("id")

        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 登录成功，"
            f"用户ID: {self._user_id}"
        )
        return result

    async def _upload_keys(self):
        """
        Upload fresh cryptographic keys after login.

        PaperPhone requires key upload for new device sessions.
        The bot generates new keys each time it starts.
        """
        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 上传加密密钥..."
        )

        # Generate fresh keys
        ik_pub_b64, _ik_priv_b64 = self._crypto.generate_identity_keypair()
        spk_pub_b64, _spk_priv_b64, spk_sig_b64 = (
            self._crypto.generate_signed_prekey()
        )
        prekeys = self._crypto.generate_one_time_prekeys(10)
        kem_pub_b64 = self._crypto.generate_kem_keypair()

        await self._api_request(
            "PUT",
            "/api/users/keys",
            json_data={
                "ik_pub": ik_pub_b64,
                "spk_pub": spk_pub_b64,
                "spk_sig": spk_sig_b64,
                "kem_pub": kem_pub_b64,
                "prekeys": prekeys,
            },
        )

        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 密钥上传完成。"
        )

    # ── WebSocket Connection ─────────────────────────────────────────────

    async def _ws_connect(self):
        """
        Establish WebSocket connection to PaperPhone and authenticate.
        """
        # Determine WebSocket URL
        ws_url = self.server_url.replace("http://", "ws://").replace(
            "https://", "wss://"
        )
        ws_url = f"{ws_url}/ws"

        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 连接 WebSocket: {ws_url}"
        )

        http = await self._get_http_session()
        self._ws = await http.ws_connect(
            ws_url,
            heartbeat=30,
            timeout=aiohttp.ClientTimeout(total=15),
        )

        # Send auth message
        await self._ws.send_json(
            {"type": "auth", "token": self._jwt_token}
        )

        # Wait for auth_ok
        auth_response = await self._ws.receive_json(timeout=10)
        if auth_response.get("type") == "auth_ok":
            logger.info(
                f"PaperPhoneAdapter '{self.metadata.id}': WebSocket 认证成功。"
            )
        elif auth_response.get("type") == "error":
            raise RuntimeError(
                f"WebSocket 认证失败: {auth_response.get('msg')}"
            )
        else:
            logger.warning(
                f"PaperPhoneAdapter '{self.metadata.id}': "
                f"收到意外的认证响应: {auth_response}"
            )

    async def _ws_loop(self):
        """
        Main WebSocket message loop.

        Listens for incoming messages and dispatches them to the AstrBot
        event queue after decryption and conversion.
        """
        while not self._stop_event.is_set():
            try:
                if self._ws is None or self._ws.closed:
                    logger.warning(
                        f"PaperPhoneAdapter '{self.metadata.id}': "
                        "WebSocket 断开，尝试重连..."
                    )
                    await asyncio.sleep(3)
                    await self._ws_connect()
                    continue

                msg = await asyncio.wait_for(
                    self._ws.receive(), timeout=60
                )

                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    await self._handle_ws_message(data)
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    logger.warning(
                        f"PaperPhoneAdapter '{self.metadata.id}': "
                        "WebSocket 已关闭。"
                    )
                    self._ws = None
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(
                        f"PaperPhoneAdapter '{self.metadata.id}': "
                        f"WebSocket 错误: {self._ws.exception()}"
                    )
                    self._ws = None

            except asyncio.TimeoutError:
                # Heartbeat timeout — connection is still alive, just no messages
                continue
            except asyncio.CancelledError:
                logger.info(
                    f"PaperPhoneAdapter '{self.metadata.id}': "
                    "WebSocket 循环被取消。"
                )
                break
            except Exception as e:
                logger.error(
                    f"PaperPhoneAdapter '{self.metadata.id}': "
                    f"WebSocket 循环异常: {e}",
                    exc_info=True,
                )
                self._ws = None
                await asyncio.sleep(5)

    async def _handle_ws_message(self, data: dict):
        """Handle a single WebSocket message from PaperPhone."""
        msg_type = data.get("type")

        if msg_type == "message":
            from_id = data.get("from")
            group_id = data.get("group_id")

            # ── Private messages: not supported (E2E encryption) ──
            if not group_id and from_id and from_id != self._user_id:
                logger.info(
                    f"PaperPhoneAdapter: 收到私聊消息，跳过 "
                    f"(from={str(from_id)[:8]}...)"
                )
                # Send a one-time notice to the sender
                if from_id not in self._dm_notified_users:
                    self._dm_notified_users.add(from_id)
                    try:
                        await self._send_private_message(
                            from_id,
                            "⚠️ Bot 无法处理端对端加密消息。\n"
                            "请在群聊中与我交互，Bot 只能运行在不加密的群聊会话中。",
                        )
                    except Exception as e:
                        logger.warning(
                            f"PaperPhoneAdapter: 发送私聊提示失败: {e}"
                        )
                return

            # ── Group messages: process normally ──
            abm = await self.convert_message(data)
            if abm:
                event = PaperPhoneEvent(
                    message_obj=abm,
                    platform_meta=self.meta(),
                    adapter_instance=self,
                )
                self.commit_event(event)
                logger.debug(
                    f"PaperPhoneAdapter '{self.metadata.id}': "
                    f"已提交消息事件到队列。"
                )
        elif msg_type == "typing":
            pass  # Ignore typing indicators
        elif msg_type == "ack":
            logger.debug(
                f"PaperPhoneAdapter: 收到消息确认 msg_id={data.get('msg_id')}"
            )
        elif msg_type == "auth_ok":
            pass  # Already handled in _ws_connect
        elif msg_type == "session_revoked":
            logger.error(
                f"PaperPhoneAdapter '{self.metadata.id}': "
                "会话已被撤销，需要重新登录。"
            )
            self._jwt_token = None
        elif msg_type == "error":
            logger.error(
                f"PaperPhoneAdapter: 服务器错误: {data.get('msg')}"
            )
        elif msg_type in (
            "friend_request",
            "friend_accepted",
            "online",
            "offline",
            "group_member_added",
        ):
            logger.info(
                f"PaperPhoneAdapter: 系统事件 [{msg_type}]: "
                f"{json.dumps(data, ensure_ascii=False)[:200]}"
            )
        else:
            logger.debug(
                f"PaperPhoneAdapter: 未处理的消息类型 [{msg_type}]"
            )

    # ── Message Conversion ───────────────────────────────────────────────

    async def convert_message(self, data: dict) -> Optional[AstrBotMessage]:
        """
        Convert a PaperPhone WebSocket message to an AstrBotMessage.

        Only handles group messages (unencrypted).
        Private (E2E encrypted) messages are rejected upstream.
        """
        from_id = data.get("from")
        msg_id = data.get("id", "")
        msg_type = data.get("msg_type", "text")
        group_id = data.get("group_id")

        # Skip messages from self
        if from_id == self._user_id:
            return None

        # Only process group messages
        if not group_id:
            return None

        if not from_id:
            logger.warning(
                f"PaperPhoneAdapter '{self.metadata.id}': "
                "消息缺少 from 字段。"
            )
            return None

        abm = AstrBotMessage()
        abm.message = []
        abm.message_id = msg_id
        abm.user_id = from_id
        abm.self_id = self._user_id or ""
        abm.raw_message = data

        # Get sender info
        from_nickname = data.get("from_nickname", "")
        if not from_nickname:
            from_nickname = await self._fetch_user_nickname(from_id)
        abm.nickname = from_nickname
        abm.sender = MessageMember(user_id=from_id, nickname=from_nickname)

        # Extract message content (group messages are unencrypted)
        ciphertext = data.get("ciphertext", "")
        plaintext = ""

        if msg_type in ("text", "bot_text"):
            plaintext = ciphertext or ""
            abm.message_str = plaintext
            abm.message.append(Plain(text=plaintext))

        elif msg_type == "image":
            plaintext = ciphertext or ""
            abm.message_str = "[图片]"
            if plaintext.startswith("http"):
                abm.message.append(Image(url=plaintext))
            else:
                abm.message.append(Plain(text=f"[图片: {plaintext[:100]}]"))

        else:
            plaintext = ciphertext or f"[{msg_type}]"
            abm.message_str = plaintext
            abm.message.append(Plain(text=plaintext))

        # Always group message
        abm.type = MessageType.GROUP_MESSAGE
        abm.group_id = str(group_id)
        abm.session_id = str(group_id)

        if not abm.message:
            logger.debug(
                f"PaperPhoneAdapter: 消息内容为空，跳过 msg_id={msg_id}"
            )
            return None

        return abm

    # ── Message Sending ──────────────────────────────────────────────────

    async def _fetch_recipient_ik(self, user_id: str) -> str:
        """
        Fetch recipient's identity public key for encryption.

        GET /api/users/:id/ik -> { ik_pub: base64 }
        """
        if user_id in self._ik_pub_cache:
            return self._ik_pub_cache[user_id]

        result = await self._api_request("GET", f"/api/users/{user_id}/ik")
        ik_pub = result.get("ik_pub", "")

        if ik_pub:
            self._ik_pub_cache[user_id] = ik_pub

        return ik_pub

    async def _fetch_user_nickname(self, user_id: str) -> str:
        """Fetch user's nickname via API."""
        try:
            result = await self._api_request("GET", f"/api/users/{user_id}/ik")
            # The /ik endpoint only returns ik_pub; we'd need another endpoint.
            # For now, use the user_id as a fallback.
            return f"User_{user_id[:8]}"
        except Exception:
            return f"User_{user_id[:8]}"

    async def _upload_image(self, image: Image) -> Optional[str]:
        """
        Upload an image to PaperPhone's /api/upload endpoint.

        Handles Image components with:
        - url: downloads from the URL first, then uploads
        - file (local path): reads the file and uploads
        - file (base64://...): decodes and uploads

        Returns the uploaded image URL on success, or None on failure.
        """
        file_bytes: Optional[bytes] = None
        filename = "image.png"
        content_type = "image/png"

        try:
            # ── Case 1: Image has a URL ──
            if hasattr(image, "url") and image.url:
                url = image.url
                logger.debug(
                    f"PaperPhoneAdapter: 下载图片: {url[:100]}..."
                )
                http = await self._get_http_session()
                timeout = aiohttp.ClientTimeout(total=30)
                async with http.get(url, timeout=timeout) as resp:
                    if resp.status >= 400:
                        logger.error(
                            f"PaperPhoneAdapter: 下载图片失败: "
                            f"HTTP {resp.status}"
                        )
                        return None
                    file_bytes = await resp.read()
                    # Determine filename and content type from URL/response
                    ct = resp.headers.get("Content-Type", "image/png")
                    content_type = ct.split(";")[0].strip()
                    # Extract extension from URL
                    url_path = url.split("?")[0].split("#")[0]
                    ext = os.path.splitext(url_path)[1] or ".png"
                    filename = f"image{ext}"

            # ── Case 2: Image has a file path (base64 encoded) ──
            elif hasattr(image, "file") and image.file:
                file_val = image.file
                if file_val.startswith("base64://"):
                    b64_data = file_val[len("base64://"):]
                    file_bytes = base64.b64decode(b64_data)
                    filename = "image.png"
                    content_type = "image/png"
                elif file_val.startswith(("http://", "https://")):
                    # file field can also be a URL in some cases
                    logger.debug(
                        f"PaperPhoneAdapter: 下载图片(file字段): "
                        f"{file_val[:100]}..."
                    )
                    http = await self._get_http_session()
                    timeout = aiohttp.ClientTimeout(total=30)
                    async with http.get(file_val, timeout=timeout) as resp:
                        if resp.status >= 400:
                            logger.error(
                                f"PaperPhoneAdapter: 下载图片失败: "
                                f"HTTP {resp.status}"
                            )
                            return None
                        file_bytes = await resp.read()
                        ct = resp.headers.get("Content-Type", "image/png")
                        content_type = ct.split(";")[0].strip()
                        ext = os.path.splitext(
                            file_val.split("?")[0]
                        )[1] or ".png"
                        filename = f"image{ext}"
                elif os.path.isfile(file_val):
                    # Local file path
                    with open(file_val, "rb") as f:
                        file_bytes = f.read()
                    ext = os.path.splitext(file_val)[1] or ".png"
                    filename = os.path.basename(file_val)
                    # Guess content type from extension
                    ext_map = {
                        ".png": "image/png",
                        ".jpg": "image/jpeg",
                        ".jpeg": "image/jpeg",
                        ".gif": "image/gif",
                        ".webp": "image/webp",
                        ".bmp": "image/bmp",
                        ".svg": "image/svg+xml",
                    }
                    content_type = ext_map.get(ext.lower(), "image/png")
                else:
                    logger.warning(
                        f"PaperPhoneAdapter: 无法识别的图片 file 值: "
                        f"{file_val[:100]}"
                    )
                    return None
            # ── Case 3: Image has path attribute ──
            elif hasattr(image, "path") and image.path:
                path_val = image.path
                if os.path.isfile(path_val):
                    with open(path_val, "rb") as f:
                        file_bytes = f.read()
                    ext = os.path.splitext(path_val)[1] or ".png"
                    filename = os.path.basename(path_val)
                    ext_map = {
                        ".png": "image/png",
                        ".jpg": "image/jpeg",
                        ".jpeg": "image/jpeg",
                        ".gif": "image/gif",
                        ".webp": "image/webp",
                    }
                    content_type = ext_map.get(ext.lower(), "image/png")
                else:
                    logger.warning(
                        f"PaperPhoneAdapter: 图片路径不存在: {path_val}"
                    )
                    return None
            else:
                logger.warning(
                    "PaperPhoneAdapter: Image 组件无 url/file/path 属性，"
                    "无法上传。"
                )
                return None

            if not file_bytes:
                logger.warning("PaperPhoneAdapter: 图片数据为空。")
                return None

            # ── Upload to PaperPhone server ──
            upload_url = f"{self.server_url}/api/upload"
            headers = {}
            if self._jwt_token:
                headers["Authorization"] = f"Bearer {self._jwt_token}"

            data = aiohttp.FormData()
            data.add_field(
                "file",
                file_bytes,
                filename=filename,
                content_type=content_type,
            )

            http = await self._get_http_session()
            timeout = aiohttp.ClientTimeout(total=60)
            async with http.post(
                upload_url, data=data, headers=headers, timeout=timeout
            ) as resp:
                if resp.status >= 400:
                    resp_text = await resp.text()
                    logger.error(
                        f"PaperPhoneAdapter: 上传图片失败: "
                        f"HTTP {resp.status}: {resp_text[:200]}"
                    )
                    return None
                result = await resp.json()
                uploaded_url = result.get("url", "")
                logger.info(
                    f"PaperPhoneAdapter: 图片上传成功: {uploaded_url}"
                )
                return uploaded_url

        except Exception as e:
            logger.error(
                f"PaperPhoneAdapter: 上传图片异常: {e}", exc_info=True
            )
            return None

    async def send_by_session(
        self, session: MessageSesion, message_chain: MessageChain
    ):
        """
        Send a message back to PaperPhone through the WebSocket connection.

        Only supports group messages. Private messages are not supported
        because the bot cannot handle E2E encryption reliably.

        Handles mixed text+image messages by splitting them into separate
        WebSocket sends: text parts as msg_type="text", images as
        msg_type="image" (after uploading to the server).
        """
        if self._ws is None or self._ws.closed:
            logger.error(
                f"PaperPhoneAdapter '{self.metadata.id}': "
                "WebSocket 未连接，无法发送消息。"
            )
            return

        # Block private message replies from AstrBot
        if session.message_type == MessageType.FRIEND_MESSAGE:
            logger.warning(
                f"PaperPhoneAdapter: Bot 不支持私聊回复 "
                f"(session={session.session_id[:8]}...)，已跳过。"
            )
            return

        # Extract components to send
        components_to_send = []
        if hasattr(message_chain, "chain") and isinstance(
            message_chain.chain, list
        ):
            components_to_send = message_chain.chain
        elif isinstance(message_chain, list):
            components_to_send = message_chain
        elif isinstance(message_chain, str):
            components_to_send = [Plain(text=message_chain)]
        else:
            logger.error(
                f"PaperPhoneAdapter: message_chain 类型无法处理: "
                f"{type(message_chain)}"
            )
            return

        # Build a list of (msg_type, content) segments to send.
        # Text parts are batched together; each Image becomes a separate send.
        segments: List[Tuple[str, str]] = []
        text_buffer: List[str] = []

        for component in components_to_send:
            if isinstance(component, Plain):
                text_buffer.append(component.text)
            elif isinstance(component, Image):
                # Flush accumulated text before the image
                if text_buffer:
                    segments.append(("text", "\n".join(text_buffer)))
                    text_buffer = []
                # Upload the image and get its URL
                uploaded_url = await self._upload_image(component)
                if uploaded_url:
                    segments.append(("image", uploaded_url))
                else:
                    logger.warning(
                        "PaperPhoneAdapter: 图片上传失败，跳过该图片。"
                    )
            else:
                text_buffer.append(str(component))

        # Flush remaining text
        if text_buffer:
            segments.append(("text", "\n".join(text_buffer)))

        if not segments:
            logger.debug("PaperPhoneAdapter: 空消息，跳过发送。")
            return

        try:
            if session.message_type == MessageType.GROUP_MESSAGE:
                for msg_type, content in segments:
                    if not content.strip():
                        continue
                    await self._send_group_message(
                        session.session_id, content, msg_type=msg_type
                    )
            else:
                logger.warning(
                    f"PaperPhoneAdapter: 不支持的消息类型: "
                    f"{session.message_type}"
                )
        except Exception as e:
            logger.error(
                f"PaperPhoneAdapter: 发送消息失败: {e}", exc_info=True
            )

    async def _send_private_message(self, to_user_id: str, plaintext: str):
        """Send an encrypted private message via WebSocket."""
        # Fetch recipient's public key
        recipient_ik_pub = await self._fetch_recipient_ik(to_user_id)
        if not recipient_ik_pub:
            logger.error(
                f"PaperPhoneAdapter: 无法获取用户 {to_user_id} 的公钥，"
                "发送失败。"
            )
            return

        # Encrypt for both recipient and self
        encrypted = self._crypto.encrypt_dual(
            recipient_ik_pub,
            self._crypto.ik_public_b64 or "",
            plaintext,
        )

        # Send via WebSocket
        ws_message = {
            "type": "message",
            "to": to_user_id,
            "msg_type": "text",
            "ciphertext": encrypted["ciphertext"],
            "header": json.dumps(encrypted["header"]),
            "self_ciphertext": encrypted["self_ciphertext"],
            "self_header": json.dumps(encrypted["self_header"]),
        }

        await self._ws.send_json(ws_message)
        logger.info(
            f"PaperPhoneAdapter: 已发送私聊消息到 {to_user_id[:8]}..."
        )

    async def _send_group_message(
        self, group_id: str, content: str, msg_type: str = "text"
    ):
        """
        Send a message to a group via WebSocket.

        Args:
            group_id: Target group ID.
            content: Message content (plain text or image URL).
            msg_type: "text" for text messages, "image" for image messages.
        """
        ws_message = {
            "type": "message",
            "group_id": group_id,
            "msg_type": msg_type,
            "ciphertext": content,
            "header": None,
        }

        await self._ws.send_json(ws_message)
        logger.info(
            f"PaperPhoneAdapter: 已发送群聊消息到 group={group_id[:8]}... "
            f"(类型={msg_type})"
        )

    # ── Main Run & Shutdown ──────────────────────────────────────────────

    async def run(self):
        """
        Main adapter lifecycle:
        1. Login or auto-register
        2. Upload fresh crypto keys
        3. Connect WebSocket
        4. Enter message loop
        """
        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 启动中..."
        )

        try:
            # Step 1: Login (or register first if needed)
            try:
                await self._login()
            except RuntimeError as e:
                if "401" in str(e) and self.auto_register:
                    logger.info(
                        f"PaperPhoneAdapter '{self.metadata.id}': "
                        "登录失败，尝试自动注册..."
                    )
                    reg_result = await self._register()
                    self._jwt_token = reg_result.get("token")
                    user_info = reg_result.get("user", {})
                    self._user_id = user_info.get("id")
                else:
                    raise

            # Step 2: Upload fresh cryptographic keys
            await self._upload_keys()

            # Step 3: Connect WebSocket
            await self._ws_connect()

            # Step 4: Message loop
            logger.info(
                f"PaperPhoneAdapter '{self.metadata.id}': "
                f"已就绪，Bot 用户: {self.username} ({self._user_id})"
            )
            await self._ws_loop()

        except asyncio.CancelledError:
            logger.info(
                f"PaperPhoneAdapter '{self.metadata.id}': "
                "运行任务被取消。"
            )
        except Exception as e:
            logger.error(
                f"PaperPhoneAdapter '{self.metadata.id}': "
                f"运行异常: {e}",
                exc_info=True,
            )
        finally:
            await self._cleanup()
            logger.info(
                f"PaperPhoneAdapter '{self.metadata.id}': 已停止。"
            )

    async def _cleanup(self):
        """Clean up WebSocket and HTTP resources."""
        if self._ws and not self._ws.closed:
            await self._ws.close()
            self._ws = None
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
            self._http_session = None

    async def shutdown(self):
        """Graceful shutdown."""
        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': 执行 shutdown..."
        )
        self._stop_event.set()
        await asyncio.sleep(0.1)
        await self._cleanup()
        logger.info(
            f"PaperPhoneAdapter '{self.metadata.id}': Shutdown 完成。"
        )
