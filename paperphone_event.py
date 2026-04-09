"""
PaperPhone Event Module

Defines the PaperPhoneEvent class that bridges PaperPhone messages
to the AstrBot event system.
"""

from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.platform import AstrBotMessage, PlatformMetadata, MessageType
from astrbot.api.message_components import Plain
from astrbot import logger

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .paperphone_adapter import PaperPhoneAdapter


class PaperPhoneEvent(AstrMessageEvent):
    """
    Represents a message event received from PaperPhone.

    Wraps AstrBotMessage into the AstrBot event system and provides
    the send() method to reply back through the PaperPhone adapter.
    """

    adapter: "PaperPhoneAdapter"

    def __init__(
        self,
        message_obj: AstrBotMessage,
        platform_meta: PlatformMetadata,
        adapter_instance: "PaperPhoneAdapter",
    ):
        # ── Extract message_str ──────────────────────────────────────────
        message_str_for_event = ""
        if hasattr(message_obj, "message_str") and message_obj.message_str is not None:
            message_str_for_event = message_obj.message_str
        elif (
            message_obj.message
            and isinstance(message_obj.message, list)
            and len(message_obj.message) > 0
        ):
            first_segment = message_obj.message[0]
            if isinstance(first_segment, Plain):
                message_str_for_event = first_segment.text
            else:
                message_str_for_event = f"[{type(first_segment).__name__} ...]"
        else:
            logger.debug(
                "PaperPhoneEvent: message_obj 中无法提取有效的 message_str"
            )

        # ── Extract session_id ───────────────────────────────────────────
        session_id_for_event = "unknown_session"
        if hasattr(message_obj, "session_id") and message_obj.session_id is not None:
            session_id_for_event = message_obj.session_id
        elif hasattr(message_obj, "type"):
            if (
                message_obj.type == MessageType.GROUP_MESSAGE
                and hasattr(message_obj, "group_id")
                and message_obj.group_id
            ):
                session_id_for_event = message_obj.group_id
            elif (
                message_obj.type == MessageType.FRIEND_MESSAGE
                and hasattr(message_obj, "user_id")
                and message_obj.user_id
            ):
                session_id_for_event = message_obj.user_id
            elif hasattr(message_obj, "user_id") and message_obj.user_id:
                session_id_for_event = message_obj.user_id
            else:
                logger.warning(
                    "PaperPhoneEvent: message_obj 中无法提取有效的 session_id"
                )
        else:
            logger.warning(
                "PaperPhoneEvent: message_obj 中缺少 type 属性"
            )

        # ── Call parent __init__ ─────────────────────────────────────────
        super().__init__(
            message_str=message_str_for_event,
            message_obj=message_obj,
            platform_meta=platform_meta,
            session_id=session_id_for_event,
        )

        self.adapter = adapter_instance

    async def send(self, message_chain: MessageChain):
        """Send a reply back through the PaperPhone adapter."""
        logger.info(
            f"PaperPhoneEvent.send() 被调用，session: {self.session}"
        )

        if hasattr(self, "adapter") and self.adapter:
            await self.adapter.send_by_session(
                session=self.session,
                message_chain=message_chain,
            )
            logger.info("PaperPhoneEvent.send(): 消息已发送。")
        else:
            logger.error(
                "PaperPhoneEvent.send(): 无法发送消息，adapter 实例未设置！"
            )

        await super().send(message_chain)
