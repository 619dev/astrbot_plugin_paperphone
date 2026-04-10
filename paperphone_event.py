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
        # For group messages, use group_id as session_id.
        # session_id was set in convert_message as abm.session_id = group_id.
        # group_id is a property backed by the Group object.
        session_id_for_event = "unknown_session"

        # Primary: use session_id if set on the message object
        if hasattr(message_obj, "session_id") and message_obj.session_id:
            session_id_for_event = str(message_obj.session_id)
        # Fallback: use group_id for group messages
        elif message_obj.group_id:
            session_id_for_event = str(message_obj.group_id)
        # Last fallback: use sender ID
        elif hasattr(message_obj, "sender") and message_obj.sender:
            session_id_for_event = str(message_obj.sender.user_id)
        else:
            logger.warning(
                "PaperPhoneEvent: 无法提取有效的 session_id，使用默认值"
            )

        logger.debug(
            f"PaperPhoneEvent.__init__: "
            f"message_str='{message_str_for_event[:50]}' "
            f"session_id={session_id_for_event[:16]}... "
            f"platform_id={platform_meta.id}"
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
            f"PaperPhoneEvent.send() 被调用，"
            f"session={self.unified_msg_origin}"
        )

        if hasattr(self, "adapter") and self.adapter:
            try:
                await self.adapter.send_by_session(
                    session=self.session,
                    message_chain=message_chain,
                )
                logger.info("PaperPhoneEvent.send(): 消息已发送。")
            except Exception as e:
                logger.error(
                    f"PaperPhoneEvent.send(): 发送消息失败: {e}",
                    exc_info=True,
                )
        else:
            logger.error(
                "PaperPhoneEvent.send(): 无法发送消息，adapter 实例未设置！"
            )

        await super().send(message_chain)
