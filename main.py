from astrbot.api.star import Context, Star, register


@register(
    name="astrbot_plugin_paperphone",
    author="619dev",
    desc="PaperPhone 平台适配器插件，使 AstrBot 能以普通用户身份接入 PaperPhone 即时通讯。",
    version="1.0.3",
)
class PaperPhonePluginStar(Star):
    def __init__(self, context: Context):
        super().__init__(context)

        # Import the adapter to trigger @register_platform_adapter
        from .paperphone_adapter import PaperPhoneAdapter  # noqa: F401

        if hasattr(self, "logger") and self.logger is not None:
            self.logger.info(
                "PaperPhonePluginStar 初始化成功，PaperPhoneAdapter 已注册。"
            )
        else:
            print(
                "[INFO] PaperPhonePluginStar initialized. "
                "PaperPhoneAdapter registered."
            )
