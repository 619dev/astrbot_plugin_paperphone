# AstrBot PaperPhone 适配器插件

使 [AstrBot](https://github.com/AstrBotDevs/AstrBot) 能以普通用户身份接入 [PaperPhone](https://github.com/619dev/PaperPhone) 即时通讯平台。

> **⚠️ 重要限制：本插件仅支持群聊会话。**
> PaperPhone 的私聊消息采用端对端加密（E2EE），Bot 无法可靠解密私聊消息内容。当用户发送私聊消息时，Bot 会自动回复提示，引导用户在群聊中交互。

## ✨ 功能

- 👥 **群聊消息收发** — 接收和回复群组消息
- 🔄 **自动重连** — WebSocket 断线自动重连
- 📝 **自动注册** — 可选自动注册 Bot 账户
- 🚫 **私聊自动提示** — 收到私聊消息时自动告知用户前往群聊交互

## ⚠️ 关于私聊限制

PaperPhone 的私聊消息采用逐消息的端对端加密协议（Curve25519 ECDH + XSalsa20-Poly1305）。Bot 每次启动时会重新生成加密密钥，而发送方可能使用了 Bot 旧的公钥进行加密，导致 Bot 无法解密已有的私聊消息。因此：

- ❌ Bot **不处理**私聊消息
- ✅ Bot **仅处理**群聊消息（群聊消息不加密）
- 💬 收到私聊时，Bot 会发送一次性提示：*"Bot 无法处理端对端加密消息，请在群聊中与我交互"*

## 📦 安装

### 方式一：AstrBot WebUI 安装

在 AstrBot 管理面板的插件市场中搜索 `paperphone`，一键安装。

### 方式二：手动安装

```bash
cd AstrBot/data/plugins
git clone https://github.com/619dev/astrbot_plugin_paperphone
```

## ⚙️ 配置

在 AstrBot WebUI 中添加 PaperPhone 平台适配器，填写以下配置：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `server_url` | PaperPhone 服务器地址 | `http://localhost:3000` |
| `username` | Bot 账户用户名 | — |
| `password` | Bot 账户密码 | — |
| `auto_register` | 账户不存在时自动注册 | `true` |
| `bot_nickname` | Bot 显示昵称 | `AstrBot` |

### 快速开始

1. **部署 PaperPhone 服务器**（参考 [PaperPhone 文档](https://github.com/619dev/PaperPhone)）

2. **注册 Bot 账户**（二选一）：
   - 在 PaperPhone 客户端手动注册一个账户
   - 或设置 `auto_register: true`，插件会自动注册

3. **在 AstrBot 中配置**：
   ```yaml
   server_url: "https://your-paperphone-server.com"
   username: "my_bot"
   password: "secure_password"
   auto_register: true
   bot_nickname: "我的助手"
   ```

4. **启动 AstrBot**，插件会自动连接到 PaperPhone

5. **在 PaperPhone 客户端中**：
   - 将 Bot 添加到群聊中
   - 在群聊中 @Bot 或发消息即可开始对话

## 🏗️ 技术架构

```
PaperPhone 用户 ←→ PaperPhone Server ←→ [WebSocket] ←→ AstrBot Plugin ←→ AstrBot Core
                                              ↑
                                     仅处理群聊消息（明文）
```

### 依赖

- `aiohttp` — 异步 HTTP 和 WebSocket 客户端
- `PyNaCl` — libsodium 加密库的 Python 绑定（用于登录密钥生成和私聊提示发送）

## 📄 许可

AGPL-3.0
