# AstrBot PaperPhone 适配器插件

使 [AstrBot](https://github.com/AstrBotDevs/AstrBot) 能以普通用户身份接入 [PaperPhone](https://github.com/619dev/PaperPhone) 端对端加密即时通讯平台。

## ✨ 功能

- 🔐 **完整 E2E 加密支持** — 在 Python 端实现 PaperPhone 的加密协议（Curve25519 ECDH + XSalsa20-Poly1305），与 PaperPhone 客户端完全互操作
- 💬 **私聊消息收发** — 加密/解密私聊消息
- 👥 **群聊消息收发** — 支持群组消息
- 🔄 **自动重连** — WebSocket 断线自动重连
- 📝 **自动注册** — 可选自动注册 Bot 账户

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
   - 搜索并添加 Bot 为好友
   - 给 Bot 发消息即可开始对话

## 🔒 安全说明

- Bot 使用与普通 PaperPhone 用户完全相同的加密协议
- 每次启动时会生成新的加密密钥并上传到服务器
- 私钥仅存储在 AstrBot 运行时内存中
- 所有私聊消息均经过端对端加密

## 🏗️ 技术架构

```
PaperPhone 用户 ←→ PaperPhone Server ←→ [WebSocket] ←→ AstrBot Plugin ←→ AstrBot Core
                                              ↑
                                     PyNaCl E2E 加密/解密
```

### 加密协议

本插件使用 PyNaCl（libsodium 的 Python 绑定）实现 PaperPhone 的无状态逐消息加密：

1. **密钥交换**：Curve25519 ECDH
2. **KDF**：BLAKE2b（`PaperPhone-E2EE-v2` info 标签）
3. **对称加密**：XSalsa20-Poly1305

### 依赖

- `aiohttp` — 异步 HTTP 和 WebSocket 客户端
- `PyNaCl` — libsodium 加密库的 Python 绑定

## 📄 许可

AGPL-3.0
