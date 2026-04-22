# EasyNet

轻量级 UDP 内网穿透工具。将内网服务的 TCP 端口安全映射到公网服务器的指定端口，无需公网 IP 即可实现远程访问。

## 特性

- **零外部依赖**：C99 编写，嵌入式 Monocypher（加密）与 tomlc99（配置解析），单仓库即可编译
- **跨平台**：支持 Windows（MSYS/MinGW）与 Linux（x86_64 / aarch64）
- **默认加密**：全流量 XChaCha20-Poly1305 AEAD 加密，基于预共享密钥
- **可靠隧道**：会话级轻量 ARQ（128 slot 发送/接收窗口、累积 ACK、超时重传），公网丢包场景下仍可维持稳定连接
- **带宽优化**：快速重传（3 dup ACK）、自适应 RTO（EWMA 动态重传超时）、ACK 捎带 + 延迟 ACK，公网 RDP 实测带宽利用率 75%+
- **多路复用**：单条 UDP 隧道同时承载多条 TCP 连接，互不影响
- **流控背压**：发送窗口满时自动暂停 TCP 读取，利用 TCP 自身流控避免拥塞

## 快速开始

### 1. 编译

需要 [Task](https://taskfile.dev/)（推荐）或直接 `gcc`。

```bash
# 使用 Task
task build

# 或直接编译（Linux）
gcc src/*.c -std=c99 -Wall -Wextra -O2 -pthread -Isrc -o easynet

# 或直接编译（Windows MinGW）
gcc src/*.c -std=c99 -Wall -Wextra -O2 -pthread -Isrc -D_WIN32_WINNT=0x0600 -o easynet.exe -lws2_32 -lbcrypt
```

### 2. 服务端配置 `server.toml`

```toml
mode = "server"
bind_addr = "0.0.0.0"
bind_port = 19000
password = "YourStrongPassword"
```

在公网服务器上运行：

```bash
./easynet -c server.toml
```

### 3. 客户端配置 `client.toml`

```toml
mode = "client"
server_addr = "1.2.3.4"       # 公网服务器 IP
server_port = 19000
password = "YourStrongPassword"

[[tunnels]]
local_addr = "127.0.0.1"
local_port = 3389              # 内网 RDP 服务端口
remote_port = 21000            # 公网映射端口
protocol = "tcp"
```

在内网机器上运行：

```bash
./easynet -c client.toml
```

### 4. 连接

外部用户通过 `mstsc` 或远程桌面客户端连接 `server_addr:21000`，即可访问内网的 `127.0.0.1:3389`。

可配置多条隧道，例如同时穿透 SSH、HTTP、数据库：

```toml
[[tunnels]]
local_addr = "127.0.0.1"
local_port = 22
remote_port = 22000
protocol = "tcp"

[[tunnels]]
local_addr = "127.0.0.1"
local_port = 8080
remote_port = 28080
protocol = "tcp"
```

## 项目结构

```
EasyNet/
├── src/
│   ├── main.c          # 程序入口
│   ├── client.c/h      # 客户端主循环 + ARQ 逻辑
│   ├── server.c/h      # 服务端主循环 + ARQ 逻辑
│   ├── net_common.c/h  # 跨平台 Socket / poll 封装
│   ├── crypto.c/h      # BLAKE2b 密钥派生 + XChaCha20-Poly1305 加密
│   ├── protocol.c/h    # 协议编解码（REGISTER / HEARTBEAT / SESSION_DATA / ACK）
│   ├── session.c/h     # Session 池管理 + ARQ 窗口状态
│   ├── worker.c/h      # 工作线程（加密 / 解密 / 发送）
│   ├── threading.c/h   # 跨平台线程、Mutex、Cond、任务队列
│   ├── config.c/h      # TOML 配置解析
│   ├── toml.c/h        # 嵌入式 tomlc99
│   └── monocypher.c/h  # 嵌入式 Monocypher
├── document/
│   ├── 设计方案.md      # 架构设计文档
│   └── 实施方案v1.0.md  # 实现细节文档
├── Taskfile.yml        # 构建脚本
├── server.toml         # 服务端配置示例
├── client.toml         # 客户端配置示例
└── README.md           # 本文件
```

## 架构概要

```
                    +-------------------+        UDP Tunnel (Encrypted)        +-------------------+
  External User --> |   EasyNet Server  |  <=================================>  |   EasyNet Client  |
  (RDP/SSH/HTTP)    |   (公网服务器)     |                                    |   (内网机器)       |
                    +-------------------+                                    +-------------------+
                            |                                                      |
                            | TCP                                                  | TCP
                            v                                                      v
                    +-------------------+                                    +-------------------+
                    |   Listen Ports    |                                    |   Local Services  |
                    |   (remote_port)   |                                    |   (local_port)    |
                    +-------------------+                                    +-------------------+
```

- **主线程**：`poll` 事件循环，处理 UDP/TCP 可读可写、维护 Session 状态、ARQ 定时器
- **工作线程**：4 个 Worker 通过任务队列并行处理加密/解密与 I/O，按 `session_id % 4` 哈希分发保证会话有序
- **ARQ 机制**：
  - 发送窗口 128 slots，UDP socket 缓冲区扩至 1MB，支持 TCP 批量读取
  - **累积 ACK + 快速重传**：3 次重复 ACK 立即触发单包重传，无需等待超时
  - **自适应 RTO**：Jacobson/Karels EWMA（SRTT/RTTVAR），RTO 动态范围 100–2000ms
  - **ACK 捎带**：DATA 包携带反向 ACK，减少约 50% 独立 ACK 包；无数据时 50ms 延迟 ACK fallback
  - 重传时重新生成随机 Nonce 加密

## 构建命令速查

| 目标 | 命令 |
|------|------|
| 编译 | `task build` |
| 静态编译（Windows 发布） | `task build-static` |
| 运行服务端 | `task run-server` |
| 运行客户端 | `task run-client` |
| 清理 | `task clean` |

## 注意事项

1. **密码一致性**：服务端与客户端的 `password` 必须完全相同，用于派生加密密钥与认证令牌
2. **防火墙**：服务端需要开放 `bind_port`（UDP）以及所有 `remote_port`（TCP）的入站连接
3. **安全**：`password` 应使用强随机字符串，目前仅支持单客户端连接单服务端
4. **性能**：Phase 2 带宽优化后，公网 RDP + 动态网页场景实测带宽利用率可达 75% 以上，1080p 远程桌面长时间稳定运行

## 许可证

本项目采用 MIT 许可证。加密库 Monocypher 与 TOML 解析库 tomlc99 均为独立的开源组件，保留其原有许可证。
