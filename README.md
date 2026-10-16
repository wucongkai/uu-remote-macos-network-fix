# UU 远程 macOS 网络连接修复

记录一次 UU 远程在特定网络下无法连接服务器的问题，并保存当时实际修复成功的 Python 脚本。

## 解决的是什么问题

同一个网络下，Windows 电脑可以使用 UU 远程，Mac 提示“无法连接至服务器，请检查网络状态或配置”；Mac 改连手机热点后又能正常使用。Mac 在原网络中使用有线或 Wi-Fi 都曾失败。

排查发现，相关域名的常规 UDP DNS 查询超时，而 TCP DNS 查询可以返回地址；即使直接连接已解析的服务器 IP，正常 TLS 握手仍会超时。保留服务器域名、证书验证及握手内容，仅调整初始 TLS 记录的分段后，HTTPS 连接恢复，UU 随后也恢复正常。

因此，本次修复针对的是 **Mac 与当前网络之间的 DNS / TLS 握手兼容问题**。具体是哪台网络设备或哪条策略导致，尚未确认；不能据此断言运营商封禁或 UU 服务故障。完整记录见 [故障分析](docs/diagnosis.md)。

## 修复方式

```text
UU 远程
  │ 应用内 SOCKS5 代理
  ▼
127.0.0.1:17891（本脚本）
  ├─ 通过 TCP 查询 DNS
  ├─ 将初始 TLS 握手记录拆成两条记录
  └─ 直接连接官方服务器，转发后续字节
```

- 只监听本机回环地址，支持 SOCKS5 CONNECT 和 HTTP CONNECT。
- 使用 `223.5.5.5:53` 查询 TCP DNS，失败后尝试 `119.29.29.29:53`，缓存公开 IPv4 地址。
- 将初始 TLS 握手记录的载荷拆成 `1` 字节和剩余部分，两次发送间隔约 `20 ms`；握手消息字节保持一致。
- 不终止或解密 TLS，不安装证书，不关闭客户端的证书验证。
- 不修改系统 DNS、系统代理或防火墙。UU 的代理需要在应用内手动设置。

## 运行

需要 Python 3，仅使用标准库，无需 `pip install`。本次在 macOS 的 Python 3.9 环境使用。

```sh
git clone https://github.com/wucongkai/uu-remote-macos-network-fix.git
cd uu-remote-macos-network-fix
python3 uu_connection_proxy.py
```

终端出现 `UU connection adapter listening on 127.0.0.1:17891` 后，在 UU 远程的网络代理设置中填写：

| 配置项 | 值 |
| --- | --- |
| 模式 | 手动设置 |
| 类型 | SOCKS5 |
| 服务器 | `127.0.0.1` |
| 端口 | `17891` |
| 用户名、密码 | 留空 |

保存后使用 UU 的代理检测，必要时完全退出并重新打开 UU。终端关闭或按 `Ctrl+C` 会停止脚本。

可选参数：

```sh
python3 uu_connection_proxy.py --port 17891 --log /absolute/path/connection.log
```

日志父目录必须已存在。指定日志文件时使用轮转，单文件最大约 512 KiB，保留两份历史文件；日志记录目标域名/IP、协议和连接状态，不记录账号密码或报文正文。

## 验证

脚本运行期间，在另一个终端执行：

```sh
curl --proxy socks5h://127.0.0.1:17891 --noproxy '' \
  --head --connect-timeout 6 --max-time 10 \
  --silent --show-error --output /dev/null \
  --write-out 'HTTP=%{http_code} TLS_verify=%{ssl_verify_result}\n' \
  https://api.nrd.nie.163.com/
```

使用 `socks5h` 让代理解析域名，避免客户端先走有问题的本地 DNS。`curl` 成功退出且 `TLS_verify=0` 表示本次 TLS 证书验证通过。此根路径曾返回 HTTP `404`，它也能证明 HTTPS 请求已到达服务器；不代表远程桌面会话已经建立。最终仍需在 UU 中验证连接。

离线检查（不需要访问 UU）：

```sh
python3 -m unittest discover -s tests -v
```

## macOS 登录自动启动

[launchd 模板](examples/local.uuremote.connection-repair.plist) 供需要长期运行 Python 版本的用户参考。先把模板中的 Python、脚本及日志路径改为自己的**绝对路径**，确认 Python 可正常运行且日志目录已存在，再安装：

```sh
mkdir -p "$HOME/Library/LaunchAgents"
cp examples/local.uuremote.connection-repair.plist "$HOME/Library/LaunchAgents/"
plutil -lint "$HOME/Library/LaunchAgents/local.uuremote.connection-repair.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/local.uuremote.connection-repair.plist"
```

这会在当前用户登录后启动后台服务，`KeepAlive` 会在服务退出后重启它。停止并取消登录启动：

```sh
launchctl bootout "gui/$(id -u)/local.uuremote.connection-repair"
rm "$HOME/Library/LaunchAgents/local.uuremote.connection-repair.plist"
```

随后在 UU 内恢复原来的代理模式。本仓库不直接修改 UU 内部配置文件。

**如果已安装“UU 连接助手”应用版，请不要同时启用此 Python 启动项。** 两者使用同一标签和端口。本次修复的电脑后来已迁移至应用版后台核心并启用登录启动；本仓库保留的是最初解决问题的 Python 版本，不包含该应用及其 Swift 源码。

## 范围与限制

- 此脚本是特定问题的修复记录，其他网络不一定需要或适用。
- 只建立到目标 `443` 端口的 TCP 隧道，不支持 UDP 转发、SOCKS5 UDP ASSOCIATE 或 IPv6 上游解析。
- 域名请求限定在 `163.com`、`netease.com`、`gameviewer.com`、`126.net`、`127.net` 及其子域。这些后缀范围比 UU 本身更广。
- SOCKS5 也允许客户端直接请求公开 IP 的 `443` 端口；字面私有/回环地址会被拒绝。因此不能将它理解成严格按 UU 应用身份隔离的代理。
- 本机代理不需要认证，本机其他进程也可以访问。不要将监听地址改为 `0.0.0.0` 后直接对外暴露。
- 第三方 TCP DNS 能看到所查询的域名。本仓库不包含实际运行日志、个人设备标识或本机配置备份。
- 若 UU 官方端点、TLS 行为或网络策略变化，可能需要重新诊断。

## 文件

| 文件 | 用途 |
| --- | --- |
| `uu_connection_proxy.py` | 实际修复时使用的原始 Python 脚本 |
| `docs/diagnosis.md` | 现象、对照实验、结论及其边界 |
| `examples/local.uuremote.connection-repair.plist` | 使用者自行填写路径的登录启动模板 |
| `tests/test_proxy.py` | TLS 字节保持及本机目标拒绝的离线检查 |

本项目与网易 / UU 官方无关联。
