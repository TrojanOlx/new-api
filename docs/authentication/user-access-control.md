# 管理员用户级 IP 与设备访问控制

管理员可以为单个用户配置 IP allowlist 和软设备画像策略。策略属于用户，而不是 API Key：该用户已有 Key、后续创建的 Key、只读 Token 路由、流式请求和 WebSocket 都继承同一策略。Dashboard 登录会话不执行这项 API Token 策略。

## 策略模式

IP 策略有两种模式：

- `unrestricted`：不增加用户级 IP 限制。Token 自身的 IP allowlist 仍独立生效。
- `allowlist`：客户端 IP 必须同时满足用户级和 Token 级 allowlist。条目可以是 IPv4、IPv6 或 CIDR；裸 IP 保持裸格式，CIDR 会清除 host bits；拒绝 `/0`，规范化去重后最多 64 条。

设备策略有四种模式：

- `off`：不计算或记录设备画像，稳定请求路径不增加设备查询和数据库写入。
- `observe`：创建或更新待审核画像并观察网络活动，但设备状态和网络冲突不拒绝请求。
- `allowlist`：仅允许状态为 `allowed` 且指纹别名为 `trusted` 的逻辑设备。有效升级宽限别名也可临时放行；未知、待审核、已阻止、宽限过期或跨 IP 活跃冲突均拒绝。
- `blacklist`：只拒绝已阻止的逻辑设备或指纹别名，其余画像继续观察并放行。

IP 不匹配、设备不允许和活动网络冲突返回 `403 access_denied`。当 `allowlist` 必须强制执行，但策略栅栏、设备数据或指纹 Secret 不可用时，返回 `503 access_control_unavailable`，并携带 `Retry-After: 3`。

## 软画像与隐私边界

设备画像是逻辑设备和版本化 HMAC 别名，不是物理设备身份。服务端只持久化 HMAC、逻辑设备、别名、短摘要、计数和最近 IP；窗口 ID 不进入永久指纹，安装 ID 只保存 HMAC。JA4 和 HTTP/2 特征只接受来自可信反向代理的内部 Header。

User-Agent 最多取 512 字节，其余标识最多取 128 字节。证据不足时会创建 `low` 置信度的待审核画像；此类画像可能碰撞，管理员不能把它等同于硬件身份。

Codex 客户端升级时，兼容性证据仍匹配的新版指纹会作为同一逻辑设备的别名进入宽限。默认宽限为 48 小时；`DEVICE_UPGRADE_GRACE_HOURS=0` 表示别名立即到期。管理员确认后别名变为 `trusted`；发生跨 IP 活跃冲突时，宽限别名会回到待审核状态。

活动网络检测只防止同一逻辑设备在窗口内同时从不同 IP 使用。相同公网 IP 下的多个 Agent、窗口、线程和普通并发请求不受限制，也不会自动封禁同一局域网中的其他设备。该功能不读取 MAC 地址或硬件序列号，不提供 mTLS、DPoP、TPM/WebAuthn 设备私钥绑定，也不能证明请求来自某台物理机器。

普通用户的自助接口、页面和浏览器响应不包含策略、设备、IP、备注或完整 HMAC。管理员审计只记录模式、资源 ID、计数和短指纹，不记录完整 IP allowlist 或完整 HMAC。

## 环境变量

生产环境在所有 New API 节点上使用相同配置：

| 变量 | 默认值与范围 | 说明 |
| --- | --- | --- |
| `DEVICE_FINGERPRINT_SECRET` | 无默认值；去除首尾空白后至少 32 个字符 | 设备与 IP HMAC 密钥。未就绪时不能启用设备 `allowlist`。 |
| `DEVICE_UPGRADE_GRACE_HOURS` | `48`，范围 `0-72` | 兼容升级别名的宽限小时数；`0` 表示立即到期。 |
| `DEVICE_ACTIVE_NETWORK_WINDOW_MINUTES` | `15`，范围 `1-60` | 同一逻辑设备跨 IP 活跃冲突检测窗口。 |
| `DEVICE_PROFILE_RETENTION_DAYS` | `90`，范围 `30-3650` | 未允许、未阻止设备画像的保留天数。 |

生成 Secret：

```bash
openssl rand -hex 32
```

Secret 必须纳入长期备份和灾难恢复，并在所有节点保持一致。变更 Secret 会使历史 HMAC 无法命中，已有允许设备会表现为新画像；启用任何设备 `allowlist` 前不得轮换 Secret。Secret 轮换也不能作为普通回滚手段。

## Caddy 与可信代理

仓库的通用 `docker-compose.yml` 保留 `3000:3000` 以兼容本地 quick-start。生产 Caddy 部署必须通过 override 取消 `new-api` 的宿主机端口发布，只允许同一受控 Docker 网络中的 Caddy 访问 `new-api:3000`。

普通的 `ports: []` 在 Compose 合并时不一定能清除基础文件中的端口。使用支持 `!reset` custom tag 的 Docker Compose 时，可以创建不入库的生产 override：

```yaml
services:
  new-api:
    ports: !reset []
```

渲染并检查最终配置：

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml config
```

输出中的 `new-api` 必须没有 `ports`。如果当前 Docker Compose 不支持 `!reset`，使用不继承基础 `ports` 的独立生产 Compose 文件；不能仅写 `ports: []` 后假定宿主机端口已取消。

检查生产容器和实际代理网段：

```bash
docker inspect caddy new-api \
  --format '{{.Name}}{{range $name,$network := .NetworkSettings.Networks}} network={{$name}} ip={{$network.IPAddress}}{{end}}{{println}}'

docker network inspect sub2api_sub2api-network \
  --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}'

docker inspect new-api \
  --format '{{range .Config.Env}}{{println .}}{{end}}' |
  grep -E '^(TRUSTED_PROXIES|DEVICE_)='
```

将 `docker network inspect` 得到的实际 Caddy 代理 IP 或最小必要网段显式配置到 `TRUSTED_PROXIES`。不要照抄示例网段，也不要在生产环境依赖未配置时默认信任全部 RFC1918/ULA 网络。Docker 网络和主机防火墙必须阻止其他容器或主机绕过 Caddy 直连 New API。

Caddy 转发前必须删除客户端提供的内部特征 Header，防止伪造：

```caddyfile
reverse_proxy new-api:3000 {
    header_up -X-New-Api-Edge-JA4
    header_up -X-New-Api-Edge-H2
}
```

标准 Caddy 不负责生成 JA4/HTTP2 值。若部署定制模块，只能在清除客户端同名值后注入受信值；没有这些值时，设备画像继续使用其他可用证据。

## 分阶段启用

1. 部署代码，保持所有用户为 `unrestricted + off`。
2. 配置并备份 `DEVICE_FINGERPRINT_SECRET`，核对所有节点一致；限制 New API 入口，配置精确 `TRUSTED_PROXIES`，并清理外部 JA4/H2 Header。
3. 选择一个测试用户切换为 `observe`。
4. 连续采集至少 24 小时，检查低置信画像、版本升级别名、跨 IP 活动和设备表增长。
5. 管理员把确认过的逻辑设备设为 `allowed`，并把对应指纹别名设为 `trusted`。
6. 仅对该用户切换为设备 `allowlist`，验证其所有旧 Key、新 Key、流式请求和 WebSocket。
7. 完成观测后再逐用户推广，不做全局一次性切换。

## 回滚

访问异常时，先把受影响用户恢复为 IP `unrestricted` 和设备 `off`。这会停止设备策略判断，不需要删除逻辑设备、指纹别名或最近 IP 表，也不要轮换 Secret。

回退旧镜像时保留新增用户列和三张设备表，旧程序会忽略它们。只有数据库迁移失败时才恢复原镜像和迁移前数据库备份。回滚后重新启用前，应确认 Secret、可信代理、Caddy Header 清理和端口隔离仍满足要求。
