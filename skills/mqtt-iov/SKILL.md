---
name: mqtt-iov
description: 测试 MQTT broker 或车联网/IoT 后端（遥测、TSP 云、设备影子、按 VIN/设备 ID 下发指令）时调用。覆盖匿名接入、主题枚举、ACL 越权、弱口令、保留消息敏感信息、TLS 配置与 broker 版本漏洞。
---

# MQTT & 车联网（IoV）后端测试

MQTT 是 IoT 与车联网（TSP/遥测）后端最常见的消息总线。本 skill 在**已授权**前提下，系统化评估 MQTT broker 及其承载的业务主题的安全性。

---

## 边界与禁止（Agent 必读 · 违反即越界）

| 范围 | 允许 | 禁止 |
|---|---|---|
| **接入** | 测试匿名连接、弱口令、客户端 ID 冲突 | 对真实凭据做大规模爆破、拖垮 broker |
| **主题** | 订阅枚举、读取可见消息、`$SYS` 统计 | 向**控制类/指令类**主题 publish 可能影响物理设备的报文 |
| **越权** | 验证一个设备身份能否读/写另一个设备的主题（跨 VIN 水平越权） | 真正触发对方车辆/设备的动作（开锁、启动、OTA、转向等） |
| **可用性** | 读取、被动观察 | DoS、消息风暴、清空保留消息、顶号踢线生产设备 |

> ⚠️ **物理安全红线**：车联网/工控 MQTT 的指令主题（如 `.../command`、`.../rpc/request`）可能直接驱动真实车辆或设备。**默认只做“能不能发”的权限判定（用无害探针报文或在隔离测试设备上验证），绝不向生产目标发送会产生物理动作的指令**；确需验证须有书面授权并在安全可控环境进行。发现越权写权限本身即为高危漏洞，无需真的造成后果来“证明”。

---

## 工具

- `mosquitto_sub` / `mosquitto_pub`（`mosquitto-clients` 包）——最通用。
- `mqttx`（MQTTX CLI）、`mqtt`（HiveMQ mqtt-cli）——支持 MQTT 5.0、WebSocket。
- `mqttsa`、`mqtt-pwn`——MQTT 安全评估/枚举专用。
- `nmap` NSE：`mqtt-subscribe`。
- 端口：`1883` 明文 / `8883` TLS / `9001`（常见 WebSocket，路径多为 `/mqtt`）。

---

## 执行路线图

```
Phase 0 识别端口与形态 → Phase 1 匿名接入 → Phase 2 主题枚举 + $SYS 指纹
  → Phase 3 认证 / ACL 越权 → Phase 4 保留消息 / 敏感数据 → Phase 5 TLS + 版本漏洞
  → 汇总 + insert_components + report_finding
```

### Phase 0 — 端口与形态

```bash
nmap -p 1883,8883,9001,61613,15675 -sV <HOST>
```

区分：原生 MQTT（1883/8883）、MQTT over WebSocket（9001 `/mqtt`、或 nginx 后的 `wss://host/mqtt`）、以及 broker 管理口（EMQX Dashboard 18083、RabbitMQ-MQTT 插件 15672）。

### Phase 1 — 匿名接入

```bash
# 能连上且能收到任何东西 = 匿名可读（高危起点）
mosquitto_sub -h <HOST> -p 1883 -t '$SYS/#' -v -W 5
mosquitto_sub -h <HOST> -p 1883 -t '#' -v -W 10        # 通配订阅全部主题
```

- 连接被拒 / 需要用户名密码 → 进 Phase 3。
- `$SYS/#` 可读通常说明匿名放开（`allow_anonymous true`）——记为发现。

### Phase 2 — 主题枚举 + broker 指纹

```bash
mosquitto_sub -h <HOST> -t '$SYS/broker/version' -v -C 1    # broker 及版本
mosquitto_sub -h <HOST> -t '$SYS/broker/clients/#' -v -W 5   # 在线客户端数
```

- 用 `#` 订阅几十秒，归纳主题命名规律：IoV 常见 `vehicle/{vin}/telemetry`、`device/{id}/up`、`tsp/{tenant}/...`、`$share/...`（共享订阅）。
- 从主题结构推断**租户/设备标识位**（VIN、deviceId、IMEI）——这是 Phase 3 越权的锚点。
- 不要只贴原始消息刷屏，归纳“有哪些主题族 + 标识位在第几段”。

### Phase 3 — 认证与 ACL 越权（核心）

```bash
# 弱口令/默认口令（小字典、低速，禁止大规模爆破）
mosquitto_sub -h <HOST> -u admin -P public -t '#' -v -W 5
# 常见默认：admin/public、admin/admin、emqx/public、guest/guest、mqtt/mqtt
```

**水平越权（IoV 最关键）**：用设备 A 的身份，尝试订阅/写入设备 B 的主题。

```bash
# 以 A 的凭据，订阅 B 的 VIN 主题——能收到即跨设备越权读
mosquitto_sub -h <HOST> -u <A_user> -P <A_pass> -t 'vehicle/<OTHER_VIN>/#' -v -W 10
# 以 A 的凭据，向 B 的指令主题“尝试发布”——用无害占位报文判定“是否被 ACL 放行”
#   仅验证写权限，不发真实指令；被 broker 接受(未断开/无 ACL 拒绝)即越权
mosquitto_pub -h <HOST> -u <A_user> -P <A_pass> -t 'vehicle/<OTHER_VIN>/noop-probe' -m 'authz-test' -q 1
```

判定点：ACL 是否按 client-id/username 把设备限制在自己的主题子树；通配符 `#`/`+` 是否被限制；`$share` 共享订阅是否绕过 ACL。**发现可跨 VIN 读遥测或可写他人指令主题 = 严重越权**，据此 `report_finding`，无需实际触发物理动作。

### Phase 4 — 保留消息与敏感数据

- 保留消息（retained）在订阅瞬间即推送历史值，常含：凭据、Token、位置、固件 URL、配置。
- `mosquitto_sub -t '#' -v` 开头收到的即保留消息；归纳其中的敏感字段。
- LWT（遗嘱消息）、`$SYS` 中的 IP/主机名也可能泄露内网拓扑。

### Phase 5 — TLS 与版本漏洞

```bash
# 是否强制 TLS、证书是否自签/过期、是否要求客户端证书(mTLS)
openssl s_client -connect <HOST>:8883 -servername <HOST> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

- 明文 1883 承载业务 = 传输层未加密（中间人可读写）。
- 按 broker 版本查 CVE：Mosquitto、EMQX、HiveMQ、VerneMQ、NanoMQ 均有历史认证绕过/拒绝服务问题。
- 管理面（EMQX Dashboard、RabbitMQ 管理台）默认口令、未鉴权 API 一并测（这部分回到 Web 测试方法，可配合 api-recon）。

---

## 车联网（IoV / TSP）专项要点

- **标识位越权**是 IoV 的头号问题：VIN/IMEI/deviceId 往往可预测或可从 App/固件提取，ACL 若只认“连上了”而不认“连的是不是你自己的设备”，就能横向控制整个车队。
- MQTT 常只是一环：配合 TSP 云的 HTTP API（用 api-recon）、车机 App 逆向（提取 broker 地址/证书/主题规律）、固件分析（binwalk 提取内置凭据）一起打。
- 指令下发链路（App → 云 → MQTT → 车机）中，重点验证**鉴权是否在每一跳都校验设备归属**，而非仅在 App 层。

---

## 交付

- 对每个确认问题 `report_finding`：匿名接入、弱/默认口令、跨设备越权读/写、明文传输、保留消息泄露敏感数据、管理面未授权、已知 CVE。
- `insert_components` 写入 broker 组件（type=mqtt、component_name、version、port）。
- 证据保留：订阅/发布命令与 broker 响应、$SYS 指纹、越权判定的请求/响应；**不保留真实遥测隐私数据正文**，只记字段名与越权事实。
