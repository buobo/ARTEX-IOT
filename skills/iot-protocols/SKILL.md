---
name: iot-protocols
description: 遇到 Web/HTTP 之外的 IoT/OT 协议端口或设备时调用——CoAP、Modbus/工控、BLE 蓝牙、Zigbee/802.15.4、UPnP/SSDP、mDNS/DNS-SD、AMQP 等。给出每种协议的发现、枚举、鉴权与越权测试方法；写入/控制类操作默认只读、需授权。
---

# IoT / OT 协议测试速查

Web 之外，IoT/OT 设备暴露大量非 HTTP 协议。本 skill 按协议给出**授权测试**下的发现与评估方法。MQTT 单列在 `mqtt-iov`；卫星在 `satcom-recon`。

---

## 边界与禁止（Agent 必读）

| 允许 | 禁止 |
|---|---|
| 发现、枚举资源/服务、读取、鉴权与越权**判定** | 向 OT/工控设备**写寄存器/线圈**、改设备状态等可能影响物理过程的操作 |
| 被动嗅探、读取广播/发现响应 | 对生产设备做 DoS、固件刷写、出厂重置、配网劫持 |
| 小字典弱口令探测 | 大规模爆破、拖垮低算力设备 |

> ⚠️ **工控/OT 物理安全红线**：Modbus/BACnet/DNP3 等的**写操作**可能直接驱动阀门、电机、PLC，危及现场安全与人身。**默认只读（read coils/registers、discover）**；发现“可未授权写”本身即为高危漏洞，据此上报，**不要真的写**。

---

## 端口速查

| 协议 | 端口 | 说明 |
|---|---|---|
| CoAP | 5683/udp（5684 DTLS） | 受限设备 REST-like |
| Modbus | 502/tcp | 工控，最常见 |
| BACnet | 47808/udp | 楼宇自控 |
| DNP3 | 20000/tcp | 电力/水务 |
| UPnP/SSDP | 1900/udp | 发现；放大攻击面 |
| mDNS/DNS-SD | 5353/udp | 局域网服务发现 |
| AMQP | 5672/tcp（RabbitMQ 管理 15672） | 消息队列 |
| BLE | — | 需蓝牙适配器 |
| Zigbee/802.15.4 | — | 需 KillerBee 硬件 |

一轮基线：

```bash
nmap -sU -sV -p 5683,1900,5353,47808 <HOST>
nmap -sV -p 502,20000,5672,15672 <HOST>
```

---

## CoAP（5683/udp）

```bash
coap-client -m get coap://<HOST>/.well-known/core      # 资源发现（核心入口）
nmap -sU -p 5683 --script coap-resources <HOST>
```

- 枚举 `/.well-known/core` 列出的资源，逐个 GET 读值。
- 测 DTLS（5684）是否强制、是否接受无认证请求；PUT/POST/DELETE 写操作仅做**权限判定**（是否被拒），不实际改设备状态。

## Modbus（502/tcp，工控——只读）

```bash
nmap -p 502 --script modbus-discover <HOST>            # 枚举 unit id / 设备标识
# mbtget / pymodbus 只读：读线圈与寄存器
mbtget -r3 -a 0 -n 10 <HOST>                           # 读 holding registers
```

- Modbus 无内建认证——可达即可读，这本身常是暴露面结论。
- **绝不发写功能码**（05/06/0F/10）到生产设备；如需验证“可写”，仅在授权的隔离测试 PLC 上进行。

## BLE（需蓝牙适配器）

```bash
bluetoothctl scan on                                   # 发现设备
gatttool -b <MAC> --primary                            # 枚举 GATT 服务
gatttool -b <MAC> --characteristics                    # 枚举特征
gatttool -b <MAC> --char-read -a <handle>              # 读特征值
```

- 关注：是否 Just-Works 配对（无 MITM 保护）、特征是否明文可读写敏感数据、是否可重放。
- 进阶：`bettercap`（BLE 模块）、`nRF Connect`、`btlejack`（劫持/嗅探连接，需授权）。

## Zigbee / 802.15.4（需 KillerBee 硬件）

```bash
zbstumbler                                             # 扫描信道/网络
zbdump -f 15 -w capture.pcap                           # 抓指定信道
```

- 关注默认/泄露的网络密钥（Trust Center Link Key，经典 `ZigBeeAlliance09`）、明文入网、重放开关/锁指令（仅授权测试设备）。

## UPnP / SSDP（1900/udp）

```bash
nmap -sU -p 1900 --script upnp-info <HOST>
upnpc -l                                               # 列出 IGD 端口映射能力
```

- 关注：可未授权添加端口映射（内网穿透）、暴露的设备描述 XML 泄露型号/序列号、SSDP 反射放大面。

## mDNS / DNS-SD（5353/udp）

```bash
avahi-browse -a -t                                     # 枚举局域网所有广播服务
nmap -sU -p 5353 --script dns-service-discovery <HOST>
```

- 快速摸清局域网里有哪些设备与服务（打印机、NAS、摄像头、智能家居、Chromecast 等）及其主机名/端口，为后续定向测试提供地图。

## AMQP（5672 / RabbitMQ 管理 15672）

```bash
nmap -p 5672 --script amqp-info <HOST>
# RabbitMQ 管理台默认 guest/guest（历史版本允许远程登录）
curl -s -u guest:guest http://<HOST>:15672/api/overview | head
```

---

## 配套：固件与硬件（有样机/固件时）

- 固件提取与分析：`binwalk -eM firmware.bin`、`firmware-mod-kit`，找硬编码凭据、证书、私钥、后门、升级地址、broker/API 地址。
- 硬件调试口（UART/JTAG/SPI Flash）：需物理接触与设备，属硬件测试范畴，本 skill 仅提示其存在。
- 固件里提取到的 broker 地址/证书/主题规律回喂 `mqtt-iov`；提取到的 API 回喂 `api-recon`。

---

## 交付

- 每个确认问题 `report_finding`：未认证可达、默认/泄露密钥、明文传输、可未授权写（OT）、可未授权改端口映射（UPnP）、管理台默认口令、固件硬编码凭据等。
- `insert_components` 写入发现的组件（type、component_name、version、port、binary_path）。
- OT/物理相关发现要在报告中**明确标注未执行写操作、仅做权限判定**，并给出修复建议（加认证、网络隔离、禁用默认账户/密钥）。
