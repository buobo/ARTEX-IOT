---
name: firmware-extract
description: "拿到固件文件（.bin/.img/.trx/.chk/.tar.gz 等）需要解包、识别文件系统、判断是否加密/填充时调用。给出 binwalk/unsquashfs/jffs2/ubifs 的具体命令、失败排查与解包后的交接物。"
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [iot, firmware, binwalk, extraction, reverse-engineering]
    category: ctf
    related_skills: [iot-security, iot-hardware, iot-vuln-exploit]
---

# 固件提取与解包

固件解包、文件系统识别、加密固件处理时加载此skill。

## 固件获取

1. 官网下载固件更新包（最简单）
2. 流量拦截OTA升级URL
3. 编程器直接读Flash（见iot-hardware skill）
4. UART shell中dd导出
5. 利用已知漏洞读取（如路径穿越）

## 固件提取

```bash
binwalk firmware.bin           # 扫描结构
binwalk -e firmware.bin        # 自动提取
binwalk -Me firmware.bin       # 递归提取
binwalk -A firmware.bin        # 识别CPU架构
binwalk -E firmware.bin        # 熵分析（高熵=加密）
```

### ZIP封装 + U-Boot uImage + gzip/SquashFS

部分摄像头升级包表面是自定义格式，但 `binwalk` 会识别出 ZIP 条目；若 ZIP 前有厂商头，`unzip` 可能提示 offset 错误但仍能提取大部分文件。可先列出并提取：

```bash
unzip -l firmware.bin
mkdir extracted
unzip -o firmware.bin -d extracted
```

分区文件若识别为 U-Boot legacy uImage，通常跳过 64 字节头即可检查内部格式：

```bash
mkdir parts
for f in extracted/*.img; do
  n=$(basename "$f" .img)
  dd if="$f" of="parts/$n.gz" bs=64 skip=1 status=none
done
file parts/*
```

注意：文件名带 `.gz` 不代表内部仍是 gzip；uImage 头后的 payload 可能直接是 SquashFS 或 JFFS2。对确实是 gzip 的 payload 解压后，再用 `unsquashfs` 提取 SquashFS：

```bash
for p in parts/*squash.gz; do
  unsquashfs -d rootfs/$(basename "$p" .gz) "$p"
done
```

若 ZIP 提取返回非零退出码，要检查输出目录和每个文件的 `file` 结果；厂商头导致的 ZIP offset 警告不一定意味着所有分区不可用。

### 常见文件系统
| 文件系统 | 特点 | 提取工具 |
|----------|------|----------|
| SquashFS | 最常见，只读压缩 | unsquashfs / sasquatch(非标准) |
| JFFS2 | 可读写，NOR Flash | jefferson |
| UBIFS | NAND Flash | ubi_reader |
| CramFS | 只读压缩，旧设备 | cramfsck |
| YAFFS2 | NAND Flash | unyaffs |

## 固件加密处理

### 判断是否加密
1. binwalk -E 熵分析：高熵(>0.9)且无可识别结构 = 加密
2. 无magic bytes、无文件系统签名
3. 文件头可能有自定义标识（如MH01、shrs等）

### 解密策略
1. **找过渡版本**：加密前最后一个版本含解密程序
2. **逆向升级程序**：分析固件中的解密逻辑
3. **硬件直读**：运行中设备Flash存储的是解密后固件
4. **厂商工具**：部分厂商有公开的解密工具

### D-Link固件解密实战

**方法1：旧版本imgdecrypt**
- 找未加密旧固件 → 提取imgdecrypt二进制
- QEMU模拟运行 → 输出AES密钥
- 案例：DIR-882 v1.04含imgdecrypt → key:C05FBF1936C99429CE2A0781F08D6AD8

**方法2：delink工具**
- devttys0/delink (Rust) 专门解密D-Link固件
- 案例：M30固件用delink解密后binwalk提取squashfs

**方法3：头部结构分析**
- M30: 偏移0x20存IV(32 hex字符)，0x18存加密大小
- 0x41起为OpenSSL Salted__数据
- 密钥派生：EVP_BytesToKey SHA256变体(非MD5)

### DrayTek固件解密
- 旧版提取ChaCha20密钥
- draytools工具解密
- GPL源码编译定制QEMU

## 逆向分析要点

- 基址恢复：分析中断向量表、绝对地址引用、字符串偏移
- 符号恢复：FLIRT签名、BinDiff对比、同版本未strip库
- VxWorks：非标准符号表修复（TP-Link TL-WDR7661案例）
- 交叉引用：字符串定位关键函数（如"password"、"login"）

## 在线资源

- firmware.re — 在线固件分析
- EMBA (github) — 自动化固件安全分析框架
- FACT (Firmware Analysis Comparison Toolkit)
- Onekey (原IoT Inspector) — 商业固件分析平台

## Reusable workflow: multi-image ARM camera firmware with hidden ATE UDP service

For camera upgrade packages that contain a ZIP archive and several U-Boot images:

1. Inspect the package with `binwalk` and `unzip -l`. If ZIP offsets are misaligned, extract with `unzip` anyway and verify the resulting files with `file`.
2. For each U-Boot image, remove the 64-byte legacy uImage header (`dd if=image of=image.gz bs=64 skip=1`) and decompress with gzip. The resulting payload may be SquashFS even when the filename ends in `.squash.img`.
3. Extract all SquashFS partitions. Read `/etc/init.d/rcS` and `S##` scripts first; the important service may be launched from a mounted application partition rather than `/usr/sbin`.
4. Enumerate the application ELF files and search strings for `ATE`, `factory`, `test`, `ez_udp_server`, `HandleCmd`, `OpenTelnetd`, `StartRtspServer`, `popen`, `system`, and `recvfrom`/`sendto`.
5. Do not rely only on ASCII searches for the challenge port. Locate the relevant string references, then inspect ARM disassembly. A port may be loaded with `movw` and passed through a byte-order helper; in the CP7 camera case, the ATE service loads `movw r0, #7329` and runs in `CAte::ThreadProc`/`ez_udp_server`.
6. Treat strings such as `ATE_ControlPkt cmd %s`, `CAte::HandleCmd`, and command names (`OpenTelnetd`, `storage_get_status_test`, `Tenda_mfg_htmlVersionInfo`) as protocol clues. Probe the actual target only after obtaining its HOST, trying the documented UDP port and both JSON-like and plain-text command forms.
7. Check state/configuration paths referenced by the handler, such as `/tmp/ateState/ate/info`, because the request format may be key/value or JSON and the handler may gate commands on factory-test flags.

This workflow distinguishes an externally mapped challenge port from a genuinely hard-coded firmware service and avoids prematurely focusing on the web UI.

## ATE UDP测试接口分析

消费级摄像头固件可能在主业务程序中内置工厂测试（ATE）UDP服务。推荐流程：

1. 从启动脚本确认主程序：重点检查 `/etc/init.d/S*`、`rcS`、挂载分区和常驻 ELF（常见如 `/opt/app/bin/Kylin`）。
2. 对 ARM ELF 做静态定位：
   ```bash
   readelf -Ws app | grep -E 'recvfrom|sendto|socket|bind|popen|system'
   strings -a -t x app | grep -Ei 'ATE|ez_udp|test|factory|flag'
   arm-linux-gnueabi-objdump -d app
   ```
3. 在反汇编中重点寻找 `movw r0, #<port>`、`recvfrom()` 调用，以及 `recvfrom` 后的 `strstr()`/JSON解析逻辑。端口可能只以二进制常量存在，字符串搜索不一定能找到。
4. ATE服务常见特征：`CAte::ThreadProc`、`ez_udp_server`、`ATE_ControlPkt`、`CAte::HandleCmd`，以及测试关键词（例如 `rf_test_flag`、`td_finishtest`、`td_throughtest`、`repair`）。
5. 先用无害请求确认服务是否到达，再根据返回错误反推协议格式。若返回结构化的 `format failed`，说明网络路径和JSON解析入口正常，但字段结构仍不符合要求；不要把它误判为端口不可达。
6. 外部题目端口可能是 TCP/UDP 代理，不能假设外部端口能直接接受内部服务的明文协议；必须分别确认传输层和转发方向。

## Pitfalls

1. sasquatch vs unsquashfs：非标准SquashFS必须用sasquatch而非unsquashfs
2. binwalk提取不完整时尝试手动dd + 文件系统工具
3. 加密固件的过渡版本可能已从官网下架，需archive.org或第三方站
4. 题目给出的 `HOST:PORT` 可能是平台端口映射，不一定会以 ASCII 端口号出现在固件中；不能只用 `strings` 搜端口。应同时检查启动脚本、配置文件、ELF 中的 `socket/bind/recvfrom` 调用，并确认远程 UDP 行为。
5. 对厂商 ZIP + uImage 包，先验证 ZIP 提取目录和每个分区的 `file` 类型；不要因 `unzip` 的前置偏移警告而直接判定固件损坏。
