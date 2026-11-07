# AIC8800 WiFi — macOS 用户态驱动 + GUI

AIC8800D80 USB WiFi 芯片的 **macOS 用户态驱动**：不写内核扩展，纯用户态
libusb 完成「SCSI 模式切换 → 固件下载 → WPA2 四路握手」全链路，并提供一个
一键操作的 SwiftUI app。

设备三阶段：`1111:1111`（虚拟光驱）→ `a69c:8d80`（Boot ROM）→ `a69c:8d81`（WiFi 运行态）。

## 状态（实测）

在 AIC8800D80 模块 + WPA2-PSK(CCMP) AP 上，`aic8800-tool connect` 可完成完整四路握手
（Msg1→2→3→4，固件 DATA_CFM `09` = AP 已 ACK，GTK 解密成功）。2026-11-07 连续多次
验证通过。PTK 安装到固件的 CFM 尚未收到（不影响握手，属数据通路下一步）。

## 快速开始

```bash
# 1) 编译 CLI 工具（依赖 libusb-1.0.27，脚本头注释有准备步骤）
bash scripts/build-tool.sh

# 2) 提取固件（版权归 AICSemi，本仓库不随源码分发）
bash scripts/fetch-firmware.sh /path/to/aic8800_linux_driver.tar.gz

# 3) 打包 app（SwiftUI，swiftc 直接编译，无需 Xcode 工程）
bash scripts/build-app.sh
open build/AIC8800WiFi.app
```

app 内填 SSID + 密码 → 「一键连接」。设备在光驱态时 app 会自动弹出系统授权框
（模式切换需要 root，走 macOS 标准管理员提权，不经过 sudo 管道）。

## 快速开始（CLI）

```bash
# 光驱态 -> Boot ROM（需 root；或在 app 里一键完成）
sudo bash scripts/mode-switch.sh

# 上传固件 + 连接（免 root；密码走环境变量，不进命令行/ps）
AIC_SSID="<你的SSID>" AIC_PASS="<你的密码>" bash scripts/connect.sh
```

## 仓库结构

```
app/                    SwiftUI app 源码
  AIC8800WiFiApp.swift    @main 入口
  ContentView.swift       主界面（状态徽章 / 输入 / 握手进度 / 日志）
  DriverController.swift  进程管理 + 输出解析状态机
  Resources/
    fw/                   固件（不入库，用 scripts/fetch-firmware.sh 提取）
    aic8800-tool          CLI 二进制（不入库，用 scripts/build-tool.sh 构建）
scripts/
  build-tool.sh           从源码编译 CLI 工具（需 libusb-1.0.27）
  fetch-firmware.sh       从厂商 Linux 驱动包提取固件
  build-app.sh            编译打包 .app（swiftc + ad-hoc 签名）
  mode-switch.sh          光驱态 -> Boot ROM（root）
  connect.sh              免 root：固件上传 + WPA2 连接
src/                     C 源码（aic8800-tool.c / aic-modeswitch.c）
```

## 固件与许可

- **固件二进制不在本仓库**：版权归 AICSemi。官方 Linux 驱动包（GPL-2.0）内含全部
  所需文件，`scripts/fetch-firmware.sh` 帮你提取到 `app/Resources/fw/`。
  注意：**驱动包的 GPL 覆盖驱动源码，不覆盖固件二进制本体**——固件仍是厂商专有。
- **CLI 二进制不在本仓库**：请从 `src/` 用 `scripts/build-tool.sh` 构建（可审计）。
- libusb 以动态链接方式依赖（LGPL-2.1），请从 https://libusb.info/ 获取其源码；
  本仓库不打包 libusb。
- 自身代码 MIT（见 LICENSE）。

## 参考与致谢

- [gtxaspec/aic8800-wifi](https://github.com/gtxaspec/aic8800-wifi)（GPL-2.0）——
  协议与初始化序列的主要依据
- [olamellberg/AIC8800D80](https://github.com/olamellberg/AIC8800D80)（MIT）——
  SCSI 模式切换 CDB 逆向
- EdoardoMantovani/aic8800-offensive-userspace-driver —— **无许可证**，仅作
  消息流行为对照，未复制任何代码
- [libusb](https://libusb.info/)（LGPL-2.1）—— 动态链接，不随仓库分发

## 已知边界

- 只实现了 STA 模式 + WPA2-PSK(CCMP)；AP 模式、WPA3、5G 关联未验证
- PTK 安装 CFM 未回（GTK 安装正常）；加密数据通路待下一步
- ad-hoc 签名的 app 仅限本机运行；分发需 Developer ID + notarytool
- 单芯片型号（AIC8800D80 / u02 固件）验证；其他型号需自行适配

## 环境变量（调试用）

| 变量 | 作用 |
|---|---|
| `AIC_PASS` | 连接密码（避免进命令行） |
| `AIC_STAMAC` | 强制指定 STA MAC（默认读 efuse） |
| `AIC_SSID` | SSID（脚本用） |
| `AIC_FW_DIR` | 固件目录（默认 app/Resources/fw） |
| `AIC_NO_REINIT` | 跳过全量初始化（设备已运行时） |
| `AIC_MSGDUMP` | dump 全部消息收发 |
| `AIC_DEBUG_MAC` | dump GET_MAC_ADDR 的 CFM 原文 |
| `AIC_KEYADD_TIMEOUT` | 密钥安装 CFM 等待 ms（默认 500） |
| `AIC_NO_SCANU` / `AIC_PRECONNECT_SLEEP` | 扫描/连接前行为 |

完整列表见源码内注释。
