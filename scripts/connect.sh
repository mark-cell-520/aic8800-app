#!/bin/bash
# ============================================================
# connect.sh — AIC8800 免 root 全流程（Boot ROM 上传固件 + WPA2 连接）
#
# 用法: AIC_SSID=<ssid> AIC_PASS=<password> bash connect.sh
#   - 密码走环境变量 AIC_PASS，不出现在命令行（ps 不可见）
#   - 设备在运行态(8d81/8d83)时跳过上传直接连接
#   - 设备在光驱态时退出码 2，提示需先提权模式切换
#
# 退出码: 0=握手完成  1=失败  2=需要先模式切换（光驱态）
# ============================================================
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# 工具路径：仓库布局 $DIR/app/Resources/aic8800-tool；
# app bundle 内脚本在 Contents/Resources/scripts/ 下，工具在上一层。
TOOL="${AIC_TOOL:-}"
if [ -z "$TOOL" ]; then
    for cand in "$DIR/app/Resources/aic8800-tool" "$DIR/aic8800-tool" "$DIR/../aic8800-tool"; do
        [ -x "$cand" ] && TOOL="$cand" && break
    done
fi
TOOL="${TOOL:-$DIR/app/Resources/aic8800-tool}"
# 固件目录优先级：AIC_FW_DIR > app/Resources/fw（fetch-firmware.sh 提取位置）
FW="${AIC_FW_DIR:-$DIR/app/Resources/fw}"

AIC_SSID="${AIC_SSID:-}"

if [ -z "$AIC_SSID" ]; then echo "缺少 AIC_SSID"; exit 1; fi
if [ ! -x "$TOOL" ]; then
    echo "未找到 CLI 工具: $TOOL"
    echo "请先从源码构建: bash scripts/build-tool.sh（依赖 libusb-1.0.27）"
    exit 1
fi

STAGE=$("$TOOL" status 2>/dev/null | grep "设备阶段" || echo "")
echo "当前: $STAGE"

case "$STAGE" in
    *1111:1111*|*大容量存储*)
        echo "设备在光驱态，需要先提权执行模式切换（app 会自动处理）。"
        exit 2
        ;;
    *8d80*|*"Boot ROM"*)
        if ! ls "$FW"/fmacfw_8800d80_u02.bin > /dev/null 2>&1; then
            echo "未找到固件（查找目录: $FW）"
            echo "本仓库不随源码分发厂商固件（版权归 AICSemi）。"
            echo "请运行: bash scripts/fetch-firmware.sh <厂商Linux驱动包.tar.gz>"
            echo "或用 AIC_FW_DIR 指定固件目录。"
            exit 1
        fi
        echo "===== 固件下载 $(date) ====="
        # 工具内部完成 5 步：adid/patch -> ext patch -> patch table 逐条应用
        #                -> 主固件 -> patch_config + 启动 + USB 重置等重枚举
        "$TOOL" fw-upload "$FW" || exit 1
        sleep 3
        echo "--- 下载后设备阶段 ---"
        "$TOOL" status 2>/dev/null | grep "设备阶段" || true
        ;;
esac

echo "===== WPA2 连接: SSID=$AIC_SSID ====="
# 密码通过环境变量 AIC_PASS 传给工具（已支持），不进命令行
"$TOOL" connect "$AIC_SSID"
RC=$?
echo "connect 退出码: $RC"
exit $RC
