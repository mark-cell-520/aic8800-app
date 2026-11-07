#!/bin/bash
# ============================================================
# mode-switch.sh — 光驱态(1111:1111) -> Boot ROM(a69c:8d80)
#
# 需要 root（USB 大容量存储接口被内核驱动独占，免 root 会 LIBUSB_ERROR_ACCESS）。
# 由 app 通过 osascript "with administrator privileges" 提权执行，
# 不接任何密码参数——认证由系统弹窗完成。
#
# 用法: sudo bash mode-switch.sh
# ============================================================
set -eu
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

echo "===== AIC8800 模式切换 $(date) ====="
STAGE=$("$TOOL" status 2>/dev/null | grep "设备阶段" || echo "未知")
echo "当前: $STAGE"

case "$STAGE" in
    *1111:1111*|*大容量存储*)
        echo "--- 设备在光驱态，执行 SCSI 模式切换 ---"
        if "$TOOL" mode-switch; then
            sleep 3
            echo "--- 重枚举后设备阶段 ---"
            "$TOOL" status 2>/dev/null | grep "设备阶段" || echo "(未重枚举，请重新插拔)"
            echo "MODE_SWITCH=OK"
        else
            echo "MODE_SWITCH=FAIL"
            exit 1
        fi
        ;;
    *8d80*|*"Boot ROM"*)
        echo "设备已在 Boot ROM 态，无需切换。"
        echo "MODE_SWITCH=OK"
        ;;
    *8d81*|*8d83*|*运行*)
        echo "设备已在运行态，无需切换。"
        echo "MODE_SWITCH=OK"
        ;;
    *)
        echo "未识别设备，请检查 USB 连接。"
        echo "MODE_SWITCH=FAIL"
        exit 1
        ;;
esac
echo "===== 模式切换结束 ====="
