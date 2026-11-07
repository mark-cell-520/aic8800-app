#!/bin/bash
# ============================================================
# fetch-firmware.sh — 从厂商 Linux 驱动包提取 AIC8800D80 固件
#
# 本仓库按开源惯例不随源码再分发厂商固件二进制（版权归 AICSemi）。
# AICSemi 官方放出的 Linux 驱动包（GPL-2.0）内含全部所需固件，
# 本脚本帮你把它提取到 app/Resources/fw/。
#
# 用法: bash scripts/fetch-firmware.sh [厂商驱动包.tar.gz 路径]
#       不带参数时打印下载指引。
# ============================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FW_OUT="$ROOT/app/Resources/fw"
mkdir -p "$FW_OUT"

NEEDED="fmacfw_8800d80_u02.bin fw_adid_8800d80_u02.bin fw_patch_8800d80_u02.bin fw_patch_table_8800d80_u02.bin fw_patch_8800d80_u02_ext0.bin"

if [ $# -lt 1 ]; then
    cat <<'GUIDE'
===== 固件获取指引 =====

1. 下载 AICSemi 官方 Linux 驱动包（含固件，GPL-2.0）：
   搜索 "AICSemi aic8800 linux driver" 或到芯片供应商/模组厂
   官网获取（文件名通常类似 aic8800_linux_driver.tar.gz）。

2. 解压后在包内找到固件目录（通常在 driver-src/fw/ 或
   fw/ 下），把这 5 个文件拷出来：
     fmacfw_8800d80_u02.bin
     fw_adid_8800d80_u02.bin
     fw_patch_8800d80_u02.bin
     fw_patch_table_8800d80_u02.bin
     fw_patch_8800d80_u02_ext0.bin

3. 重新运行本脚本并传入驱动包路径：
     bash scripts/fetch-firmware.sh ~/Downloads/aic8800_linux_driver.tar.gz
   或手动拷贝到 app/Resources/fw/。

注意：固件版权归 AICSemi，本仓库不提供下载、不做再分发。
GUIDE
    exit 2
fi

PKG="$1"
[ -f "$PKG" ] || { echo "找不到驱动包: $PKG"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "==> 解压 $PKG"
tar xf "$PKG" -C "$TMP" 2>/dev/null || { echo "解压失败（支持 .tar.gz/.tar.bz2/.tgz）"; exit 1; }

echo "==> 查找并拷贝固件"
found=0
for f in $NEEDED; do
    hit="$(find "$TMP" -name "$f" -print -quit 2>/dev/null)"
    if [ -n "$hit" ]; then
        cp "$hit" "$FW_OUT/$f"
        echo "  ✓ $f ($(stat -f%z "$FW_OUT/$f") 字节)"
        found=$((found+1))
    else
        echo "  ✗ $f 未找到"
    fi
done

if [ "$found" -eq 5 ]; then
    echo "==> 固件就绪: $FW_OUT"
    echo "    可以运行: bash scripts/build-app.sh && open build/AIC8800WiFi.app"
    exit 0
fi
echo "==> 只找到 $found/5 个文件，请检查驱动包版本是否匹配（8800d80_u02）"
exit 1
