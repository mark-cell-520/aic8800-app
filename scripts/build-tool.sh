#!/bin/bash
# ============================================================
# build-tool.sh — 从源码编译 aic8800-tool / aic-modeswitch
#
# 依赖 libusb-1.0.27 源码目录（需先 ./configure && make）：
#   curl -O https://github.com/libusb/libusb/releases/download/v1.0.27/libusb-1.0.27.tar.bz2
#   tar xf libusb-1.0.27.tar.bz2 && cd libusb-1.0.27 && ./configure && make
#
# 产物写入 app/Resources/（app bundle 直接打包）
# ============================================================
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIBUSB_SRC="${LIBUSB_SRC:-$ROOT/libusb-1.0.27}"
LIBUSB_DYLIB="$LIBUSB_SRC/libusb/.libs/libusb-1.0.0.dylib"
OUT="$ROOT/app/Resources"

if [ ! -f "$LIBUSB_DYLIB" ]; then
    echo "找不到 $LIBUSB_DYLIB —— 请先按脚本头注释编译 libusb" >&2
    exit 1
fi

for f in aic8800-tool aic-modeswitch; do
    echo "==> 编译 $f"
    clang -O2 -o "$OUT/$f" "$ROOT/src/$f.c" \
        "$LIBUSB_DYLIB" \
        -I"$LIBUSB_SRC/libusb" \
        -framework CoreFoundation -framework IOKit -lpthread
    # install_name 保持 /usr/local/lib/libusb-1.0.0.dylib（libusb 默认安装位置）：
    # 这样产物不绑定构建机绝对路径、库文件可替换（LGPL 要求），
    # 已装 libusb 的机器可直接运行；未安装则 brew install libusb。
done
echo "完成: $OUT/aic8800-tool, $OUT/aic-modeswitch"
