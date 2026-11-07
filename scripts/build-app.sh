#!/bin/bash
# ============================================================
# build-app.sh — 一键编译打包 AIC8800WiFi.app（无需 Xcode 工程）
#
#   bash scripts/build-app.sh
#
# 产物: ./build/AIC8800WiFi.app（ad-hoc 签名，本机可直接 open）
# 说明: 脚本与资源已拷入 bundle，app 不依赖本仓库外的任何文件。
# ============================================================
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/build/AIC8800WiFi.app"
BUNDLE_ID="${AIC_BUNDLE_ID:-com.github.mark-cell-520.aic8800wifi}"

echo "==> 清理旧产物"
rm -rf "$ROOT/build"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "==> 编译 SwiftUI app"
swiftc -O \
    -target arm64-apple-macosx13 \
    -o "$APP/Contents/MacOS/AIC8800WiFi" \
    "$ROOT"/app/*.swift \
    -framework SwiftUI -framework AppKit -framework Foundation

echo "==> 准备 CLI 工具"
if [ ! -f "$ROOT/app/Resources/aic8800-tool" ]; then
    echo "  未找到预编译工具，先从源码构建（需要 libusb-1.0.27，见 build-tool.sh 头注释）"
    bash "$ROOT/scripts/build-tool.sh" || { echo "  工具构建失败"; exit 1; }
fi

echo "==> 拷入资源（aic8800-tool + 固件[如有] + 脚本）"
cp "$ROOT/app/Resources/aic8800-tool" "$APP/Contents/Resources/"
mkdir -p "$APP/Contents/Resources/fw"
if ls "$ROOT"/app/Resources/fw/*.bin > /dev/null 2>&1; then
    cp "$ROOT"/app/Resources/fw/*.bin "$APP/Contents/Resources/fw/"
    echo "  固件已打包（$(ls "$APP/Contents/Resources/fw"/*.bin | wc -l | tr -d ' ') 个文件）"
else
    echo "  ⚠ 未找到固件——app 可构建但无法下载固件。"
    echo "    运行 bash scripts/fetch-firmware.sh 按指引从厂商驱动包提取。"
fi
mkdir -p "$APP/Contents/Resources/scripts"
cp "$ROOT"/scripts/connect.sh "$ROOT"/scripts/mode-switch.sh "$APP/Contents/Resources/scripts/"
chmod +x "$APP/Contents/Resources/aic8800-tool" "$APP/Contents/Resources/scripts/"*.sh

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>AIC8800WiFi</string>
    <key>CFBundleDisplayName</key><string>AIC8800 WiFi</string>
    <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
    <key>CFBundleVersion</key><string>1.0.0</string>
    <key>CFBundleShortVersionString</key><string>1.0.0</string>
    <key>CFBundleExecutable</key><string>AIC8800WiFi</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST

echo "==> ad-hoc 签名"
codesign --force --sign - "$APP"

echo "==> 完成: $APP"
echo "    运行: open \"$APP\""
