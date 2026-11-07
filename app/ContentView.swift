//
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HeartFlow (mark-cell-520)
//
import SwiftUI

struct ContentView: View {
    @StateObject private var ctrl = DriverController()

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {

            // ---- 顶部：标题 + 设备状态 ----
            HStack {
                Image(systemName: "wifi")
                    .font(.title)
                Text("AIC8800 WiFi")
                    .font(.title2).bold()
                Spacer()
                StageBadge(stage: ctrl.stage)
                Button("刷新状态") { ctrl.refreshStatus() }
                    .disabled(ctrl.busy)
            }

            Divider()

            // ---- 输入区 ----
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text("SSID").frame(width: 64, alignment: .trailing)
                    TextField("热点名称", text: $ctrl.ssid)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 320)
                }
                GridRow {
                    Text("密码").frame(width: 64, alignment: .trailing)
                    SecureField("WiFi 密码", text: $ctrl.password)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 320)
                }
            }

            // ---- 操作区 ----
            HStack(spacing: 12) {
                Button(action: { ctrl.connect() }) {
                    Label(ctrl.busy ? "连接中…" : "一键连接", systemImage: "bolt.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(ctrl.busy || ctrl.ssid.isEmpty)

                Button("终止") { ctrl.cancel() }
                    .disabled(!ctrl.busy)

                Spacer()

                if ctrl.progress.airAck {
                    Label("空口 ACK 已确认", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                        .font(.caption)
                }
            }

            // ---- 握手进度 ----
            HandshakeBar(progress: ctrl.progress)
                .padding(.vertical, 4)

            Divider()

            // ---- 日志 ----
            HStack {
                Text("日志").font(.headline)
                Spacer()
                Text(ctrl.statusText).font(.caption).foregroundStyle(.secondary)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(ctrl.logs) { line in
                            Text(line.text)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(color(for: line.level))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(line.id)
                        }
                    }
                    .padding(6)
                }
                .background(Color(NSColor.textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .onChange(of: ctrl.logs.count) { _ in
                    if let last = ctrl.logs.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }

            if let err = ctrl.lastError {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
            }
        }
        .padding(16)
        .frame(minWidth: 720, minHeight: 560)
        .onAppear { ctrl.refreshStatus() }
    }

    private func color(for level: DriverController.LogLine.Level) -> Color {
        switch level {
        case .info: return .primary
        case .ok:   return .green
        case .warn: return .orange
        case .err:  return .red
        case .step: return .blue
        }
    }
}

/// 设备阶段徽章
struct StageBadge: View {
    let stage: DeviceStage
    var body: some View {
        let (text, color): (String, Color) = {
            switch stage {
            case .unknown: return ("未识别", .gray)
            case .disc:    return ("光驱态·需授权", .orange)
            case .rom:     return ("Boot ROM", .blue)
            case .running: return ("运行态", .green)
            }
        }()
        Text(text)
            .font(.caption).bold()
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}

/// 四路握手进度条：关联 + Msg1..4
struct HandshakeBar: View {
    let progress: HandshakeProgress
    private let steps: [(String, Bool)] = []

    var body: some View {
        let items: [(String, Bool)] = [
            ("关联", progress.associated),
            ("Msg1", progress.msg1),
            ("Msg2", progress.msg2),
            ("Msg3", progress.msg3),
            ("Msg4", progress.msg4),
        ]
        HStack(spacing: 6) {
            ForEach(Array(items.enumerated()), id: \.offset) { idx, item in
                HStack(spacing: 4) {
                    Image(systemName: item.1 ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(item.1 ? Color.green : Color.secondary)
                    Text(item.0).font(.caption)
                }
                if idx < items.count - 1 {
                    Rectangle()
                        .fill(item.1 ? Color.green : Color.secondary.opacity(0.3))
                        .frame(height: 2)
                        .frame(maxWidth: 28)
                }
            }
            Spacer()
            if progress.completed {
                Image(systemName: "wifi.circle.fill")
                    .foregroundStyle(.green)
            }
        }
    }
}

#Preview {
    ContentView()
}
