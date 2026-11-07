//
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HeartFlow (mark-cell-520)
//
import Foundation
import Combine

/// 设备阶段（对应 aic8800-tool status 输出）
enum DeviceStage: String {
    case unknown = "未识别"
    case disc    = "光驱态(1111:1111)"     // 需提权模式切换
    case rom     = "Boot ROM(8d80)"        // 可免 root 上传固件
    case running = "运行态(8d81)"          // 可直接连接

    var needsPrivileged: Bool { self == .disc }
}

/// 四路握手进度
struct HandshakeProgress {
    var associated = false      // SM_CONNECT_IND status=0
    var msg1 = false            // 收到 Msg1
    var msg2 = false            // 已发 Msg2
    var msg3 = false            // 收到 Msg3
    var msg4 = false            // 已发 Msg4
    var airAck = false          // DATA_CFM payload 首位 09 = AP 已 ACK
    var completed = false       // 连接建立完成

    var doneCount: Int {
        ([associated, msg1, msg2, msg3, msg4] as [Bool]).filter { $0 }.count
    }
}

/// 驱动控制器：管进程生命周期、输出解析、状态机。
/// 所有子进程输出逐行读入 @Published 属性，驱动 UI。
/// 子进程输出缓冲（readabilityHandler 在后台线程回调，需加锁）
private final class DataBuffer {
    private var data = Data()
    private let lock = NSLock()
    func append(_ d: Data) { lock.lock(); data.append(d); lock.unlock() }
    func contents() -> Data { lock.lock(); defer { lock.unlock() }; return data }
}

final class DriverController: ObservableObject {
    @Published var stage: DeviceStage = .unknown
    @Published var ssid = ""
    @Published var password = ""
    @Published var busy = false
    @Published var logs: [LogLine] = []
    @Published var progress = HandshakeProgress()
    @Published var statusText = "就绪"
    @Published var lastError: String?

    struct LogLine: Identifiable, Equatable {
        let id = UUID()
        let text: String
        let level: Level
        enum Level: String { case info, ok, warn, err, step }
        static func == (l: LogLine, r: LogLine) -> Bool { l.id == r.id }
    }

    private var process: Process?
    private let queue = DispatchQueue(label: "aic8800.driver")

    /// app bundle 内的资源根（scripts/ 在 bundle 外时回退到开发目录）
    private var resourceRoot: URL {
        if let r = Bundle.main.resourceURL { return r }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    }

    // MARK: - 设备状态

    func refreshStatus() {
        queue.async { [weak self] in
            guard let self else { return }
            let tool = self.resourceRoot.appendingPathComponent("aic8800-tool").path
            let out = self.run(tool, args: ["status"], timeout: 8).output
            let stage = self.parseStage(out)
            DispatchQueue.main.async {
                self.stage = stage
                if !out.isEmpty { self.append(out, level: .info) }
            }
        }
    }

    private func parseStage(_ text: String) -> DeviceStage {
        if text.contains("1111:1111") || text.contains("大容量存储") { return .disc }
        if text.contains("8d80") || text.contains("Boot ROM") { return .rom }
        if text.contains("8d81") || text.contains("8d83") || text.contains("运行") { return .running }
        return .unknown
    }

    // MARK: - 一键连接

    func connect() {
        guard !ssid.isEmpty else { lastError = "请填写 SSID"; return }
        guard !busy else { return }
        busy = true
        progress = HandshakeProgress()
        logs.removeAll()
        lastError = nil
        statusText = "检测设备…"
        queue.async { [weak self] in self?.runPipeline() }
    }

    private func runPipeline() {
        // 1) 提权模式切换（仅光驱态需要）
        if self.stage.needsPrivileged {
            self.onMain { self.statusText = "等待授权（模式切换需 root）…" }
            let ok = self.privilegedModeSwitch()
            guard ok else {
                self.onMain {
                    self.busy = false
                    self.statusText = "已取消或授权失败"
                    self.append("模式切换未完成（用户取消或认证失败）", level: .err)
                    self.lastError = "模式切换需要管理员授权"
                }
                return
            }
            self.onMain { self.stage = .rom }
        }

        // 2) 免 root：上传固件（如需）+ WPA2 连接
        self.onMain { self.statusText = "上传固件 / 连接中…" }
        let script = self.resourceRoot.appendingPathComponent("scripts/connect.sh").path
        // 最小环境：不全量继承 app 的环境变量（缩小敏感变量暴露面），
        // 只带脚本/工具运行必需的三项 + 业务参数。
        var env: [String: String] = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin",
            "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
            "AIC_SSID": self.ssid,
            "AIC_PASS": self.password,          // 只进环境变量，不进命令行
        ]
        let result = self.run(script, args: [], env: env, timeout: 240, streaming: true)

        self.onMain {
            self.busy = false
            if result.exitCode == 0 {
                self.statusText = "已完成"
                self.progress.completed = true
            } else if result.exitCode == 2 {
                self.statusText = "需要模式切换"
            } else {
                self.statusText = "失败"
                self.lastError = "connect 退出码 \(result.exitCode)"
            }
        }
    }

    /// 光驱态 -> Boot ROM：走 osascript 管理员提权，系统弹窗认证。
    /// 脚本不接密码参数，认证完全由系统完成。
    private func privilegedModeSwitch() -> Bool {
        let script = resourceRoot.appendingPathComponent("scripts/mode-switch.sh").path
        // 路径经 argv 传给 AppleScript（quoted form 处理），不在 AppleScript 源码里
        // 做字符串插值——路径含反斜杠/换行时插值会变形（虽不可注入，但会执行错路径）。
        let src = """
        on run argv
            do shell script ("bash " & quoted form of (item 1 of argv)) with administrator privileges
        end run
        """
        let out = run("/usr/bin/osascript", args: ["-e", src, "--", script], timeout: 120).output
        if !out.isEmpty { append(out, level: .info) }
        // 成功判据只认脚本输出的机器可判定行（mode-switch.sh 的 MODE_SWITCH=OK）。
        // 此前用裸子串 "8d80" 匹配——失败输出里带 8d80 也会误判成功。
        return out.contains("MODE_SWITCH=OK")
    }

    func cancel() {
        // 杀整个进程组（负 pid），连孙子进程 aic8800-tool 一起终止
        if let p = process {
            kill(-p.processIdentifier, SIGTERM)
            kill(p.processIdentifier, SIGTERM)
        }
        busy = false
        statusText = "已终止"
        append("用户终止操作", level: .warn)
    }

    // MARK: - 输出解析

    /// 主线程批量解析输出行（供 readabilityHandler 回调用）
    func parseLines(_ lines: [String]) {
        for line in lines { parseLine(line) }
    }

    private func append(_ text: String, level: LogLine.Level) {
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            logs.append(LogLine(text: String(line), level: level))
        }
        if logs.count > 800 { logs.removeFirst(logs.count - 800) }
    }

    private func parseLine(_ line: String) {
        // 阶段推进
        if line.contains("SM_CONNECT_IND") && line.contains("status=0") {
            progress.associated = true
            statusText = "已关联，等待握手…"
        }
        if line.contains("收到 Msg1/4") { progress.msg1 = true }
        if line.contains("已发 Msg2/4") { progress.msg2 = true }
        if line.contains("收到 Msg3/4") { progress.msg3 = true }
        if line.contains("已发 Msg4/4") { progress.msg4 = true }
        if line.contains("DATA_CFM") && line.contains(" 09 ") { progress.airAck = true }
        if line.contains("连接建立完成") { progress.completed = true; statusText = "已完成" }
        if line.contains("握手未完成") { lastError = "握手未完成" }

        // 日志分级
        var level: LogLine.Level = .info
        if line.contains("✅") || line.contains("完成") || line.contains("成功") { level = .ok }
        else if line.contains("❌") || line.contains("失败") || line.contains("错误") { level = .err }
        else if line.contains("⚠") || line.contains("超时") { level = .warn }
        else if line.hasPrefix("[") || line.contains("=====") { level = .step }
        append(line, level: level)
    }

    // MARK: - 进程执行

    private struct RunResult { var exitCode: Int32 = -1; var output = "" }

    /// 同步执行；streaming=true 时逐行回调（用于实时日志）
    private func run(_ path: String, args: [String], env: [String: String]? = nil,
                     timeout: TimeInterval, streaming: Bool = false) -> RunResult {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        if let env { proc.environment = env }

        let pipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = errPipe
        let buf = DataBuffer()
        let errBuf = DataBuffer()
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard !data.isEmpty else { return }
            buf.append(data)
            if streaming, let text = String(data: data, encoding: .utf8) {
                let lines = text.split(separator: "\n", omittingEmptySubsequences: true)
                    .map(String.init)
                // parseLine 会写 @Published 属性，必须回主线程（否则数据竞争/UI 崩溃）
                self?.onMain { self?.parseLines(lines) }
            }
        }
        errPipe.fileHandleForReading.readabilityHandler = { h in
            let data = h.availableData
            if !data.isEmpty { errBuf.append(data) }
        }

        let sem = DispatchSemaphore(value: 0)
        proc.terminationHandler = { _ in sem.signal() }
        do {
            try proc.run()
        } catch {
            return RunResult(exitCode: -1)
        }
        // 独立进程组：终止时连孙子进程（aic8800-tool）一起杀，
        // 否则 bash 死了工具还占着 USB 端点，后续运行报 BUSY。
        setpgid(proc.processIdentifier, 0)
        if streaming {
            DispatchQueue.main.async { self.process = proc }
        } else {
            self.process = proc
        }

        let deadline = DispatchTime.now() + timeout
        if sem.wait(timeout: deadline) == .timedOut {
            // 先停 handler 再 terminate，收尾时统一排空（否则输出丢失+fd 泄漏）
            pipe.fileHandleForReading.readabilityHandler = nil
            errPipe.fileHandleForReading.readabilityHandler = nil
            if let p = self.process { kill(-p.processIdentifier, SIGTERM); kill(p.processIdentifier, SIGTERM) }
            proc.terminate()
            let rest = pipe.fileHandleForReading.readDataToEndOfFile()
            if !rest.isEmpty { buf.append(rest) }
            return RunResult(exitCode: -2,
                             output: String(data: buf.contents(), encoding: .utf8) ?? "")
        }
        // 等管道读完再收尾（termination 后仍可能有缓冲数据）
        pipe.fileHandleForReading.readabilityHandler = nil
        errPipe.fileHandleForReading.readabilityHandler = nil
        let rest = pipe.fileHandleForReading.readDataToEndOfFile()
        if !rest.isEmpty { buf.append(rest) }
        let errRest = errPipe.fileHandleForReading.readDataToEndOfFile()
        if !errRest.isEmpty { errBuf.append(errRest) }
        var out = String(data: buf.contents(), encoding: .utf8) ?? ""
        let errText = String(data: errBuf.contents(), encoding: .utf8) ?? ""
        if !errText.isEmpty { out += errText }
        return RunResult(exitCode: proc.terminationStatus, output: out)
    }

    private func onMain(_ block: @escaping () -> Void) {
        DispatchQueue.main.async(execute: block)
    }
}
