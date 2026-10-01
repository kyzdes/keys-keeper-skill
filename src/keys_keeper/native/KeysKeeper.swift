import AppKit
import SwiftUI
import WebKit

struct AgentCount: Decodable, Identifiable {
    let id: String
    let name: String
    let count: Int
}

struct DailySummary: Decodable {
    let date: String
    let since: String
    let updated_at: String
    let total: Int
    let agent_total: Int
    let failed: Int
    let unknown: Int
    let desktop: Int
    let agents: [AgentCount]
    let last_access: String?
    let complete: Bool
}

final class ActivityModel: ObservableObject {
    @Published var summary: DailySummary?
    @Published var unavailable = false
    @Published var opening = false
    @Published var windowVisible = false
}

struct PanelMaterial: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .popover
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }
    func updateNSView(_ view: NSVisualEffectView, context: Context) {}
}

final class ActivityPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override func cancelOperation(_ sender: Any?) { orderOut(sender) }
}

final class Bridge {
    let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let queue = DispatchQueue(label: "com.kyzdes.keys-keeper.bridge")
    private var buffer = Data()
    var receive: (([String: Any]) -> Void)?
    var stopped: (() -> Void)?

    func start() throws {
        guard let python = Bundle.main.object(forInfoDictionaryKey: "KKPythonExecutable") as? String,
              let resources = Bundle.main.resourceURL else {
            throw NSError(domain: "KeysKeeper", code: 1)
        }
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = ["-u", "-m", "keys_keeper.desktop_bridge"]
        var environment = ProcessInfo.processInfo.environment
        environment["PYTHONPATH"] = resources.appendingPathComponent("python").path
        environment["PYTHONNOUSERSITE"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["KEYS_KEEPER_CALLER"] = "desktop"
        if let home = Bundle.main.object(forInfoDictionaryKey: "KKDataHome") as? String {
            environment["KEYS_KEEPER_HOME"] = home
        }
        process.environment = environment
        process.standardInput = input
        process.standardOutput = output
        // Never send capability URLs or backend exception text to system logs.
        process.standardError = FileHandle.nullDevice
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self = self else { return }
            if data.isEmpty { handle.readabilityHandler = nil; return }
            self.queue.async {
                self.buffer.append(data)
                while let end = self.buffer.firstIndex(of: 10) {
                    let line = self.buffer.prefix(upTo: end)
                    self.buffer.removeSubrange(...end)
                    if let message = try? JSONSerialization.jsonObject(with: line) as? [String: Any] {
                        DispatchQueue.main.async { self.receive?(message) }
                    }
                }
            }
        }
        process.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async { self?.stopped?() }
        }
        try process.run()
    }

    func send(_ command: String, page: String? = nil) {
        guard process.isRunning else { return }
        var request = ["command": command]
        if let page = page { request["page"] = page }
        guard var data = try? JSONSerialization.data(withJSONObject: request) else { return }
        data.append(10)
        try? input.fileHandleForWriting.write(contentsOf: data)
    }

    func stop() {
        stopped = nil
        output.fileHandleForReading.readabilityHandler = nil
        send("quit")
        try? input.fileHandleForWriting.close()
        let child = process
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
            if child.isRunning { child.terminate() }
        }
    }
}

struct ActivityView: View {
    @ObservedObject var model: ActivityModel
    let toggleWindow: () -> Void
    let openAudit: () -> Void
    let refresh: () -> Void
    let quit: () -> Void
    @Environment(\.colorScheme) private var colorScheme

    private var accent: Color {
        colorScheme == .dark ? Color(red: 0.85, green: 0.46, blue: 0.31)
                            : Color(red: 0.67, green: 0.27, blue: 0.16)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "key.horizontal").font(.system(size: 22, weight: .medium))
                    .foregroundStyle(accent).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Keys Keeper").font(.system(size: 16, weight: .semibold))
                    Text("На этом Mac").font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
                Button(action: refresh) {
                    Image(systemName: "arrow.clockwise").frame(width: 26, height: 26)
                }.buttonStyle(.borderless).help("Обновить статистику")
                    .accessibilityLabel("Обновить статистику")
            }.padding(.bottom, 22)

            HStack(alignment: .firstTextBaseline) {
                Text("Обращения агентов").font(.system(size: 14, weight: .medium))
                Spacer()
                Text(model.unavailable ? "—" : model.summary.map { String($0.agent_total) } ?? "—")
                    .font(.system(size: 30, weight: .semibold, design: .rounded))
                    .monospacedDigit()
            }
            Text("Сегодня, с 00:00").font(.system(size: 12)).foregroundStyle(.secondary)
                .padding(.top, 2).padding(.bottom, 14)

            if let summary = model.summary, !model.unavailable {
                if summary.agents.isEmpty {
                    Text("Обращений с определённым агентом пока нет.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true).padding(.bottom, 10)
                } else {
                    ForEach(summary.agents) { agent in
                        statistic(agent.name, value: agent.count, icon: "terminal")
                    }
                }
                Divider().padding(.vertical, 10)
                statistic("Все обращения", value: summary.total)
                statistic("Источник не определён", value: summary.unknown)
                    .help("Старые записи и вызовы без признака агента. По одной оболочке zsh определить агента нельзя.")
                if summary.desktop > 0 { statistic("Из приложения", value: summary.desktop) }
                statistic("С ошибкой", value: summary.failed)
                if !summary.complete {
                    Label("Журнал прочитан не полностью", systemImage: "exclamationmark.triangle")
                        .font(.system(size: 12)).foregroundStyle(.orange).padding(.top, 9)
                }
            } else if !model.unavailable {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Читаем журнал обращений…").font(.system(size: 12)).foregroundStyle(.secondary)
                }.padding(.vertical, 12)
            }

            if model.unavailable {
                Text("Не удалось обновить данные. Нажмите «Обновить».")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true).padding(.top, 10)
            }
            Text("Считаются операции с ключами. Источник определяется по признакам запуска.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true).padding(.top, 12)

            Divider().padding(.vertical, 14)
            Button(action: toggleWindow) {
                HStack {
                    Image(systemName: model.windowVisible ? "rectangle.compress.vertical" : "macwindow")
                    Text(model.opening ? "Открываем…" : (model.windowVisible ? "Скрыть окно" : "Открыть Keys Keeper"))
                    Spacer()
                    Text("⌘O").font(.system(size: 11)).opacity(0.8)
                }.padding(.vertical, 5).frame(maxWidth: .infinity)
            }.buttonStyle(.borderedProminent).tint(accent).disabled(model.opening)
                .keyboardShortcut("o", modifiers: .command)
            HStack {
                Button("Журнал обращений", action: openAudit).buttonStyle(.link)
                Spacer()
                Button("Выйти", action: quit).buttonStyle(.link)
                    .keyboardShortcut("q", modifiers: .command)
            }.font(.system(size: 12)).padding(.top, 12)
        }.padding(20).frame(width: 356).fixedSize(horizontal: false, vertical: true)
            .background(PanelMaterial()).clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func statistic(_ label: String, value: Int, icon: String? = nil) -> some View {
        HStack(spacing: 8) {
            if let icon = icon { Image(systemName: icon).foregroundStyle(.secondary).accessibilityHidden(true) }
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(String(value)).monospacedDigit().fontWeight(.medium)
        }.font(.system(size: 13)).padding(.vertical, 5)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate {
    private let model = ActivityModel()
    private var statusItem: NSStatusItem!
    private var activityPanel: ActivityPanel!
    private var window: NSWindow?
    private var webView: WKWebView?
    private var bridge: Bridge?
    private var timer: Timer?
    private var allowedPort: Int?
    private var serverCapability: String?
    private var pendingPage: String?
    private var requestedPage = "home"
    private var openRequest = 0

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenu()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.autosaveName = "KeysKeeperStatusItem"
        if let button = statusItem.button {
            let icon = NSImage(systemSymbolName: "key.horizontal", accessibilityDescription: "Keys Keeper")
            icon?.isTemplate = true
            button.image = icon
            button.imagePosition = .imageLeading
            button.target = self
            button.action = #selector(togglePopover)
            button.toolTip = "Keys Keeper — обращения агентов за сегодня"
        }
        activityPanel = ActivityPanel(contentRect: NSRect(x: 0, y: 0, width: 356, height: 420),
                                      styleMask: [.borderless], backing: .buffered, defer: false)
        activityPanel.title = "Keys Keeper — статистика"
        activityPanel.isOpaque = false
        activityPanel.backgroundColor = .clear
        activityPanel.hasShadow = true
        activityPanel.level = .popUpMenu
        activityPanel.isReleasedWhenClosed = false
        activityPanel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        activityPanel.delegate = self
        activityPanel.contentViewController = NSHostingController(rootView: ActivityView(
            model: model,
            toggleWindow: { [weak self] in self?.toggleWindow() },
            openAudit: { [weak self] in self?.openWindow(page: "audit") },
            refresh: { [weak self] in self?.refresh() },
            quit: { NSApplication.shared.terminate(nil) }
        ))
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in self?.refresh() }
        // First launch introduces the menu bar panel. Start the admin server
        // only when the owner chooses to open the vault window.
        DispatchQueue.main.async { [weak self] in self?.togglePopover() }
    }

    private func setupMenu() {
        let menu = NSMenu()
        let appMenu = NSMenu()
        let statistics = appMenu.addItem(withTitle: "Статистика за сегодня", action: #selector(togglePopover), keyEquivalent: "k")
        statistics.target = self
        statistics.keyEquivalentModifierMask = [.command, .shift]
        appMenu.addItem(withTitle: "Открыть / скрыть Keys Keeper", action: #selector(toggleWindow), keyEquivalent: "o").target = self
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Выйти из Keys Keeper", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let appItem = NSMenuItem()
        appItem.submenu = appMenu
        menu.addItem(appItem)
        let edit = NSMenu(title: "Правка")
        for (title, action, key) in [("Отменить", "undo:", "z"), ("Вырезать", "cut:", "x"),
                                     ("Копировать", "copy:", "c"), ("Вставить", "paste:", "v"),
                                     ("Выбрать всё", "selectAll:", "a")] {
            edit.addItem(withTitle: title, action: Selector(action), keyEquivalent: key)
        }
        let editItem = NSMenuItem(title: "Правка", action: nil, keyEquivalent: "")
        editItem.submenu = edit
        menu.addItem(editItem)
        NSApplication.shared.mainMenu = menu
    }

    @objc private func togglePopover() {
        if activityPanel.isVisible { activityPanel.orderOut(nil); return }
        model.windowVisible = window?.isVisible == true && window?.isMiniaturized == false
        refresh()
        NSApplication.shared.activate(ignoringOtherApps: true)
        // A retained panel also works when macOS has hidden the status item
        // behind a crowded menu bar. App-menu and keyboard access stay usable.
        DispatchQueue.main.async { [weak self] in
            self?.sizeActivityPanel()
            self?.activityPanel.makeKeyAndOrderFront(nil)
        }
    }

    private func sizeActivityPanel() {
        guard let view = activityPanel.contentView else { return }
        view.layoutSubtreeIfNeeded()
        let screen = statusItem.button?.window?.screen ?? NSScreen.main ?? NSScreen.screens.first
        guard let screen = screen else { return }
        let available = screen.visibleFrame
        let height = min(max(view.fittingSize.height, 260), available.height - 28)
        var right = available.maxX - 14
        var top = available.maxY - 8
        if let button = statusItem.button, let anchor = button.window, anchor.isVisible,
           !button.visibleRect.intersection(button.bounds).isEmpty {
            let rect = anchor.convertToScreen(button.convert(button.bounds, to: nil))
            if rect.intersects(screen.frame) { right = rect.maxX; top = min(top, rect.minY - 6) }
        }
        let left = max(available.minX + 14, min(right - 356, available.maxX - 370))
        activityPanel.setFrame(NSRect(x: left, y: top - height, width: 356, height: height), display: true)
    }

    private func ensureBridge() -> Bool {
        if bridge?.process.isRunning == true { return true }
        allowedPort = nil
        serverCapability = nil
        let worker = Bridge()
        worker.receive = { [weak self, weak worker] message in
            guard let self = self, self.bridge === worker else { return }
            self.receive(message)
        }
        worker.stopped = { [weak self, weak worker] in
            guard let self = self, self.bridge === worker else { return }
            self.allowedPort = nil
            self.serverCapability = nil
            self.statisticsUnavailable()
            if self.model.opening { self.openingFailed() }
        }
        do {
            try worker.start()
            bridge = worker
            return true
        } catch {
            statisticsUnavailable()
            model.opening = false
            return false
        }
    }

    private func refresh() {
        if ensureBridge() { bridge?.send("summary") }
    }

    private func statisticsUnavailable() {
        model.unavailable = true
        statusItem.button?.title = " —"
        statusItem.button?.toolTip = "Keys Keeper — статистика недоступна"
        DispatchQueue.main.async { [weak self] in
            if self?.activityPanel.isVisible == true { self?.sizeActivityPanel() }
        }
    }

    private func receive(_ message: [String: Any]) {
        switch message["type"] as? String {
        case "summary":
            if let payload = message["summary"],
               let data = try? JSONSerialization.data(withJSONObject: payload),
               let summary = try? JSONDecoder().decode(DailySummary.self, from: data) {
                model.summary = summary
                model.unavailable = false
                statusItem.button?.title = " \(summary.agent_total)"
                statusItem.button?.toolTip = "Keys Keeper · сегодня: \(summary.agent_total) обращений агентов, \(summary.total) всего"
                DispatchQueue.main.async { [weak self] in
                    if self?.activityPanel.isVisible == true { self?.sizeActivityPanel() }
                }
            }
        case "open":
            guard let raw = message["url"] as? String,
                  let url = URL(string: raw), url.scheme == "http", url.host == "127.0.0.1",
                  let port = url.port, port > 0,
                  let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let token = parts.queryItems?.first(where: { $0.name == "t" })?.value,
                  token.count == 64, token.allSatisfy({ $0.isHexDigit }) else {
                openingFailed()
                return
            }
            let reuse = message["page"] as? String == "home" && serverCapability == token
                        && webView?.url?.port == port
            allowedPort = port
            serverCapability = token
            pendingPage = message["page"] as? String
            if reuse, let window = window {
                pendingPage = nil
                model.opening = false
                if window.isMiniaturized { window.deminiaturize(nil) }
                window.makeKeyAndOrderFront(nil)
                NSApplication.shared.activate(ignoringOtherApps: true)
                model.windowVisible = true
            } else { showWebWindow(url) }
        default:
            if message["command"] as? String == "open" { openingFailed() }
            else { statisticsUnavailable() }
        }
    }

    @objc private func toggleWindow() {
        if window?.isVisible == true && window?.isMiniaturized == false {
            window?.orderOut(nil)
            model.windowVisible = false
        } else { openWindow(page: "home") }
        activityPanel.orderOut(nil)
    }

    private func openWindow(page: String) {
        activityPanel.orderOut(nil)
        requestedPage = page
        // Ask the bridge to verify its server is alive before reusing the page.
        // The matching capability in the response preserves unfinished input;
        // a replacement listener always bootstraps a fresh web session.
        guard ensureBridge() else { showFailure(); return }
        model.opening = true
        openRequest += 1
        let request = openRequest
        bridge?.send("open", page: page)
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self = self, self.model.opening, self.openRequest == request else { return }
            self.openingFailed()
        }
    }

    private func showWebWindow(_ url: URL) {
        if window == nil {
            let config = WKWebViewConfiguration()
            config.websiteDataStore = .nonPersistent()
            let view = WKWebView(frame: .zero, configuration: config)
            view.navigationDelegate = self
            view.uiDelegate = self
            let shell = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1120, height: 780),
                                 styleMask: [.titled, .closable, .miniaturizable, .resizable],
                                 backing: .buffered, defer: false)
            shell.title = "Keys Keeper"
            shell.minSize = NSSize(width: 820, height: 580)
            shell.contentView = view
            shell.isReleasedWhenClosed = false
            shell.delegate = self
            shell.setFrameAutosaveName("KeysKeeperMainWindow")
            shell.center()
            window = shell
            webView = view
        }
        webView?.load(URLRequest(url: url))
        if window?.isMiniaturized == true { window?.deminiaturize(nil) }
        window?.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        model.windowVisible = true
    }

    private func showFailure() {
        let alert = NSAlert()
        alert.messageText = "Не удалось открыть Keys Keeper"
        alert.informativeText = "Проверьте установку Keys Keeper CLI и попробуйте открыть окно ещё раз."
        alert.addButton(withTitle: "Повторить")
        alert.addButton(withTitle: "Закрыть")
        if alert.runModal() == .alertFirstButtonReturn {
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.openWindow(page: self.requestedPage)
            }
        }
    }

    private func openingFailed() {
        model.opening = false
        allowedPort = nil
        serverCapability = nil
        showFailure()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        if sender === window { model.windowVisible = false }
        return false
    }

    func windowDidResignKey(_ notification: Notification) {
        if notification.object as? NSWindow === activityPanel { activityPanel.orderOut(nil) }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openWindow(page: "home")
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
        bridge?.stop()
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url,
              url.scheme == "http", url.host == "127.0.0.1", url.port == allowedPort else {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if pendingPage == "audit", let port = allowedPort {
            pendingPage = nil
            webView.load(URLRequest(url: URL(string: "http://127.0.0.1:\(port)/audit")!))
        } else { pendingPage = nil; model.opening = false }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if (error as NSError).code == NSURLErrorCancelled { return }
        if model.opening { openingFailed() }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        if model.opening { openingFailed() }
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "Подтвердить")
        alert.addButton(withTitle: "Отмена")
        completionHandler(alert.runModal() == .alertFirstButtonReturn)
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "Понятно")
        alert.runModal()
        completionHandler()
    }

    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.begin { result in completionHandler(result == .OK ? panel.urls : nil) }
    }
}

let application = NSApplication.shared
let appDelegate = AppDelegate()
application.delegate = appDelegate
application.setActivationPolicy(.accessory)
application.run()
