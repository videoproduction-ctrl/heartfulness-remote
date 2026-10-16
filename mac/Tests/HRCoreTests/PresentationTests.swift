import XCTest
@testable import HRCore

/// Payloads exactly as the Go agent marshals them (agent/internal/core/types.go,
/// agent/internal/accesslog/log.go), plus the plain-language presentation layer.
final class GoPayloadTests: XCTestCase {
    private func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try JSONDecoder().decode(type, from: Data(json.utf8))
    }

    func testStateAsMarshalledByGo() throws {
        // core.State: serverError/setupURL omitted when empty, sas pre-formatted ("196 924"),
        // lastUsed 0 = never, fingerprint on devices and session device, session codec.
        let json = """
        {"server":"online","claimed":true,"killed":false,
         "session":{"device":{"pub":"cHVi","name":"iPhone","kind":"browser","fingerprint":"aaaa-bbbb-cccc-dddd"},
                    "since":1760000000,"transport":"relay","rttMs":42,"codec":"h264"},
         "pending":[{"requestId":"EBESExQVFhcYGRobHB0eHw","name":"Office PC","kind":"app","sas":"196 924","expiresAt":1760000300}],
         "devices":[{"pub":"cHVi","name":"iPhone","kind":"browser","addedAt":1759990000,"lastUsed":0,"fingerprint":"aaaa-bbbb-cccc-dddd"}]}
        """
        let s = try decode(AgentState.self, json)
        XCTAssertEqual(s.server, .online)
        XCTAssertNil(s.serverError)
        XCTAssertNil(s.setupURL)
        let session = try XCTUnwrap(s.session)
        XCTAssertEqual(session.codec, "h264")
        XCTAssertEqual(session.rttMs, 42)
        XCTAssertEqual(session.device.fingerprint, "aaaa-bbbb-cccc-dddd")
        XCTAssertEqual(SessionText.connectionLine(session), "Through your relay server · 42 ms · H.264")
        XCTAssertEqual(s.pending.first?.sas, "196 924")
        XCTAssertEqual(SASFormatter.format(s.pending[0].sas), "196 924")
        XCTAssertEqual(s.devices.first?.fingerprint, "aaaa-bbbb-cccc-dddd")
        XCTAssertNil(s.devices.first?.lastUsed, "0 means never used")
        XCTAssertEqual(s.devices.first?.addedAt?.date, Date(timeIntervalSince1970: 1_759_990_000))
    }

    func testStateWithoutSession() throws {
        let s = try decode(AgentState.self, #"{"server":"connecting","claimed":false,"killed":true,"session":null,"pending":[],"devices":[]}"#)
        XCTAssertEqual(s.server, .connecting)
        XCTAssertTrue(s.killed)
        XCTAssertNil(s.session)
    }

    func testEventAsMarshalledByGo() throws {
        let e = try decode(AgentEvent.self, #"{"event":"pair-request","device":{"pub":"cHVi","name":"Office PC","kind":"app","fingerprint":"aaaa-bbbb"},"detail":"196 924"}"#)
        XCTAssertEqual(e.name, .pairRequest)
        XCTAssertEqual(e.device?.fingerprint, "aaaa-bbbb")
        XCTAssertEqual(e.detailText, "196 924")
        let killed = try decode(AgentEvent.self, #"{"event":"killed","detail":"on this Mac"}"#)
        XCTAssertNil(killed.device)
        XCTAssertEqual(killed.detailText, "on this Mac")
    }

    func testEncoderCommandsAsMarshalledByGo() throws {
        // core.EncoderCmd uses omitempty everywhere; HEVC sessions send profile "main".
        let start = try decode(EncoderCommand.self, #"{"cmd":"start","codec":"h265","profile":"main","fps":60,"kbps":12000,"display":69734272}"#)
        XCTAssertEqual(start.action, .start(codec: .h265, fps: 60, kbps: 12000, display: 69_734_272, profile: .high))
        let base = try decode(EncoderCommand.self, #"{"cmd":"start","codec":"h264","profile":"baseline","fps":30,"kbps":3000}"#)
        XCTAssertEqual(base.action, .start(codec: .h264, fps: 30, kbps: 3000, display: nil, profile: .baseline))
        let bitrate = try decode(EncoderCommand.self, #"{"cmd":"bitrate","fps":30,"kbps":3500}"#)
        XCTAssertEqual(bitrate.action, .bitrate(kbps: 3500))
        let display = try decode(EncoderCommand.self, #"{"cmd":"display","id":2}"#)
        XCTAssertEqual(display.action, .display(id: 2))
    }

    func testInputAsMarshalledByGo() throws {
        let m = try decode(InputMessage.self, #"{"t":"b","b":0,"d":true,"x":0.5,"y":0.25,"display":69734272}"#)
        XCTAssertEqual(m.kind, .button)
        XCTAssertEqual(m.displayID, 69_734_272)
        let reset = try decode(InputMessage.self, #"{"t":"reset","display":0}"#)
        XCTAssertEqual(reset.kind, .reset)
        XCTAssertNil(reset.displayID)
    }

    func testSignRequestFromGo() throws {
        let r = try decode(SignRequest.self, #"{"id":18446744073709551,"data":"SFIxL2NlcnQA"}"#)
        XCTAssertEqual(r.id, .int(18_446_744_073_709_551))
        let out = try JSONSerialization.jsonObject(with: HRJSON.encode(SignResult(id: r.id, sig: "c2ln"))) as? [String: Any]
        XCTAssertEqual((out?["id"] as? NSNumber)?.int64Value, 18_446_744_073_709_551)
    }

    func testAccessLogAsWrittenByGo() throws {
        let json = """
        {"entries":[
          {"seq":1,"ts":1760000000,"event":"session-start","device":"iPhone","deviceFp":"aaaa-bbbb","transport":"relay","prev":"x","mac":"y"},
          {"seq":2,"ts":1760000600,"event":"session-end","device":"iPhone","deviceFp":"aaaa-bbbb","transport":"relay","durationSec":600,"detail":"host-disconnected","prev":"x","mac":"y"},
          {"seq":3,"ts":1760000700,"event":"file-received","device":"iPhone","file":"cut-v3.mov","size":2048,"prev":"x","mac":"y"},
          {"seq":4,"ts":1760000800,"event":"log-tamper-detected","detail":"line 3: mac mismatch","prev":"x","mac":"y"}
        ],"verified":true}
        """
        let log = try decode(LogResult.self, json)
        XCTAssertTrue(log.verified)
        let rows = log.displayEntries
        XCTAssertEqual(rows.map { $0.id }, [4, 3, 2, 1])
        XCTAssertEqual(Set(rows.map { $0.id }).count, rows.count, "ids must be unique for the table")

        XCTAssertEqual(rows[0].title, "Warning: log changed outside the app")
        XCTAssertTrue(rows[0].isWarning)
        XCTAssertEqual(rows[0].summary, "line 3: mac mismatch")

        XCTAssertEqual(rows[1].title, "File received")
        XCTAssertEqual(rows[1].file, "cut-v3.mov")
        XCTAssertEqual(rows[1].size, 2048)
        XCTAssertTrue(rows[1].summary.hasPrefix("cut-v3.mov ("))

        XCTAssertEqual(rows[2].title, "Disconnected")
        XCTAssertEqual(rows[2].durationSeconds, 600)
        XCTAssertEqual(rows[2].summary, "Through your relay server · 10 min · you disconnected it on this Mac")

        XCTAssertEqual(rows[3].title, "Connected")
        XCTAssertEqual(rows[3].device, "iPhone")
        XCTAssertEqual(rows[3].deviceFingerprint, "aaaa-bbbb")
        XCTAssertEqual(rows[3].time, Date(timeIntervalSince1970: 1_760_000_000))
        XCTAssertEqual(rows[3].summary, "Through your relay server")
        XCTAssertFalse(rows[3].isWarning)
    }

    func testResetTrustStoreCommand() throws {
        let o = try XCTUnwrap(JSONSerialization.jsonObject(with: HRJSON.encode(AgentCommand.resetTrustStore)) as? [String: Any])
        XCTAssertEqual(o["cmd"] as? String, "reset-trust-store")
        XCTAssertEqual(o.count, 1)
    }

    func testLocalhostRuleMatchesAgent() {
        XCTAssertTrue(ServerAddress.isLocalhost("localhost"))
        XCTAssertTrue(ServerAddress.isLocalhost("127.0.0.1"))
        XCTAssertTrue(ServerAddress.isLocalhost("127.1.2.3"))
        XCTAssertTrue(ServerAddress.isLocalhost("::1"))
        XCTAssertFalse(ServerAddress.isLocalhost("127.0.0.256"))
        XCTAssertFalse(ServerAddress.isLocalhost("foo.localhost"))
        XCTAssertFalse(ServerAddress.isLocalhost("10.0.0.1"))
        if case .failure(let e) = ServerAddress.normalize("http://foo.localhost:8080") {
            XCTAssertEqual(e, .insecure)
        } else {
            XCTFail("http://foo.localhost must be refused (the agent refuses it too)")
        }
        XCTAssertEqual(try ServerAddress.normalize("heartfulness-remote.duckdns.org").get(), "https://heartfulness-remote.duckdns.org")
    }
}

final class PresentationTests: XCTestCase {
    private let server = "https://heartfulness-remote.duckdns.org"

    private func summary(_ state: AgentState, running: Bool = true, server: String? = nil, problem: String? = nil) -> HostStatusSummary {
        HostStatusSummary.make(state: state, agentRunning: running, serverAddress: server ?? self.server, problem: problem)
    }

    func testStatusPrecedence() {
        XCTAssertEqual(summary(AgentState(), server: "").kind, .offline)
        XCTAssertTrue(summary(AgentState(), server: "").detail.contains("server address"))
        XCTAssertEqual(summary(AgentState(server: .online, claimed: true), running: false).detail, "Starting…")

        let online = summary(AgentState(server: .online, claimed: true))
        XCTAssertEqual(online.kind, .online)
        XCTAssertEqual(online.title, "Your Mac is ready")
        XCTAssertTrue(online.detail.contains("heartfulness-remote.duckdns.org"))

        let unclaimed = summary(AgentState(server: .online, claimed: false))
        XCTAssertEqual(unclaimed.kind, .online)
        XCTAssertTrue(unclaimed.detail.contains("pair your phone"))

        let session = SessionInfo(device: DeviceRef(name: "iPad"))
        let connected = summary(AgentState(server: .online, claimed: true, session: session))
        XCTAssertEqual(connected.kind, .connected)
        XCTAssertEqual(connected.title, "iPad is connected")

        let blocked = summary(AgentState(server: .online, claimed: true, killed: true, session: session))
        XCTAssertEqual(blocked.kind, .blocked)
        XCTAssertEqual(blocked.title, "Connections blocked")

        XCTAssertEqual(summary(AgentState(server: .connecting)).title, HostStatusSummary.offlineTitle)
        XCTAssertEqual(summary(AgentState(server: .connecting)).detail, "Connecting to heartfulness-remote.duckdns.org…")
        XCTAssertEqual(summary(AgentState(server: .offline)).kind, .offline)

        let claimedElsewhere = summary(AgentState(server: .error, serverError: "already-claimed"))
        XCTAssertEqual(claimedElsewhere.kind, .offline)
        XCTAssertTrue(claimedElsewhere.detail.contains("already set up"))

        let tampered = summary(AgentState(server: .error, serverError: "trust-store-tampered", killed: true))
        XCTAssertEqual(tampered.kind, .attention)

        XCTAssertEqual(summary(AgentState(server: .online, claimed: true), problem: "Keychain locked").kind, .attention)
    }

    func testServerErrorTexts() {
        for code in ["already-claimed", "host-not-allowed", "bad-signature", "too-many-pending", "replaced",
                     "rate-limited", "auth-timeout", "trust-store-tampered", "trust-store-host-mismatch",
                     "trust-store-error", "server-error", "", "something-new"] {
            XCTAssertFalse(ServerErrorText.message(for: code).isEmpty, code)
        }
        XCTAssertTrue(ServerErrorText.isTrustStoreProblem("trust-store-host-mismatch"))
        XCTAssertFalse(ServerErrorText.isTrustStoreProblem("already-claimed"))
        XCTAssertTrue(ServerErrorText.message(for: "something-new").contains("something-new"))
    }

    func testSessionTexts() {
        XCTAssertEqual(SessionText.endReason("idle"), "there was no activity for a while")
        XCTAssertEqual(SessionText.endReason("client:user"), "the other device ended it")
        XCTAssertNil(SessionText.endReason("weird"))
        XCTAssertNil(SessionText.endReason(nil))
        XCTAssertEqual(SessionText.duration(seconds: 20), "20 s")
        XCTAssertEqual(SessionText.duration(seconds: 75), "1 min")
        XCTAssertEqual(SessionText.duration(seconds: 3600), "1 h")
        XCTAssertEqual(SessionText.duration(seconds: 3725), "1 h 2 min")
        XCTAssertEqual(SessionText.connectionLine(SessionInfo(device: DeviceRef(name: "x"), transport: "direct")), "Direct connection")
    }

    func testSettingsTexts() {
        XCTAssertEqual(SettingsText.idle(minutes: 5), "5 minutes")
        XCTAssertEqual(SettingsText.idle(minutes: 30), "30 minutes")
        XCTAssertEqual(SettingsText.idle(minutes: 60), "1 hour")
        XCTAssertEqual(SettingsText.idle(minutes: 90), "1 hour 30 minutes")
        XCTAssertEqual(SettingsText.idle(minutes: 120), "2 hours")
        XCTAssertEqual(SettingsText.bitrate(kbps: 20_000), "20 Mbit/s")
        XCTAssertEqual(SettingsText.bitrate(kbps: 2_500), "2.5 Mbit/s")
        XCTAssertEqual(SettingsText.bitrate(kbps: 800), "800 kbit/s")
        for minutes in HostSettings.idleTimeoutChoices { XCTAssertFalse(SettingsText.idle(minutes: minutes).isEmpty) }
    }

    func testDeviceKinds() {
        XCTAssertEqual(DeviceKindText.label("browser"), "Web browser")
        XCTAssertEqual(DeviceKindText.label("app"), "Heartfulness Remote app")
        XCTAssertEqual(DeviceKindText.label("?"), "Device")
        XCTAssertTrue(DeviceKindText.isBrowser("browser"))
        XCTAssertTrue(DeviceKindText.isBrowser("phone"))
        XCTAssertFalse(DeviceKindText.isBrowser("app"))
    }

    func testEventNotifications() throws {
        let iPad = DeviceRef(pub: "cHVi", name: "iPad", kind: "browser")
        let start = try XCTUnwrap(EventNotification.make(for: AgentEvent(event: "session-start", device: iPad, detail: .string("relay"))))
        XCTAssertEqual(start.title, "iPad connected to this Mac")
        XCTAssertFalse(start.isPairing)

        let end = try XCTUnwrap(EventNotification.make(for: AgentEvent(event: "session-end", device: iPad, detail: .string("idle"))))
        XCTAssertEqual(end.body, "iPad is no longer connected (there was no activity for a while).")

        let pair = try XCTUnwrap(EventNotification.make(for: AgentEvent(event: "pair-request", device: iPad, detail: .string("196 924"))))
        XCTAssertTrue(pair.isPairing)
        XCTAssertTrue(pair.body.contains("196 924"))

        let idle = try XCTUnwrap(EventNotification.make(for: AgentEvent(event: "idle-warning", device: iPad, detail: .string("60"))))
        XCTAssertTrue(idle.body.contains("in 60 seconds"))

        let killed = try XCTUnwrap(EventNotification.make(for: AgentEvent(event: "killed", detail: .string("by iPhone"))))
        XCTAssertEqual(killed.body, "Nobody can connect to this Mac until you allow connections again (blocked by iPhone).")

        XCTAssertNotNil(EventNotification.make(for: AgentEvent(event: "trust-store-tampered", detail: .string("x"))))
        XCTAssertNotNil(EventNotification.make(for: AgentEvent(event: "file-received", device: iPad, detail: .string("a.mov"))))
        XCTAssertNil(EventNotification.make(for: AgentEvent(event: "future-thing")))
    }

    func testAccessLogTitles() {
        for event in ["session-start", "session-end", "pairing-approved", "pairing-denied", "device-added",
                      "device-removed", "killed", "resumed", "file-received", "file-sent", "trust-store-tampered",
                      "log-tamper-detected", "setup-failed", "trust-store-reset", "agent-start", "offer-rejected",
                      "approval-rejected"] {
            XCTAssertNotEqual(AccessLogText.title(for: event), event, event)
        }
        XCTAssertEqual(AccessLogText.title(for: "brand-new"), "brand-new")
    }
}
