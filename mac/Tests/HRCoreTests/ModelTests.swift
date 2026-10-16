import XCTest
@testable import HRCore

final class ModelTests: XCTestCase {
    private func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try JSONDecoder().decode(type, from: Data(json.utf8))
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: STATE

    func testFullStateDecodes() throws {
        let json = """
        {"server":"online","claimed":true,"setupURL":null,"killed":false,
         "session":{"device":{"pub":"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc","name":"iPhone","kind":"browser"},
                    "since":1760000000,"transport":"relay","rttMs":42.5},
         "pending":[{"requestId":"EBESExQVFhcYGRobHB0eHw","name":"Office PC","kind":"tauri","sas":"196924","expiresAt":1760000300}],
         "devices":[{"pub":"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc","name":"iPhone","kind":"browser","addedAt":1759990000,"lastUsed":null}]}
        """
        let s = try decode(AgentState.self, json)
        XCTAssertEqual(s.server, .online)
        XCTAssertTrue(s.claimed)
        XCTAssertNil(s.setupURL)
        XCTAssertFalse(s.killed)
        let session = try XCTUnwrap(s.session)
        XCTAssertEqual(session.device.name, "iPhone")
        XCTAssertEqual(session.device.kind, "browser")
        XCTAssertEqual(session.since?.date, Date(timeIntervalSince1970: 1_760_000_000))
        XCTAssertTrue(session.isRelayed)
        XCTAssertEqual(session.rttMs, 42.5)
        XCTAssertEqual(s.pending.count, 1)
        XCTAssertEqual(s.pending[0].requestId, "EBESExQVFhcYGRobHB0eHw")
        XCTAssertEqual(s.pending[0].sas, "196924")
        XCTAssertEqual(s.pending[0].expiresAt?.date, Date(timeIntervalSince1970: 1_760_000_300))
        XCTAssertEqual(s.devices.count, 1)
        XCTAssertNil(s.devices[0].lastUsed)
        XCTAssertEqual(s.devices[0].addedAt?.date, Date(timeIntervalSince1970: 1_759_990_000))
    }

    func testOfflineStateWithNullSessionAndErrors() throws {
        let json = #"{"server":"error","serverError":"server already claimed","claimed":false,"setupURL":"https://r.example/#setup=abc.def","killed":true,"session":null,"pending":[],"devices":[]}"#
        let s = try decode(AgentState.self, json)
        XCTAssertEqual(s.server, .error)
        XCTAssertEqual(s.serverError, "server already claimed")
        XCTAssertEqual(s.setupURL, "https://r.example/#setup=abc.def")
        XCTAssertTrue(s.killed)
        XCTAssertNil(s.session)
    }

    func testStateToleratesMissingFieldsAndUnknownValues() throws {
        let s = try decode(AgentState.self, #"{"server":"something-new","extra":1}"#)
        XCTAssertEqual(s.server, .error)
        XCTAssertFalse(s.claimed)
        XCTAssertFalse(s.killed)
        XCTAssertNil(s.session)
        XCTAssertEqual(s.pending, [])
        XCTAssertEqual(s.devices, [])
        let empty = try decode(AgentState.self, "{}")
        XCTAssertEqual(empty.server, .offline)
    }

    func testTimestampsInMillisecondsAndRFC3339() throws {
        let json = """
        {"server":"connecting","session":{"device":{"name":"Laptop"},"since":"2025-10-09T09:06:40Z","transport":"direct","rttMs":7},
         "pending":[{"requestId":"r","name":"n","kind":"browser","sas":42,"expiresAt":1760000300000}],
         "devices":[{"pub":"p","name":"d","kind":"tauri","addedAt":"2025-10-09T09:06:40.123456789Z","lastUsed":"1760000000"}]}
        """
        let s = try decode(AgentState.self, json)
        XCTAssertEqual(s.server, .connecting)
        XCTAssertEqual(s.session?.since?.date, Date(timeIntervalSince1970: 1_760_000_800))
        XCTAssertEqual(s.session?.isRelayed, false)
        XCTAssertEqual(s.pending[0].expiresAt?.date, Date(timeIntervalSince1970: 1_760_000_300))
        XCTAssertEqual(s.pending[0].sas, "000042")
        let added = try XCTUnwrap(s.devices[0].addedAt?.date.timeIntervalSince1970)
        XCTAssertEqual(added, 1_760_000_800.123, accuracy: 0.01)
        XCTAssertEqual(s.devices[0].lastUsed?.date, Date(timeIntervalSince1970: 1_760_000_000))
    }

    func testDeviceDisplayNameFallback() {
        XCTAssertEqual(DeviceRef(name: "  ").displayName, "A device")
        XCTAssertEqual(TrustedDevice(pub: "p", name: "Studio iMac", kind: "tauri").displayName, "Studio iMac")
    }

    // MARK: EVENT

    func testEventWithDeviceObject() throws {
        let e = try decode(AgentEvent.self, #"{"event":"session-start","device":{"pub":"x","name":"iPad","kind":"browser"}}"#)
        XCTAssertEqual(e.name, .sessionStart)
        XCTAssertEqual(e.deviceName, "iPad")
        XCTAssertNil(e.detailText)
    }

    func testEventWithDeviceStringAndDetail() throws {
        let e = try decode(AgentEvent.self, #"{"event":"file-received","device":"Phone","detail":{"name":"cut-v3.mov","size":1048576}}"#)
        XCTAssertEqual(e.name, .fileReceived)
        XCTAssertEqual(e.deviceName, "Phone")
        XCTAssertEqual(e.detailText, "cut-v3.mov")
    }

    func testEventNames() throws {
        for name in ["session-start", "session-end", "pair-request", "device-added", "device-removed",
                     "killed", "resumed", "idle-warning", "file-received"] {
            let e = try decode(AgentEvent.self, "{\"event\":\"\(name)\"}")
            XCTAssertNotNil(e.name, name)
            XCTAssertNil(e.device)
        }
        let unknown = try decode(AgentEvent.self, #"{"event":"future-thing","detail":"text"}"#)
        XCTAssertNil(unknown.name)
        XCTAssertEqual(unknown.detailText, "text")
    }

    // MARK: ENCODER

    func testEncoderStart() throws {
        let c = try decode(EncoderCommand.self, #"{"cmd":"start","codec":"h265","fps":60,"kbps":15000,"display":1}"#)
        XCTAssertEqual(c.action, .start(codec: .h265, fps: 60, kbps: 15000, display: 1, profile: .high))
        let b = try decode(EncoderCommand.self, #"{"cmd":"start","codec":"h264","fps":30,"kbps":4000,"display":69734272,"profile":"baseline"}"#)
        XCTAssertEqual(b.action, .start(codec: .h264, fps: 30, kbps: 4000, display: 69_734_272, profile: .baseline))
    }

    func testEncoderStartDefaultsAndClamping() throws {
        let c = try decode(EncoderCommand.self, #"{"cmd":"start","fps":1000,"kbps":1}"#)
        XCTAssertEqual(c.action, .start(codec: .h264, fps: 120, kbps: 250, display: nil, profile: .high))
        let numeric = try decode(EncoderCommand.self, #"{"cmd":"start","codec":2,"display":"5"}"#)
        XCTAssertEqual(numeric.action, .start(codec: .h265, fps: 60, kbps: EncoderCommand.defaultKbps, display: 5, profile: .high))
        let hevcName = try decode(EncoderCommand.self, #"{"cmd":"start","codec":"hevc","display":0}"#)
        XCTAssertEqual(hevcName.action, .start(codec: .h265, fps: 60, kbps: EncoderCommand.defaultKbps, display: nil, profile: .high))
    }

    func testEncoderOtherCommands() throws {
        XCTAssertEqual(try decode(EncoderCommand.self, #"{"cmd":"stop"}"#).action, .stop)
        XCTAssertEqual(try decode(EncoderCommand.self, #"{"cmd":"keyframe"}"#).action, .keyframe)
        XCTAssertEqual(try decode(EncoderCommand.self, #"{"cmd":"bitrate","kbps":8000}"#).action, .bitrate(kbps: 8000))
        XCTAssertEqual(try decode(EncoderCommand.self, #"{"cmd":"display","id":2}"#).action, .display(id: 2))
        XCTAssertEqual(try decode(EncoderCommand.self, #"{"cmd":"display"}"#).action, .unknown("display"))
        XCTAssertEqual(try decode(EncoderCommand.self, #"{"cmd":"warp"}"#).action, .unknown("warp"))
    }

    // MARK: INPUT / AUDIO_CTL / CLIPBOARD_SET

    func testInputMessages() throws {
        let m = try decode(InputMessage.self, #"{"t":"m","x":0.25,"y":0.75,"display":1}"#)
        XCTAssertEqual(m.kind, .move)
        XCTAssertEqual(m.x, 0.25)
        XCTAssertEqual(m.displayID, 1)

        let b = try decode(InputMessage.self, #"{"t":"b","b":2,"d":true,"x":0.5,"y":0.5,"display":0}"#)
        XCTAssertEqual(b.kind, .button)
        XCTAssertEqual(b.b, 2)
        XCTAssertEqual(b.d, true)
        XCTAssertNil(b.displayID)

        let w = try decode(InputMessage.self, #"{"t":"w","dx":0,"dy":-120.5,"x":0.1,"y":0.2}"#)
        XCTAssertEqual(w.kind, .wheel)
        XCTAssertEqual(w.dy, -120.5)

        let k = try decode(InputMessage.self, #"{"t":"k","c":"KeyA","d":false}"#)
        XCTAssertEqual(k.kind, .key)
        XCTAssertEqual(k.c, "KeyA")
        XCTAssertEqual(k.d, false)

        let t = try decode(InputMessage.self, #"{"t":"txt","s":"héllo 👋"}"#)
        XCTAssertEqual(t.kind, .text)
        XCTAssertEqual(t.s, "héllo 👋")

        XCTAssertEqual(try decode(InputMessage.self, #"{"t":"reset"}"#).kind, .reset)
        XCTAssertEqual(try decode(InputMessage.self, #"{"t":"zz"}"#).kind, .unknown)
        XCTAssertEqual(try decode(InputMessage.self, #"{"t":"b","b":0,"d":1}"#).d, true)
    }

    func testAudioControlAndClipboard() throws {
        XCTAssertTrue(try decode(AudioControl.self, #"{"cmd":"start"}"#).isStart)
        XCTAssertFalse(try decode(AudioControl.self, #"{"cmd":"stop"}"#).isStart)
        XCTAssertEqual(try decode(ClipboardSet.self, #"{"text":"hello\nworld"}"#).text, "hello\nworld")
    }

    // MARK: SIGN_REQUEST / SIGN_RESULT

    func testSignRequestIdIsEchoedVerbatim() throws {
        let r1 = try decode(SignRequest.self, #"{"id":17,"data":"SFIxL2NlcnQA"}"#)
        XCTAssertEqual(r1.id, .int(17))
        let out1 = try jsonObject(HRJSON.encode(SignResult(id: r1.id, sig: "c2ln")))
        XCTAssertEqual(out1["id"] as? Int, 17)
        XCTAssertEqual(out1["sig"] as? String, "c2ln")
        XCTAssertNil(out1["error"])

        let r2 = try decode(SignRequest.self, #"{"id":"abc-1","data":""}"#)
        let out2 = try jsonObject(HRJSON.encode(SignResult(id: r2.id, sig: "", error: "label-not-allowed")))
        XCTAssertEqual(out2["id"] as? String, "abc-1")
        XCTAssertEqual(out2["error"] as? String, "label-not-allowed")
    }

    // MARK: LOG

    func testLogResult() throws {
        let json = """
        {"entries":[{"ts":1760000000,"event":"session-start","device":"iPhone","prev":"aa","mac":"bb"},
                    {"time":"2025-10-09T09:06:40Z","type":"pair-approved","device":{"name":"Laptop"},"detail":"approved on Mac"}],
         "verified":true}
        """
        let log = try decode(LogResult.self, json)
        XCTAssertTrue(log.verified)
        XCTAssertNil(log.error)
        let rows = log.displayEntries
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0].event, "pair-approved")   // newest first
        XCTAssertEqual(rows[0].device, "Laptop")
        XCTAssertEqual(rows[0].detail, "approved on Mac")
        XCTAssertEqual(rows[1].event, "session-start")
        XCTAssertEqual(rows[1].device, "iPhone")
        XCTAssertEqual(rows[1].time, Date(timeIntervalSince1970: 1_760_000_000))

        let tampered = try decode(LogResult.self, #"{"entries":[],"verified":false,"error":"line 12: mac mismatch"}"#)
        XCTAssertFalse(tampered.verified)
        XCTAssertEqual(tampered.error, "line 12: mac mismatch")
    }

    // MARK: CONFIG / COMMAND

    func testConfigFieldNames() throws {
        let cfg = AgentConfig(serverURL: "https://r.example", hostPub: "ebVW", hostName: "Studio Mac",
                              dataDir: "/Users/me/Library/Application Support/Heartfulness Remote",
                              storageKey: "c2VjcmV0",
                              settings: HostSettings().agentSettings,
                              hevcAvailable: true, audioAvailable: false)
        let o = try jsonObject(HRJSON.encode(cfg))
        XCTAssertEqual(Set(o.keys), ["serverURL", "hostPub", "hostName", "dataDir", "storageKey", "settings", "hevcAvailable", "audioAvailable"])
        XCTAssertEqual(o["serverURL"] as? String, "https://r.example")
        XCTAssertEqual(o["hevcAvailable"] as? Bool, true)
        XCTAssertEqual(o["audioAvailable"] as? Bool, false)
        let settings = try XCTUnwrap(o["settings"] as? [String: Any])
        XCTAssertEqual(Set(settings.keys), ["allowBrowserClients", "relayOnly", "idleTimeoutMin", "maxKbps", "codec"])
        XCTAssertEqual(settings["allowBrowserClients"] as? Bool, true)
        XCTAssertEqual(settings["relayOnly"] as? Bool, false)
        XCTAssertEqual(settings["idleTimeoutMin"] as? Int, 30)
        XCTAssertEqual(settings["codec"] as? String, "auto")
        // Slashes are not escaped (readable dataDir / URLs).
        let text = String(decoding: try HRJSON.encode(cfg), as: UTF8.self)
        XCTAssertTrue(text.contains("https://r.example"))
    }

    func testCommandEncodings() throws {
        func cmd(_ c: AgentCommand) throws -> [String: Any] { try jsonObject(HRJSON.encode(c)) }

        let simple: [(AgentCommand, String)] = [(.kill, "kill"), (.resume, "resume"), (.disconnect, "disconnect"),
                                                (.newSetupCode, "new-setup-code"), (.quit, "quit")]
        for (c, name) in simple {
            let o = try cmd(c)
            XCTAssertEqual(o["cmd"] as? String, name)
            XCTAssertEqual(o.count, 1)
        }

        XCTAssertEqual(try cmd(.approve(requestId: "r1"))["requestId"] as? String, "r1")
        XCTAssertEqual(try cmd(.approve(requestId: "r1"))["cmd"] as? String, "approve")
        XCTAssertEqual(try cmd(.deny(requestId: "r2"))["cmd"] as? String, "deny")
        XCTAssertEqual(try cmd(.deny(requestId: "r2"))["requestId"] as? String, "r2")
        XCTAssertEqual(try cmd(.revoke(devicePub: "pub"))["devicePub"] as? String, "pub")
        XCTAssertEqual(try cmd(.clipboard(text: "hi"))["text"] as? String, "hi")
        XCTAssertEqual(try cmd(.logRead(limit: 500))["cmd"] as? String, "log-read")
        XCTAssertEqual(try cmd(.logRead(limit: 500))["limit"] as? Int, 500)

        let s = AgentSettings(allowBrowserClients: false, relayOnly: true, idleTimeoutMin: 15, maxKbps: 8000, codec: .h265)
        let so = try cmd(.settings(s))
        XCTAssertEqual(so["cmd"] as? String, "settings")
        XCTAssertEqual(so["relayOnly"] as? Bool, true)
        XCTAssertEqual(so["codec"] as? String, "h265")
        let nested = try XCTUnwrap(so["settings"] as? [String: Any])
        XCTAssertEqual(nested["idleTimeoutMin"] as? Int, 15)
        XCTAssertEqual(nested["allowBrowserClients"] as? Bool, false)

        let d = DisplayInfo(id: 1, name: "Built-in Retina Display", width: 1512, height: 982, scale: 2, primary: true)
        let dO = try cmd(.displays(list: [d], active: 1))
        XCTAssertEqual(dO["cmd"] as? String, "displays")
        XCTAssertEqual(dO["active"] as? Int, 1)
        let list = try XCTUnwrap(dO["list"] as? [[String: Any]])
        XCTAssertEqual(Set(list[0].keys), ["id", "name", "width", "height", "scale", "primary"])
        XCTAssertEqual(list[0]["primary"] as? Bool, true)
        XCTAssertEqual(list[0]["width"] as? Int, 1512)
    }

    func testJSONValueRoundTrip() throws {
        let json = #"{"a":[1,2.5,"x",true,null],"b":{"c":-3}}"#
        let v = try decode(JSONValue.self, json)
        XCTAssertEqual(v["b"]?["c"], .int(-3))
        let again = try JSONDecoder().decode(JSONValue.self, from: HRJSON.encode(v))
        XCTAssertEqual(v, again)
    }
}
