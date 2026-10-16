import XCTest
@testable import HRCore

final class SettingsTests: XCTestCase {
    func testDefaults() {
        let s = HostSettings()
        XCTAssertEqual(s.serverURL, "")
        XCTAssertTrue(s.allowBrowserClients)
        XCTAssertFalse(s.relayOnly)
        XCTAssertEqual(s.idleTimeoutMin, 30)
        XCTAssertEqual(s.maxKbps, 20_000)
        XCTAssertEqual(s.codec, .auto)
        XCTAssertFalse(s.setupCompleted)
        XCTAssertTrue(HostSettings.idleTimeoutChoices.allSatisfy { HostSettings.idleTimeoutRange.contains($0) })
        XCTAssertTrue(HostSettings.idleTimeoutChoices.contains(HostSettings.defaultIdleTimeoutMin))
        XCTAssertTrue(HostSettings.bitrateChoicesKbps.contains(HostSettings.defaultMaxKbps))
    }

    func testClamping() {
        var s = HostSettings()
        s.idleTimeoutMin = 1
        s.maxKbps = 999_999
        XCTAssertEqual(s.clamped().idleTimeoutMin, 5)
        XCTAssertEqual(s.clamped().maxKbps, 100_000)
        s.idleTimeoutMin = 500
        XCTAssertEqual(s.agentSettings.idleTimeoutMin, 120)
    }

    func testPersistenceRoundTripAndLenientDecoding() throws {
        var s = HostSettings(serverURL: "https://r.example", allowBrowserClients: false, relayOnly: true,
                             idleTimeoutMin: 45, maxKbps: 50_000, codec: .h265, setupCompleted: true)
        let data = try HRJSON.encode(s)
        XCTAssertEqual(try JSONDecoder().decode(HostSettings.self, from: data), s)

        let partial = try JSONDecoder().decode(HostSettings.self, from: Data(#"{"serverURL":"https://x.example","idleTimeoutMin":2,"codec":"vp9"}"#.utf8))
        XCTAssertEqual(partial.serverURL, "https://x.example")
        XCTAssertEqual(partial.idleTimeoutMin, 5)
        XCTAssertEqual(partial.codec, .auto)
        XCTAssertTrue(partial.allowBrowserClients)
        s = try JSONDecoder().decode(HostSettings.self, from: Data("{}".utf8))
        XCTAssertEqual(s, HostSettings())
    }

    func testServerAddressAcceptsBareNames() {
        XCTAssertEqual(try ServerAddress.normalize("heartfulness-remote.dedyn.io").get(), "https://heartfulness-remote.dedyn.io")
        XCTAssertEqual(try ServerAddress.normalize("  Heartfulness-Remote.DEDYN.io/ \n").get(), "https://heartfulness-remote.dedyn.io")
        XCTAssertEqual(try ServerAddress.normalize("https://remote.example.com/").get(), "https://remote.example.com")
        XCTAssertEqual(try ServerAddress.normalize("HTTPS://remote.example.com:443").get(), "https://remote.example.com")
        XCTAssertEqual(try ServerAddress.normalize("https://remote.example.com:8443").get(), "https://remote.example.com:8443")
        XCTAssertEqual(try ServerAddress.normalize("remote.example.com.").get(), "https://remote.example.com")
    }

    func testServerAddressDevelopmentLocalhost() {
        XCTAssertEqual(try ServerAddress.normalize("http://localhost:8080").get(), "http://localhost:8080")
        XCTAssertEqual(try ServerAddress.normalize("http://127.0.0.1:8080/").get(), "http://127.0.0.1:8080")
        XCTAssertEqual(try ServerAddress.normalize("localhost:8443").get(), "https://localhost:8443")
        XCTAssertEqual(try ServerAddress.normalize("http://[::1]:8080").get(), "http://[::1]:8080")
    }

    func testServerAddressRejections() {
        XCTAssertEqual(failure("   "), .empty)
        XCTAssertEqual(failure("http://remote.example.com"), .insecure)
        XCTAssertEqual(failure("https://remote.example.com/app"), .hasPath)
        XCTAssertEqual(failure("https://remote.example.com/?x=1"), .hasPath)
        XCTAssertEqual(failure("https://remote.example.com/#setup=abc"), .hasPath)
        XCTAssertEqual(failure("https://user:pw@remote.example.com"), .hasCredentials)
        XCTAssertEqual(failure("ftp://remote.example.com"), .invalid)
        XCTAssertEqual(failure("not a url"), .invalid)
        XCTAssertEqual(failure("remote_example"), .invalid)
        XCTAssertEqual(failure("intranet"), .invalid)
        for error in [ServerAddress.ValidationError.empty, .invalid, .insecure, .hasPath, .hasCredentials] {
            XCTAssertFalse(error.message.isEmpty)
        }
        XCTAssertEqual(ServerAddress.displayName("https://heartfulness-remote.dedyn.io"), "heartfulness-remote.dedyn.io")
    }

    private func failure(_ input: String) -> ServerAddress.ValidationError? {
        if case .failure(let e) = ServerAddress.normalize(input) { return e }
        return nil
    }
}

final class AnnexBTests: XCTestCase {
    func testConvertsFourByteLengthPrefixes() throws {
        let avcc = Data([0, 0, 0, 2, 0x65, 0xAA, 0, 0, 0, 3, 0x41, 0x01, 0x02])
        let out = try AnnexB.fromLengthPrefixed(avcc)
        XCTAssertEqual([UInt8](out), [0, 0, 0, 1, 0x65, 0xAA, 0, 0, 0, 1, 0x41, 0x01, 0x02])
        XCTAssertEqual(AnnexB.splitNALUnits(out), [Data([0x65, 0xAA]), Data([0x41, 0x01, 0x02])])
    }

    func testOtherLengthSizesAndEmptyNALs() throws {
        let two = Data([0, 1, 0x09, 0, 0, 0, 2, 0x41, 0x42])
        XCTAssertEqual([UInt8](try AnnexB.fromLengthPrefixed(two, lengthSize: 2)), [0, 0, 0, 1, 0x09, 0, 0, 0, 1, 0x41, 0x42])
        XCTAssertEqual(try AnnexB.fromLengthPrefixed(Data()), Data())
    }

    func testRejectsTruncatedInput() {
        XCTAssertThrowsError(try AnnexB.fromLengthPrefixed(Data([0, 0, 0, 5, 1, 2])))
        XCTAssertThrowsError(try AnnexB.fromLengthPrefixed(Data([0, 0, 1])))
        XCTAssertThrowsError(try AnnexB.fromLengthPrefixed(Data([1]), lengthSize: 0))
    }

    func testKeyframeAccessUnitStartsWithParameterSets() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x1F])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])
        let idr = Data([0, 0, 0, 3, 0x65, 0x88, 0x84])
        let au = try AnnexB.accessUnit(parameterSets: [sps, pps], lengthPrefixed: idr)
        let nals = AnnexB.splitNALUnits(au)
        XCTAssertEqual(nals.count, 3)
        XCTAssertEqual(nals.compactMap { AnnexB.h264Type($0) }, [7, 8, 5])
        XCTAssertEqual(au.prefix(4), Data([0, 0, 0, 1]))
    }

    func testHEVCTypes() {
        XCTAssertEqual(AnnexB.hevcType(Data([0x40, 0x01])), 32)   // VPS
        XCTAssertEqual(AnnexB.hevcType(Data([0x42, 0x01])), 33)   // SPS
        XCTAssertEqual(AnnexB.hevcType(Data([0x44, 0x01])), 34)   // PPS
        XCTAssertEqual(AnnexB.hevcType(Data([0x26, 0x01])), 19)   // IDR_W_RADL
        XCTAssertNil(AnnexB.hevcType(Data()))
    }

    func testSplitHandlesThreeByteStartCodes() {
        let stream = Data([0, 0, 1, 0x67, 0x10, 0, 0, 0, 1, 0x68, 0x20])
        XCTAssertEqual(AnnexB.splitNALUnits(stream), [Data([0x67, 0x10]), Data([0x68, 0x20])])
    }
}

final class FirewallTests: XCTestCase {
    func testGlobalStateParsing() {
        XCTAssertEqual(FirewallOutputParser.globalState("Firewall is enabled. (State = 1)\n"), true)
        XCTAssertEqual(FirewallOutputParser.globalState("Firewall is disabled. (State = 0)\n"), false)
        XCTAssertEqual(FirewallOutputParser.globalState("Firewall is blocking all non-essential incoming connections. (State = 2)"), true)
        XCTAssertNil(FirewallOutputParser.globalState("something unexpected"))
    }

    func testStealthParsing() {
        XCTAssertEqual(FirewallOutputParser.stealthMode("Stealth mode enabled\n"), true)
        XCTAssertEqual(FirewallOutputParser.stealthMode("Stealth mode disabled\n"), false)
        XCTAssertEqual(FirewallOutputParser.stealthMode("Firewall stealth mode is on\n"), true)
        XCTAssertEqual(FirewallOutputParser.stealthMode("Firewall stealth mode is off\n"), false)
        XCTAssertNil(FirewallOutputParser.stealthMode(""))
        XCTAssertTrue(FirewallState(enabled: true, stealth: true).fullyProtected)
        XCTAssertFalse(FirewallState(enabled: true, stealth: nil).fullyProtected)
    }

    func testAppleScriptLiteralEscaping() {
        XCTAssertEqual(AppleScriptText.literal("plain"), "\"plain\"")
        XCTAssertEqual(AppleScriptText.literal("a \"quoted\" \\ path"), "\"a \\\"quoted\\\" \\\\ path\"")
    }

    func testEnableFirewallScript() {
        let script = AppleScriptText.enableFirewallScript(allowing: [
            "/Users/me/Applications/Heartfulness Remote.app",
            "/Users/me/Applications/Heartfulness Remote.app/Contents/MacOS/hr-agent",
        ])
        XCTAssertTrue(script.hasPrefix("do shell script \"/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on; "))
        XCTAssertTrue(script.contains("--setstealthmode on"))
        XCTAssertTrue(script.hasSuffix(" with administrator privileges"))
        XCTAssertTrue(script.contains("(quoted form of \"/Users/me/Applications/Heartfulness Remote.app\")"))
        XCTAssertTrue(script.contains("(quoted form of \"/Users/me/Applications/Heartfulness Remote.app/Contents/MacOS/hr-agent\")"))
        XCTAssertEqual(script.components(separatedBy: "--add ").count - 1, 2)
        XCTAssertEqual(script.components(separatedBy: "--unblockapp ").count - 1, 2)
    }
}
