import XCTest
@testable import HRCore
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Several Macs per account (PROTOCOL.md §10): STATE fields, Mac ID, and the owner-facing text.
final class MultiMacTests: XCTestCase {
    private func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try JSONDecoder().decode(type, from: Data(json.utf8))
    }

    // MARK: STATE

    func testPendingJoinStateAsMarshalledByGo() throws {
        // core.State field order and names; setupURL omitted (omitempty) on a claimed server.
        let json = """
        {"server":"online","claimed":true,"joined":false,"macId":"967244390",
         "joinURL":"https://remote.example.test/#join=4OHi4-Tl5ufo6Q.c2VydmVyLXB1Yg",
         "joinCode":"4DQ6-FY7E-4XTO-P2HJ","killed":false,"session":null,"pending":[],"devices":[]}
        """
        let s = try decode(AgentState.self, json)
        XCTAssertTrue(s.claimed)
        XCTAssertFalse(s.joined)
        XCTAssertEqual(s.macId, "967244390")
        XCTAssertEqual(s.joinURL, "https://remote.example.test/#join=4OHi4-Tl5ufo6Q.c2VydmVyLXB1Yg")
        XCTAssertEqual(s.joinCode, "4DQ6-FY7E-4XTO-P2HJ")
        XCTAssertNil(s.setupURL)
        XCTAssertEqual(s.account, .notInAccount)
    }

    func testJoinedAndUnclaimedStates() throws {
        let joined = try decode(AgentState.self, #"{"server":"online","claimed":true,"joined":true,"macId":"000000042","killed":false,"session":null,"pending":[],"devices":[]}"#)
        XCTAssertTrue(joined.joined)
        XCTAssertNil(joined.joinURL)
        XCTAssertNil(joined.joinCode)
        XCTAssertEqual(joined.account, .inAccount)

        let unclaimed = try decode(AgentState.self, #"{"server":"online","claimed":false,"joined":false,"macId":"482913557","setupURL":"https://r.example/#setup=abc.def","killed":false,"session":null,"pending":[],"devices":[]}"#)
        XCTAssertEqual(unclaimed.account, .serverNotSetUp)
        XCTAssertEqual(unclaimed.setupURL, "https://r.example/#setup=abc.def")
        XCTAssertNil(unclaimed.joinCode)
    }

    func testOlderAgentWithoutJoinedField() throws {
        // Before multi-Mac support a claimed server meant "this Mac is the owner's".
        let claimed = try decode(AgentState.self, #"{"server":"online","claimed":true,"killed":false}"#)
        XCTAssertTrue(claimed.joined)
        XCTAssertEqual(claimed.macId, "")
        XCTAssertEqual(claimed.account, .inAccount)
        let unclaimed = try decode(AgentState.self, #"{"server":"online","claimed":false}"#)
        XCTAssertFalse(unclaimed.joined)
        XCTAssertEqual(unclaimed.account, .serverNotSetUp)
        // Empty strings are treated as absent.
        let empty = try decode(AgentState.self, #"{"claimed":true,"joined":false,"joinURL":"","joinCode":""}"#)
        XCTAssertNil(empty.joinURL)
        XCTAssertNil(empty.joinCode)
        XCTAssertEqual(empty.account, .notInAccount)
        // The memberwise initializer keeps the same default.
        XCTAssertTrue(AgentState(server: .online, claimed: true).joined)
        XCTAssertFalse(AgentState(server: .online, claimed: true, joined: false).joined)
    }

    func testStateEncodesGoFieldNames() throws {
        let s = AgentState(server: .online, claimed: true, joined: false, macId: "482913557",
                           joinURL: "https://r.example/#join=a.b", joinCode: "K7QP-3MZD-WX2R-9TFA")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(s)) as? [String: Any])
        XCTAssertEqual(object["macId"] as? String, "482913557")
        XCTAssertEqual(object["joined"] as? Bool, false)
        XCTAssertEqual(object["joinURL"] as? String, "https://r.example/#join=a.b")
        XCTAssertEqual(object["joinCode"] as? String, "K7QP-3MZD-WX2R-9TFA")
        XCTAssertEqual(try decode(AgentState.self, String(decoding: JSONEncoder().encode(s), as: UTF8.self)), s)
    }

    // MARK: Mac ID

    func testMacIDFormatting() {
        XCTAssertEqual(MacIDFormatter.format("482913557"), "482 913 557")
        XCTAssertEqual(MacIDFormatter.format("482 913 557"), "482 913 557")
        XCTAssertEqual(MacIDFormatter.format("000000042"), "000 000 042")
        XCTAssertEqual(MacIDFormatter.format("48291355"), "48291355")
        XCTAssertEqual(MacIDFormatter.format("48291355a"), "48291355a")
        XCTAssertEqual(MacIDFormatter.format(""), "")
        XCTAssertEqual(MacIDFormatter.digits("482-913-557"), "482913557")
        XCTAssertNil(MacIDFormatter.digits("４８２９１３５５７"))   // full-width digits are not accepted
        XCTAssertNil(MacIDFormatter.digits("4829135570"))
        XCTAssertEqual(AccountText.macIDLine("482913557"), "Mac ID 482 913 557")
        XCTAssertNil(AccountText.macIDLine(""))
    }

    func testMacIDFromDigest() {
        // Vector host key: SHA-256(TBS("HR1/mac-id", hostPub)) starts b0 dc 8e 66 = 2967244390 → 967244390.
        XCTAssertEqual(MacIDFormatter.code(fromDigest: [0xb0, 0xdc, 0x8e, 0x66, 0x77, 0x05, 0x30, 0x9d]), "967244390")
        XCTAssertEqual(MacIDFormatter.code(fromDigest: [0x3B, 0x9A, 0xCA, 0x00]), "000000000")   // exactly 10^9
        XCTAssertEqual(MacIDFormatter.code(fromDigest: [0x00, 0x00, 0x00, 0x2A]), "000000042")
        XCTAssertNil(MacIDFormatter.code(fromDigest: [1, 2, 3]))
        let pub = Data(repeating: 7, count: 32)
        let tbs = MacIDFormatter.transcript(hostPub: pub)
        XCTAssertEqual(tbs, TBS.build(label: "HR1/mac-id", fields: [pub]))
        XCTAssertEqual(tbs.count, "HR1/mac-id".utf8.count + 1 + 4 + 32)
        XCTAssertEqual(TBS.label(of: tbs), "HR1/mac-id")
        // The Mac ID is never something the host key signs.
        XCTAssertFalse(SigningPolicy.isAllowed(tbs))
    }

    func testJoinVectorsLoad() throws {
        let v = try Vectors.load()
        let join = try XCTUnwrap(v.join, "testdata/vectors.json has no \"join\" section")
        XCTAssertNotNil(MacIDFormatter.digits(join.macId))
        XCTAssertEqual(join.code.count, 19)
        XCTAssertEqual(Base64URL.decode(join.t)?.count, 10)
    }

    #if canImport(CryptoKit)
    func testMacIDVectorWithCryptoKit() throws {
        let v = try Vectors.load()
        let join = try XCTUnwrap(v.join)
        let hostPub = try XCTUnwrap(Base64URL.decode(v.hostPub))
        let digest = Array(SHA256.hash(data: MacIDFormatter.transcript(hostPub: hostPub)))
        XCTAssertEqual(MacIDFormatter.code(fromDigest: digest), join.macId)
    }
    #endif

    // MARK: Text

    func testStatusWhenNotInAccount() {
        let server = "https://heartfulness-remote.duckdns.org"
        let pending = HostStatusSummary.make(state: AgentState(server: .online, claimed: true, joined: false),
                                             agentRunning: true, serverAddress: server)
        XCTAssertEqual(pending.kind, .online)
        XCTAssertEqual(pending.title, "Almost ready")
        XCTAssertTrue(pending.detail.contains("add this Mac to your account"))
        let joined = HostStatusSummary.make(state: AgentState(server: .online, claimed: true, joined: true),
                                            agentRunning: true, serverAddress: server)
        XCTAssertEqual(joined.title, "Your Mac is ready")
        // A session or the kill switch still wins.
        let blocked = HostStatusSummary.make(state: AgentState(server: .online, claimed: true, joined: false, killed: true),
                                             agentRunning: true, serverAddress: server)
        XCTAssertEqual(blocked.kind, .blocked)
    }

    func testAccountNotificationsAndLog() throws {
        let phone = DeviceRef(pub: "cHVi", name: "Owner's iPhone", kind: "browser")
        let added = try XCTUnwrap(EventNotification.make(for: AgentEvent(event: "device-added", device: phone)))
        let joined = try XCTUnwrap(EventNotification.make(for: AgentEvent(event: "joined-account", device: phone)))
        XCTAssertEqual(joined.title, "This Mac is in your account")
        XCTAssertTrue(joined.body.contains("Owner's iPhone"))
        XCTAssertEqual(joined.identifier, added.identifier, "the join notice replaces “Device added”")
        let removed = try XCTUnwrap(EventNotification.make(for: AgentEvent(event: "removed-from-account")))
        XCTAssertEqual(removed.title, "This Mac was removed from your account")
        XCTAssertFalse(removed.isPairing)
        XCTAssertEqual(AccessLogText.title(for: "joined-account"), "Added to your account")
        XCTAssertEqual(AccessLogText.title(for: "removed-from-account"), "Removed from your account")
        XCTAssertFalse(AccountText.scanSteps.isEmpty)
        XCTAssertTrue(AccountText.typeInstead.contains("Add a Mac"))
        XCTAssertTrue(AccountText.inAccountDetail(serverName: "r.example").contains("r.example"))
    }
}
