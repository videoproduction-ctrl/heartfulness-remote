import CryptoKit
import Foundation
import HRCore
import Security

// MARK: - Keychain (legacy login keychain, generic passwords)

enum KeychainError: Error, Equatable {
    case notFound
    case accessDenied(OSStatus)
    case unexpected(OSStatus)
    case corrupt(String)
}

/// Thin wrapper over SecItem* for generic-password items in the login keychain.
/// Deliberately does NOT use kSecUseDataProtectionKeychain (needs a provisioning profile).
enum Keychain {
    static let service = "org.heartfulness.remote"

    private static func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    static func read(_ account: String) -> Result<Data, KeychainError> {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess {
            guard let data = item as? Data else { return .failure(.corrupt("keychain item is not data")) }
            return .success(data)
        }
        return .failure(classify(status))
    }

    /// Adds a new item. Never overwrites: returns errSecDuplicateItem if it already exists.
    static func add(_ account: String, data: Data, label: String) -> OSStatus {
        var attributes = baseQuery(account)
        attributes[kSecValueData as String] = data
        attributes[kSecAttrLabel as String] = label
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecParam {
            // Some keychain configurations reject the accessibility attribute; retry without it.
            attributes.removeValue(forKey: kSecAttrAccessible as String)
            status = SecItemAdd(attributes as CFDictionary, nil)
        }
        return status
    }

    @discardableResult
    static func delete(_ account: String) -> OSStatus {
        SecItemDelete(baseQuery(account) as CFDictionary)
    }

    static func classify(_ status: OSStatus) -> KeychainError {
        switch status {
        case errSecItemNotFound:
            return .notFound
        case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed, errSecNoAccessForItem:
            return .accessDenied(status)
        default:
            return .unexpected(status)
        }
    }

    static func describe(_ status: OSStatus) -> String {
        if let text = SecCopyErrorMessageString(status, nil) as String? { return "\(text) (\(status))" }
        return "error \(status)"
    }
}

// MARK: - Host identity

enum KeyProtection: String {
    case secureEnclave = "Secure Enclave + Keychain"
    case keychain = "Keychain"
}

/// Why the identity could not be loaded. Never triggers creation of a new key —
/// only a genuinely missing item (errSecItemNotFound) does.
enum HostKeyError: Error, Equatable {
    case keychainAccess(OSStatus)
    case keychainFailure(String)
    case secureEnclave(String)
    case corrupt(String)

    var title: String {
        switch self {
        case .keychainAccess: return "Keychain access needed"
        case .keychainFailure: return "Keychain problem"
        case .secureEnclave: return "This Mac's security chip couldn't unlock the identity"
        case .corrupt: return "The saved identity is damaged"
        }
    }

    /// Plain-language explanation for the owner.
    var message: String {
        switch self {
        case .keychainAccess:
            return "Heartfulness Remote keeps its secret key in your keychain. After an update, macOS asks again whether the app may use it. Click “Try again”, then choose “Always Allow” and type your Mac login password if asked."
        case .keychainFailure(let detail):
            return "The keychain reported a problem (\(detail)). Click “Try again”. If it keeps happening, restart your Mac."
        case .secureEnclave(let detail):
            return "The key is locked to this Mac's security chip and could not be opened (\(detail)). If you moved to a new Mac, create a new identity — you will need to set up your phone again."
        case .corrupt(let detail):
            return "The saved identity could not be read (\(detail)). You can create a new identity — you will need to set up your phone again."
        }
    }

    /// Whether offering "Create new identity" makes sense (never for plain access denials).
    var allowsReset: Bool {
        switch self {
        case .secureEnclave, .corrupt: return true
        case .keychainAccess, .keychainFailure: return false
        }
    }
}

/// The Mac's Ed25519 host identity plus the agent's storage key. Immutable, thread-safe.
final class HostSigner: @unchecked Sendable {
    let privateKey: Curve25519.Signing.PrivateKey
    let publicKey: Data
    let storageKey: Data
    let protection: KeyProtection

    init(privateKey: Curve25519.Signing.PrivateKey, storageKey: Data, protection: KeyProtection) {
        self.privateKey = privateKey
        self.publicKey = privateKey.publicKey.rawRepresentation
        self.storageKey = storageKey
        self.protection = protection
    }

    var publicKeyB64: String { Base64URL.encode(publicKey) }

    var fingerprint: String {
        Fingerprint.format(sha256Digest: Array(SHA256.hash(data: publicKey)))
    }

    /// Mac ID (PROTOCOL.md §10.1): nine digits, no spaces ("" never happens for a 32-byte digest).
    var macID: String {
        MacIDFormatter.code(fromDigest: Array(SHA256.hash(data: MacIDFormatter.transcript(hostPub: publicKey)))) ?? ""
    }

    /// Answers a SIGN_REQUEST. Only host-signed transcript labels (PROTOCOL §3) are signed.
    func respond(to request: SignRequest) -> SignResult {
        guard let data = Base64URL.decode(request.data) else {
            return SignResult(id: request.id, sig: "", error: "bad-data")
        }
        guard SigningPolicy.isAllowed(data) else {
            let label = TBS.label(of: data) ?? "?"
            Log.keys.error("Refused to sign transcript with label \(label, privacy: .public)")
            return SignResult(id: request.id, sig: "", error: "label-not-allowed")
        }
        do {
            let signature = try privateKey.signature(for: data)
            return SignResult(id: request.id, sig: Base64URL.encode(signature))
        } catch {
            Log.keys.error("Signing failed")
            return SignResult(id: request.id, sig: "", error: "sign-failed")
        }
    }
}

enum HostKeyStore {
    private enum Account {
        static let storageKey = "storage-key"
        static let wrappedSeed = "host-key-se"     // seed sealed with a Secure Enclave key
        static let plainSeed = "host-key-seed"     // seed stored directly (fallback)
    }

    /// Loads the identity, creating it only if it truly does not exist yet.
    static func loadOrCreate() -> Result<HostSigner, HostKeyError> {
        let storageKey: Data
        switch Keychain.read(Account.storageKey) {
        case .success(let data):
            guard data.count == 32 else { return .failure(.corrupt("storage key has the wrong size")) }
            storageKey = data
        case .failure(.notFound):
            let fresh = randomBytes(32)
            let status = Keychain.add(Account.storageKey, data: fresh, label: "Heartfulness Remote storage key")
            if status == errSecDuplicateItem {
                return loadOrCreate()   // created concurrently; read it back
            }
            guard status == errSecSuccess else { return .failure(failure(for: status)) }
            storageKey = fresh
        case .failure(let error):
            return .failure(map(error))
        }

        switch loadSeed() {
        case .success(let loaded):
            do {
                let key = try Curve25519.Signing.PrivateKey(rawRepresentation: loaded.seed)
                return .success(HostSigner(privateKey: key, storageKey: storageKey, protection: loaded.protection))
            } catch {
                return .failure(.corrupt("host key seed is invalid"))
            }
        case .failure(let error):
            return .failure(error)
        }
    }

    /// Deletes the identity so the next load creates a new one (owner-initiated only).
    static func deleteIdentity() {
        Keychain.delete(Account.wrappedSeed)
        Keychain.delete(Account.plainSeed)
        Keychain.delete(Account.storageKey)
        Log.keys.notice("Host identity deleted at the owner's request")
    }

    private static func loadSeed() -> Result<(seed: Data, protection: KeyProtection), HostKeyError> {
        switch Keychain.read(Account.wrappedSeed) {
        case .success(let blob):
            do {
                let seed = try SecureEnclaveWrap.unwrap(blob)
                return .success((seed: seed, protection: KeyProtection.secureEnclave))
            } catch {
                Log.keys.error("Secure Enclave unwrap failed: \(String(describing: error), privacy: .public)")
                return .failure(.secureEnclave(String(describing: error)))
            }
        case .failure(.notFound):
            break
        case .failure(let error):
            return .failure(map(error))
        }

        switch Keychain.read(Account.plainSeed) {
        case .success(let seed):
            guard seed.count == 32 else { return .failure(.corrupt("host key has the wrong size")) }
            return .success((seed: seed, protection: KeyProtection.keychain))
        case .failure(.notFound):
            return createSeed()
        case .failure(let error):
            return .failure(map(error))
        }
    }

    /// Both items are genuinely absent: first run. Create and store a new identity.
    private static func createSeed() -> Result<(seed: Data, protection: KeyProtection), HostKeyError> {
        let seed = Curve25519.Signing.PrivateKey().rawRepresentation
        if SecureEnclave.isAvailable {
            do {
                let blob = try SecureEnclaveWrap.wrap(seed: seed)
                let status = Keychain.add(Account.wrappedSeed, data: blob, label: "Heartfulness Remote host key (Secure Enclave)")
                if status == errSecSuccess {
                    Log.keys.notice("Created host identity (Secure Enclave + Keychain)")
                    return .success((seed: seed, protection: KeyProtection.secureEnclave))
                }
                if status == errSecDuplicateItem { return loadSeed() }
                Log.keys.error("Could not store wrapped host key: \(Keychain.describe(status), privacy: .public)")
            } catch {
                Log.keys.error("Secure Enclave unavailable at runtime, falling back to Keychain: \(String(describing: error), privacy: .public)")
            }
        }
        let status = Keychain.add(Account.plainSeed, data: seed, label: "Heartfulness Remote host key")
        if status == errSecDuplicateItem { return loadSeed() }
        guard status == errSecSuccess else { return .failure(failure(for: status)) }
        Log.keys.notice("Created host identity (Keychain)")
        return .success((seed: seed, protection: KeyProtection.keychain))
    }

    private static func map(_ error: KeychainError) -> HostKeyError {
        switch error {
        case .notFound: return .keychainFailure("item not found")
        case .accessDenied(let status): return .keychainAccess(status)
        case .unexpected(let status): return .keychainFailure(Keychain.describe(status))
        case .corrupt(let detail): return .corrupt(detail)
        }
    }

    private static func failure(for status: OSStatus) -> HostKeyError {
        map(Keychain.classify(status))
    }

    static func randomBytes(_ count: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }
}

// MARK: - Secure Enclave wrapping of the Ed25519 seed

/// Seals the 32-byte Ed25519 seed with AES-GCM under a key derived (ECDH + HKDF-SHA256)
/// from a Secure Enclave P-256 key and an ephemeral P-256 key. The SE key never leaves
/// the chip; its opaque `dataRepresentation` is stored in the keychain with the box.
enum SecureEnclaveWrap {
    enum WrapError: Error {
        case accessControl
        case seal
        case corrupt
        case verify
    }

    private struct Blob: Codable {
        var v: Int
        var se: String
        var eph: String
        var box: String
    }

    private static let sharedInfo = Data("HR1/host-key-wrap".utf8)
    private static let salt = Data("HR1/host-key-wrap/salt".utf8)

    static func wrap(seed: Data) throws -> Data {
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &cfError
        ) else {
            throw WrapError.accessControl
        }
        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: sharedInfo, outputByteCount: 32)
        let sealed = try AES.GCM.seal(seed, using: key)
        guard let combined = sealed.combined else { throw WrapError.seal }
        let blob = Blob(v: 1,
                        se: Base64URL.encode(enclaveKey.dataRepresentation),
                        eph: Base64URL.encode(ephemeral.publicKey.rawRepresentation),
                        box: Base64URL.encode(combined))
        let data = try HRJSON.encode(blob)
        // Prove we can open it again before relying on it.
        guard try unwrap(data) == seed else { throw WrapError.verify }
        return data
    }

    static func unwrap(_ data: Data) throws -> Data {
        let blob = try JSONDecoder().decode(Blob.self, from: data)
        guard blob.v == 1,
              let enclaveData = Base64URL.decode(blob.se),
              let ephemeralRaw = Base64URL.decode(blob.eph),
              let combined = Base64URL.decode(blob.box) else {
            throw WrapError.corrupt
        }
        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: enclaveData)
        let ephemeralPublic = try P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralRaw)
        let shared = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeralPublic)
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: sharedInfo, outputByteCount: 32)
        let box = try AES.GCM.SealedBox(combined: combined)
        let seed = try AES.GCM.open(box, using: key)
        guard seed.count == 32 else { throw WrapError.corrupt }
        return seed
    }
}
