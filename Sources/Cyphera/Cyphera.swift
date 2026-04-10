import Foundation

public class Cyphera {
    private var policies: [String: PolicyConfig] = [:]
    private var tagIndex: [String: String] = [:]
    private var keys: [String: Data] = [:]

    public init(config: [String: Any]) throws {
        // Load keys
        if let keysDict = config["keys"] as? [String: Any] {
            for (name, val) in keysDict {
                let material: String
                if let s = val as? String {
                    material = s
                } else if let d = val as? [String: Any], let m = d["material"] as? String {
                    material = m
                } else {
                    throw CypheraError.configError("Invalid key format for '\(name)'")
                }
                keys[name] = Data(hexString: material)
            }
        }

        // Load policies + build tag index
        if let policiesDict = config["policies"] as? [String: Any] {
            for (name, val) in policiesDict {
                guard let pol = val as? [String: Any] else {
                    throw CypheraError.configError("Invalid policy format for '\(name)'")
                }
                let tagEnabled = (pol["tag_enabled"] as? Bool) ?? true
                let tag = pol["tag"] as? String

                if tagEnabled && tag == nil {
                    throw CypheraError.configError("Policy '\(name)' has tag_enabled=true but no tag")
                }

                if tagEnabled, let tag = tag {
                    if let existing = tagIndex[tag] {
                        throw CypheraError.tagCollision("'\(tag)' used by both '\(existing)' and '\(name)'")
                    }
                    tagIndex[tag] = name
                }

                policies[name] = PolicyConfig(
                    engine: (pol["engine"] as? String) ?? "ff1",
                    alphabet: resolveAlphabet(pol["alphabet"] as? String),
                    keyRef: pol["key_ref"] as? String,
                    tag: tag,
                    tagEnabled: tagEnabled,
                    tagLength: (pol["tag_length"] as? Int) ?? 3,
                    pattern: pol["pattern"] as? String,
                    algorithm: (pol["algorithm"] as? String) ?? "sha256"
                )
            }
        }
    }

    public func protect(_ value: String, policy policyName: String) throws -> String {
        let policy = try getPolicy(policyName)

        switch policy.engine {
        case "ff1": return try protectFpe(value, policy: policy, isFF3: false)
        case "ff3": return try protectFpe(value, policy: policy, isFF3: true)
        case "mask": return try protectMask(value, policy: policy)
        case "hash": return try protectHash(value, policy: policy)
        default: throw CypheraError.configError("Unknown engine: \(policy.engine)")
        }
    }

    public func access(_ protectedValue: String, policy policyName: String? = nil) throws -> String {
        if let policyName = policyName {
            let policy = try getPolicy(policyName)
            return try accessFpe(protectedValue, policy: policy)
        }

        // Tag-based lookup — check longest tags first
        let tags = tagIndex.keys.sorted { $0.count > $1.count }
        for tag in tags {
            if protectedValue.hasPrefix(tag) {
                let policy = try getPolicy(tagIndex[tag]!)
                return try accessFpe(protectedValue, policy: policy)
            }
        }

        throw CypheraError.noMatchingTag("No matching tag found. Use access(value, policy:) for untagged values.")
    }

    // MARK: - FPE protect

    private func protectFpe(_ value: String, policy: PolicyConfig, isFF3: Bool) throws -> String {
        let key = try resolveKey(policy.keyRef)
        let alphabet = policy.alphabet

        let (encryptable, positions, chars) = extractPassthroughs(value, alphabet: alphabet)
        guard !encryptable.isEmpty else {
            throw CypheraError.encryptionFailed("No encryptable characters in input")
        }

        let encrypted: String
        if isFF3 {
            let cipher = try FF3(key: key, tweak: Data(count: 8), alphabet: alphabet)
            encrypted = try cipher.encrypt(encryptable)
        } else {
            let cipher = try FF1(key: key, tweak: Data(), alphabet: alphabet)
            encrypted = try cipher.encrypt(encryptable)
        }

        let withPt = reinsertPassthroughs(encrypted, positions: positions, chars: chars)

        if policy.tagEnabled, let tag = policy.tag {
            return tag + withPt
        }
        return withPt
    }

    // MARK: - FPE access

    private func accessFpe(_ protectedValue: String, policy: PolicyConfig) throws -> String {
        guard ["ff1", "ff3"].contains(policy.engine) else {
            throw CypheraError.notReversible("Cannot reverse '\(policy.engine)'")
        }

        let key = try resolveKey(policy.keyRef)
        let alphabet = policy.alphabet

        var withoutTag = protectedValue
        if policy.tagEnabled, let tag = policy.tag {
            withoutTag = String(protectedValue.dropFirst(tag.count))
        }

        let (encryptable, positions, chars) = extractPassthroughs(withoutTag, alphabet: alphabet)

        let decrypted: String
        if policy.engine == "ff3" {
            let cipher = try FF3(key: key, tweak: Data(count: 8), alphabet: alphabet)
            decrypted = try cipher.decrypt(encryptable)
        } else {
            let cipher = try FF1(key: key, tweak: Data(), alphabet: alphabet)
            decrypted = try cipher.decrypt(encryptable)
        }

        return reinsertPassthroughs(decrypted, positions: positions, chars: chars)
    }

    // MARK: - Mask

    private func protectMask(_ value: String, policy: PolicyConfig) throws -> String {
        guard let pattern = policy.pattern else {
            throw CypheraError.configError("Mask policy requires 'pattern'")
        }
        let len = value.count
        let mask = "*"

        switch pattern {
        case "last4", "last_4":
            return String(repeating: mask, count: max(0, len - 4)) + String(value.suffix(4))
        case "last2", "last_2":
            return String(repeating: mask, count: max(0, len - 2)) + String(value.suffix(2))
        case "first1", "first_1":
            return String(value.prefix(1)) + String(repeating: mask, count: max(0, len - 1))
        case "first3", "first_3":
            return String(value.prefix(3)) + String(repeating: mask, count: max(0, len - 3))
        default:
            return String(repeating: mask, count: len)
        }
    }

    // MARK: - Hash

    private func protectHash(_ value: String, policy: PolicyConfig) throws -> String {
        throw CypheraError.configError("Hash engine not yet implemented in Swift SDK")
    }

    // MARK: - Helpers

    private func getPolicy(_ name: String) throws -> PolicyConfig {
        guard let p = policies[name] else {
            throw CypheraError.unknownPolicy(name)
        }
        return p
    }

    private func resolveKey(_ keyRef: String?) throws -> Data {
        guard let keyRef = keyRef else {
            throw CypheraError.configError("No key_ref in policy")
        }
        guard let key = keys[keyRef] else {
            throw CypheraError.unknownKey(keyRef)
        }
        return key
    }

    private func extractPassthroughs(_ value: String, alphabet: String) -> (String, [Int], [Character]) {
        var encryptable = ""
        var positions: [Int] = []
        var chars: [Character] = []

        for (i, c) in value.enumerated() {
            if alphabet.contains(c) {
                encryptable.append(c)
            } else {
                positions.append(i)
                chars.append(c)
            }
        }
        return (encryptable, positions, chars)
    }

    private func reinsertPassthroughs(_ encrypted: String, positions: [Int], chars: [Character]) -> String {
        var result = Array(encrypted)
        for i in 0..<positions.count {
            let pos = positions[i]
            if pos <= result.count {
                result.insert(chars[i], at: pos)
            } else {
                result.append(chars[i])
            }
        }
        return String(result)
    }
}

// MARK: - Factory Methods

extension Cyphera {
    public static func fromFile(_ path: String) throws -> Cyphera {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        guard let config = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CypheraError.configError("Invalid JSON in \(path)")
        }
        return try Cyphera(config: config)
    }

    public static func load() throws -> Cyphera {
        // 1. CYPHERA_POLICY_FILE env var
        if let envPath = ProcessInfo.processInfo.environment["CYPHERA_POLICY_FILE"],
           FileManager.default.fileExists(atPath: envPath) {
            return try fromFile(envPath)
        }

        // 2. ./cyphera.json
        let localPath = FileManager.default.currentDirectoryPath + "/cyphera.json"
        if FileManager.default.fileExists(atPath: localPath) {
            return try fromFile(localPath)
        }

        // 3. /etc/cyphera/cyphera.json
        let systemPath = "/etc/cyphera/cyphera.json"
        if FileManager.default.fileExists(atPath: systemPath) {
            return try fromFile(systemPath)
        }

        throw CypheraError.configError(
            "No policy file found. Checked: CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json"
        )
    }
}

// MARK: - Internal Types

struct PolicyConfig {
    let engine: String
    let alphabet: String
    let keyRef: String?
    let tag: String?
    let tagEnabled: Bool
    let tagLength: Int
    let pattern: String?
    let algorithm: String
}
