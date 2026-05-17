import Foundation

#if canImport(CommonCrypto)
import CommonCrypto
#else
import CryptoSwift
#endif

public class Cyphera {
    private var configurations: [String: Configuration] = [:]
    private var headerIndex: [String: String] = [:]
    private var keys: [String: Data] = [:]

    public init(config: [String: Any]) throws {
        // Load keys
        if let keysDict = config["keys"] as? [String: Any] {
            for (name, val) in keysDict {
                if let s = val as? String {
                    keys[name] = Data(hexString: s)
                } else if let d = val as? [String: Any] {
                    if let m = d["material"] as? String {
                        keys[name] = Data(hexString: m)
                    } else if let source = d["source"] as? String {
                        keys[name] = try resolveKeySource(name: name, source: source, config: d)
                    } else {
                        throw CypheraError.configError("Key '\(name)' must have either 'material' or 'source'")
                    }
                } else {
                    throw CypheraError.configError("Invalid key format for '\(name)'")
                }
            }
        }

        // Load configurations + build header index
        if let configurationsDict = config["configurations"] as? [String: Any] {
            for (name, val) in configurationsDict {
                guard let cfg = val as? [String: Any] else {
                    throw CypheraError.configError("Invalid configuration format for '\(name)'")
                }
                let headerEnabled = (cfg["header_enabled"] as? Bool) ?? true
                let header = cfg["header"] as? String

                if headerEnabled && header == nil {
                    throw CypheraError.configError("Configuration '\(name)' has header_enabled=true but no header")
                }

                if headerEnabled, let header = header {
                    if let existing = headerIndex[header] {
                        throw CypheraError.headerCollision("'\(header)' used by both '\(existing)' and '\(name)'")
                    }
                    headerIndex[header] = name
                }

                configurations[name] = Configuration(
                    engine: (cfg["engine"] as? String) ?? "ff1",
                    alphabet: resolveAlphabet(cfg["alphabet"] as? String),
                    keyRef: cfg["key_ref"] as? String,
                    header: header,
                    headerEnabled: headerEnabled,
                    headerLength: (cfg["header_length"] as? Int) ?? 3,
                    pattern: cfg["pattern"] as? String,
                    algorithm: (cfg["algorithm"] as? String) ?? "sha256"
                )
            }
        }
    }

    public func protect(_ value: String, configuration configurationName: String) throws -> String {
        let configuration = try getConfiguration(configurationName)

        switch configuration.engine {
        case "ff1": return try protectFpe(value, configuration: configuration, isFF3: false)
        case "ff3": return try protectFpe(value, configuration: configuration, isFF3: true)
        case "mask": return try protectMask(value, configuration: configuration)
        case "hash": return try protectHash(value, configuration: configuration)
        default: throw CypheraError.configError("Unknown engine: \(configuration.engine)")
        }
    }

    public func access(_ protectedValue: String, configuration configurationName: String? = nil) throws -> String {
        if let configurationName = configurationName {
            let configuration = try getConfiguration(configurationName)
            return try accessFpe(protectedValue, configuration: configuration, explicitConfiguration: true)
        }

        // Header-based lookup — check longest headers first
        let headers = headerIndex.keys.sorted { $0.count > $1.count }
        for header in headers {
            if protectedValue.hasPrefix(header) {
                let configuration = try getConfiguration(headerIndex[header]!)
                return try accessFpe(protectedValue, configuration: configuration)
            }
        }

        throw CypheraError.noMatchingHeader("No matching header found. Use access(value, configuration:) for headerless values.")
    }

    public func accessByHeader(_ protectedValue: String) throws -> String {
        return try access(protectedValue)
    }

    // MARK: - FPE protect

    private func protectFpe(_ value: String, configuration: Configuration, isFF3: Bool) throws -> String {
        let key = try resolveKey(configuration.keyRef)
        let alphabet = configuration.alphabet

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

        if configuration.headerEnabled, let header = configuration.header {
            return header + withPt
        }
        return withPt
    }

    // MARK: - FPE access

    private func accessFpe(_ protectedValue: String, configuration: Configuration, explicitConfiguration: Bool = false) throws -> String {
        guard ["ff1", "ff3"].contains(configuration.engine) else {
            throw CypheraError.notReversible("Cannot reverse '\(configuration.engine)'")
        }

        let key = try resolveKey(configuration.keyRef)
        let alphabet = configuration.alphabet

        var withoutHeader = protectedValue
        if !explicitConfiguration && configuration.headerEnabled, let header = configuration.header {
            withoutHeader = String(protectedValue.dropFirst(header.count))
        }

        let (encryptable, positions, chars) = extractPassthroughs(withoutHeader, alphabet: alphabet)

        let decrypted: String
        if configuration.engine == "ff3" {
            let cipher = try FF3(key: key, tweak: Data(count: 8), alphabet: alphabet)
            decrypted = try cipher.decrypt(encryptable)
        } else {
            let cipher = try FF1(key: key, tweak: Data(), alphabet: alphabet)
            decrypted = try cipher.decrypt(encryptable)
        }

        return reinsertPassthroughs(decrypted, positions: positions, chars: chars)
    }

    // MARK: - Mask

    private func protectMask(_ value: String, configuration: Configuration) throws -> String {
        guard let pattern = configuration.pattern else {
            throw CypheraError.configError("Mask configuration requires 'pattern'")
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

    private func protectHash(_ value: String, configuration: Configuration) throws -> String {
        let algo = configuration.algorithm.replacingOccurrences(of: "-", with: "").lowercased()
        let data = Data(value.utf8)

        if let keyRef = configuration.keyRef, let key = keys[keyRef] {
            return try hmacHash(data: data, key: key, algorithm: algo)
        }
        return try plainHash(data: data, algorithm: algo)
    }

    private func plainHash(data: Data, algorithm: String) throws -> String {
        #if canImport(CommonCrypto)
        switch algorithm {
        case "sha256":
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
            return Data(hash).hexString
        case "sha384":
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
            data.withUnsafeBytes { CC_SHA384($0.baseAddress, CC_LONG(data.count), &hash) }
            return Data(hash).hexString
        case "sha512":
            var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
            data.withUnsafeBytes { CC_SHA512($0.baseAddress, CC_LONG(data.count), &hash) }
            return Data(hash).hexString
        default:
            throw CypheraError.configError("Unsupported hash algorithm: \(algorithm)")
        }
        #else
        switch algorithm {
        case "sha256": return Data(CryptoSwift.Digest.sha256(Array(data))).hexString
        case "sha384": return Data(CryptoSwift.Digest.sha384(Array(data))).hexString
        case "sha512": return Data(CryptoSwift.Digest.sha512(Array(data))).hexString
        default: throw CypheraError.configError("Unsupported hash algorithm: \(algorithm)")
        }
        #endif
    }

    private func hmacHash(data: Data, key: Data, algorithm: String) throws -> String {
        #if canImport(CommonCrypto)
        let ccAlgo: CCHmacAlgorithm
        let digestLen: Int
        switch algorithm {
        case "sha256": ccAlgo = CCHmacAlgorithm(kCCHmacAlgSHA256); digestLen = Int(CC_SHA256_DIGEST_LENGTH)
        case "sha384": ccAlgo = CCHmacAlgorithm(kCCHmacAlgSHA384); digestLen = Int(CC_SHA384_DIGEST_LENGTH)
        case "sha512": ccAlgo = CCHmacAlgorithm(kCCHmacAlgSHA512); digestLen = Int(CC_SHA512_DIGEST_LENGTH)
        default: throw CypheraError.configError("Unsupported hash algorithm: \(algorithm)")
        }
        var hash = [UInt8](repeating: 0, count: digestLen)
        data.withUnsafeBytes { dataPtr in
            key.withUnsafeBytes { keyPtr in
                CCHmac(ccAlgo, keyPtr.baseAddress, key.count, dataPtr.baseAddress, data.count, &hash)
            }
        }
        return Data(hash).hexString
        #else
        let variant: CryptoSwift.HMAC.Variant
        switch algorithm {
        case "sha256": variant = .sha2(.sha256)
        case "sha384": variant = .sha2(.sha384)
        case "sha512": variant = .sha2(.sha512)
        default: throw CypheraError.configError("Unsupported hash algorithm: \(algorithm)")
        }
        let hmac = try CryptoSwift.HMAC(key: Array(key), variant: variant).authenticate(Array(data))
        return Data(hmac).hexString
        #endif
    }

    // MARK: - Helpers

    private func getConfiguration(_ name: String) throws -> Configuration {
        guard let c = configurations[name] else {
            throw CypheraError.unknownConfiguration(name)
        }
        return c
    }

    private func resolveKey(_ keyRef: String?) throws -> Data {
        guard let keyRef = keyRef else {
            throw CypheraError.configError("No key_ref in configuration")
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

// MARK: - Key Source Resolution

private let cloudSources: Set<String> = ["aws-kms", "gcp-kms", "azure-kv", "vault"]

private func resolveKeySource(name: String, source: String, config: [String: Any]) throws -> Data {
    if source == "env" {
        guard let varName = config["var"] as? String else {
            throw CypheraError.configError("Key '\(name)': source 'env' requires 'var' field")
        }
        guard let val = ProcessInfo.processInfo.environment[varName] else {
            throw CypheraError.configError("Key '\(name)': environment variable '\(varName)' is not set")
        }
        let encoding = config["encoding"] as? String ?? "hex"
        if encoding == "base64" {
            guard let data = Data(base64Encoded: val) else {
                throw CypheraError.configError("Key '\(name)': invalid base64 in env var '\(varName)'")
            }
            return data
        }
        return Data(hexString: val)
    }

    if source == "file" {
        guard let path = config["path"] as? String else {
            throw CypheraError.configError("Key '\(name)': source 'file' requires 'path' field")
        }
        let raw = try String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let encoding = config["encoding"] as? String
            ?? (path.hasSuffix(".b64") || path.hasSuffix(".base64") ? "base64" : "hex")
        if encoding == "base64" {
            guard let data = Data(base64Encoded: raw) else {
                throw CypheraError.configError("Key '\(name)': invalid base64 in file '\(path)'")
            }
            return data
        }
        return Data(hexString: raw)
    }

    if cloudSources.contains(source) {
        throw CypheraError.configError(
            "Key '\(name)' requires source '\(source)' but cyphera-keychain is not available.\n" +
            "Add dependency: cyphera-keychain"
        )
    }

    throw CypheraError.configError("Key '\(name)': unknown source '\(source)'. Valid: env, file, \(cloudSources.sorted().joined(separator: ", "))")
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
        // 1. CYPHERA_CONFIG_FILE env var
        if let envPath = ProcessInfo.processInfo.environment["CYPHERA_CONFIG_FILE"],
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
            "No configuration file found. Checked: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json"
        )
    }
}

// MARK: - Internal Types

struct Configuration {
    let engine: String
    let alphabet: String
    let keyRef: String?
    let header: String?
    let headerEnabled: Bool
    let headerLength: Int
    let pattern: String?
    let algorithm: String
}
