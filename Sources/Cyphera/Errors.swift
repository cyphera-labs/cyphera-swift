import Foundation

public enum CypheraError: Error, LocalizedError {
    case invalidRadix(String)
    case invalidKeyLength(String)
    case invalidTweakLength(String)
    case invalidInputLength(String)
    case invalidCharacter(String)
    case encryptionFailed(String)
    case unknownConfiguration(String)
    case unknownKey(String)
    case notReversible(String)
    case noMatchingHeader(String)
    case headerCollision(String)
    case configError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidRadix(let msg): return "Invalid radix: \(msg)"
        case .invalidKeyLength(let msg): return "Invalid key length: \(msg)"
        case .invalidTweakLength(let msg): return "Invalid tweak length: \(msg)"
        case .invalidInputLength(let msg): return "Invalid input length: \(msg)"
        case .invalidCharacter(let msg): return "Invalid character: \(msg)"
        case .encryptionFailed(let msg): return "Encryption failed: \(msg)"
        case .unknownConfiguration(let msg): return "Unknown configuration: \(msg)"
        case .unknownKey(let msg): return "Unknown key: \(msg)"
        case .notReversible(let msg): return "Not reversible: \(msg)"
        case .noMatchingHeader(let msg): return "No matching header: \(msg)"
        case .headerCollision(let msg): return "Header collision: \(msg)"
        case .configError(let msg): return "Config error: \(msg)"
        }
    }
}
