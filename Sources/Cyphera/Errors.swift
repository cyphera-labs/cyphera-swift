import Foundation

public enum CypheraError: Error, LocalizedError {
    case invalidRadix(String)
    case invalidKeyLength(String)
    case invalidTweakLength(String)
    case invalidInputLength(String)
    case invalidCharacter(String)
    case encryptionFailed(String)
    case unknownPolicy(String)
    case unknownKey(String)
    case notReversible(String)
    case noMatchingTag(String)
    case tagCollision(String)
    case configError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidRadix(let msg): return "Invalid radix: \(msg)"
        case .invalidKeyLength(let msg): return "Invalid key length: \(msg)"
        case .invalidTweakLength(let msg): return "Invalid tweak length: \(msg)"
        case .invalidInputLength(let msg): return "Invalid input length: \(msg)"
        case .invalidCharacter(let msg): return "Invalid character: \(msg)"
        case .encryptionFailed(let msg): return "Encryption failed: \(msg)"
        case .unknownPolicy(let msg): return "Unknown policy: \(msg)"
        case .unknownKey(let msg): return "Unknown key: \(msg)"
        case .notReversible(let msg): return "Not reversible: \(msg)"
        case .noMatchingTag(let msg): return "No matching tag: \(msg)"
        case .tagCollision(let msg): return "Tag collision: \(msg)"
        case .configError(let msg): return "Config error: \(msg)"
        }
    }
}
