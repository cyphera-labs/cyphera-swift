import Foundation

public let ALPHA_DIGITS = "0123456789"
public let ALPHA_ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz"
public let ALPHA_ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
public let ALPHA_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
public let ALPHA_ALPHANUMERIC = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

public let ALPHABETS: [String: String] = [
    "digits": ALPHA_DIGITS,
    "alpha_lower": ALPHA_ALPHA_LOWER,
    "alpha_upper": ALPHA_ALPHA_UPPER,
    "alpha": ALPHA_ALPHA,
    "alphanumeric": ALPHA_ALPHANUMERIC,
]

func resolveAlphabet(_ name: String?) -> String {
    guard let name = name, !name.isEmpty else {
        return ALPHA_ALPHANUMERIC
    }
    return ALPHABETS[name] ?? name
}
