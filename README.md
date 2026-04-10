# cyphera-swift

[![CI](https://github.com/cyphera-labs/cyphera-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-swift/actions/workflows/ci.yml)
[![Swift 5.9+](https://img.shields.io/badge/Swift-5.9+-orange)](https://swift.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Data protection SDK for Swift — format-preserving encryption (FF1/FF3), data masking, and hashing.

```swift
.package(url: "https://github.com/cyphera-labs/cyphera-swift.git", from: "0.0.1-alpha.1")
```

## Usage

```swift
import Cyphera

// Load policy from file
let cyphera = try Cyphera.load()

// Protect data — policy decides the engine
let protected = try cyphera.protect("123-45-6789", policy: "ssn")
// → "T01k7R-m2-9xPqR4n"

// Access data — tag-based, no policy name needed
let original = try cyphera.access(protected)
// → "123-45-6789"
```

## Engines

| Engine | Reversible | Description |
|--------|-----------|-------------|
| ff1    | Yes       | NIST SP 800-38G FF1 |
| ff3    | Yes       | NIST SP 800-38G Rev 1 FF3-1 |
| mask   | No        | Simple pattern masking |
| hash   | No        | SHA-256/384/512, HMAC (coming soon) |

## Policy File (cyphera.json)

```json
{
  "policies": {
    "ssn": {
      "engine": "ff1",
      "key_ref": "demo-key",
      "tag": "T01"
    },
    "credit_card": {
      "engine": "ff1",
      "key_ref": "demo-key",
      "tag": "T02"
    },
    "name": {
      "engine": "ff1",
      "alphabet": "alpha_lower",
      "key_ref": "demo-key",
      "tag": "T03"
    }
  },
  "keys": {
    "demo-key": {
      "material": "2B7E151628AED2A6ABF7158809CF4F3C"
    }
  }
}
```

## Primitives

For direct engine access without the policy layer:

```swift
import Cyphera

let key = Data(hexString: "2B7E151628AED2A6ABF7158809CF4F3C")
let tweak = Data(count: 0)

let ff1 = try FF1(key: key, tweak: tweak, alphabet: "0123456789")
let encrypted = try ff1.encrypt("0123456789")   // "2433477484"
let decrypted = try ff1.decrypt("2433477484")   // "0123456789"
```

## Cross-Language Compatible

All Cyphera SDKs produce identical output for the same key, tweak, and alphabet:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Python:      T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
Swift:       T01i6J-xF-07pX
```

## Platform Support

- macOS 10.15+, iOS 13+, tvOS 13+, watchOS 6+
- Linux (via CryptoSwift fallback)
- Uses native CommonCrypto/CryptoKit on Apple platforms for hardware-accelerated AES

## Status

Alpha. API is unstable.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
