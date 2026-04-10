import Foundation
import BigInt

public class FF1 {
    private let key: Data
    private let tweak: Data
    private let alphabet: String
    private let radix: BigInt
    private let charMap: [Character: Int]
    private let chars: [Character]
    private let aes: AESHelper

    public init(key: Data, tweak: Data, alphabet: String = ALPHA_ALPHANUMERIC) throws {
        guard [16, 24, 32].contains(key.count) else {
            throw CypheraError.invalidKeyLength("key must be 16, 24, or 32 bytes, got \(key.count)")
        }
        guard alphabet.count >= 2 else {
            throw CypheraError.invalidRadix("alphabet must have >= 2 chars")
        }

        self.key = key
        self.tweak = tweak
        self.alphabet = alphabet
        self.radix = BigInt(alphabet.count)
        self.chars = Array(alphabet)
        var map: [Character: Int] = [:]
        for (i, c) in alphabet.enumerated() { map[c] = i }
        self.charMap = map
        self.aes = AESHelper(key: key)
    }

    public func encrypt(_ plaintext: String) throws -> String {
        let digits = try toDigits(plaintext)
        let result = try ff1Encrypt(digits, T: tweak)
        return fromDigits(result)
    }

    public func decrypt(_ ciphertext: String) throws -> String {
        let digits = try toDigits(ciphertext)
        let result = try ff1Decrypt(digits, T: tweak)
        return fromDigits(result)
    }

    private func toDigits(_ s: String) throws -> [Int] {
        var digits: [Int] = []
        for (i, c) in s.enumerated() {
            guard let d = charMap[c] else {
                throw CypheraError.invalidCharacter("'\(c)' at pos \(i) not in alphabet")
            }
            digits.append(d)
        }
        return digits
    }

    private func fromDigits(_ d: [Int]) -> String {
        String(d.map { chars[$0] })
    }

    private func aesEcb(_ block: Data) throws -> Data {
        try aes.encrypt(block)
    }

    // CBC-MAC PRF
    private func prf(_ data: Data) throws -> Data {
        var y = Data(count: 16)
        for i in stride(from: 0, to: data.count, by: 16) {
            var tmp = Data(count: 16)
            for j in 0..<16 {
                tmp[j] = y[j] ^ data[i + j]
            }
            y = try aesEcb(tmp)
        }
        return y
    }

    // Expand S for multi-block keystream
    private func expandS(_ R: Data, d: Int) throws -> Data {
        let blocks = (d + 15) / 16
        var out = Data(count: blocks * 16)
        out.replaceSubrange(0..<16, with: R)

        for j in 1..<blocks {
            var x = Data(count: 16)
            // Write j as big-endian uint64 in last 8 bytes
            let jBig = UInt64(j)
            x[8] = UInt8((jBig >> 56) & 0xFF)
            x[9] = UInt8((jBig >> 48) & 0xFF)
            x[10] = UInt8((jBig >> 40) & 0xFF)
            x[11] = UInt8((jBig >> 32) & 0xFF)
            x[12] = UInt8((jBig >> 24) & 0xFF)
            x[13] = UInt8((jBig >> 16) & 0xFF)
            x[14] = UInt8((jBig >> 8) & 0xFF)
            x[15] = UInt8(jBig & 0xFF)
            // XOR with R
            for k in 0..<16 { x[k] ^= R[k] }
            let enc = try aesEcb(x)
            out.replaceSubrange(j*16..<(j+1)*16, with: enc)
        }
        return Data(out[0..<d])
    }

    private func num(_ digits: [Int]) -> BigInt {
        var r = BigInt(0)
        for d in digits { r = r * radix + BigInt(d) }
        return r
    }

    private func str(_ num: BigInt, length: Int) -> [Int] {
        var result = Array(repeating: 0, count: length)
        var temp = num
        for i in stride(from: length - 1, through: 0, by: -1) {
            let (q, r) = temp.quotientAndRemainder(dividingBy: radix)
            result[i] = Int(r)
            temp = q
        }
        return result
    }

    private func computeB(v: Int) -> Int {
        let pow = radix.power(v) - 1
        if pow == 0 { return 1 }
        let bitLen = BigUInt(pow).bitWidth
        return (bitLen + 7) / 8
    }

    private func buildP(u: Int, n: Int, t: Int) -> Data {
        var P = Data(count: 16)
        P[0] = 1; P[1] = 2; P[2] = 1
        let radixInt = Int(radix)
        P[3] = UInt8((radixInt >> 16) & 0xFF)
        P[4] = UInt8((radixInt >> 8) & 0xFF)
        P[5] = UInt8(radixInt & 0xFF)
        P[6] = 10
        P[7] = UInt8(u & 0xFF)
        // n as uint32 big-endian at offset 8
        P[8] = UInt8((n >> 24) & 0xFF)
        P[9] = UInt8((n >> 16) & 0xFF)
        P[10] = UInt8((n >> 8) & 0xFF)
        P[11] = UInt8(n & 0xFF)
        // t as uint32 big-endian at offset 12
        P[12] = UInt8((t >> 24) & 0xFF)
        P[13] = UInt8((t >> 16) & 0xFF)
        P[14] = UInt8((t >> 8) & 0xFF)
        P[15] = UInt8(t & 0xFF)
        return P
    }

    private func buildQ(T: Data, i: Int, numBytes: Data, b: Int) -> Data {
        let pad = (16 - ((T.count + 1 + b) % 16)) % 16
        let totalLen = T.count + pad + 1 + b
        var Q = Data(count: totalLen)
        Q.replaceSubrange(0..<T.count, with: T)
        Q[T.count + pad] = UInt8(i)
        let start = max(0, numBytes.count - b)
        let dest = Q.count - (numBytes.count - start)
        if numBytes.count > start {
            Q.replaceSubrange(dest..<dest + (numBytes.count - start),
                              with: numBytes[start..<numBytes.count])
        }
        return Q
    }

    private func bigIntToBytes(_ x: BigInt, b: Int) -> Data {
        var hex = String(x, radix: 16)
        while hex.count < b * 2 { hex = "0" + hex }
        // Take last b*2 chars
        if hex.count > b * 2 {
            hex = String(hex.suffix(b * 2))
        }
        return Data(hexString: hex)
    }

    private func ff1Encrypt(_ pt: [Int], T: Data) throws -> [Int] {
        let n = pt.count
        let u = n / 2
        let v = n - u
        var A = Array(pt[0..<u])
        var B = Array(pt[u..<n])

        let b = computeB(v: v)
        let d = 4 * ((b + 3) / 4) + 4
        let P = buildP(u: u, n: n, t: T.count)

        for i in 0..<10 {
            let numB = bigIntToBytes(num(B), b: b)
            let Q = buildQ(T: T, i: i, numBytes: numB, b: b)
            let R = try prf(P + Q)
            let S = try expandS(R, d: d)
            let y = BigInt(Data: S)
            let m = i % 2 == 0 ? u : v
            let c = (num(A) + y) % radix.power(m)
            A = B
            B = str(c, length: m)
        }
        return A + B
    }

    private func ff1Decrypt(_ ct: [Int], T: Data) throws -> [Int] {
        let n = ct.count
        let u = n / 2
        let v = n - u
        var A = Array(ct[0..<u])
        var B = Array(ct[u..<n])

        let b = computeB(v: v)
        let d = 4 * ((b + 3) / 4) + 4
        let P = buildP(u: u, n: n, t: T.count)

        for i in stride(from: 9, through: 0, by: -1) {
            let numA = bigIntToBytes(num(A), b: b)
            let Q = buildQ(T: T, i: i, numBytes: numA, b: b)
            let R = try prf(P + Q)
            let S = try expandS(R, d: d)
            let y = BigInt(Data: S)
            let m = i % 2 == 0 ? u : v
            let mod = radix.power(m)
            var c = (num(B) - y) % mod
            if c < 0 { c += mod }
            B = A
            A = str(c, length: m)
        }
        return A + B
    }
}

// Helper extensions for hex/Data conversion
extension Data {
    init(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            if let num = UInt8(hexString[i..<j], radix: 16) {
                data.append(num)
            }
            i = j
        }
        self = data
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

extension BigInt {
    init(Data data: Data) {
        var result = BigInt(0)
        for byte in data {
            result = result * 256 + BigInt(byte)
        }
        self = result
    }
}
