import Foundation
import BigInt

public class FF3 {
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
        guard tweak.count == 8 else {
            throw CypheraError.invalidTweakLength("tweak must be exactly 8 bytes, got \(tweak.count)")
        }
        guard alphabet.count >= 2 else {
            throw CypheraError.invalidRadix("alphabet must have >= 2 chars")
        }

        // FF3 reverses the key
        self.key = Data(key.reversed())
        self.tweak = tweak
        self.alphabet = alphabet
        self.radix = BigInt(alphabet.count)
        self.chars = Array(alphabet)
        var map: [Character: Int] = [:]
        for (i, c) in alphabet.enumerated() { map[c] = i }
        self.charMap = map
        self.aes = AESHelper(key: Data(key.reversed()))
    }

    public func encrypt(_ plaintext: String) throws -> String {
        let digits = try toDigits(plaintext)
        let result = try ff3Encrypt(digits)
        return fromDigits(result)
    }

    public func decrypt(_ ciphertext: String) throws -> String {
        let digits = try toDigits(ciphertext)
        let result = try ff3Decrypt(digits)
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

    private func calcP(round: Int, w: Data, half: [Int]) throws -> BigInt {
        var input = Data(count: 16)

        // First 4 bytes: W XOR round number in last byte
        input[0] = w[0]; input[1] = w[1]; input[2] = w[2]; input[3] = w[3]
        input[3] ^= UInt8(round)

        // Last 12 bytes: NUM_radix(REV(half))
        let revHalf = Array(half.reversed())
        let halfNum = num(revHalf)

        let hb: Data
        if halfNum == 0 {
            hb = Data(count: 1)
        } else {
            hb = bigIntToBytes(halfNum)
        }
        if hb.count <= 12 {
            for (i, b) in hb.enumerated() {
                input[16 - hb.count + i] = b
            }
        } else {
            for i in 0..<12 {
                input[4 + i] = hb[hb.count - 12 + i]
            }
        }

        // REVB before AES
        let revInput = Data(input.reversed())
        let aesOut = try aes.encrypt(revInput)
        // REVB after AES
        let revOut = Data(aesOut.reversed())

        // Convert to BigInt
        var result = BigInt(0)
        for byte in revOut {
            result = result * 256 + BigInt(byte)
        }
        return result
    }

    private func ff3Encrypt(_ pt: [Int]) throws -> [Int] {
        let n = pt.count
        let u = (n + 1) / 2  // ceil(n/2)
        let v = n - u
        var A = Array(pt[0..<u])
        var B = Array(pt[u..<n])

        for i in 0..<8 {
            let w = i % 2 == 0 ? Data(tweak[4..<8]) : Data(tweak[0..<4])
            if i % 2 == 0 {
                let p = try calcP(round: i, w: w, half: B)
                let m = radix.power(u)
                let aNum = num(A.reversed())
                let y = (aNum + p) % m
                A = str(y, length: u).reversed()
            } else {
                let p = try calcP(round: i, w: w, half: A)
                let m = radix.power(v)
                let bNum = num(B.reversed())
                let y = (bNum + p) % m
                B = str(y, length: v).reversed()
            }
        }
        return A + B
    }

    private func ff3Decrypt(_ ct: [Int]) throws -> [Int] {
        let n = ct.count
        let u = (n + 1) / 2
        let v = n - u
        var A = Array(ct[0..<u])
        var B = Array(ct[u..<n])

        for i in stride(from: 7, through: 0, by: -1) {
            let w = i % 2 == 0 ? Data(tweak[4..<8]) : Data(tweak[0..<4])
            if i % 2 == 0 {
                let p = try calcP(round: i, w: w, half: B)
                let m = radix.power(u)
                let aNum = num(A.reversed())
                var y = (aNum - p) % m
                if y < 0 { y += m }
                A = str(y, length: u).reversed()
            } else {
                let p = try calcP(round: i, w: w, half: A)
                let m = radix.power(v)
                let bNum = num(B.reversed())
                var y = (bNum - p) % m
                if y < 0 { y += m }
                B = str(y, length: v).reversed()
            }
        }
        return A + B
    }

    private func bigIntToBytes(_ value: BigInt) -> Data {
        var result: [UInt8] = []
        var temp = value
        let base = BigInt(256)
        while temp > 0 {
            let (q, r) = temp.quotientAndRemainder(dividingBy: base)
            result.insert(UInt8(r), at: 0)
            temp = q
        }
        return Data(result)
    }
}
