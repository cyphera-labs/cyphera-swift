import XCTest
@testable import Cyphera

final class FF1Tests: XCTestCase {

    let DIGITS = "0123456789"
    let ALPHANUMERIC = "0123456789abcdefghijklmnopqrstuvwxyz"

    func hex(_ s: String) -> Data { Data(hexString: s) }

    func nist(_ keyHex: String, _ tweakHex: String, _ alphabet: String, _ pt: String, _ ct: String,
              file: StaticString = #filePath, line: UInt = #line) throws {
        let key = hex(keyHex)
        let tweak = tweakHex.isEmpty ? Data() : hex(tweakHex)
        let c = try FF1(key: key, tweak: tweak, alphabet: alphabet)
        let encrypted = try c.encrypt(pt)
        XCTAssertEqual(encrypted, ct, "encrypt(\(pt))", file: file, line: line)
        let decrypted = try c.decrypt(ct)
        XCTAssertEqual(decrypted, pt, "decrypt(\(ct))", file: file, line: line)
    }

    // NIST SP 800-38G FF1 test vectors — AES-128
    func testSample1() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3C", "", DIGITS,
                 "0123456789", "2433477484")
    }

    func testSample2() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3C", "39383736353433323130", DIGITS,
                 "0123456789", "6124200773")
    }

    func testSample3() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3C", "3737373770717273373737", ALPHANUMERIC,
                 "0123456789abcdefghi", "a9tv40mll9kdu509eum")
    }

    // NIST SP 800-38G FF1 test vectors — AES-192
    func testSample4() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "", DIGITS,
                 "0123456789", "2830668132")
    }

    func testSample5() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "39383736353433323130", DIGITS,
                 "0123456789", "2496655549")
    }

    func testSample6() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "3737373770717273373737", ALPHANUMERIC,
                 "0123456789abcdefghi", "xbj3kv35jrawxv32ysr")
    }

    // NIST SP 800-38G FF1 test vectors — AES-256
    func testSample7() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "", DIGITS,
                 "0123456789", "6657667009")
    }

    func testSample8() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "39383736353433323130", DIGITS,
                 "0123456789", "1001623463")
    }

    func testSample9() throws {
        try nist("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "3737373770717273373737", ALPHANUMERIC,
                 "0123456789abcdefghi", "xs8a0azh2avyalyzuwd")
    }
}
