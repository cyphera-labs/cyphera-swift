import XCTest
@testable import Cyphera

final class CypheraTests: XCTestCase {

    func makeConfig() -> [String: Any] {
        return [
            "keys": [
                "demo-key": ["material": "2B7E151628AED2A6ABF7158809CF4F3C"]
            ],
            "policies": [
                "ssn": [
                    "engine": "ff1",
                    "key_ref": "demo-key",
                    "tag": "T01"
                ],
                "credit_card": [
                    "engine": "ff1",
                    "key_ref": "demo-key",
                    "tag": "T02"
                ],
                "name": [
                    "engine": "ff1",
                    "alphabet": "alpha_lower",
                    "key_ref": "demo-key",
                    "tag": "T03"
                ],
                "ssn_untagged": [
                    "engine": "ff1",
                    "alphabet": "digits",
                    "key_ref": "demo-key",
                    "tag_enabled": false
                ]
            ]
        ]
    }

    func testProtectAndAccess() throws {
        let c = try Cyphera(config: makeConfig())

        let ssn = "123-45-6789"
        let protected = try c.protect(ssn, policy: "ssn")

        // Should start with tag
        XCTAssert(protected.hasPrefix("T01"), "Protected value should start with tag T01, got: \(protected)")

        // Should preserve dashes
        let dashCount = protected.filter { $0 == "-" }.count
        XCTAssertEqual(dashCount, 2, "Should preserve 2 dashes")

        // Round-trip via tag-based access
        let recovered = try c.access(protected)
        XCTAssertEqual(recovered, ssn, "Tag-based access should recover original")
    }

    func testTagBasedAccess() throws {
        let c = try Cyphera(config: makeConfig())

        let p1 = try c.protect("123-45-6789", policy: "ssn")
        let p2 = try c.protect("4111-1111-1111-1111", policy: "credit_card")

        XCTAssert(p1.hasPrefix("T01"))
        XCTAssert(p2.hasPrefix("T02"))

        let r1 = try c.access(p1)
        let r2 = try c.access(p2)

        XCTAssertEqual(r1, "123-45-6789")
        XCTAssertEqual(r2, "4111-1111-1111-1111")
    }

    func testUntaggedRoundTrip() throws {
        let c = try Cyphera(config: makeConfig())

        let ssn = "123456789"
        let protected = try c.protect(ssn, policy: "ssn_untagged")

        // No tag prefix
        XCTAssertEqual(protected.count, 9, "Untagged digits should be same length")

        // Must pass policy name for untagged access
        let recovered = try c.access(protected, policy: "ssn_untagged")
        XCTAssertEqual(recovered, ssn)
    }

    func testDeterminism() throws {
        let c = try Cyphera(config: makeConfig())

        let a = try c.protect("123-45-6789", policy: "ssn")
        let b = try c.protect("123-45-6789", policy: "ssn")

        XCTAssertEqual(a, b, "FPE should be deterministic with same key/tweak")
    }

    func testMask() throws {
        var config = makeConfig()
        var policies = config["policies"] as! [String: Any]
        policies["ssn_mask"] = [
            "engine": "mask",
            "pattern": "last4",
            "tag_enabled": false
        ] as [String: Any]
        config["policies"] = policies

        let c = try Cyphera(config: config)
        let masked = try c.protect("123-45-6789", policy: "ssn_mask")
        XCTAssertEqual(masked, "*******6789")
    }

    func testTagCollision() {
        let config: [String: Any] = [
            "keys": ["k": ["material": "2B7E151628AED2A6ABF7158809CF4F3C"]],
            "policies": [
                "a": ["engine": "ff1", "key_ref": "k", "tag": "T01"],
                "b": ["engine": "ff1", "key_ref": "k", "tag": "T01"]
            ]
        ]
        XCTAssertThrowsError(try Cyphera(config: config))
    }

    func testNoMatchingTag() throws {
        let c = try Cyphera(config: makeConfig())
        XCTAssertThrowsError(try c.access("ZZZsomething"))
    }

    func testNonReversibleAccess() throws {
        var config = makeConfig()
        var policies = config["policies"] as! [String: Any]
        policies["m"] = [
            "engine": "mask",
            "pattern": "full",
            "tag": "M01"
        ] as [String: Any]
        config["policies"] = policies

        let c = try Cyphera(config: config)
        let masked = try c.protect("hello", policy: "m")
        XCTAssertThrowsError(try c.access(masked))
    }
}
