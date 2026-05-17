import XCTest
@testable import Cyphera

final class CypheraTests: XCTestCase {

    func makeConfig() -> [String: Any] {
        return [
            "keys": [
                "demo-key": ["material": "2B7E151628AED2A6ABF7158809CF4F3C"]
            ],
            "configurations": [
                "ssn": [
                    "engine": "ff1",
                    "key_ref": "demo-key",
                    "header": "T01"
                ],
                "credit_card": [
                    "engine": "ff1",
                    "key_ref": "demo-key",
                    "header": "T02"
                ],
                "name": [
                    "engine": "ff1",
                    "alphabet": "alpha_lower",
                    "key_ref": "demo-key",
                    "header": "T03"
                ],
                "ssn_headerless": [
                    "engine": "ff1",
                    "alphabet": "digits",
                    "key_ref": "demo-key",
                    "header_enabled": false
                ]
            ]
        ]
    }

    func testProtectAndAccess() throws {
        let c = try Cyphera(config: makeConfig())

        let ssn = "123-45-6789"
        let protected = try c.protect(ssn, configuration: "ssn")

        // Should start with header
        XCTAssert(protected.hasPrefix("T01"), "Protected value should start with header T01, got: \(protected)")

        // Should preserve dashes
        let dashCount = protected.filter { $0 == "-" }.count
        XCTAssertEqual(dashCount, 2, "Should preserve 2 dashes")

        // Round-trip via header-based access
        let recovered = try c.access(protected)
        XCTAssertEqual(recovered, ssn, "Header-based access should recover original")
    }

    func testHeaderBasedAccess() throws {
        let c = try Cyphera(config: makeConfig())

        let p1 = try c.protect("123-45-6789", configuration: "ssn")
        let p2 = try c.protect("4111-1111-1111-1111", configuration: "credit_card")

        XCTAssert(p1.hasPrefix("T01"))
        XCTAssert(p2.hasPrefix("T02"))

        let r1 = try c.access(p1)
        let r2 = try c.access(p2)

        XCTAssertEqual(r1, "123-45-6789")
        XCTAssertEqual(r2, "4111-1111-1111-1111")
    }

    func testHeaderlessRoundTrip() throws {
        let c = try Cyphera(config: makeConfig())

        let ssn = "123456789"
        let protected = try c.protect(ssn, configuration: "ssn_headerless")

        // No header prefix
        XCTAssertEqual(protected.count, 9, "Headerless digits should be same length")

        // Must pass configuration name for headerless access
        let recovered = try c.access(protected, configuration: "ssn_headerless")
        XCTAssertEqual(recovered, ssn)
    }

    func testDeterminism() throws {
        let c = try Cyphera(config: makeConfig())

        let a = try c.protect("123-45-6789", configuration: "ssn")
        let b = try c.protect("123-45-6789", configuration: "ssn")

        XCTAssertEqual(a, b, "FPE should be deterministic with same key/tweak")
    }

    func testMask() throws {
        var config = makeConfig()
        var configurations = config["configurations"] as! [String: Any]
        configurations["ssn_mask"] = [
            "engine": "mask",
            "pattern": "last4",
            "header_enabled": false
        ] as [String: Any]
        config["configurations"] = configurations

        let c = try Cyphera(config: config)
        let masked = try c.protect("123-45-6789", configuration: "ssn_mask")
        XCTAssertEqual(masked, "*******6789")
    }

    func testHeaderCollision() {
        let config: [String: Any] = [
            "keys": ["k": ["material": "2B7E151628AED2A6ABF7158809CF4F3C"]],
            "configurations": [
                "a": ["engine": "ff1", "key_ref": "k", "header": "T01"],
                "b": ["engine": "ff1", "key_ref": "k", "header": "T01"]
            ]
        ]
        XCTAssertThrowsError(try Cyphera(config: config))
    }

    func testNoMatchingHeader() throws {
        let c = try Cyphera(config: makeConfig())
        XCTAssertThrowsError(try c.access("ZZZsomething"))
    }

    func testNonReversibleAccess() throws {
        var config = makeConfig()
        var configurations = config["configurations"] as! [String: Any]
        configurations["m"] = [
            "engine": "mask",
            "pattern": "full",
            "header": "M01"
        ] as [String: Any]
        config["configurations"] = configurations

        let c = try Cyphera(config: config)
        let masked = try c.protect("hello", configuration: "m")
        XCTAssertThrowsError(try c.access(masked))
    }

    // 2-arg access(value, configuration:) on a header_enabled=true configuration
    // must error — the two-arg form is for header_enabled=false only. For
    // headered configs, the header itself identifies the configuration.
    func testExplicitAccessOnHeaderedConfigurationErrors() throws {
        let c = try Cyphera(config: makeConfig())
        let protected = try c.protect("123-45-6789", configuration: "ssn")
        XCTAssertThrowsError(try c.access(protected, configuration: "ssn")) { error in
            guard case CypheraError.explicitAccessOnHeaderedConfiguration(let name) = error else {
                XCTFail("Expected explicitAccessOnHeaderedConfiguration, got \(error)")
                return
            }
            XCTAssertEqual(name, "ssn")
        }
    }
}
