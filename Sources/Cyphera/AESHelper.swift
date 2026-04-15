import Foundation

#if canImport(CommonCrypto)
import CommonCrypto
#else
import CryptoSwift
#endif

struct AESHelper {
    private let key: [UInt8]

    init(key: Data) {
        self.key = Array(key)
    }

    func encrypt(_ data: Data) throws -> Data {
        guard data.count == 16 else {
            throw CypheraError.encryptionFailed("AES input must be exactly 16 bytes")
        }

        #if canImport(CommonCrypto)
        var outLength: Int = 0
        var outBytes = [UInt8](repeating: 0, count: data.count)
        let status = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
            // This is single-block encryption used as a building block, not ECB mode applied to user data.
            CCOptions(kCCOptionECBMode),
            key, key.count,
            nil,
            Array(data), data.count,
            &outBytes, outBytes.count,
            &outLength
        )
        guard status == kCCSuccess else {
            throw CypheraError.encryptionFailed("AES-ECB failed with status \(status)")
        }
        return Data(outBytes)
        #else
        // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
        // This is single-block encryption used as a building block, not ECB mode applied to user data.
        let aes = try CryptoSwift.AES(key: key, blockMode: ECB(), padding: .noPadding)
        let encrypted = try aes.encrypt(Array(data))
        return Data(encrypted)
        #endif
    }
}
