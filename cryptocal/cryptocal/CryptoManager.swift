import Foundation
import CryptoKit
import Security

class CryptoManager {
    static let shared = CryptoManager()
    
    private init() { }
    
    func generateSymmetricKey() -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }
    
    func sha256Hash(data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }
    
    func encrypt(data: Data, using key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined!
    }
    
    func decrypt(data: Data, using key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
}