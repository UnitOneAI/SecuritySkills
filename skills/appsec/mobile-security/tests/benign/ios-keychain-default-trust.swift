import Foundation
import Security

final class KeychainSessionStore {
    func save(refreshToken: String) throws {
        let item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.safe.session",
            kSecAttrAccount as String: "refresh-token",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(refreshToken.utf8)
        ]

        SecItemDelete(item as CFDictionary)
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    func makeSession() -> URLSession {
        URLSession(configuration: .ephemeral)
    }
}
