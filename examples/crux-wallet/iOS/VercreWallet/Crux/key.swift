//
//  key.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 13/11/2024.
//

import Foundation
import Security
import SharedTypes

enum KeyStoreError: Error {
    case generic(Error)
    case message(String)
}

// NOTE: While KeyChain has a kSecClassKey, we use kSecClassGenericPassword to
// store the key bytes as a simple secret. Doing this implies we need a service
// (mapped to 'purpose') and account (mapped to 'id') as the compound key. We
// dispense with specific kSecClassKey storage as this adds complexity around key
// management and types that we avoid since the key value is being used in the
// Crux layer, not directly in Swift itself.

// See: https://www.andyibanez.com/posts/using-ios-keychain-swift/ for a
// reasonable resource for this strange API.
//
// See: https://medium.com/@emt.joshhart/how-to-save-a-realm-encryption-key-to-keychain-in-swift-22fc87aa0ad
// for working with secure random bytes instead of strings as in article above.

/// Keyring generates keys and manages access to the iOS KeyChain
struct Keyring {
    /// This tag namespaces the keys to our app.
    private static let baseTag: String = "io.vercre.wallet"
    
    /// Size of key in bytes
    private static let keySize: Int = 32
    
    /// Size of the key in bits
    private static let keyLength: CFNumber = keySize * 8 as CFNumber
        
    /// Convert a boolean true to a core foundation boolean true
    private static let cfTrue: CFBoolean = true as CFBoolean
    
    /// Create a tag for a key
    private static func keyTag(id: String, purpose: String) -> CFData {
        let tag = "\(baseTag).\(id).\(purpose)"
        return tag.data(using: .utf8)! as CFData
    }
    
    /// Query for writing to the KeyChain
    private static func writeQuery(id: String, purpose: String, data: Data) -> CFDictionary {
        return [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: keyTag(id: id, purpose: purpose),
            kSecAttrKeySizeInBits: keyLength,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecReturnData: cfTrue
        ] as CFDictionary
    }
    
    /// Query for reading from the KeyChain
    private static func readQuery(id: String, purpose: String) -> CFDictionary {
        return [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: keyTag(id: id, purpose: purpose),
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: cfTrue
        ] as CFDictionary
    }
    
    /// Key generation
    private static func generateKey() -> Data? {
        var bytes = [UInt8](repeating: 0, count: Int(keySize))
        let status = SecRandomCopyBytes(kSecRandomDefault, keySize, &bytes)
        guard status == errSecSuccess else {
            return nil
        }
        return Data(bytes)
    }
    
    /// Retrieve a key from KeyChain
    static func getKey(id: String, purpose: String) -> Data? {
        let query: CFDictionary = readQuery(id: id, purpose: purpose)
        var ref: CFTypeRef?
        let status = SecItemCopyMatching(query, &ref)
        guard status != errSecItemNotFound else {
            return nil
        }
        guard status == errSecSuccess else {
            print(">>> keychain error \(status)")
            return nil
        }
        return ref as! Data?
    }
    
    /// Create a key and store it in KeyChain
    static func createKey(id: String, purpose: String) -> Data? {
        guard let key = generateKey() else {
            return nil
        }
        let query: CFDictionary = writeQuery(id: id, purpose: purpose, data: key)
        let status = SecItemAdd(query, nil)
        guard status == errSecSuccess else {
            if status == errSecDuplicateItem {
                print(">>> attempt to write duplicate key")
            } else {
                print(">>> keychain error \(status)")
            }
            return nil
        }
        return key
    }
}

let key_length: Int = 32

func requestKeyStore(_ request: KeyStoreOperation) async -> Result<KeyStoreResponse, KeyStoreError> {
    switch request {
    case .get(let id, let purpose):
        print(">>> keystore get \(id) \(purpose)")
        if let storedKey = Keyring.getKey(id: id, purpose: purpose) {
            print(">>> keystore key found \(storedKey)")
            let entry = KeyStoreEntry(data: Array(storedKey))
            return .success(.retrieved(key: entry))
        }
        if let createdKey = Keyring.createKey(id: id, purpose: purpose) {
            print(">>> keystore key created \(createdKey)")
            let entry = KeyStoreEntry(data: Array(createdKey))
            return .success(.retrieved(key: entry))
        }
        return .failure(.message("key not found or could not be generated"))
    }
}
