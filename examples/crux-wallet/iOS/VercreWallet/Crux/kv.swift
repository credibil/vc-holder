//
//  kv.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 13/11/2024.
//

import Foundation
import SharedTypes

enum KeyValueError: Error {
    case generic(Error)
    case message(String)
}

func requestKeyValue(_ request: KeyValueOperation) async -> Result<KeyValueResponse, KeyValueError> {
    
    debugPrint("Requesting key value: \(request)")
    
    switch request {
    case .get(key: let key):
        if let storedValue = UserDefaults.standard.data(forKey: key) {
            return .success(.get(value: .bytes([UInt8](storedValue))))
        } else {
            return .success(.get(value: .none))
        }
    case .set(key: let key, value: let value):
        if let previousValue = UserDefaults.standard.data(forKey: key) {
            UserDefaults.standard.set(value, forKey: key)
            return .success(.set(previous: .bytes([UInt8](previousValue))))
        } else {
            UserDefaults.standard.set(value, forKey: key)
            return .success(.set(previous: .none))
        }
    case .delete(key: let key):
        if let previousValue = UserDefaults.standard.data(forKey: key) {
            UserDefaults.standard.removeObject(forKey: key)
            return .success(.delete(previous: .bytes([UInt8](previousValue))))
        } else {
            return .success(.delete(previous: .none))
        }
    case .exists(key: let key):
        if let _ = UserDefaults.standard.data(forKey: key) {
            return .success(.exists(is_present: true))
        } else {
            return .success(.exists(is_present: false))
        }
    case .listKeys(prefix: _, cursor: _):
        var keys: [String] = []
        for k in UserDefaults.standard.dictionaryRepresentation().keys {
            keys.append(k)
        }
        return .success(.listKeys(keys: keys, next_cursor: 0))
    }
}
