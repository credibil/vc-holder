//
//  store.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 06/11/2024.
//

import Foundation
import SharedTypes
import SwiftData

@Model
final class StoredObject {
    
    // The index or key for the object. Unique for a catalog.
    @Attribute(.unique) var id: String
    
    // The data to be stored as an array of bytes. It's up to the Crux layer to know how to
    // serialize/deserialize into its model.
    var data: Data
    
    init(id: String, data: Data) {
        self.id = id
        self.data = data
    }
    
    convenience init(id: String, bytes: [UInt8]) {
        self.init(id: id, data: Data(bytes))
    }
}

protocol Storer<T> {
    associatedtype T
    func save(_ item: T) throws
    func list() throws -> [T]
    func delete(_ item: T) throws
}

protocol Store<T> : Storer {
    associatedtype T = PersistentModel
    var container: ModelContainer { get }
}

extension Store {
    func save<T: PersistentModel>(_ item: T) throws {
        let context = ModelContext(container)
        context.insert(item)
        try context.save()
    }
    
    func list<T: PersistentModel>() throws -> [T] {
        let context = ModelContext(container)
        let fetchDescriptor = FetchDescriptor<T>()
        return try context.fetch(fetchDescriptor)
    }
    
    func delete<T: PersistentModel>(_ item: T) throws {
        let context = ModelContext(container)
        let id = item.persistentModelID
        try context.delete(model: T.self, where: #Predicate { item in item.persistentModelID == id })
        try context.save()
    }
}

final class ObjectStore: Store {
    typealias T = StoredObject
    let container: ModelContainer
    
    // Can use in-memory store for unit testing
    init(catalog: String) throws {
        let storeUrl = URL.documentsDirectory.appending(path: "\(catalog).store")
        
        let config = ModelConfiguration(url: storeUrl)
        self.container = try ModelContainer(for: StoredObject.self, configurations: config)
    }
}

enum StoreError: Error {
    case generic(Error)
    case message(String)
}

func requestStore(_ request: StoreOperation) async -> Result<StoreResponse, StoreError> {
    do {
        switch request {
        case .save(let catalog, let id, let data):
            let store = try ObjectStore(catalog: catalog)
            do {
                try store.save(StoredObject(id: id, bytes: data))
                return .success(.saved)
            } catch {
                return .failure(.message(error.localizedDescription))
            }
        case .list(let catalog):
            let store = try ObjectStore(catalog: catalog)
            do {
                let objects : [StoredObject] = try store.list()
                var entries: [StoreEntry] = []
                for object in objects {
                    entries.append(StoreEntry.data(Array(object.data)))
                }
                return .success(.list(entries: entries))
            } catch {
                return .failure(.message(error.localizedDescription))
            }
        case .delete(catalog: let catalog, id: let id):
            let store = try ObjectStore(catalog: catalog)
            do {
                // Find the object with the specified ID
                let object: StoredObject? = try store.list().first(where: { $0.id == id })
                if object != nil {
                    try store.delete(object!)
                }
                return .success(.deleted)
            } catch {
                return .failure(.message(error.localizedDescription))
            }
        }
    } catch {
        return .failure(.message(error.localizedDescription))
    }
}
