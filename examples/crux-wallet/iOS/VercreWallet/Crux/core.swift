//
//  core.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 15/10/2024.
//

import Foundation
import SharedTypes

@MainActor // ensures this code runs on the main UI thread
class Core: ObservableObject {
    @Published var view: ViewModel
    
    init() {
        self.view = try! .bincodeDeserialize(input: [UInt8](VercreWallet.view()))
    }
    
    func update(_ event: Event) {
        let effects = [UInt8](processEvent(Data(try! event.bincodeSerialize())))
        
        let requests: [Request] = try! .bincodeDeserialize(input: effects)
        for request in requests {
            processEffect(request)
        }
    }
    
    func processEffect(_ request: Request) {
        
        debugPrint("Processing effect: \(request)")
        
        switch request.effect {
        case .render:
            view = try! .bincodeDeserialize(input: [UInt8](VercreWallet.view()))
        case let .http(req):
            Task {
                let response = try! await requestHttp(req).get()
                let effects = [UInt8](handleResponse(
                    request.id,
                    Data(try! HttpResult.ok(response).bincodeSerialize())
                ))
                let requests: [Request] = try! .bincodeDeserialize(input: effects)
                for request in requests {
                    processEffect(request)
                }
            }
        case let .serverSentEvents(req):
            Task {
                for await result in await requestSse(req) {
                    let response = try result.get()
                    let effects = [UInt8](handleResponse(request.id, Data(try! response.bincodeSerialize())))
                    let requests: [Request] = try! .bincodeDeserialize(input: effects)
                    for request in requests {
                        processEffect(request)
                    }
                }
            }
        case let .store(req):
            Task {
                let response = try! await requestStore(req).get()
                let effects = [UInt8](handleResponse(request.id, Data(try! StoreResult.ok(response: response).bincodeSerialize())))
                let requests: [Request] = try! .bincodeDeserialize(input: effects)
                for request in requests {
                    processEffect(request)
                }
            }
        case let .keyValue(req):
            Task {
                let response = try! await requestKeyValue(req).get()
                let effects = [UInt8](handleResponse(request.id, Data(try! KeyValueResult.ok(response: response).bincodeSerialize())))
                let requests: [Request] = try! .bincodeDeserialize(input: effects)
                for request in requests {
                    processEffect(request)
                }
            }
        case let .keyStore(req):
            Task {
                let response = try! await requestKeyStore(req).get()
                let effects = [UInt8](handleResponse(request.id, Data(try! KeyStoreResult.ok(response: response).bincodeSerialize())))
                let requests: [Request] = try! .bincodeDeserialize(input: effects)
                for request in requests {
                    processEffect(request)
                }
            }
        }
    }
}
