//
//  sse.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 15/10/2024.
//

import SharedTypes
import SwiftUI

enum SseError: Error {
    case generic(Error)
    case message(String)
}

func requestSse(_ request: SseRequest) async -> AsyncStream<Result<SseResponse, SseError>> {
    return AsyncStream { continuation in
        Task {
            let req = URLRequest(url: URL(string: request.url)!)
            do {
                let (_, _) = try await URLSession.shared.bytes(for: req)
            } catch {
                
            }
        }
    }
}
