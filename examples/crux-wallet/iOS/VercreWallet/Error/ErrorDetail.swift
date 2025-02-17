//
//  ErrorDetail.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 21/11/2024.
//

import SwiftUI

struct ErrorDetail: View {
    @Environment(\.update) var update
    var message: String?
    
    var body: some View {
        VStack {
            Text(message ?? "No current error")
            Button("Dismiss") {
                update(.ready)
            }
            .padding()
            .buttonStyle(.borderedProminent)
        }
    }
}

#Preview {
    ErrorDetail(message: "An error has occurred.")
}
