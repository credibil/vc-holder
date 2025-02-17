//
//  SwiftUIView.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 17/01/2025.
//

import SharedTypes
import SwiftUI

struct IssuancePin: View {
    @Environment(\.update) var update
    var txCode: TxCode
    @State private var pin: String = ""
    @State private var waiting: Bool = false
    
    enum FocusField: Hashable {
        case pinEntry
    }
    @FocusState private var focusField: FocusField?
    
    var body: some View {
        VStack {
            if waiting {
                Text("Retrieving Credential").font(.title).padding(.bottom, 8)
                ProgressView()
            } else {
                Text("Transaction Code").font(.title).padding(.bottom, 8)
                Text(txCode.description).padding(.bottom, 8)
                TextField("Transaction Code ", text: $pin)
                    .textFieldStyle(.roundedBorder)
                    .padding()
                    .keyboardType(txCode.input_mode == "numeric" ? .decimalPad : .default)
                    .focused($focusField, equals: .pinEntry)
                    .onAppear {
                        self.focusField = .pinEntry
                    }
                Button("OK") {
                    waiting = true
                    update(.issuancePin(pin))
                }
                .buttonStyle(.borderedProminent)
                .padding()
            }
        }
    }
}

#Preview {
    let txCode = TxCode(
        input_mode: "numeric",
        length: 6,
        description: "Enter the code sent to you by email"
    )
    IssuancePin(txCode: txCode)
}
