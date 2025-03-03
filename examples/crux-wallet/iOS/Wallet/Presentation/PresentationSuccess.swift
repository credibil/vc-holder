//
//  PresentationSuccess.swift
//  Wallet
//
//  Created by Andrew Goldie on 05/02/2025.
//

import SharedTypes
import SwiftUI

struct PresentationSuccess: View {
    @Environment(\.update) var update
    
    var body: some View {
        VStack {
            Text("Success! \nThe verifier has verified your credential.").padding(.horizontal, 20).multilineTextAlignment(.center)
            Button("OK") {
                update(Event.credential(CredentialEvent.ready))
            }
            .padding()
            .buttonStyle(.borderedProminent)
        }
    }
}

#Preview {
    PresentationSuccess()
}
