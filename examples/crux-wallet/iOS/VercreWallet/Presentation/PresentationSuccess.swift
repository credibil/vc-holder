//
//  PresentationSuccess.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 05/02/2025.
//

import SwiftUI

struct PresentationSuccess: View {
    @Environment(\.update) var update
    
    var body: some View {
        VStack {
            Text("Success! \nThe verifier has verified your credential.").padding(.horizontal, 20).multilineTextAlignment(.center)
            Button("OK") {
                update(.ready)
            }
            .padding()
            .buttonStyle(.borderedProminent)
        }
    }
}

#Preview {
    PresentationSuccess()
}
