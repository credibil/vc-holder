//
//  ClaimList.swift
//  Wallet
//
//  Created by Andrew Goldie on 22/11/2024.
//

import SharedTypes
import SwiftUI

struct ClaimList: View {
    let claims: [ClaimView]
    
    var body: some View {
        VStack(alignment: .leading) {
            ForEach(claims, id: \.self.name) { claim in
                DetailItem(title: claim.name, content: claim.value, compact: true)
            }
        }
    }
}

#Preview {
    let claims: [ClaimView] = [
        .init(name: "Given Name", value: "Normal"),
        .init(name: "Family Name", value: "Person"),
    ]
    ClaimList(claims: claims)
}
