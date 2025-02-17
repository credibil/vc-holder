//
//  ClaimTitleList.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 25/11/2024.
//

import SharedTypes
import SwiftUI

struct ClaimTitleList: View {
    let claims: [ClaimView]
    
    var body: some View {
        VStack(alignment: .leading) {
            ForEach(claims, id: \.self.name) { claim in
                ClaimTitleItem(title: claim.name, compact: true)
            }
        }
    }
}

#Preview {
    let claims: [ClaimView] = [
        .init(name: "Given Name", value: "Normal"),
        .init(name: "Family Name", value: "Person"),
    ]
    ClaimTitleList(claims: claims)
}
