//
//  ClaimTitleItem.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 25/11/2024.
//

import SwiftUI

struct ClaimTitleItem: View {
    var title: String
    var compact: Bool = false
    
    var body: some View {
        VStack(alignment: .leading) {
            Text(title)
        }.padding(.top, compact ? 0 : 12)
            .padding(.bottom, 4)
        .padding(.leading, 12)
        .padding(.trailing, 12)
    }
}

#Preview {
    ClaimTitleItem(title: "Information")
}
