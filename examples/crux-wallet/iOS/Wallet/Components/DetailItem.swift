//
//  DetailItem.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 05/11/2024.
//

import SwiftUI

struct DetailItem: View {
    var title: String
    var content: String
    var compact: Bool = false
    
    var body: some View {
        VStack(alignment: .leading) {
            Text(title).font(.caption).opacity(0.5)
            Text(content)
        }.padding(.top, compact ? 0 : 12)
            .padding(.bottom, 4)
        .padding(.leading, 12)
        .padding(.trailing, 12)
    }
}

#Preview {
    DetailItem(title: "Information", content: "This is a preview of your application.")
}
