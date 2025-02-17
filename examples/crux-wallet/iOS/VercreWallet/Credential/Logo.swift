//
//  Logo.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 05/11/2024.
//

import SwiftUI

struct Logo: View {
    let data: String

    var body: some View {
        if let bytes = Data(base64Encoded: data, options: .ignoreUnknownCharacters) {
            let image = UIImage(data: bytes)
            return Image(uiImage: image ?? UIImage())
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 50, height: 50, alignment: .topLeading)
        } else {
            return Image(uiImage: UIImage())
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 50, height: 50, alignment: .topLeading)
        }
    }
}

#Preview {
    Logo(data: "")
}
