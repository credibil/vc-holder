//
//  Color.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 05/11/2024.
//

import SwiftUI

// Convert a CSS hex color into a UIColor. Infallible: will default to opaque white.
extension UIColor {
    public convenience init(hex: String) {
        let r, g, b, a: CGFloat
        if hex.hasPrefix("#") {
            var nhex = hex
            if nhex.count == 7 {
                nhex = nhex + "ff"
            }
            let start = nhex.index(nhex.startIndex, offsetBy: 1)
            let hexColor = String(nhex[start...])
            if hexColor.count == 8 {
                let scanner = Scanner(string: hexColor)
                var hexNumber: UInt64 = 0
                if scanner.scanHexInt64(&hexNumber) {
                    r = CGFloat((hexNumber & 0xff000000) >> 24) / 255
                    g = CGFloat((hexNumber & 0x00ff0000) >> 16) / 255
                    b = CGFloat((hexNumber & 0x0000ff00) >> 8) / 255
                    a = CGFloat(hexNumber & 0x000000ff) / 255
                    self.init(red: r, green: g, blue: b, alpha: a)
                    return
                }
            }
        }
        self.init(Color.white)
        return
    }
}
