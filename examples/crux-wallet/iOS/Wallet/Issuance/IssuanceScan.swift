//
//  SwiftUIView.swift
//  Wallet
//
//  Created by Andrew Goldie on 21/10/2024.
//

import SwiftUI
import CodeScanner

struct IssuanceScan: View {
    @Environment(\.update) var update
    @ObservedObject var core: Core
    @State private var scannerVisible = false
    @State var scanResult: String = "Scan a Verifiable Credential offer QR code"
    @State private var offer: String?
    
    init(core: Core) {
        self.core = core
    }
    
    var scannerSheet: some View {
        CodeScannerView(
            codeTypes: [.qr],
            simulatedData: "openid-credential-offer://credential_offer=wibble",
            completion: handleScan
        )
    }

    var body: some View {
        VStack(spacing: 48) {
            Text(scanResult)
            if offer != nil {
                ProgressView()
            } else {
                Button("Scan Offer", systemImage: "qrcode.viewfinder") {
                    self.scannerVisible = true
                }
                .buttonStyle(.borderedProminent)
                .tint(.blue)
                .sheet(isPresented: $scannerVisible) {
                    self.scannerSheet
                }
            }
        }
    }
    
    func handleScan(result: Result<ScanResult, ScanError>) {
        self.scannerVisible = false
        switch result {
        case .success(let code):
            self.scanResult = "Offer scanned"
            let parts = code.string.components(separatedBy: "credential_offer=")
            guard parts.count == 2 else {
                self.scanResult = "Invalid QR code"
                return
            }
            let offer = parts[1]
            debugPrint("Offer: \(offer)")
            update(.issuanceOffer(offer))
            self.offer = offer
        case .failure(let error):
            debugPrint(error.localizedDescription)
            self.scanResult = "Failed to scan QR code"
        }
    }
}

#Preview {
    IssuanceScan(core: Core())
}
