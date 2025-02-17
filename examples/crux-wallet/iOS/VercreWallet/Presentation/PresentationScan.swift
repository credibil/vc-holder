//
//  PresentationScan.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 04/02/2025.
//

import SwiftUI
import CodeScanner

struct PresentationScan: View {
    @Environment(\.update) var update
    @ObservedObject var core: Core
    @State private var scannerVisible: Bool = false
    @State var scanResult: String = "Scan a verifier's presentation request QR code"
    @State private var requestUrl: String?
    
    init(core: Core) {
        self.core = core
    }
    
    var scannerSheet: some View {
        CodeScannerView(
            codeTypes: [.qr],
            simulatedData: "http://localhost:8080/wibble",
            completion: handleScan
        )
    }
    
    var body: some View {
        VStack(spacing: 48) {
            Text(scanResult)
            if requestUrl != nil {
                ProgressView()
            } else {
                Button("Scan Request", systemImage: "qrcode:viewfinder") {
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
            self.scanResult = "Request scanned"
            let url = code.string
            debugPrint("Request URL: \(url)")
            update(.presentationRequest(url))
            self.requestUrl = url
        case .failure(let error):
            debugPrint(error.localizedDescription)
            self.scanResult = "Failed to scan QR code"
        }
    }
}

#Preview {
    PresentationScan(core: Core())
}
