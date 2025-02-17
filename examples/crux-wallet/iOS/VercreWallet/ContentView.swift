//
//  ContentView.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 15/10/2024.
//

import SharedTypes
import SwiftUI

struct ContentView: View {
    @ObservedObject var core: Core
    
    init(core: Core) {
        self.core = core
        core.update(.ready)
    }
    
    var body: some View {
        NavigationStack() {
            switch core.view.active_view {
            case .credentialList:
                CredentialList(credentials: core.view.credential_view.credentials)
                    .navBar(context: core.view.active_view)
            case .credentialDetail:
                if let credential = core.view.credential_view.credentials.first(where: { $0.id == core.view.credential_view.id }) {
                    CredentialDetailView(credential: credential)
                        .navBar(context: core.view.active_view)
                }
            case .issuanceScan:
                IssuanceScan(core: Core()).navBar(context: core.view.active_view)
            case .issuanceOffer:
                IssuanceOffer(credential: core.view.issuance_view.credentials[0]).navBar(context: core.view.active_view)
            case .issuancePin:
                IssuancePin(txCode: core.view.issuance_view.tx_code)
                    .navBar(context: core.view.active_view)
            case .presentationScan:
                PresentationScan(core: Core()).navBar(context: core.view.active_view)
            case .presentationRequest:
                PresentationRequest(credentials: core.view.presentation_view.credentials).navBar(context: core.view.active_view)
            case .presentationSuccess:
                PresentationSuccess().navBar(context: core.view.active_view)
            case .error:
                ErrorDetail(message: core.view.error)
            }
        }
        .environment(\.update, { e in core.update(e)})
    }
}

private struct UpdateKey: EnvironmentKey {
    static let defaultValue: (Event) -> Void = { _ in }
}

extension EnvironmentValues {
    var update: (Event) -> Void {
        get { self[UpdateKey.self] }
        set { self[UpdateKey.self] = newValue }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView(core: Core())
    }
}
