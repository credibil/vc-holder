//
//  QRScanner.swift
//  VercreWallet
//
//  Created by Andrew Goldie on 23/10/2024.
//

import SwiftUI
import VisionKit

// Implementation of a VisionKit data scanner in a SwiftUI view.
@available(iOS 16.0, *)
struct QRScanner: UIViewControllerRepresentable {
    
    static let scanLabel = "Scan"
    static let cancelLabel = "Cancel"
    
    var scannerViewController: DataScannerViewController = DataScannerViewController(
        recognizedDataTypes: [.barcode()],
        qualityLevel: .accurate,
        recognizesMultipleItems: false,
        isHighFrameRateTrackingEnabled: false,
        isHighlightingEnabled: true
    )
    
    class Coordinator: NSObject, DataScannerViewControllerDelegate {
        var parent: QRScanner
        var roundBoxMappings: [UUID: UIView] = [:]
        
        init(_ parent: QRScanner) {
            self.parent = parent
        }
        
        // --- DataScannerViewControllerDelegate methods ----------------------
        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            for item in addedItems {
                processItem(item: item)
            }
        }
        
        func dataScanner(_ dataScanner: DataScannerViewController, didRemove removedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            for item in removedItems {
                if let roundBoxView = roundBoxMappings[item.id] {
                    if roundBoxView.superview != nil {
                        roundBoxView.removeFromSuperview()
                        roundBoxMappings.removeValue(forKey: item.id)
                    }
                }
            }
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didUpdate updatedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            for item in updatedItems {
                if let roundBoxView = roundBoxMappings[item.id] {
                    if roundBoxView.superview != nil {
                        let frame = CGRect(
                            x: item.bounds.topLeft.x,
                            y: item.bounds.topLeft.y,
                            width: abs(item.bounds.topRight.x - item.bounds.topLeft.x) + 15,
                            height: abs(item.bounds.topLeft.y - item.bounds.bottomLeft.y) + 15
                        )
                        roundBoxView.frame = frame
                    }
                }
            }
        }
        
        func dataScanner(_ dataScanner: DataScannerViewController, didTapOn item: RecognizedItem) {
            processItem(item: item)
        }
        // --------------------------------------------------------------------
        
        func processItem(item: RecognizedItem) {
            switch item {
            case .barcode:
                break
            case .text:
                print("Text scanning is unsupported: \(item)")
            @unknown default:
                print("Unknown item type: \(item)")
            }
        }
        
        @objc func startScanning(_ sender: UIButton) {
            if sender.title(for: .normal) == scanLabel {
                try? parent.scannerViewController.startScanning()
                sender.setTitle(cancelLabel, for: .normal)
            } else {
                parent.scannerViewController.stopScanning()
                sender.setTitle(scanLabel, for: .normal)
            }
        }
    }
    
    func makeUIViewController(context: Context) -> DataScannerViewController {
        scannerViewController.delegate = context.coordinator
        
        // Add a button to start scanning
        let scanButton = UIButton(type: .system)
        scanButton.backgroundColor = .systemBlue
        scanButton.setTitle(QRScanner.scanLabel, for: .normal)
        scanButton.setTitleColor(.white, for: .normal)
        var config = UIButton.Configuration.filled()
        config.contentInsets = NSDirectionalEdgeInsets(top: 5, leading: 5, bottom: 5, trailing: 5)
        scanButton.configuration = config
        scanButton.addTarget(context.coordinator, action: #selector(Coordinator.startScanning(_:)), for: .touchUpInside)
        scannerViewController.view.addSubview(scanButton)
        
        // Set up button constraints
        scanButton.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            scanButton.centerXAnchor.constraint(equalTo: scannerViewController.view.centerXAnchor),
            scanButton.bottomAnchor.constraint(equalTo: scannerViewController.view.safeAreaLayoutGuide.bottomAnchor, constant: -20)
        ])
        
        return scannerViewController
    }
    
    func updateUIViewController(_ uiViewController: DataScannerViewController, context: Context) {
        // Update any view controller settings here
    }
    
    func makeCoordinator() -> Coordinator {
        return Coordinator(self)
    }
}

#Preview {
    if #available(iOS 16.0, *) {
        QRScanner()
    } else {
        // Fallback on earlier versions
    }
}
