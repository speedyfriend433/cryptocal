import SwiftUI
import CryptoKit
import CommonCrypto
import BigInt
import CryptoSwift
import BigNum 

struct ContentView: View {
    var body: some View {
        TabView {
            CryptoToolsView()
                .tabItem {
                    Label("Crypto", systemImage: "lock.shield")
                }
            KeyManagementView()
                .tabItem {
                    Label("Keys", systemImage: "key")
                }
            Text("More features coming soon")
                .tabItem {
                    Label("More", systemImage: "ellipsis.circle")
                }
        }
    }
}

struct CryptoToolsView: View {
    @State private var resultText = "Hello, world!"
    @State private var userInput = ""
    @State private var ciphertext: Data? = nil

    private let symmetricKey = CryptoManager.shared.generateSymmetricKey()
    
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            TextField("Enter text to hash/encrypt", text: $userInput)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
            Text(resultText)
                .padding()
            Button("Hash Input String") {
                let inputData = Data(userInput.utf8)
                let hashedData = CryptoManager.shared.sha256Hash(data: inputData)
                resultText = hashedData.map { String(format: "%02hhx", $0) }.joined()
            }
            .padding()
            Button("Encrypt Input String") {
                do {
                    let inputData = Data(userInput.utf8)
                    let encryptedData = try CryptoManager.shared.encrypt(data: inputData, using: symmetricKey)
                    ciphertext = encryptedData
                    resultText = encryptedData.base64EncodedString()
                } catch {
                    resultText = "Encryption error: \(error.localizedDescription)"
                }
            }
            .padding()
            Button("Decrypt String") {
                guard let encryptedData = ciphertext else {
                    resultText = "No ciphertext available"
                    return
                }
                do {
                    let decryptedData = try CryptoManager.shared.decrypt(data: encryptedData, using: symmetricKey)
                    if let decryptedString = String(data: decryptedData, encoding: .utf8) {
                        resultText = decryptedString
                    } else {
                        resultText = "Failed to decode decrypted text"
                    }
                } catch {
                    resultText = "Decryption error: \(error.localizedDescription)"
                }
            }
            .padding()
            Button("Hash Sample String") {
                let sample = "cryptocal"
                let hashedData = CryptoManager.shared.sha256Hash(data: Data(sample.utf8))
                resultText = hashedData.map { String(format: "%02hhx", $0) }.joined()
            }
            .padding()
        }
        .padding()
    }
}

struct KeyManagementView: View {
    @State private var signingPublicKeyBase64 = ""
    @State private var encryptionPublicKeyBase64 = ""
    @State private var mnemonicPhrase: String = ""
    @State private var bip39SeedHex: String = ""
    @State private var bip32MasterKeyHex: String = ""
    @State private var bip32ChainCodeHex: String = ""
    @State private var childKeyHex: String = ""
    @State private var childChainCodeHex: String = ""
    @State private var childIndexText: String = "0"
    @State private var derivedAddress: String = ""
    @State private var signingPrivateKey: Curve25519.Signing.PrivateKey?
    @State private var encryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    @State private var eip55Address: String = ""
    @State private var qrImage: UIImage? = nil

    var body: some View {
        VStack {
            Image(systemName: "key")
                .resizable()
                .frame(width: 50, height: 50)
                .padding()
            Text("Key Management")
                .font(.headline)
                .padding()
            Button("Generate New Key Pairs") {
                let signPriv = Curve25519.Signing.PrivateKey()
                let encPriv = Curve25519.KeyAgreement.PrivateKey()
                signingPrivateKey = signPriv
                encryptionPrivateKey = encPriv
                signingPublicKeyBase64 = signPriv.publicKey.rawRepresentation.base64EncodedString()
                encryptionPublicKeyBase64 = encPriv.publicKey.rawRepresentation.base64EncodedString()
            }
            .padding()

            VStack(alignment: .leading) {
                Text("Signing Public Key:")
                    .font(.caption)
                ScrollView(.horizontal) {
                    Text(signingPublicKeyBase64)
                        .font(.system(size: 10, design: .monospaced))
                        .padding(.vertical, 4)
                }
            }.padding()

            VStack(alignment: .leading) {
                Text("Encryption Public Key:")
                    .font(.caption)
                ScrollView(.horizontal) {
                    Text(encryptionPublicKeyBase64)
                        .font(.system(size: 10, design: .monospaced))
                        .padding(.vertical, 4)
                }
            }.padding()

            Divider().padding()

            Button("Generate Mnemonic Phrase") {
                mnemonicPhrase = generateMnemonic()
                bip39SeedHex = ""
            }
            .padding()

            VStack(alignment: .leading) {
                Text("Generated Mnemonic:")
                    .font(.caption)
                ScrollView {
                    Text(mnemonicPhrase)
                        .font(.system(size: 14, design: .monospaced))
                        .padding()
                }
                .frame(height: 100)
            }
            .padding()

            Button("Derive BIP32 Master Keys") {
                let seedData = Data(hexString: bip39SeedHex)
                let derived = deriveMasterKeyFromSeed(seedData: seedData)
                bip32MasterKeyHex = derived.masterKey.map { String(format: "%02hhx", $0) }.joined()
                bip32ChainCodeHex = derived.chainCode.map { String(format: "%02hhx", $0) }.joined()
            }
            .padding()

            VStack(alignment: .leading) {
                Text("BIP32 Master Private Key:")
                    .font(.caption)
                ScrollView(.horizontal) {
                    Text(bip32MasterKeyHex)
                        .font(.system(size: 12, design: .monospaced))
                        .padding(.vertical, 4)
                }
            }.padding()

            VStack(alignment: .leading) {
                Text("BIP32 Master Chain Code:")
                    .font(.caption)
                ScrollView(.horizontal) {
                    Text(bip32ChainCodeHex)
                        .font(.system(size: 12, design: .monospaced))
                        .padding(.vertical, 4)
                }
            }.padding()

            Divider().padding()

            Button("Derive BIP39 Seed") {
                bip39SeedHex = mnemonicToSeedHex(mnemonicPhrase: mnemonicPhrase, passphrase: "")
            }
            .padding()

            VStack(alignment: .leading) {
                Text("BIP39 Seed (hex):")
                    .font(.caption)
                ScrollView {
                    Text(bip39SeedHex)
                        .font(.system(size: 12, design: .monospaced))
                        .padding()
                }
                .frame(height: 120) 
            }
            .padding()
        }
    }

    private func generateMnemonic() -> String {
        let entropy = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        guard let wordlistUrl = Bundle.main.url(forResource: "english", withExtension: "txt"),
              let wordlistContent = try? String(contentsOf: wordlistUrl, encoding: .utf8),
              !wordlistContent.isEmpty else {
            return "Wordlist not found"
        }
        let wordlist = wordlistContent.components(separatedBy: .newlines).filter { !$0.isEmpty }
        guard wordlist.count == 2048 else {
            return "Invalid wordlist"
        }
        let hash = SHA256.hash(data: entropy)
        let checksumBits = entropy.count * 8 / 32
        let entropyBitsStr = entropy.reduce("") { $0 + String($1, radix: 2).leftPadded(to:8) }
        let checksumBitsStr = hash.reduce("") { $0 + String($1, radix: 2).leftPadded(to:8) }
        let bits = entropyBitsStr + checksumBitsStr.prefix(checksumBits)

        var mnemonicWords = [String]()
        for i in stride(from: 0, to: bits.count, by: 11) {
            let indexBits = bits.dropFirst(i).prefix(11)
            if let idx = Int(indexBits, radix: 2), idx < wordlist.count {
                mnemonicWords.append(wordlist[idx])
            }
        }
        return mnemonicWords.joined(separator: " ")
    }

    private func mnemonicToSeedHex(mnemonicPhrase: String, passphrase: String = "") -> String {
        let normalizedMnemonic = mnemonicPhrase.decomposedStringWithCompatibilityMapping
        let normalizedPassphrase = ("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping

        guard let passwordData = normalizedMnemonic.data(using: .utf8),
              let saltData = normalizedPassphrase.data(using: .utf8) else {
            return "Error preparing data"
        }

        var derivedKey = [UInt8](repeating: 0, count: 64)
        let result = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            normalizedMnemonic, passwordData.count,
            [UInt8](saltData), saltData.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
            2048,
            &derivedKey, 64)
        
        guard result == kCCSuccess else {
            return "Error deriving seed"
        }

        return derivedKey.map { String(format: "%02hhx", $0) }.joined()
    }
}

extension String {
    func leftPadded(to length: Int) -> String {
        String(repeating: "0", count: max(0, length - count)) + self
    }
}

#Preview {
    ContentView()
}

extension Data {
    init(hexString: String) {
        self.init()
        var hex = hexString
        if hex.hasPrefix("0x") { hex = String(hex.dropFirst(2)) }
        let chars = Array(hex)
        for i in stride(from: 0, to: chars.count, by: 2) {
            let byteString = String(chars[i..<(Swift.min(i+2, chars.count))])
            if let byte = UInt8(byteString, radix: 16) {
                append(byte)
            }
        }
    }
}

private func deriveMasterKeyFromSeed(seedData: Data) -> (masterKey: Data, chainCode: Data) {
    let key = "Bitcoin seed".data(using: .ascii)!
    let digest = HMAC<SHA512>.authenticationCode(for: seedData, using: SymmetricKey(data: key))
    let digestData = Data(digest)
    let masterKey = digestData.prefix(32)
    let chainCode = digestData.suffix(32)
    return (masterKey, chainCode)
}

private func deriveChildKey(parentKey: Data, parentChainCode: Data, index: UInt32) -> (childKey: Data, childChainCode: Data) {
    var data = Data()
    let hardened = index >= 0x80000000

    if hardened {
        data.append(0x00)
        data.append(parentKey)
    } else {
        guard let pubkey = try? P256.Signing.PrivateKey(rawRepresentation: parentKey).publicKey.rawRepresentation else {
            return (Data(), Data())
        }
        data.append(pubkey)
    }

    var idx = index.bigEndian
    data.append(Data(bytes: &idx, count: MemoryLayout.size(ofValue: idx)))

    let digest = HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: parentChainCode))
    let digestData = Data(digest)
    let IL = digestData.prefix(32)
    let IR = digestData.suffix(32)

    guard let ILbn = Bignum(data: IL), let parentbn = Bignum(data: parentKey) else {
        return (Data(), Data())
    }
    let order = Bignum.curveOrder()
    let childbn = (ILbn + parentbn) % order
    let childKey = childbn.asData(padTo: 32)

    return (childKey, Data(IR))
}

private func deriveEthereumAddress(fromPrivateKey privKey: Data) -> String {
    guard let secKey = try? P256.Signing.PrivateKey(rawRepresentation: privKey) else {
        return "Invalid private key"
    }
    let pubKeyData = secKey.publicKey.rawRepresentation
    let pubKey: Data
    if pubKeyData.count == 65 && pubKeyData[0] == 0x04 {
        pubKey = pubKeyData.dropFirst()
    } else {
        pubKey = pubKeyData
    }
}


#Preview {
    ContentView()
}

struct ShareSheet: UIViewControllerRepresentable {
    var activityItems: [Any]
    
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
