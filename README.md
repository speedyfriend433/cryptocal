# CryptoCal

CryptoCal is an educational cryptography toolkit for developers, built entirely with Swift and SwiftUI for iOS and macOS Catalyst. It supports key generation, BIP32/39 derivation, Bitcoin & Ethereum address formats, and various cryptographic utilities.


## Features

- Generate Ed25519 (signing key) and X25519 (encryption key) key pairs
- Generate BIP39 mnemonic phrases and derive BIP32 master keys
- Derive child keys via hardened/non-hardened derivation paths
- Hash functions: SHA256, SHA3/Keccak-256
- Symmetric encryption and decryption helpers
- Encode Bitcoin addresses (Base58Check)
- Ethereum address derivation (EIP-55 checksummed)
- Display QR codes of wallet addresses
- Sign and verify messages
- Export QR code as PNG/share sheet
- Built-in sample text encryption and hashing playground
- Supports CommonCrypto for PBKDF2 seed derivation
- 100% Swift + SwiftUI


## Getting Started

### Prerequisites

- **Xcode 14** or later
- iOS 15+ or macOS 12+ deployment target
- Swift Package Manager

### Dependencies

This project uses:

- [CryptoKit](https://developer.apple.com/documentation/cryptokit)
- [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift)
- [BigInt](https://github.com/attaswift/BigInt)

Make sure these packages are included via Swift Package Manager.

### Setup

1. Clone the repository

```bash
git clone https://github.com/speedyfriend433/CryptoCal.git
cd CryptoCal
```
2. Open `CryptoCal.xcodeproj` in Xcode
3. Build and run on simulator or device
4. Make sure `english.txt` wordlist (BIP39) is included in the application bundle for mnemonic generation



## Usage

- Tap **Keys** tab to generate key pairs, BIP39 mnemonics, derive master keys or child keys
- Tap **Crypto** tab for hashing strings, encrypting/decrypting text
- Generate Bitcoin or Ethereum addresses with QR codes
- Share/export QR codes as PNG
- Sign and verify arbitrary messages



## Security Notice

This app is for **educational/demo purposes only**.  
**Do not** use it to manage or protect _real cryptocurrency keys_ or store sensitive funds.



## License

MIT License. See `LICENSE.md` for details.



## Credits

- Uses [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift) by Marcin Krzyżanowski
- Uses [BigInt](https://github.com/attaswift/BigInt)
- Inspired by BIP-32, BIP-39 specifications



## Contact

For questions or contributions, open an issue or PR.  
Author: speedyfriend433 (@speedyfriend433)
