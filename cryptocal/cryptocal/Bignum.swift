import Foundation
import BigInt

struct Bignum {
    private var value: BignumWrapper
    
    static func curveOrder() -> Bignum {
        guard let bn = Bignum(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") else {
            fatalError("Failed to create curve order")
        }
        return bn
    }

    init?(data: Data) {
        value = BignumWrapper(data: data)
    }

    init?(hex: String) {
        guard let wrapper = BignumWrapper(hex: hex) else { return nil }
        self.value = wrapper
    }
  
    static func +(lhs: Bignum, rhs: Bignum) -> Bignum {
        Bignum(wrapper: lhs.value + rhs.value)
    }

    static func %(lhs: Bignum, rhs: Bignum) -> Bignum {
        Bignum(wrapper: lhs.value % rhs.value)
    }

    func asData(padTo: Int) -> Data {
        value.asData(padTo: padTo)
    }
    
    private init(wrapper: BignumWrapper) {
        value = wrapper
    }
}

struct BignumWrapper {
    let value: BigInt

    init(data: Data) {
        self.value = BigInt(data.reduce("0x", {$0 + String(format:"%02x",$1)}), radix: 16)!
    }
    
    init?(hex: String) {
        guard let bigint = BigInt(hex, radix: 16) else { return nil }
        self.value = bigint
    }

    init(bigint: BigInt) {
        self.value = bigint
    }

    static func +(lhs: BignumWrapper, rhs: BignumWrapper) -> BignumWrapper {
        BignumWrapper(bigint: lhs.value + rhs.value)
    }

    static func %(lhs: BignumWrapper, rhs: BignumWrapper) -> BignumWrapper {
        BignumWrapper(bigint: lhs.value % rhs.value)
    }

    func asData(padTo: Int = 32) -> Data {
        var bytes = self.value.magnitude.serialize()
        if bytes.count < padTo {
            bytes = Data(repeating: 0, count: padTo - bytes.count) + bytes
        }
        return Data(bytes)
    }
}