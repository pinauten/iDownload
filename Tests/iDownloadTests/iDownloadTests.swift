//
//  iDownloadTests.swift
//  iDownload
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import XCTest
@testable import iDownload

public class MyHandler: KRWHandler {
    func random64() -> UInt64 {
        return UInt64(arc4random()) << 14
    }
    
    public func getSupportedActions() -> KRWOptions {
        return [.virtRW, .physRW, .kalloc, .kcall, .PPLBypass]
    }
    
    public func getInfo() throws -> (kernelBase: UInt64, slide: UInt64) {
        return (kernelBase: random64(), slide: random64())
    }
    
    public func resolveAddress(forName: String) throws -> KRWAddress? {
        return nil
    }
    
    public func kread(address: KRWAddress, size: UInt) throws -> Data {
        var res = Data(count: Int(size))
        for i in 0..<Int(size) {
            res[i] = UInt8(arc4random() & 0xFF)
        }
        
        return res
    }
    
    public func kwrite(address: KRWAddress, data: Data) throws {
        return
    }
    
    public func kalloc(size: UInt) throws -> UInt64 {
        throw KRWError.notSupported
    }
    
    public func kfree(address: UInt64) throws {
        throw KRWError.notSupported
    }
    
    public func kcall(func: KRWAddress, a1: UInt64, a2: UInt64, a3: UInt64, a4: UInt64, a5: UInt64, a6: UInt64, a7: UInt64, a8: UInt64) throws -> UInt64 {
        throw KRWError.notSupported
    }
}

final class iDownloadTests: XCTestCase {
    func testExample() throws {
        let krw = MyHandler()
        
        try launch_iDownload(krw: krw)
        
        dispatchMain()
    }
}
