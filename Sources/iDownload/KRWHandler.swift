//
//  KRWHandler.swift
//  iDownload
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation
import SwiftUtils

public enum KRWError: Error {
    case notSupported
    case PPLBypassNotSupported
    
    case readFailed
    case writeFailed
    
    case customError(description: String)
}

public struct KRWOptions: OptionSet {
    public let rawValue: Int
    
    public init(rawValue: Int) {
        self.rawValue = rawValue
    }
    
    public static let virtRW    = Self(rawValue: 1 << 0)
    public static let physRW    = Self(rawValue: 1 << 1)
    public static let kalloc    = Self(rawValue: 1 << 2)
    public static let kcall     = Self(rawValue: 1 << 3)
    public static let PPLBypass = Self(rawValue: 1 << 4)
}

public struct KRWAddress {
    public struct Options: OptionSet {
        public let rawValue: Int
        
        public init(rawValue: Int) {
            self.rawValue = rawValue
        }
        
        public static let physical = Self(rawValue: 1 << 0)
        public static let PPL      = Self(rawValue: 1 << 1)
    }
    
    public init(address: UInt64, options: Options) {
        self.address = address
        self.options = options
    }
    
    public let address: UInt64
    public let options: Options
}

public protocol KRWHandler {
    func getSupportedActions() -> KRWOptions
    
    func getInfo() throws -> (kernelBase: UInt64, slide: UInt64)
    
    func resolveAddress(forName: String) throws -> KRWAddress?
    
    func kread(address:  KRWAddress, size: UInt) throws -> Data
    func kwrite(address: KRWAddress, data: Data) throws
    
    func kalloc(size: UInt)      throws -> UInt64
    func kfree (address: UInt64) throws
    
    func kcall(func: KRWAddress, a1: UInt64, a2: UInt64, a3: UInt64, a4: UInt64, a5: UInt64, a6: UInt64, a7: UInt64, a8: UInt64) throws -> UInt64
}

public extension KRWHandler {
    func r64(_ addr: KRWAddress) -> UInt64? {
        do {
            let res = try kread(address: addr, size: UInt(MemoryLayout<UInt64>.size))
            return res.tryGetGeneric(type: UInt64.self)
        } catch {
            return nil
        }
    }
    
    func rPtr(_ addr: KRWAddress) -> UInt64? {
        guard let ptr = r64(addr) else {
            return nil
        }
        
        if ((ptr >> 55) & 1) != 0 {
            return ptr | 0xFFFFFF8000000000
        }
        
        return ptr
    }
    
    func r32(_ addr: KRWAddress) -> UInt32? {
        do {
            let res = try kread(address: addr, size: UInt(MemoryLayout<UInt32>.size))
            return res.tryGetGeneric(type: UInt32.self)
        } catch {
            return nil
        }
    }
    
    func r16(_ addr: KRWAddress) -> UInt16? {
        do {
            let res = try kread(address: addr, size: UInt(MemoryLayout<UInt16>.size))
            return res.tryGetGeneric(type: UInt16.self)
        } catch {
            return nil
        }
    }
    
    func r8(_ addr: KRWAddress) -> UInt8? {
        do {
            let res = try kread(address: addr, size: UInt(MemoryLayout<UInt8>.size))
            return res.tryGetGeneric(type: UInt8.self)
        } catch {
            return nil
        }
    }
    
    func w64(_ addr: KRWAddress, value: UInt64) -> Bool {
        let data = Data(fromObject: value)
        
        do {
            try kwrite(address: addr, data: data)
            return true
        } catch {
            return false
        }
    }
    
    func w32(_ addr: KRWAddress, value: UInt32) -> Bool {
        let data = Data(fromObject: value)
        
        do {
            try kwrite(address: addr, data: data)
            return true
        } catch {
            return false
        }
    }
    
    func w16(_ addr: KRWAddress, value: UInt16) -> Bool {
        let data = Data(fromObject: value)
        
        do {
            try kwrite(address: addr, data: data)
            return true
        } catch {
            return false
        }
    }
    
    func w8(_ addr: KRWAddress, value: UInt8) -> Bool {
        let data = Data(fromObject: value)
        
        do {
            try kwrite(address: addr, data: data)
            return true
        } catch {
            return false
        }
    }
}
