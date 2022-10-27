//
//  iDownload.swift
//  iDownload
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation
import Dispatch
import SwiftUtils

public enum iDownloadLaunchError: Error {
    case failedToCreateSocket
    case setsockoptFailed
    case bindFailed
    case listenFailed
}

public enum iDownloadError: Error {
    case disconnected
    case custom(_: String)
    case execError(status: Int32)
    case childDied(signal: Int32)
}

public typealias iDownloadCmd = (_: iDownloadHandler, _: String, _: [String]) throws -> Void

public class iDownloadHandler {
    public let socket: FileHandle
    public let krw: KRWHandler?
    public let otherCmds: [String: iDownloadCmd]
    public var cwd = URL(fileURLWithPath: "/")
    
    private var _slide: UInt64?
    public var slide: UInt64 {
        if let s = _slide {
            return s
        }
        
        if let info = try? krw?.getInfo() {
            _slide = info.slide
            return info.slide
        }
        
        return 0
    }
    
    var buf = Data()
    
    init(socket: FileHandle, krw: KRWHandler? = nil, otherCmds: [String: iDownloadCmd]? = nil) {
        self.socket    = socket
        self.krw       = krw
        self.otherCmds = otherCmds ?? [:]
    }
    
    func main() throws {
        try sendline("iDownload version 2.0 ready.")
        while true {
            try send("iDownload> ")
            
            let cmdArgs = try readCmd()
            guard cmdArgs.count >= 1 else {
                continue
            }
            
            let cmd  = cmdArgs[0]
            let args = [String](cmdArgs.dropFirst())
            
            do {
                try handleCmd(cmd: cmd, args: args)
            } catch iDownloadError.disconnected {
                return
            } catch iDownloadError.custom(let e) {
                try sendline("\(cmd): Error: \(e)")
            } catch KRWError.customError(description: let e) {
                try sendline("\(cmd): KRW Error: \(e)")
            } catch let e {
                try sendline("\(cmd): Error: \(e)")
            }
        }
    }
    
    public func handleCmd(cmd: String, args: [String]) throws {
        if cmd == "help" {
            try help()
            return
        }
        
        if let hndlr = otherCmds[cmd] {
            try hndlr(self, cmd, args)
            return
        }
        
        switch cmd {
        case "krwhelp":
            try krwhelp()
            
        case "exit":
            try sendline("Bye!")
            throw iDownloadError.disconnected
            
        case "exit_full":
            try sendline("Bye!")
            exit(0)
        
        case "pwd":
            try sendline(cwd.path)
            
        case "cd":
            try cd(args)
            
        case "ls":
            if args.count == 0 {
                try ls("")
            } else {
                for arg in args {
                    try ls(arg)
                }
            }
            
        case "kinfo":
            try kinfo()
            
        case "slide":
            try slide(args: args)
            
        case "r64", "r32", "r16", "r8", "kread":
            try kread(cmd: cmd, args: args)
            
        case "w64", "w32", "w16", "w8":
            try kwrite(cmd: cmd, args: args)
            
        case "kcall":
            try kcall(args: args)
            
        case "kalloc":
            try kalloc(args: args)
            
        case "kfree":
            try kfree(args: args)
            
        default:
            do {
                let exit = try exec(cmd, args: args)
                if exit != 0 {
                    try sendline("Exit status: \(exit)")
                }
            } catch iDownloadError.execError(status: let status) {
                if status == 2 || status == 3 {
                    try sendline("Command '\(cmd)' not recognized!")
                } else {
                    try sendline("Failed to exec '\(cmd)': posix_spawn error \(status) (\(String(cString: strerror(status))))")
                }
            } catch iDownloadError.childDied(signal: let signal) {
                try sendline("Child died: Signal: \(signal)")
            }
        }
    }
    
    public func help() throws {
        try sendline("iDownload has a shell-like interface")
        try sendline("The following commands are supported:")
        try sendline("exit:               Close connection")
        try sendline("exit_full:          Close connection and terminate server")
        try sendline("pwd:                Print current working directory")
        try sendline("cd:                 Change directory")
        try sendline("ls:                 List directory")
        
        if let backendHelp = otherCmds["help"] {
            try sendline("")
            try sendline("Your backend supports the following additional commands:")
            try backendHelp(self, "help", [])
        }
        
        if krw != nil {
            try sendline("")
            try sendline("iDownload also supports various kernel-related commands")
            try sendline("Type 'krwhelp' to see them")
        }
        
        try sendline("")
        try sendline("If a command is not recognized, iDownload will search $PATH")
    }
    
    public func krwhelp() throws {
        guard let krw = krw else {
            try sendline("Sorry, your backend doesn't support any krw features!")
            return
        }

        let supported = krw.getSupportedActions()
        
        func rw(supported: KRWOptions) throws {
            try sendline("Kernel read/write:")
            try sendline("r64/r32/r16/r8 <addr>:         Read a 64/32/16/8 bit value")
            try sendline("w64/w32/w16/w8 <addr> <value>: Write a 64/32/16/8 bit value")
            try sendline("kread <addr> <length>:         Dump kernel memory")
            
            if !supported.contains(.PPLBypass) {
                try sendline("Please note that your backend does NOT support writing to PPL addresses")
            }
            
            try sendline("")
        }
        
        func kalloc_kfree() throws {
            try sendline("Kernel memory (de)allocation:")
            try sendline("kalloc <size>:   Allocate size bytes of kernel memory")
            try sendline("kfree <pointer>: Deallocate previously allocated kernel memory")
            try sendline("")
        }
        
        func kcall() throws {
            try sendline("Kernel call:")
            try sendline("kcall <func> <up to 8 arguments>: Call a kernel function and return result")
            try sendline("Arguments must be integers/addresses/symbols")
            try sendline("")
        }
        
        try sendline("The following krw commands are supported by your backend:")
        try sendline("Kernel infos:")
        try sendline("kinfo: Display kernel base address and slide")
        try sendline("")
        try sendline("Utils:")
        try sendline("slide <addr>: Slide the given address")
        try sendline("")
        
        if supported.contains(.virtRW) {
            try rw(supported: supported)
        }
        
        if supported.contains(.kalloc) {
            try kalloc_kfree()
        }
        
        if supported.contains(.kcall) {
            try kcall()
        }
        
        try sendline("All commands that require an address (and kcall arguments) may use")
        try sendline("a @options postfix, where options is a comma-seperated list of the following:")
        try sendline("V:   Virtual address [default]")
        if supported.contains(.physRW) {
            try sendline("P:   Physical address")
        } else {
            try sendline("P:   Physical address [not supported by your backend]")
        }
        try sendline("S:   Slide address [cannot be used with P]")
        if supported.contains(.PPLBypass) {
            try sendline("PPL: Address points into PPL protected region")
            try sendline("")
            try sendline("For example, '0x1337@S,PPL' means 'Virtual address 0x1337, slide before use, require PPL bypass'")
        } else {
            try sendline("")
            try sendline("For example, '0x1337@S' means 'Virtual address 0x1337, slide before use'")
        }
        
        try sendline("(V is always assumed unless P is given)")
        try sendline("")
        try sendline("Some backends also support symbols instead of addresses.")
        try sendline("(Options will be ignored for symbols)")
    }
    
    public func cd(_ args: [String]) throws {
        guard args.count == 1 else {
            try sendline("Usage: cd <directory>")
            return
        }
        
        let dir = resolve(path: args[0])
        
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: dir, isDirectory: &isDir) else {
            try printError(errno: ENOENT)
        }
        
        guard isDir.boolValue else {
            try printError(errno: ENOTDIR)
        }
        
        cwd = URL(fileURLWithPath: dir)
    }
    
    public func ls(_ dir: String) throws {
        let dir = resolve(path: dir)
        
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: dir, isDirectory: &isDir) else {
            try printError(errno: ENOENT)
        }
        
        func listItem(_ path: String, _ item: String) throws {
            let attr = try FileManager.default.attributesOfItem(atPath: path)
            
            func getPerms() -> String {
                guard let perms = (attr[.posixPermissions] as? NSNumber)?.int16Value else {
                    return "?????????"
                }
                
                func perm3(_ val: Int16) -> String {
                    let r = ((val & 0x4) == 4) ? "r" : "-"
                    let w = ((val & 0x2) == 2) ? "w" : "-"
                    let x = ((val & 0x1) == 1) ? "x" : "-"
                    return r + w + x
                }
                
                return perm3(perms >> 6) + perm3(perms >> 3) + perm3(perms)
            }
            
            let owner = (attr[.ownerAccountName] as? String) ?? "???"
            let group = (attr[.groupOwnerAccountName] as? String) ?? "???"
            let size  = (attr[.size] as? NSNumber)?.int64Value ?? 1
            
            var itemDesc = item
            
            var special = "-"
            switch (attr[.type] as? FileAttributeType) ?? .typeRegular {
            case .typeRegular:
                break
                
            case .typeDirectory:
                special = "d"
                
            case .typeSymbolicLink:
                special = "l"
                if let dst = try? FileManager.default.destinationOfSymbolicLink(atPath: path) {
                    itemDesc += " -> \(dst)"
                }
                
            case .typeBlockSpecial:
                special = "b"
                
            case .typeCharacterSpecial:
                special = "c"
                
            case .typeSocket:
                special = "s"
                
            default:
                special = "?"
            }
            
            let mod = (attr[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
            let fmt = DateFormatter()
            fmt.dateFormat = "MMM dd HH:mm"
            
            try sendline("\(special)\(getPerms())\t\(owner)\t\(group)\t\(size)\t\(fmt.string(from: mod)) \(itemDesc)")
        }
        
        if isDir.boolValue {
            do {
                var content = try FileManager.default.contentsOfDirectory(atPath: dir)
                content = [".", ".."] + content
                
                for elem in content.sorted() {
                    do {
                        try listItem(dir + "/" + elem, elem)
                    } catch let e {
                        try sendline("ls: \(elem): \(e)")
                    }
                }
            } catch let e {
                try sendline("ls: \(e)")
            }
        } else {
            try listItem(dir, dir)
        }
    }
    
    public func kinfo() throws {
        guard let krw = krw else {
            try sendline("kinfo: No KRW support!")
            return
        }
        
        let info = try krw.getInfo()
        try sendline(String(format: "Kernel base:  %p", info.kernelBase))
        try sendline(String(format: "Kernel slide: %p", info.slide))
    }
    
    public func slide(args: [String]) throws {
        guard krw != nil else {
            try sendline("slide: No KRW support!")
            return
        }
        
        guard args.count == 1 else {
            try sendline("Usage: slide <address>")
            return
        }
        
        guard let address = parseUInt64(args[0]) else {
            throw iDownloadError.custom("Bad address!")
        }
        
        try sendline(String(format: "%p", address + slide))
    }
    
    public func kread(cmd: String, args: [String]) throws {
        guard let krw = krw else {
            try sendline("\(cmd): No KRW support!")
            return
        }
        
        var size: UInt = 0
        var isKread = false
        
        switch cmd {
        case "r64":
            size = 8
            
        case "r32":
            size = 4
            
        case "r16":
            size = 2
            
        case "r8":
            size = 1
            
        case "kread":
            isKread = true
            
            guard args.count == 2 else {
                try sendline("Usage: kread <address> <count>")
                return
            }
            
            guard let sz = parseUInt64(args[1]) else {
                throw iDownloadError.custom("Bad size \(args[1])")
            }
            
            size = UInt(sz)
            
        default:
            throw iDownloadError.custom("Bad command \(cmd)")
        }
        
        guard args.count == 1 || isKread else {
            try sendline("Usage: \(cmd) <address>")
            return
        }
        
        let address = try parseAddress(args[0])
        
        let data = try krw.kread(address: address, size: size)
        
        switch cmd {
        case "r64":
            let res = data.getGeneric(type: UInt64.self)
            
            try sendline(String(format: "%p", res))
            
        case "r32":
            let res = data.getGeneric(type: UInt32.self)
            
            try sendline(String(format: "%p", res))
            
        case "r16":
            let res = data.getGeneric(type: UInt16.self)
            
            try sendline(String(format: "%p", res))
            
        case "r8":
            let res = data.getGeneric(type: UInt8.self)
            
            try sendline(String(format: "%p", res))
            
        case "kread":
            var str = ""
            for byte in data {
                str += String(format: "%02X", byte)
            }
            
            try sendline(str)
            
        default:
            fatalError()
        }
    }
    
    public func kwrite(cmd: String, args: [String]) throws {
        guard let krw = krw else {
            try sendline("\(cmd): No KRW support!")
            return
        }
        
        guard args.count == 2 else {
            try sendline("Usage: \(cmd) <address> <value>")
            return
        }
        
        let address = try parseAddress(args[0])
        var data: Data!
        
        switch cmd {
        case "w64":
            guard let value = parseUInt64(args[1]) else {
                throw iDownloadError.custom("Bad value \(args[1])")
            }
            
            data = Data(fromObject: value)
            
        case "w32":
            guard let value = parseUInt32(args[1]) else {
                throw iDownloadError.custom("Bad value \(args[1])")
            }
            
            data = Data(fromObject: value)
        case "w16":
            guard let value = parseUInt16(args[1]) else {
                throw iDownloadError.custom("Bad value \(args[1])")
            }
            
            data = Data(fromObject: value)
            
        case "w8":
            guard let value = parseUInt8(args[1]) else {
                throw iDownloadError.custom("Bad value \(args[1])")
            }
            
            data = Data(fromObject: value)
            
        default:
            throw iDownloadError.custom("Bad command \(cmd)")
        }
        
        try krw.kwrite(address: address, data: data)
        try sendline("OK")
    }
    
    public func kcall(args: [String]) throws {
        guard let krw = krw else {
            try sendline("kcall: No KRW support!")
            return
        }
        
        guard args.count > 0 && args.count <= 9 else {
            try sendline("Usage: kcall <func> <up to 8 arguments>")
            return
        }
        
        let f = try parseAddress(args[0])
        
        var params: [UInt64] = [0, 0, 0, 0, 0, 0, 0, 0]
        for i in 0..<(args.count - 1) {
            params[i] = try parseAddress(args[i + 1]).address
        }
        
        let res = try krw.kcall(func: f, a1: params[0], a2: params[1], a3: params[2], a4: params[3], a5: params[4], a6: params[5], a7: params[6], a8: params[7])
        
        try sendline(String(format: "%p", res))
    }
    
    public func kalloc(args: [String]) throws {
        guard let krw = krw else {
            try sendline("kalloc: No KRW support!")
            return
        }
        
        guard args.count == 1 else {
            try sendline("Usage: kalloc <size>")
            return
        }
        
        guard let size = parseUInt64(args[0]) else {
            throw iDownloadError.custom("Invalid size!")
        }
        
        let res = try krw.kalloc(size: UInt(size))
        
        try sendline(String(format: "%p", res))
    }
    
    public func kfree(args: [String]) throws {
        guard let krw = krw else {
            try sendline("kfree: No KRW support!")
            return
        }
        
        guard args.count == 1 else {
            try sendline("Usage: kfree <pointer>")
            return
        }
        
        guard let ptr = parseUInt64(args[0]) else {
            throw iDownloadError.custom("Invalid pointer!")
        }
        
        try krw.kfree(address: ptr)
        
        try sendline("OK")
    }
    
    func nextChar() throws -> UInt8 {
        if buf.count > 0 {
            return buf.popFirst()!
        }
        
        guard let rd = try? socket.read(upToCount: 1),
              rd.count > 0 else {
            throw iDownloadError.disconnected
        }
        
        buf = rd
        
        return buf.popFirst()!
    }
    
    func readLine() throws -> String {
        var res = ""
        while true {
            let chr = try nextChar()
            if chr == 0xA {
                return res
            } else if chr != 0xD {
                res.append(Character(Unicode.Scalar(chr)))
            }
        }
    }
    
    func readCmd() throws -> [String] {
        var res: [String] = []
        var cur = ""
        var escaped = false
        
        for ch in try readLine() {
            if ch == " " && !escaped {
                res.append(cur)
                cur = ""
            } else if ch == "\\" && !escaped {
                escaped = true
            } else {
                cur += String(ch)
                escaped = false
            }
        }
        
        if cur.count > 0 {
            res.append(cur)
        }
        
        return res
    }
    
    public func send(_ text: String) throws {
        do {
            try socket.write(contentsOf: text.data(using: .utf8)!)
        } catch {
            throw iDownloadError.disconnected
        }
    }
    
    public func sendline(_ text: String) throws {
        try send(text)
        try send("\r\n")
    }
    
    public func printError(errno: Int32, cmd: String = #function) throws -> Never {
        let err = String(cString: strerror(errno))
        throw iDownloadError.custom(err)
    }
    
    public func resolve(path: String) -> String {
        if path.first == "/" {
            return path
        }
        
        if path.first == "~" {
            let after = String(path.dropFirst())
            if after.first == nil || after == "/" {
                return String(cString: getenv("HOME")) + after
            }
        }
        
        return cwd.appendingPathComponent(path).path
    }
    
    public func parseAddress(_ addr: String) throws -> KRWAddress {
        let split = addr.split(separator: "@")
        guard split.count >= 1 else {
            throw iDownloadError.custom("Bad address: \(addr)")
        }
        
        guard split.count <= 2 else {
            throw iDownloadError.custom("Bad address: \(addr) [multiple @ postfixes]")
        }
        
        let prefix  = String(split[0])
        let postfix = (split.count == 2) ? String(split[1]) : ""
        
        guard var addr = parseUInt64(prefix) else {
            if let res = try krw?.resolveAddress(forName: prefix) {
                // Ignore all options
                return res
            }
            
            throw iDownloadError.custom("Bad/Unknown address: \(prefix)")
        }
        
        let ops = postfix.split(separator: ",")
        
        var addrTypeKnown = false
        var slid = false
        var options: KRWAddress.Options = []
        
        for op in ops {
            switch op.uppercased() {
            case "V", "P":
                guard !addrTypeKnown else {
                    throw iDownloadError.custom("\(addr): Can only specify address type (V/P) once!")
                }
                
                addrTypeKnown = true
                if op.uppercased() == "P" {
                    guard !slid else {
                        throw iDownloadError.custom("\(addr): Cannot specify both 'S' and 'P'!")
                    }
                    
                    options.update(with: .physical)
                }
                
            case "S":
                guard !slid else {
                    throw iDownloadError.custom("\(addr): Can only specify 'S' once!")
                }
                
                guard !options.contains(.physical) else {
                    throw iDownloadError.custom("\(addr): Cannot specify both 'P' and 'S'!")
                }
                
                addr += slide
                slid  = true
                
            case "PPL":
                guard !options.contains(.PPL) else {
                    throw iDownloadError.custom("\(addr): Can only specify 'PPL' once!")
                }
                
                options.update(with: .PPL)
                
            default:
                throw iDownloadError.custom("\(addr): Bad option: \(op)")
            }
        }
        
        return KRWAddress(address: addr, options: options)
    }
    
    public func parseUInt64(_ str: String) -> UInt64? {
        str.withCString { ptr in
            var eptr: UnsafeMutablePointer<CChar>?
            
            errno = 0
            let r = strtoul(ptr, &eptr, 0)
            if r == 0 {
                // Potential conversion failure?
                if ptr == UnsafePointer(eptr) {
                    return nil
                } else if errno != 0 {
                    return nil
                }
            }
            
            if eptr != nil && eptr.unsafelyUnwrapped.pointee != 0 {
                return nil
            }
            
            return UInt64(r)
        }
    }
    
    public func parseUInt32(_ str: String) -> UInt32? {
        if let u64 = parseUInt64(str) {
            if u64 <= UInt32.max {
                return UInt32(u64)
            }
        }
        
        return nil
    }
    
    public func parseUInt16(_ str: String) -> UInt16? {
        if let u64 = parseUInt64(str) {
            if u64 <= UInt16.max {
                return UInt16(u64)
            }
        }
        
        return nil
    }
    
    public func parseUInt8(_ str: String) -> UInt8? {
        if let u64 = parseUInt64(str) {
            if u64 <= UInt8.max {
                return UInt8(u64)
            }
        }
        
        return nil
    }
    
    public func exec(_ path: String, args: [String], cwd _cwd: String? = nil) throws -> Int32 {
        var child: pid_t = 0
        var cArgs: [UnsafeMutablePointer<CChar>?] = [strdup(path)]
        for arg in args {
            cArgs.append(strdup(arg))
        }
        
        cArgs.append(nil)
        
        defer {
            for cArg in cArgs {
                if cArg != nil {
                    free(cArg)
                }
            }
        }
        
        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, socket.fileDescriptor, STDIN_FILENO)
        posix_spawn_file_actions_adddup2(&fileActions, socket.fileDescriptor, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&fileActions, socket.fileDescriptor, STDERR_FILENO)
        
        let err = withCurrentDirectorySetTo(_cwd ?? cwd.path) {
            posix_spawnp(&child, cArgs[0], &fileActions, nil, cArgs, environ)
        }
        
        guard err == 0 else {
            throw iDownloadError.execError(status: err)
        }
        
        var status: Int32 = 0
        waitpid(child, &status, 0)
        
        let wStatus = status & 0x7F
        
        if wStatus == 0 {
            // Exited
            let exitStatus = status >> 8
            return exitStatus
        } else {
            // Signaled
            throw iDownloadError.childDied(signal: wStatus)
        }
    }
}

public func launch_iDownload(krw: KRWHandler? = nil, otherCmds: [String: iDownloadCmd] = [:]) throws {
    var otherCmds = otherCmds
    
    let serverFD = socket(AF_INET, SOCK_STREAM, 0)
    guard serverFD >= 0 else {
        throw iDownloadLaunchError.failedToCreateSocket
    }
    
    var option: UInt32 = 1
    guard setsockopt(serverFD, SOL_SOCKET, SO_REUSEPORT, &option, socklen_t(MemoryLayout<UInt32>.size)) >= 0 else {
        throw iDownloadLaunchError.setsockoptFailed
    }
    
    var server = sockaddr_in()
    server.sin_family = sa_family_t(AF_INET)
    server.sin_addr.s_addr = inet_addr("127.0.0.1")
    server.sin_port = in_port_t(1337).bigEndian
    
    try withUnsafePointer(to: &server) { ptr in
        guard bind(serverFD, UnsafeRawPointer(ptr).assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size)) >= 0 else {
            throw iDownloadLaunchError.bindFailed
        }
    }
    
    guard listen(serverFD, SOMAXCONN) >= 0 else {
        throw iDownloadLaunchError.listenFailed
    }
    
    // If we have a autorun command, invoke it now
    if let autorun = otherCmds["autorun"] {
        otherCmds.removeValue(forKey: "autorun")
        
        DispatchQueue(label: "iDownload_autorun").async {
            let hndl = FileHandle(fileDescriptor: STDOUT_FILENO, closeOnDealloc: false)
            let hndlr = iDownloadHandler(socket: hndl, krw: krw, otherCmds: otherCmds)
            do {
                try autorun(hndlr, "autorun", [])
            } catch let e {
                print("iDownload autorun error: \(e)")
            }
        }
    }
    
    DispatchQueue(label: "iDownloadServer").async {
        while true {
            let newSocket = accept(serverFD, nil, nil)
            guard newSocket >= 0 else {
                print("Failed to accept new connection!")
                
                return
            }
            
            DispatchQueue(label: "iDownloadServer_\(newSocket)").async {
                let hndl = FileHandle(fileDescriptor: newSocket, closeOnDealloc: true)
                
                do {
                    let hndlr = iDownloadHandler(socket: hndl, krw: krw, otherCmds: otherCmds)
                    try hndlr.main()
                } catch let e {
                    let err = "An exception occurred: \(e)"
                    
                    try? hndl.write(contentsOf: err.data(using: .utf8)!)
                }
            }
        }
    }
}

private let iDownloadChdirLock = NSLock()

public func withCurrentDirectorySetTo<T>(_ path: String, _ f: () throws -> T) rethrows -> T {
    iDownloadChdirLock.lock()
    defer { iDownloadChdirLock.unlock() }
    
    chdir(path)
    
    return try f()
}
