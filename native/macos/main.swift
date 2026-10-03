import Foundation
import Security
import LocalAuthentication
import Darwin

// Private, one-request pipe protocol. Never log request data or platform errors.
struct Request: Decodable {
    let origin: String
    let account: String
    let passphrase: String?
}
func finish(_ result: [String: Any], _ code: Int32 = 0) -> Never {
    if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    }
    exit(code)
}
func fail(_ error: String) -> Never { finish(["ok": false, "error": error], 1) }
func check(_ status: OSStatus) {
    guard status != errSecSuccess else { return }
    switch status {
    case errSecItemNotFound: fail("not_found")
    case errSecUserCanceled: fail("cancelled")
    case errSecAuthFailed: fail("authentication_failed")
    case errSecInteractionNotAllowed: fail("interaction_not_allowed")
    case errSecMissingEntitlement: fail("invalid_signing")
    case errSecDuplicateItem: fail("already_enrolled")
    default: fail("keychain_failed")
    }
}

func isPipe(_ fd: Int32) -> Bool {
    var info = stat()
    return fstat(fd, &info) == 0 && (info.st_mode & S_IFMT) == S_IFIFO
}

var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
_ = setrlimit(RLIMIT_CORE, &noCore)
guard CommandLine.arguments.count == 2,
      ["store", "get", "delete"].contains(CommandLine.arguments[1]),
      isPipe(STDIN_FILENO), isPipe(STDOUT_FILENO) else { fail("invalid_request") }
// A bounded read prevents an accidental unbounded allocation on the pipe.
var input = Data()
while input.count <= 65536 {
    let chunk = FileHandle.standardInput.readData(ofLength: min(4096, 65537 - input.count))
    if chunk.isEmpty { break }
    input.append(chunk)
}
guard input.count <= 65536,
      let request = try? JSONDecoder().decode(Request.self, from: input),
      !request.account.isEmpty, request.account.utf8.count <= 256,
      !request.origin.isEmpty, request.origin.utf8.count <= 4096,
      let origin = URLComponents(string: request.origin),
      ["https", "http"].contains(origin.scheme ?? ""), origin.host != nil,
      origin.user == nil, origin.password == nil, origin.query == nil,
      origin.fragment == nil, origin.path.isEmpty else { fail("invalid_request") }
let command = CommandLine.arguments[1]
guard command == "store" || request.passphrase == nil else { fail("invalid_request") }
let context = LAContext()
context.localizedReason = "Unlock your VaultContext identity on this Mac"
context.touchIDAuthenticationAllowableReuseDuration = 0
// No preliminary evaluatePolicy call: retrieval itself must satisfy the item's ACL.
var query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.pocketcontext.vaultcontext.unlock.v1:" + request.origin,
    kSecAttrAccount as String: request.account,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: false,
    kSecUseAuthenticationContext as String: context,
]
switch command {
case "store":
    guard let passphrase = request.passphrase, !passphrase.isEmpty,
          passphrase.utf8.count <= 1024 else { fail("invalid_request") }
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error) else {
        fail("access_control_unavailable")
    }
    query[kSecAttrAccessControl as String] = control
    query[kSecAttrLabel as String] = "VaultContext unlock"
    query[kSecValueData as String] = Data(passphrase.utf8)
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecDuplicateItem {
        // Explicit re-enrollment also reasserts the required user-presence ACL.
        query.removeValue(forKey: kSecValueData as String)
        query.removeValue(forKey: kSecAttrAccessControl as String)
        query.removeValue(forKey: kSecAttrLabel as String)
        check(SecItemUpdate(query as CFDictionary,
            [kSecValueData as String: Data(passphrase.utf8),
             kSecAttrAccessControl as String: control] as CFDictionary))
    } else {
        check(status)
    }
    context.invalidate()
    finish(["ok": true])
case "get":
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    check(SecItemCopyMatching(query as CFDictionary, &result))
    guard let data = result as? Data,
          let passphrase = String(data: data, encoding: .utf8), !passphrase.isEmpty else {
        fail("invalid_item")
    }
    context.invalidate()
    finish(["ok": true, "passphrase": passphrase])
case "delete":
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecItemNotFound { check(status) }
    context.invalidate()
    finish(["ok": true])
default: fail("invalid_request")
}
