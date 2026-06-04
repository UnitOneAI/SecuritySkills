import Foundation
import UIKit

final class SessionStore: NSObject, URLSessionDelegate {
    func save(refreshToken: String, oneTimePassword: String) {
        UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
        UIPasteboard.general.string = oneTimePassword
        NSLog("refresh token: \(refreshToken)")
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }
}
