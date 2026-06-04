package com.example.vulnerable

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class HybridActivity : AppCompatActivity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.settings.allowFileAccessFromFileURLs = true
        webView.settings.allowUniversalAccessFromFileURLs = true
        webView.addJavascriptInterface(PrivilegedBridge(), "NativeBridge")
        webView.loadUrl(intent.getStringExtra("target_url") ?: "https://example.com")
    }
}

class PrivilegedBridge {
    @JavascriptInterface
    fun exportAccessToken(): String = TokenCache.currentAccessToken()
}

object TokenCache {
    fun currentAccessToken(): String = "access-token-from-memory"
}
