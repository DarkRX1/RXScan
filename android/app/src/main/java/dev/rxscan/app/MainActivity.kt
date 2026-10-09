package dev.rxscan.app

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import java.io.File

/**
 * RXScan Android shell: owns lifecycle and platform integration only.
 *
 * On launch it starts the shared Rust core's loopback server against the
 * app-private data directory (no Unix-home assumptions, no Termux, no
 * root) and presents the shared RXScan frontend in a WebView pointed at
 * that loopback server. Back navigates WebView history; the server keeps
 * running with the process and stops with it.
 *
 * WebView hardening: JavaScript is required by the existing frontend;
 * file/content access, geolocation, and password/form saving stay off;
 * no addJavascriptInterface bridge exists (all API traffic is the page's
 * own same-origin fetch/EventSource to /api/v1); remote debugging is
 * never enabled by this code (release builds additionally set
 * debuggable=false).
 */
class MainActivity : Activity() {

    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = 0xFF020711.toInt()

        val dataDir = File(filesDir, "rxscan-web")
        if (!dataDir.isDirectory) {
            dataDir.mkdirs()
        }
        val port = RustBridge.startServer(dataDir.absolutePath)
        if (port <= 0) {
            Log.e("RXScan", "embedded server failed to start: ${RustBridge.lastError()}")
            Toast.makeText(
                this,
                "RXScan failed to start: ${RustBridge.lastError()}",
                Toast.LENGTH_LONG,
            ).show()
            finish()
            return
        }
        Log.i("RXScan", "embedded RXScan core serving on port $port")

        webView = WebView(this)
        val settings: WebSettings = webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.saveFormData = false
        settings.savePassword = false
        settings.mediaPlaybackRequiresUserGesture = true
        webView.webViewClient = WebViewClient()
        setContentView(webView)

        if (savedInstanceState == null) {
            webView.loadUrl("http://127.0.0.1:$port/")
        } else {
            webView.restoreState(savedInstanceState)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (this::webView.isInitialized) {
            webView.saveState(outState)
        }
    }

    override fun onBackPressed() {
        if (this::webView.isInitialized && webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }

    override fun onDestroy() {
        if (isFinishing && !isChangingConfigurations) {
            RustBridge.stopServer()
            if (this::webView.isInitialized) {
                webView.destroy()
            }
        }
        super.onDestroy()
    }
}
