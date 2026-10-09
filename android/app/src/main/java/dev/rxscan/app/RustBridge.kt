package dev.rxscan.app

/**
 * Narrow typed bridge into the shared RXScan Rust core (librxscan.so).
 *
 * This is NOT a generic command bridge: it exposes exactly four typed
 * operations (start/stop/version/capabilities). All scanning, evidence,
 * and GUI behavior stays in Rust + the shared frontend, reached by the
 * WebView over loopback HTTP like the desktop `rxscan web` flow. No
 * arbitrary execution, no script injection surface, no remote endpoints.
 */
class RustBridge {
    companion object {
        init {
            System.loadLibrary("rxscan")
        }

        /** Start the loopback server; returns the bound port, -1 on failure. */
        @JvmStatic
        external fun startServer(dataDir: String): Int

        /** Stop the loopback server if running; idempotent. */
        @JvmStatic
        external fun stopServer()

        /** Core version (same crate as desktop). */
        @JvmStatic
        external fun version(): String

        /** Machine-readable capability report (restricted stays restricted). */
        @JvmStatic
        external fun capabilitiesJson(): String

        /** Last error text, empty when no error was recorded. */
        @JvmStatic
        external fun lastError(): String
    }
}
