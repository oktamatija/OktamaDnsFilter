package com.oktama.dnsfilter

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
    
    // RAHASIA BARU: Deklarasi jabat tangan ke Rust
    external fun initRustJni()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        
        // Begitu aplikasi nyala, langsung serahkan "Kunci Rumah" (Context) ke Rust!
        try {
            initRustJni()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    // Fungsi ini dipanggil dari Rust (Tidak perlu dibikin rumit pakai statis lagi)
    fun toggleVpnFromRust(enable: Boolean) {
        runOnUiThread {
            if (enable) {
                askVpnPermission()
            } else {
                val intent = Intent(this@MainActivity, VpnInterface::class.java)
                stopService(intent)
            }
        }
    }

    private fun askVpnPermission() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(vpnIntent, 100)
        } else {
            startVpnService()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 100 && resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, VpnInterface::class.java)
        startService(intent)
    }
}