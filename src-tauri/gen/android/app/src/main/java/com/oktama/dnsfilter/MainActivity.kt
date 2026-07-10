package com.oktama.dnsfilter

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

// 🌟 Format yang 100% benar dan bersih
class MainActivity : TauriActivity() {
    
    private external fun initRustJni()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        System.loadLibrary("oktama_dns_filter")
        initRustJni()
    }

    fun toggleVpnFromRust(enable: Boolean) {
        if (enable) {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                startActivityForResult(intent, 1)
            } else {
                startVpnService()
            }
        } else {
            val vpnIntent = Intent(this, OktamaVpnService::class.java)
            vpnIntent.action = "STOP_VPN"
            startService(vpnIntent)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == Activity.RESULT_OK) {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val vpnIntent = Intent(this, OktamaVpnService::class.java)
        vpnIntent.action = "START_VPN"
        startService(vpnIntent)
    }
}