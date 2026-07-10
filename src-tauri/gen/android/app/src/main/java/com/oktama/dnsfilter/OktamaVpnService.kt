package com.oktama.dnsfilter

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

class OktamaVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    external fun startDnsFilter(fd: Int, ispDns: String): Boolean
    external fun stopDnsFilter(): Boolean

    companion object {
        init {
            try {
                System.loadLibrary("oktama_dns_filter")
            } catch (e: UnsatisfiedLinkError) {
                Log.e("OktamaVPN", "Peringatan: Library Rust belum dimuat", e)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == "START_VPN") {
            Log.i("OktamaVPN", "Menerima perintah START dari Frontend.")
            startVpn()
        } else if (action == "STOP_VPN") {
            Log.i("OktamaVPN", "Menerima perintah STOP dari Frontend.")
            stopVpn()
        }
        return Service.START_NOT_STICKY
    }

    private fun startVpn() {
        if (vpnInterface != null) return
        try {
            val builder = Builder()
            
            // 🌟 1. Alamat IP Perangkat di dalam VPN
            builder.addAddress("10.0.0.2", 24)
            
            // 🌟 2. Alamat IP FIKTIF Khusus untuk Umpan DNS Server
            builder.addDnsServer("10.0.0.3")

            // 🌟 3. STRICT SPLIT-ROUTING: Kunci Keberhasilan!
            // Hanya paket yang menuju ke IP 10.0.0.3 yang akan dilempar OS ke dalam Rust.
            // Sisa internet (Chrome, WA, Game) langsung bebas melenggang lewat WiFi/Seluler!
            builder.addRoute("10.0.0.3", 32)
            
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.e("OktamaVPN", "Gagal mengecualikan aplikasi", e)
            }

            builder.setSession("Privacy Shield")
            vpnInterface = builder.establish()
            
            if (vpnInterface != null) {
                Log.i("OktamaVPN", "!!! VPN STRICT SPLIT-ROUTING DIAKTIFKAN !!!")
                val success = startDnsFilter(vpnInterface!!.fd, "8.8.8.8")
                Log.i("OktamaVPN", "Status Mesin Rust: $success")
            }

        } catch (e: Exception) {
            Log.e("OktamaVPN", "Gagal membangun VPN", e)
        }
    }

    private fun stopVpn() {
        try {
            stopDnsFilter() 
            vpnInterface?.close()
            vpnInterface = null
            Log.i("OktamaVPN", "VPN Telah Dimatikan Sesuai Perintah.")
        } catch (e: Exception) {
            Log.e("OktamaVPN", "Gagal menutup VPN", e)
        }
        stopSelf()
    }
    
    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}