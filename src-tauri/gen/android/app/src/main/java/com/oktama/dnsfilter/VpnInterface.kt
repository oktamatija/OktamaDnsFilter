package com.oktama.dnsfilter

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import android.content.pm.PackageManager
import android.net.ConnectivityManager

class VpnInterface : VpnService() {
    private var vpnFileDescriptor: ParcelFileDescriptor? = null

    companion object {
        init {
            System.loadLibrary("oktama_dns_filter")
        }
        const val ACTION_START_VPN = "com.oktama.dnsfilter.START_VPN"
        const val ACTION_STOP_VPN = "com.oktama.dnsfilter.STOP_VPN"
    }

    // 🌟 PERHATIKAN: Kita menambahkan parameter 'ispDns' agar Rust tahu rute aslinya!
    external fun startDnsFilter(fd: Int, ispDns: String): Boolean
    external fun stopDnsFilter(): Boolean

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_VPN -> {
                Log.i("OktamaVPN", "Menerima perintah: Mematikan Layanan VPN...")
                stopVpn()
            }
            else -> {
                Log.i("OktamaVPN", "Menerima perintah: Memulai Layanan VPN...")
                setupVpn()
            }
        }
        return START_NOT_STICKY 
    }

    // 🌟 KECERDASAN BUATAN: Mengambil DNS bawaan dari Jaringan saat ini
    private fun getSystemDns(): String {
        try {
            val connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = connectivityManager.activeNetwork
            val linkProperties = connectivityManager.getLinkProperties(activeNetwork)
            if (linkProperties != null) {
                val dnsServers = linkProperties.dnsServers
                if (dnsServers.isNotEmpty()) {
                    val ip = dnsServers[0].hostAddress
                    if (ip != null) return ip
                }
            }
        } catch (e: Exception) {
            Log.e("OktamaVPN", "Gagal membaca DNS ISP", e)
        }
        return "8.8.8.8" // Fallback aman jika sistem Android menolak memberikan data
    }

    private fun setupVpn() {
        if (vpnFileDescriptor != null) return

        try {
            val builder = Builder()
            
            builder.addAddress("10.0.0.2", 32)
            builder.addDnsServer("10.0.0.3")
            builder.addRoute("10.0.0.3", 32) 
            
            builder.addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
            builder.addDnsServer("fd00:1:fd00:1:fd00:1:fd00:2")
            builder.addRoute("fd00:1:fd00:1:fd00:1:fd00:2", 128)

            builder.setMtu(1500)
            
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: PackageManager.NameNotFoundException) {
                Log.e("OktamaVPN", "Gagal mengecualikan aplikasi", e)
            }
            
            vpnFileDescriptor = builder.setSession("Oktama DNS Filter")
                .setBlocking(true)
                .establish()

            vpnFileDescriptor?.let {
                val fd = it.fd
                val ispDns = getSystemDns() // Eksekusi Radar DNS
                Log.i("OktamaVPN", "VPN Sukses! FD: $fd | DNS ISP: $ispDns")
                
                // Serahkan FD dan IP DNS ISP ke mesin Rust
                startDnsFilter(fd, ispDns) 
            }
        } catch (e: Exception) {
            Log.e("OktamaVPN", "Gagal membangun VPN: ${e.message}")
        }
    }

    private fun stopVpn() {
        stopDnsFilter() 
        try {
            vpnFileDescriptor?.close()
        } catch (e: Exception) {
            Log.e("OktamaVPN", "Error saat menutup FD", e)
        }
        vpnFileDescriptor = null
        stopSelf()
    }

    override fun onDestroy() {
        Log.i("OktamaVPN", "VPN Service Dihancurkan")
        stopVpn()
        super.onDestroy()
    }
}