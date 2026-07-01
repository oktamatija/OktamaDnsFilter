use std::io::{self, Error, ErrorKind};
use reqwest::header::{CONTENT_TYPE, ACCEPT};
use std::sync::OnceLock;
use std::net::SocketAddr;

// Menggunakan HTTP Client statis agar koneksi sangat cepat
static HTTP_CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();

pub fn forward_query(query_data: &[u8], _upstream_dns: &str) -> io::Result<Vec<u8>> {
    // KEMBALI MENGGUNAKAN DOMAIN agar sertifikat SSL/TLS valid dan diterima sistem
    let doh_url = "https://cloudflare-dns.com/dns-query".to_string();

    let client = HTTP_CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            // FITUR BOOTSTRAP: Memberitahu reqwest secara manual di mana cloudflare-dns.com berada.
            // Ini mem-bypass proses pencarian DNS lokal, mencegah Infinite Loop!
            .resolve("cloudflare-dns.com", SocketAddr::from(([1, 0, 0, 1], 443))) 
            // Catatan: Menggunakan 1.0.0.1 (IP alternatif Cloudflare) karena 1.1.1.1 
            // sering diblokir total oleh beberapa ISP di Indonesia.
            .build()
            .expect("Gagal membuat HTTP Client")
    });
    
    let response = client.post(&doh_url)
        .header(CONTENT_TYPE, "application/dns-message")
        .header(ACCEPT, "application/dns-message")
        .body(query_data.to_vec())
        .send()
        .map_err(|e| Error::new(ErrorKind::Other, format!("Gagal menghubungi DoH: {}", e)))?;

    if response.status().is_success() {
        let bytes = response.bytes().map_err(|e| Error::new(ErrorKind::Other, format!("Gagal membaca respons DoH: {}", e)))?;
        Ok(bytes.to_vec())
    } else {
        Err(Error::new(ErrorKind::Other, format!("Server DoH menolak: {}", response.status())))
    }
}