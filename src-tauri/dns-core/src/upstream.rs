use std::io::{self, Error, ErrorKind};
use reqwest::Client;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub async fn forward_query(query_data: &[u8], dns_server: &str, http_client: &Client) -> io::Result<Vec<u8>> {
    if dns_server.starts_with("https://") {
        forward_query_doh_async(dns_server, query_data, http_client).await
    } else {
        forward_query_udp(dns_server, query_data).await
    }
}

async fn forward_query_doh_async(doh_url: &str, query_data: &[u8], http_client: &Client) -> io::Result<Vec<u8>> {
    println!("   ⏳ [3 - UPSTREAM DOH] Mengirim kueri ({} bytes) ke {}...", query_data.len(), doh_url);

    let request = http_client.post(doh_url)
        .header("Accept", "application/dns-message")
        .header("Content-Type", "application/dns-message")
        .body(query_data.to_vec());
    
    let response = match request.send().await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("   ❌ [3 - ERROR DOH] Reqwest gagal: {}", e);
            return Err(Error::new(ErrorKind::Other, format!("Gagal menghubungi DoH: {}", e)));
        }
    };

    println!("   📥 [4 - UPSTREAM DOH] Respons HTTP diterima: Status {}", response.status());

    if response.status().is_success() {
        match response.bytes().await {
            Ok(bytes) => {
                println!("   ✅ [4 - UPSTREAM DOH] Payload DNS murni berhasil diunduh: {} bytes", bytes.len());
                Ok(bytes.to_vec())
            },
            Err(e) => {
                eprintln!("   ❌ [4 - ERROR DOH] Gagal membaca byte respons: {}", e);
                Err(Error::new(ErrorKind::Other, format!("Gagal membaca respons DoH: {}", e)))
            }
        }
    } else {
        eprintln!("   ❌ [4 - ERROR DOH] Server menolak kueri!");
        Err(Error::new(ErrorKind::Other, format!("Server DoH menolak: {}", response.status())))
    }
}

async fn forward_query_udp(dns_server: &str, query_data: &[u8]) -> io::Result<Vec<u8>> {
    println!("   ⏳ [3 - UPSTREAM UDP] Mengirim kueri ({} bytes) ke {}...", query_data.len(), dns_server);

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("   ❌ [3 - ERROR UDP] Gagal bind socket: {}", e);
            return Err(Error::new(ErrorKind::Other, format!("Gagal UDP bind: {}", e)));
        }
    };

    if let Err(e) = timeout(Duration::from_secs(5), socket.send_to(query_data, dns_server)).await {
        eprintln!("   ❌ [3 - ERROR UDP] Timeout saat mengirim!");
        return Err(Error::new(ErrorKind::TimedOut, format!("Timeout UDP Send: {}", e)));
    }

    let mut response_buffer = [0u8; 512];
    match timeout(Duration::from_secs(5), socket.recv_from(&mut response_buffer)).await {
        Ok(Ok((size, _))) => {
            println!("   ✅ [4 - UPSTREAM UDP] Respons DNS diterima: {} bytes", size);
            Ok(response_buffer[..size].to_vec())
        },
        Ok(Err(e)) => {
            eprintln!("   ❌ [4 - ERROR UDP] Gagal membaca dari soket: {}", e);
            Err(Error::new(ErrorKind::Other, format!("Error UDP Recv: {}", e)))
        },
        Err(_) => {
            eprintln!("   ❌ [4 - ERROR UDP] Timeout! DNS ISP diam saja.");
            Err(Error::new(ErrorKind::TimedOut, "Timeout menerima UDP respons"))
        }
    }
}