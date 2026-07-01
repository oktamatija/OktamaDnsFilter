use std::net::UdpSocket;
use std::io;
use std::sync::{Arc, RwLock};
use hickory_proto::op::{Message, ResponseCode};
use crate::storage::AppConfig;

pub fn start_dns_listener(config_store: Arc<RwLock<AppConfig>>) -> io::Result<()> {
    // 1. Siapkan soket IPv4
    let socket_v4 = UdpSocket::bind("0.0.0.0:53")?;
    
    println!("🛡️ DNS Ad-Blocker Core aktif!");
    println!("✅ Mendengarkan di IPv4 (0.0.0.0:53)");

    // 2. Siapkan soket IPv6 di thread paralel (agar bisa berjalan bersamaan)
    if let Ok(socket_v6) = UdpSocket::bind("[::]:53") {
        println!("✅ Mendengarkan di IPv6 ([::]:53)\n");
        let config_v6 = Arc::clone(&config_store);
        std::thread::spawn(move || {
            run_worker(socket_v6, config_v6);
        });
    } else {
        println!("⚠️ IPv6 tidak tersedia di sistem ini.\n");
    }

    // 3. Jalankan IPv4 di thread utama
    run_worker(socket_v4, config_store);

    Ok(())
}

// Fungsi pekerja (worker) untuk menangani lalu lintas DNS
fn run_worker(socket: UdpSocket, config_store: Arc<RwLock<AppConfig>>) {
    let mut buffer = [0u8; 512];

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, source_addr)) => {
                if let Ok(parsed_message) = Message::from_vec(&buffer[..size]) {
                    
                    let current_config = {
                        config_store.read().unwrap().clone()
                    };

                    let mut is_ads = false;
                    for query in parsed_message.queries.iter() {
                        let domain_name = query.name().to_string();
                        let record_type = query.query_type(); 
                        
                        if crate::filter::is_blocked(&domain_name, &current_config) {
                            println!("🚫 [DIBLOKIR] {} meminta: {}", source_addr, domain_name);
                            is_ads = true;
                            break;
                        } else {
                            println!("✅ [AMAN] Klien meminta: {} [{}]", domain_name, record_type);
                        }
                    }

                    if is_ads {
                        let mut response = Message::error_msg(
                            parsed_message.id, 
                            parsed_message.op_code, 
                            ResponseCode::NXDomain
                        );
                        
                        for q in parsed_message.queries.iter() {
                            response.add_query(q.clone());
                        }
                        
                        if let Ok(response_bytes) = response.to_vec() {
                            let _ = socket.send_to(&response_bytes, source_addr);
                        }
                    } else {
                        match crate::upstream::forward_query(&buffer[..size], &current_config.upstream_dns) {
                            Ok(upstream_response) => {
                                let _ = socket.send_to(&upstream_response, source_addr);
                            }
                            Err(e) => {
                                eprintln!("⚠️ Gagal menghubungi upstream server: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // Abaikan error koneksi bawaan Windows yang tidak kritis
                if e.raw_os_error() == Some(10054) {
                    continue;
                }
                eprintln!("⚠️ Gagal membaca dari socket UDP: {}", e);
            }
        }
    }
}