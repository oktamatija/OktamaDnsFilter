use std::io;
use std::sync::{Arc, RwLock};
use hickory_proto::op::{Message, ResponseCode};
use crate::storage::AppConfig;
use reqwest::Client;
use once_cell::sync::Lazy;

static SHARED_HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("Gagal membuat HTTP client")
});

pub fn start_dns_listener(config_store: Arc<RwLock<AppConfig>>) -> io::Result<()> {
    // Kloning pointer konfigurasi untuk thread IPv4
    let config_v4 = Arc::clone(&config_store);
    
    crate::TOKIO_RUNTIME.spawn(async move {
        println!("🛡️ DNS Ad-Blocker Core aktif!");
        
        if let Ok(socket_v4) = tokio::net::UdpSocket::bind("0.0.0.0:53").await {
            println!("✅ Mendengarkan di IPv4 (0.0.0.0:53)");
            run_worker_async(socket_v4, config_v4).await;
        }
    });

    // Kloning pointer konfigurasi untuk thread IPv6
    let config_v6 = Arc::clone(&config_store);
    
    crate::TOKIO_RUNTIME.spawn(async move {
        if let Ok(socket_v6) = tokio::net::UdpSocket::bind("[::]:53").await {
            println!("✅ Mendengarkan di IPv6 ([::]:53)\n");
            run_worker_async(socket_v6, config_v6).await;
        }
    });

    Ok(())
}

fn get_dns_server_address(config: &AppConfig) -> String {
    if config.doh_enabled {
        config.upstream_dns.clone()
    } else {
        if let Some(first_dns) = config.isp_dns_servers.first() {
            format!("{}:53", first_dns)
        } else {
            "8.8.8.8:53".to_string()
        }
    }
}

async fn run_worker_async(socket: tokio::net::UdpSocket, config_store: Arc<RwLock<AppConfig>>) {
    let mut buffer = [0u8; 512];
    let shared_socket = Arc::new(socket);

    loop {
        match shared_socket.recv_from(&mut buffer).await {
            Ok((size, source_addr)) => {
                let packet_data = buffer[..size].to_vec();
                let cfg_store = Arc::clone(&config_store);
                let socket_clone = Arc::clone(&shared_socket);

                tokio::spawn(async move {
                    if let Ok(parsed_message) = Message::from_vec(&packet_data) {
                        let current_config = cfg_store.read().unwrap().clone();
                        let mut is_ads = false;
                        
                        for query in parsed_message.queries.iter() {
                            let mut domain_name = query.name().to_string();
                            if domain_name.ends_with('.') { domain_name.pop(); }
                            
                            if crate::filter::is_blocked(&domain_name, &current_config) {
                                is_ads = true;
                                break;
                            }
                        }

                        if is_ads {
                            let mut response = Message::error_msg(parsed_message.id, parsed_message.op_code, ResponseCode::NXDomain);
                            response.add_queries(parsed_message.queries.clone());
                            if let Ok(response_bytes) = response.to_vec() {
                                let _ = socket_clone.send_to(&response_bytes, source_addr).await;
                            }
                        } else {
                            let dns_server = get_dns_server_address(&current_config);
                            if let Ok(upstream_response) = crate::upstream::forward_query(&packet_data, &dns_server, &SHARED_HTTP_CLIENT).await {
                                let _ = socket_clone.send_to(&upstream_response, source_addr).await;
                            }
                        }
                    }
                });
            }
            Err(_) => continue,
        }
    }
}