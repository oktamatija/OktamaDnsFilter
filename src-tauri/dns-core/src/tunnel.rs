use std::sync::{Arc, RwLock};
use etherparse::{SlicedPacket, PacketBuilder, TransportSlice};
use hickory_proto::op::{Message, ResponseCode};
use reqwest::Client;
use crate::storage::AppConfig;
use std::ffi::CString;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};

use windivert_sys::{
    WinDivertOpen, WinDivertRecv, WinDivertSend, WinDivertLayer, WinDivertFlags, WinDivertClose
};

static WINDIVERT_HANDLE: AtomicUsize = AtomicUsize::new(0);

pub fn stop_windivert_interface() {
    let handle_val = WINDIVERT_HANDLE.swap(0, Ordering::SeqCst);
    if handle_val != 0 && handle_val != usize::MAX {
        unsafe { WinDivertClose(std::mem::transmute_copy(&handle_val)); }
        println!("🛑 Mesin Kernel WinDivert berhasil ditidurkan.");
    }
}

#[derive(Clone, Copy)]
struct WdHandle(usize);
unsafe impl Send for WdHandle {}
unsafe impl Sync for WdHandle {}

pub fn start_windivert_interface(config_store: Arc<RwLock<AppConfig>>) {
    if WINDIVERT_HANDLE.load(Ordering::SeqCst) != 0 { return; }

    let config = config_store.read().unwrap().clone();
    if !config.doh_enabled && !config.filtering_enabled { return; }

    let filter = CString::new("outbound and (ip or ipv6) and udp.DstPort == 53").unwrap();
    let handle = unsafe { WinDivertOpen(std::mem::transmute_copy(&filter.as_ptr()), WinDivertLayer::Network, 0, WinDivertFlags::default()) };

    let handle_val: usize = unsafe { std::mem::transmute_copy(&handle) };
    if handle_val == 0 || handle_val == usize::MAX { return; }

    WINDIVERT_HANDLE.store(handle_val, Ordering::SeqCst);
    
    let (doh_domain, doh_ip_str) = parse_doh_url_and_resolve(&config.upstream_dns);
    let doh_ip: SocketAddr = if doh_ip_str.is_empty() { SocketAddr::from(([1, 1, 1, 1], 443)) } else { doh_ip_str.parse().unwrap() };
    
    let http_client = crate::TOKIO_RUNTIME.block_on(async {
        Client::builder()
            .resolve(&doh_domain, doh_ip)
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new())
    });

    let safe_handle = WdHandle(handle_val);
    let doh_url = config.upstream_dns.clone();

    // OS Thread Khusus untuk menangkap paket WinDivert
    std::thread::spawn(move || {
        loop {
            let mut packet_buffer = vec![0u8; 1500];
            let mut read_len: u32 = 0; 
            let mut addr_buffer = [0u8; 128]; 

            let success = unsafe {
                WinDivertRecv(
                    std::mem::transmute_copy(&safe_handle.0), 
                    packet_buffer.as_mut_ptr() as *mut _,
                    packet_buffer.len() as u32,
                    &mut read_len as *mut u32,
                    addr_buffer.as_mut_ptr() as *mut _,
                )
            };

            let success_val: i32 = unsafe { std::mem::transmute_copy(&success) };
            if success_val == 0 { break; }

            if success_val != 0 && read_len > 0 {
                packet_buffer.truncate(read_len as usize);
                let client_clone = http_client.clone();
                let config_clone = Arc::clone(&config_store);
                let url_clone = doh_url.clone();
                
                // Meneruskan beban kerja ke TOKIO RUNTIME
                crate::TOKIO_RUNTIME.spawn(async move {
                    process_dns_packet(safe_handle, packet_buffer, addr_buffer, client_clone, config_clone, url_clone).await;
                });
            }
        }
    });
}

async fn process_dns_packet(
    safe_handle: WdHandle,
    mut packet_bytes: Vec<u8>,
    addr_buffer: [u8; 128], 
    http_client: Client,
    config_store: Arc<RwLock<AppConfig>>,
    doh_url: String
) {
    let config = config_store.read().unwrap().clone();

    if let Ok(sliced) = SlicedPacket::from_ip(&packet_bytes) {
        let mut v4_src = [0u8; 4]; let mut v4_dst = [0u8; 4];
        let mut v6_src = [0u8; 16]; let mut v6_dst = [0u8; 16];

        let is_ipv4 = match sliced.net {
            Some(etherparse::NetSlice::Ipv4(ref v4)) => {
                v4_src = v4.header().source(); v4_dst = v4.header().destination(); true
            },
            Some(etherparse::NetSlice::Ipv6(ref v6)) => {
                v6_src = v6.header().source(); v6_dst = v6.header().destination(); false
            },
            _ => return, 
        };

        let (src_port, dst_port) = match sliced.transport {
            Some(TransportSlice::Udp(ref u)) => (u.source_port(), u.destination_port()),
            _ => return,
        };

        if let Some(TransportSlice::Udp(udp)) = sliced.transport.as_ref() {
            if let Ok(parsed_dns) = Message::from_vec(udp.payload()) {
                let mut is_ads = false;
                
                if config.filtering_enabled {
                    for query in parsed_dns.queries.iter() {
                        let mut domain_name = query.name().to_string();
                        if domain_name.ends_with('.') { domain_name.pop(); }
let lists = std::sync::Arc::clone(&crate::storage::GLOBAL_BLOCKLISTS.read().unwrap());
if crate::filter::is_blocked(&domain_name, &config, &lists) {
                                is_ads = true;
                            break;
                        }
                    }
                }

                if is_ads {
                    let mut response = Message::error_msg(parsed_dns.id, parsed_dns.op_code, ResponseCode::NXDomain);
                    response.add_queries(parsed_dns.queries.clone());
                    let payload = response.to_vec().unwrap_or_default();
                    inject_packet(is_ipv4, v4_src, v4_dst, v6_src, v6_dst, src_port, dst_port, payload, safe_handle, addr_buffer);
                }
                else if config.doh_enabled {
                    let raw_dns_query = parsed_dns.to_vec().unwrap_or_default();
                    if let Ok(payload) = crate::upstream::forward_query(&raw_dns_query, &doh_url, &http_client).await {
                        inject_packet(is_ipv4, v4_src, v4_dst, v6_src, v6_dst, src_port, dst_port, payload, safe_handle, addr_buffer);
                    }
                } 
                else {
                    tokio::task::spawn_blocking(move || {
                        unsafe {
                            let mut write_len: u32 = 0; 
                            WinDivertSend(
                                std::mem::transmute_copy(&safe_handle.0),
                                packet_bytes.as_mut_ptr() as *mut _,
                                packet_bytes.len() as u32,
                                &mut write_len as *mut u32,
                                addr_buffer.as_ptr() as *const _,
                            );
                        }
                    }).await.unwrap_or_default();
                }
            }
        }
    }
}

fn parse_doh_url_and_resolve(doh_url: &str) -> (String, String) {
    let domain = match doh_url {
        url if url.contains("dns.google") => "dns.google",
        url if url.contains("dns.quad9.net") => "dns.quad9.net",
        url if url.contains("dns.adguard-dns.com") => "dns.adguard-dns.com",
        url if url.contains("cloudflare-dns.com") => "cloudflare-dns.com",
        url if url.contains("dns.nextdns.com") => "dns.nextdns.com",
        _ => {
            if let Some(domain_part) = doh_url.strip_prefix("https://") {
                if let Some(domain) = domain_part.split('/').next() { domain } else { "cloudflare-dns.com" }
            } else { "cloudflare-dns.com" }
        }
    };
    
    let ip = match domain {
        "dns.google" => "8.8.8.8:443".to_string(),
        "dns.quad9.net" => "9.9.9.9:443".to_string(),
        "dns.adguard-dns.com" => "94.140.14.14:443".to_string(),
        "dns.nextdns.com" => "45.90.28.0:443".to_string(),
        "cloudflare-dns.com" => "1.1.1.1:443".to_string(),
        custom_domain => {
            match (custom_domain, 443).to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() { addr.ip().to_string() } else { String::new() }
                }
                Err(_) => String::new(),
            }
        }
    };
    (domain.to_string(), ip)
}

fn inject_packet(is_ipv4: bool, v4_src: [u8;4], v4_dst: [u8;4], v6_src: [u8;16], v6_dst: [u8;16], src_port: u16, dst_port: u16, payload: Vec<u8>, safe_handle: WdHandle, original_addr: [u8; 128]) {
    let builder = if is_ipv4 {
        PacketBuilder::ipv4(v4_dst, v4_src, 64).udp(dst_port, src_port)
    } else {
        PacketBuilder::ipv6(v6_dst, v6_src, 64).udp(dst_port, src_port)
    };

    let mut response_packet = Vec::<u8>::with_capacity(builder.size(payload.len()));
    if builder.write(&mut response_packet, &payload).is_ok() {
        let mut inject_addr = original_addr; 
        inject_addr[10] &= 0xFD; 
        
        tokio::task::spawn_blocking(move || {
            unsafe {
                let mut write_len: u32 = 0; 
                WinDivertSend(
                    std::mem::transmute_copy(&safe_handle.0),
                    response_packet.as_mut_ptr() as *mut _,
                    response_packet.len() as u32,
                    &mut write_len as *mut u32,
                    inject_addr.as_ptr() as *const _,
                );
            }
        });
    }
}