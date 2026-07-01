use std::sync::{Arc, RwLock};
use std::thread;
use etherparse::{SlicedPacket, PacketBuilder, TransportSlice};
use hickory_proto::op::{Message, ResponseCode};
use reqwest::blocking::Client;
use crate::storage::AppConfig;
use std::ffi::CString;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use windivert_sys::{
    WinDivertOpen, WinDivertRecv, WinDivertSend, WinDivertLayer, WinDivertFlags, WinDivertClose
};

static WINDIVERT_HANDLE: AtomicUsize = AtomicUsize::new(0);

pub fn stop_windivert_interface() {
    let handle_val = WINDIVERT_HANDLE.swap(0, Ordering::SeqCst);
    if handle_val != 0 && handle_val != usize::MAX {
        unsafe {
            let handle_arg = std::mem::transmute_copy(&handle_val);
            WinDivertClose(handle_arg); 
        }
        println!("🛑 Mesin Kernel WinDivert berhasil ditidurkan.");
    }
}

#[derive(Clone, Copy)]
struct WdHandle(usize);
unsafe impl Send for WdHandle {}
unsafe impl Sync for WdHandle {}

pub fn start_windivert_interface(config_store: Arc<RwLock<AppConfig>>) {
    if WINDIVERT_HANDLE.load(Ordering::SeqCst) != 0 {
        return;
    }

    let config = config_store.read().unwrap().clone();

    let filter = CString::new("outbound and (ip or ipv6) and udp.DstPort == 53").unwrap();
    let flags = WinDivertFlags::default();
    
    let handle = unsafe {
        let filter_ptr = filter.as_ptr();
        let filter_arg = std::mem::transmute_copy(&filter_ptr);
        WinDivertOpen(filter_arg, WinDivertLayer::Network, 0, flags)
    };

    let handle_val: usize = unsafe { std::mem::transmute_copy(&handle) };
    if handle_val == 0 || handle_val == usize::MAX {
        return;
    }

    WINDIVERT_HANDLE.store(handle_val, Ordering::SeqCst);
    
    // --- PENCOCOKAN DOH DINAMIS ---
    // Membaca URL dari config dan memasangkan IP aslinya untuk menghindari DNS Loop
    let (doh_domain, doh_ip_str) = match config.upstream_dns.as_str() {
        "https://dns.google/dns-query" => ("dns.google", "8.8.8.8:443"),
        "https://dns.quad9.net/dns-query" => ("dns.quad9.net", "9.9.9.9:443"),
        "https://dns.adguard-dns.com/dns-query" => ("dns.adguard-dns.com", "94.140.14.14:443"),
        _ => ("cloudflare-dns.com", "1.1.1.1:443"), // Default
    };

    println!("🎯 Sniper WinDivert Aktif! Menggunakan DoH: {}", doh_domain);

    let doh_ip: SocketAddr = doh_ip_str.parse().unwrap();
    let http_client = Client::builder()
        .resolve(doh_domain, doh_ip) 
        .timeout(std::time::Duration::from_secs(3)) 
        .build()
        .unwrap_or_else(|_| Client::new());

    let safe_handle = WdHandle(handle_val);
    let doh_url = config.upstream_dns.clone();

    loop {
        let mut packet_buffer = vec![0u8; 1500];
        let mut read_len: u32 = 0; 
        let mut addr_buffer = [0u8; 128]; 

        let success = unsafe {
            let handle_arg = std::mem::transmute_copy(&safe_handle.0);
            WinDivertRecv(
                handle_arg, 
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
            let addr_clone = addr_buffer; 

            thread::spawn(move || {
                process_dns_packet(safe_handle, packet_buffer, addr_clone, client_clone, config_clone, url_clone);
            });
        }
    }
}

// PERBAIKAN: Menambahkan parameter doh_url
fn process_dns_packet(
    safe_handle: WdHandle,
    mut packet_bytes: Vec<u8>,
    addr_buffer: [u8; 128], 
    http_client: Client,
    config_store: Arc<RwLock<AppConfig>>,
    doh_url: String
) {
    let config = config_store.read().unwrap().clone();

    if let Ok(sliced) = SlicedPacket::from_ip(&packet_bytes) {
        
        let mut v4_src = [0u8; 4];
        let mut v4_dst = [0u8; 4];
        let mut v6_src = [0u8; 16];
        let mut v6_dst = [0u8; 16];

        let is_ipv4 = match sliced.net {
            Some(etherparse::NetSlice::Ipv4(ref v4)) => {
                v4_src = v4.header().source();
                v4_dst = v4.header().destination();
                true
            },
            Some(etherparse::NetSlice::Ipv6(ref v6)) => {
                v6_src = v6.header().source();
                v6_dst = v6.header().destination();
                false
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

                        if crate::filter::is_blocked(&domain_name, &config) {
                            println!("🚫 [BLOKIR] {}", domain_name);
                            is_ads = true;
                            break;
                        }
                    }
                }

                if is_ads {
                    let mut response = Message::error_msg(parsed_dns.id, parsed_dns.op_code, ResponseCode::NXDomain);
                    response.add_queries(parsed_dns.queries.clone());
                    
                    let mut payload = response.to_vec().unwrap_or_default();
                    if payload.len() >= 4 {
                        payload[2] |= 0x04; 
                        if parsed_dns.recursion_desired { payload[2] |= 0x01; } 
                        payload[3] |= 0x80; 
                    }
                    inject_packet(is_ipv4, v4_src, v4_dst, v6_src, v6_dst, src_port, dst_port, payload, safe_handle, addr_buffer);
                } 
                else if config.doh_enabled {
                    let raw_dns_query = parsed_dns.to_vec().unwrap_or_default();
                    
                    // PERBAIKAN: Menggunakan URL dinamis hasil pilihan dari UI
                    match http_client.post(&doh_url)
                        .header("Accept", "application/dns-message")
                        .header("Content-Type", "application/dns-message")
                        .body(raw_dns_query)
                        .send() 
                    {
                        Ok(resp) if resp.status().is_success() => {
                            let payload = resp.bytes().unwrap_or_default().to_vec();
                            inject_packet(is_ipv4, v4_src, v4_dst, v6_src, v6_dst, src_port, dst_port, payload, safe_handle, addr_buffer);
                        },
                        Err(e) => {
                            eprintln!("⚠️ [ERROR DOH] Gagal mencapai server DoH (Timeout/Diblokir ISP): {}", e);
                            return;
                        }
                        _ => return, 
                    }
                } 
                else {
                    unsafe {
                        let handle_arg = std::mem::transmute_copy(&safe_handle.0);
                        let mut write_len: u32 = 0; 
                        WinDivertSend(
                            handle_arg,
                            packet_bytes.as_mut_ptr() as *mut _,
                            packet_bytes.len() as u32,
                            &mut write_len as *mut u32,
                            addr_buffer.as_ptr() as *const _,
                        );
                    }
                }
            }
        }
    }
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
        
        let mut write_len: u32 = 0; 
        unsafe {
            let handle_arg = std::mem::transmute_copy(&safe_handle.0);
            WinDivertSend(
                handle_arg,
                response_packet.as_mut_ptr() as *mut _,
                response_packet.len() as u32,
                &mut write_len as *mut u32,
                inject_addr.as_ptr() as *const _,
            );
        }
    }
}