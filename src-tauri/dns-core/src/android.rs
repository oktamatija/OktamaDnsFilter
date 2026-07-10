#![cfg(target_os = "android")]

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint};
use std::os::unix::io::FromRawFd;
use std::fs::File;
use std::io::{Read, Write, ErrorKind};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::{SocketAddr, ToSocketAddrs};
use std::mem::ManuallyDrop;

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use hickory_proto::op::{Message, ResponseCode};
use reqwest::Client;

static IS_RUNNING: AtomicBool = AtomicBool::new(false);

struct DnsTask {
    payload: Vec<u8>,
    source_port: u16,
    is_ipv4: bool,
    v4_src: [u8; 4],
    v4_dst: [u8; 4],
    v6_src: [u8; 16],
    v6_dst: [u8; 16],
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

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_oktama_dnsfilter_OktamaVpnService_startDnsFilter<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    vpn_fd: jint,
    isp_dns_jstr: JString<'local>, 
) -> jboolean {
    if IS_RUNNING.load(Ordering::SeqCst) { return jni::sys::JNI_TRUE; }

    let isp_dns_str: String = env.get_string(&isp_dns_jstr).map(|s| s.into()).unwrap_or_else(|_| String::new());
    let active_isp_dns = if isp_dns_str.is_empty() { "8.8.8.8".to_string() } else { isp_dns_str };
    let isp_dns_addr = if active_isp_dns.contains(':') { format!("[{}]:53", active_isp_dns) } else { format!("{}:53", active_isp_dns) };

    IS_RUNNING.store(true, Ordering::SeqCst);
    
    // 🌟 SOLUSI ANTI FDSAN-CRASH: DUPLIKASI FILE DESCRIPTOR
    // Kita "meminjam" FD dari Kotlin tanpa mengambil hak miliknya
    let original_file = ManuallyDrop::new(unsafe { File::from_raw_fd(vpn_fd) });
    
    // Kita gandakan (clone) FD tersebut agar Rust memiliki FD-nya sendiri.
    // Jika Rust mati/menutup, ia hanya akan menutup duplikatnya, Kotlin tetap aman!
    let rust_file = match original_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ [FATAL] Gagal menduplikasi VPN FD: {}", e);
            IS_RUNNING.store(false, Ordering::SeqCst);
            return jni::sys::JNI_FALSE;
        }
    };
    
    let vpn_file = Arc::new(rust_file);
    
    crate::storage::reload_global_config();

    let (doh_domain, doh_ip_str) = {
        let config = crate::storage::GLOBAL_APP_CONFIG.read().unwrap();
        parse_doh_url_and_resolve(&config.upstream_dns)
    };
    
    let doh_ip: SocketAddr = if doh_ip_str.is_empty() { SocketAddr::from(([1, 1, 1, 1], 443)) } else { doh_ip_str.parse().unwrap_or_else(|_| SocketAddr::from(([1, 1, 1, 1], 443))) };
    
    let http_client = Arc::new(
        crate::TOKIO_RUNTIME.block_on(async {
            Client::builder()
                .resolve(&doh_domain, doh_ip)
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| Client::new())
        })
    );

    let (process_tx, mut process_rx) = tokio::sync::mpsc::channel::<DnsTask>(500);
    let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1000);

    let vpn_writer = Arc::clone(&vpn_file);
    thread::spawn(move || {
        while let Some(packet) = write_rx.blocking_recv() {
            if !IS_RUNNING.load(Ordering::SeqCst) { break; }
            let mut file_ref = &*vpn_writer; 
            let _ = file_ref.write_all(&packet);
        }
    });

    let write_tx_worker = write_tx.clone();

    crate::TOKIO_RUNTIME.spawn(async move {
        while let Some(task) = process_rx.recv().await {
            let client = Arc::clone(&http_client);
            let w_tx = write_tx_worker.clone();
            let isp_addr = isp_dns_addr.clone();

            tokio::spawn(async move {
                let config = Arc::clone(&crate::storage::GLOBAL_APP_CONFIG.read().unwrap());
                let lists = Arc::clone(&crate::storage::GLOBAL_BLOCKLISTS.read().unwrap());
                
                let use_doh = config.doh_enabled;
                let doh_url = config.upstream_dns.clone();

                if let Ok(parsed_dns) = Message::from_vec(&task.payload) {
                    let mut is_blocked = false;
                    if config.filtering_enabled {
                        for query in parsed_dns.queries.iter() {
                            let mut full_domain = query.name().to_string().to_lowercase();
                            if full_domain.ends_with('.') { full_domain.pop(); }

                            if crate::filter::is_blocked(&full_domain, &config, &lists) {
                                is_blocked = true;
                                break;
                            }

                            let parts: Vec<&str> = full_domain.split('.').collect();
                            if parts.len() > 2 {
                                let root_domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
                                if crate::filter::is_blocked(&root_domain, &config, &lists) {
                                    is_blocked = true;
                                    break;
                                }
                            }
                        }
                    }

                    let dns_response_payload = if is_blocked {
                        let mut response = Message::error_msg(parsed_dns.id, parsed_dns.op_code, ResponseCode::NXDomain);
                        response.add_queries(parsed_dns.queries.clone());
                        response.to_vec().ok()
                    } else if use_doh {
                        crate::upstream::forward_query(&task.payload, &doh_url, &client).await.ok()
                    } else {
                        crate::upstream::forward_query(&task.payload, &isp_addr, &client).await.ok()
                    };

                    if let Some(res_payload) = dns_response_payload {
                        let builder = if task.is_ipv4 {
                            PacketBuilder::ipv4(task.v4_dst, task.v4_src, 64).udp(53, task.source_port)
                        } else {
                            PacketBuilder::ipv6(task.v6_dst, task.v6_src, 64).udp(53, task.source_port)
                        };

                        let mut response_packet = Vec::<u8>::with_capacity(builder.size(res_payload.len()));
                        if builder.write(&mut response_packet, &res_payload).is_ok() {
                            let _ = w_tx.send(response_packet).await;
                        }
                    }
                }
            });
        }
    });

    let vpn_reader = Arc::clone(&vpn_file);
    
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        println!("✅ [VPN LISTENER] CCTV Siaga menyeleksi rute 0.0.0.0!");
        
        while IS_RUNNING.load(Ordering::SeqCst) {
            let mut file_ref = &*vpn_reader;
            
            match file_ref.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => {
                    let packet = &buffer[..bytes_read]; 
                    
                    if let Ok(sliced) = SlicedPacket::from_ip(packet) {
                        if let Some(TransportSlice::Udp(ref udp)) = sliced.transport {
                            if udp.destination_port() == 53 {
                                let mut task = DnsTask {
                                    payload: udp.payload().to_vec(),
                                    source_port: udp.source_port(),
                                    is_ipv4: true,
                                    v4_src: [0; 4], v4_dst: [0; 4], v6_src: [0; 16], v6_dst: [0; 16],
                                };

                                if let Some(net) = &sliced.net {
                                    match net {
                                        etherparse::NetSlice::Ipv4(ref v4) => {
                                            task.v4_src = v4.header().source(); 
                                            task.v4_dst = v4.header().destination(); 
                                            task.is_ipv4 = true;
                                        }
                                        etherparse::NetSlice::Ipv6(ref v6) => {
                                            task.v6_src = v6.header().source(); 
                                            task.v6_dst = v6.header().destination(); 
                                            task.is_ipv4 = false;
                                        }
                                    }
                                }
                                let _ = process_tx.blocking_send(task);
                            } 
                        } 
                    }
                }
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    break;
                }
            }
        }
        println!("🛑 [VPN LISTENER] CCTV Dimatikan.");
    });

    jni::sys::JNI_TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_oktama_dnsfilter_OktamaVpnService_stopDnsFilter(
    mut _env: JNIEnv, _class: JClass,
) -> jboolean {
    if IS_RUNNING.load(Ordering::SeqCst) {
        IS_RUNNING.store(false, Ordering::SeqCst);
    }
    jni::sys::JNI_TRUE
}