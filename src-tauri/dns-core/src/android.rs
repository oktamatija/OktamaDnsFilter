#![cfg(target_os = "android")]

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint};
use std::os::unix::io::FromRawFd;
use std::fs::File;
use std::io::{Read, Write};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc::sync_channel;
use std::net::UdpSocket;
use lazy_static::lazy_static;

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use hickory_proto::op::{Message, ResponseCode};
use std::net::SocketAddr;

lazy_static! {
    static ref IS_RUNNING: AtomicBool = AtomicBool::new(false);
    static ref GLOBAL_CONFIG: RwLock<Arc<crate::storage::AppConfig>> = RwLock::new(Arc::new(crate::storage::load_config()));
}

struct DnsTask {
    payload: Vec<u8>,
    source_port: u16,
    is_ipv4: bool,
    v4_src: [u8; 4],
    v4_dst: [u8; 4],
    v6_src: [u8; 16],
    v6_dst: [u8; 16],
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_oktama_dnsfilter_VpnInterface_startDnsFilter<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    vpn_fd: jint,
    isp_dns_jstr: JString<'local>, 
) -> jboolean {
    if IS_RUNNING.load(Ordering::SeqCst) {
        return jni::sys::JNI_TRUE;
    }

    let isp_dns_str: String = env.get_string(&isp_dns_jstr)
        .map(|s| s.into())
        .unwrap_or_else(|_| String::new());

    let active_isp_dns = if isp_dns_str.is_empty() { "8.8.8.8".to_string() } else { isp_dns_str };
    let isp_dns_addr = if active_isp_dns.contains(':') {
        format!("[{}]:53", active_isp_dns) 
    } else {
        format!("{}:53", active_isp_dns)
    };

    IS_RUNNING.store(true, Ordering::SeqCst);
    let mut vpn_file = unsafe { File::from_raw_fd(vpn_fd) };

    *GLOBAL_CONFIG.write().unwrap() = Arc::new(crate::storage::load_config());

    let http_client = Arc::new(reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .resolve("cloudflare-dns.com", SocketAddr::from(([1, 0, 0, 1], 443)))
        .resolve("dns.google", SocketAddr::from(([8, 8, 8, 8], 443)))
        .resolve("dns.quad9.net", SocketAddr::from(([9, 9, 9, 9], 443)))
        .resolve("dns.adguard-dns.com", SocketAddr::from(([94, 140, 14, 14], 443)))
        .build()
        .unwrap_or_default());

    let (tx, rx) = sync_channel::<DnsTask>(200);
    let rx = Arc::new(Mutex::new(rx));

    thread::spawn(|| {
        while IS_RUNNING.load(Ordering::SeqCst) {
            thread::sleep(std::time::Duration::from_secs(3));
            if !IS_RUNNING.load(Ordering::SeqCst) { break; }
            let new_cfg = Arc::new(crate::storage::load_config());
            *GLOBAL_CONFIG.write().unwrap() = new_cfg;
        }
    });

    for _ in 0..5 {
        let rx_worker = Arc::clone(&rx);
        let http_worker = Arc::clone(&http_client);
        let mut vpn_writer = match vpn_file.try_clone() {
            Ok(f) => f,
            Err(_) => continue,
        };
        let isp_dns_addr_clone = isp_dns_addr.clone();

        thread::spawn(move || {
            loop {
                let task = {
                    let lock = rx_worker.lock().unwrap();
                    match lock.recv() {
                        Ok(t) => t,
                        Err(_) => break,
                    }
                };

                let config = Arc::clone(&GLOBAL_CONFIG.read().unwrap());
                let use_doh = config.doh_enabled;

                let raw_doh = config.upstream_dns.clone().trim().to_lowercase();
                let doh_url = if raw_doh.contains("1.1.1.1") || raw_doh.contains("cloudflare") {
                    "https://cloudflare-dns.com/dns-query".to_string()
                } else if raw_doh.contains("8.8.8.8") || raw_doh.contains("google") {
                    "https://dns.google/dns-query".to_string()
                } else if raw_doh.contains("9.9.9.9") || raw_doh.contains("quad9") {
                    "https://dns.quad9.net/dns-query".to_string()
                } else if raw_doh.contains("adguard") || raw_doh.contains("94.140") {
                    "https://dns.adguard-dns.com/dns-query".to_string()
                } else if raw_doh.is_empty() {
                    "https://cloudflare-dns.com/dns-query".to_string()
                } else if !raw_doh.starts_with("http") {
                    format!("https://{}", raw_doh)
                } else {
                    raw_doh
                };

                if let Ok(parsed_dns) = Message::from_vec(&task.payload) {
                    let mut is_blocked = false;
                    
                    if config.filtering_enabled {
                        for query in parsed_dns.queries.iter() {
                            // 🌟 FOKUS SOLUSI: Konversi seluruh string kueri DNS ke huruf kecil
                            // agar cocok dengan database whitelist/manual block yang disimpan di UI.
                            let mut domain = query.name().to_string().to_lowercase();
                            if domain.ends_with('.') { domain.pop(); }
                            
                            // Debugging: Melihat domain apa yang sedang diperiksa (opsional, akan terlihat di Logcat)
                            println!("📡 [DNS-CHECK] Memeriksa domain: {}", domain);

                            if crate::filter::is_blocked(&domain, &config) {
                                println!("🚫 [DNS-BLOCKED] Memblokir domain: {}", domain);
                                is_blocked = true;
                                break;
                            }
                        }
                    }

                    let mut dns_response_payload: Option<Vec<u8>> = None;

                    if is_blocked {
                        let mut response = Message::error_msg(parsed_dns.id, parsed_dns.op_code, ResponseCode::NXDomain);
                        response.add_queries(parsed_dns.queries.clone());
                        if let Ok(mut r_payload) = response.to_vec() {
                            if r_payload.len() >= 4 {
                                r_payload[2] |= 0x04; 
                                if parsed_dns.recursion_desired { r_payload[2] |= 0x01; } 
                                r_payload[3] |= 0x80; 
                            }
                            dns_response_payload = Some(r_payload);
                        }
                    } else if use_doh {
                        if let Ok(resp) = http_worker.post(&doh_url)
                            .header("Accept", "application/dns-message")
                            .header("Content-Type", "application/dns-message")
                            .body(task.payload.clone())
                            .send() 
                        {
                            if resp.status().is_success() {
                                if let Ok(bytes) = resp.bytes() {
                                    dns_response_payload = Some(bytes.to_vec());
                                }
                            }
                        }
                    } else {
                        let bind_addr = if isp_dns_addr_clone.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
                        if let Ok(socket) = UdpSocket::bind(bind_addr) {
                            let _ = socket.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                            if socket.send_to(&task.payload, &isp_dns_addr_clone).is_ok() {
                                let mut res_buf = [0u8; 1024];
                                if let Ok((len, _)) = socket.recv_from(&mut res_buf) {
                                    dns_response_payload = Some(res_buf[..len].to_vec());
                                }
                            }
                        }
                    }

                    if let Some(res_payload) = dns_response_payload {
                        let builder = if task.is_ipv4 {
                            PacketBuilder::ipv4(task.v4_dst, task.v4_src, 64).udp(53, task.source_port)
                        } else {
                            PacketBuilder::ipv6(task.v6_dst, task.v6_src, 64).udp(53, task.source_port)
                        };

                        let mut response_packet = Vec::<u8>::with_capacity(builder.size(res_payload.len()));
                        if builder.write(&mut response_packet, &res_payload).is_ok() {
                            let _ = vpn_writer.write_all(&response_packet);
                        }
                    }
                }
            }
        });
    }

    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        
        while IS_RUNNING.load(Ordering::SeqCst) {
            match vpn_file.read(&mut buffer) {
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
                                    v4_src: [0u8; 4],
                                    v4_dst: [0u8; 4],
                                    v6_src: [0u8; 16],
                                    v6_dst: [0u8; 16],
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
                                let _ = tx.try_send(task);
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
        IS_RUNNING.store(false, Ordering::SeqCst);
    });

    jni::sys::JNI_TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_oktama_dnsfilter_VpnInterface_stopDnsFilter(
    mut _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if IS_RUNNING.load(Ordering::SeqCst) {
        IS_RUNNING.store(false, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    jni::sys::JNI_TRUE
}