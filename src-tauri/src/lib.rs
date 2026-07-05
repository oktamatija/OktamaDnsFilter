use std::sync::{Arc, RwLock, OnceLock};

#[cfg(target_os = "android")]
use std::sync::Mutex;

use tauri::Manager;
use dns_core::storage::{AppConfig, load_config, save_config};

#[cfg(target_os = "android")]
use jni::{JavaVM, JNIEnv};
#[cfg(target_os = "android")]
use jni::objects::{JObject, GlobalRef, JValue};

#[cfg(target_os = "android")]
static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

#[cfg(target_os = "android")]
static MAIN_ACTIVITY: Mutex<Option<Arc<GlobalRef>>> = Mutex::new(None);

// Brankas Baja Global
static GLOBAL_CONFIG: OnceLock<Arc<RwLock<AppConfig>>> = OnceLock::new();

pub fn get_global_config() -> Arc<RwLock<AppConfig>> {
    GLOBAL_CONFIG.get_or_init(|| {
        Arc::new(RwLock::new(load_config()))
    }).clone()
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_oktama_dnsfilter_MainActivity_initRustJni<'local>(
    env: JNIEnv<'local>, 
    class: JObject<'local>,
) {
    if JAVA_VM.get().is_none() {
        if let Ok(vm) = env.get_java_vm() {
            let _ = JAVA_VM.set(vm);
        }
    }
    
    if let Ok(global_ref) = env.new_global_ref(&class) {
        if let Ok(mut activity) = MAIN_ACTIVITY.lock() {
            *activity = Some(Arc::new(global_ref));
        }
    }

    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(500)); 
        
        // 🌟 FIX FINAL: Simpan ke variabel `enabled` agar kunci (read guard)
        // langsung dihancurkan saat bertemu titik koma (;). Lolos Borrow Checker!
        let should_enable = {
            let config_arc = get_global_config();
            let enabled = if let Ok(config) = config_arc.read() {
                config.doh_enabled || config.filtering_enabled
            } else {
                false
            };
            enabled
        }; 

        if should_enable {
            let _ = toggle_android_vpn(true);
        }
    });
}

#[cfg(target_os = "android")]
fn toggle_android_vpn(enable: bool) -> Result<(), String> {
    let vm = JAVA_VM.get().ok_or("Sistem Android belum terhubung ke Rust")?;
    
    let activity_arc = {
        let guard = MAIN_ACTIVITY.lock().map_err(|_| "Gagal mengunci referensi UI")?;
        guard.as_ref().cloned().ok_or("Layar Android belum terdaftar")?
    };

    let mut env = vm.attach_current_thread_permanently()
        .map_err(|e| format!("Gagal attach thread: {}", e))?;

    let result = env.call_method(
        activity_arc.as_ref(),
        "toggleVpnFromRust",
        "(Z)V",
        &[JValue::Bool(if enable { 1 } else { 0 })],
    );

    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        return Err("JNI membuang Exception (Dibersihkan)".to_string());
    }

    result.map_err(|e| format!("JNI Call Failed: {:?}", e))?;
    Ok(())
}

struct CleanupHandler;

impl Drop for CleanupHandler {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            dns_core::tunnel::stop_windivert_interface();
        }
        
        println!("⚠️ UI ditutup. (Di Android, VPN tetap berjalan di latar belakang)");
    }
}

#[tauri::command]
fn get_configuration() -> AppConfig {
    let config_arc = get_global_config();
    let config = config_arc.read().unwrap();
    config.clone()
}

#[tauri::command]
fn update_configuration(new_config: AppConfig) -> Result<(), String> {
    let config_arc = get_global_config();
    let mut config = config_arc.write().unwrap();
    *config = new_config.clone();
    save_config(&new_config).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn apply_engine_state() -> Result<String, String> {
    let config_arc = get_global_config();
    let config = config_arc.read().unwrap();
    
    if config.doh_enabled || config.filtering_enabled {
        #[cfg(target_os = "windows")]
        {
            let config_clone = Arc::clone(&config_arc);
            std::thread::spawn(move || {
                dns_core::tunnel::start_windivert_interface(config_clone);
            });
        }
        
        #[cfg(target_os = "android")]
        {
            if let Err(e) = toggle_android_vpn(true) {
                eprintln!("⚠️ Gagal memanggil VPN: {}", e);
            }
        }

        Ok("⚙️ Mesin Intersepsi Aktif.".to_string())
    } else {
        #[cfg(target_os = "windows")]
        {
            dns_core::tunnel::stop_windivert_interface();
        }
        
        #[cfg(target_os = "android")]
        {
            if let Err(e) = toggle_android_vpn(false) {
                eprintln!("⚠️ Gagal mematikan VPN: {}", e);
            }
        }

        Ok("🛑 Mesin Intersepsi Mati.".to_string())
    }
}

#[tauri::command]
async fn check_doh_connection(url: String) -> Result<String, String> {
    let raw = url.trim().to_lowercase();
    let safe_url = if raw.contains("1.1.1.1") || raw.contains("cloudflare") {
        "https://cloudflare-dns.com/dns-query".to_string()
    } else if raw.contains("8.8.8.8") || raw.contains("google") {
        "https://dns.google/dns-query".to_string()
    } else if raw.contains("9.9.9.9") || raw.contains("quad9") {
        "https://dns.quad9.net/dns-query".to_string()
    } else if raw.contains("adguard") || raw.contains("94.140") {
        "https://dns.adguard-dns.com/dns-query".to_string()
    } else if raw.is_empty() {
        "https://cloudflare-dns.com/dns-query".to_string()
    } else if !raw.starts_with("http") {
        format!("https://{}", raw)
    } else {
        raw
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .resolve("cloudflare-dns.com", std::net::SocketAddr::from(([1, 0, 0, 1], 443)))
        .resolve("dns.google", std::net::SocketAddr::from(([8, 8, 8, 8], 443)))
        .resolve("dns.quad9.net", std::net::SocketAddr::from(([9, 9, 9, 9], 443)))
        .resolve("dns.adguard-dns.com", std::net::SocketAddr::from(([94, 140, 14, 14], 443)))
        .build()
        .map_err(|e| e.to_string())?;

    match client.get(&safe_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() || status.as_u16() == 400 || status.as_u16() == 405 {
                Ok("Tersambung".to_string())
            } else {
                Err(format!("Server merespons aneh: {}", status))
            }
        },
        Err(e) => Err(format!("Gagal/Diblokir ISP: {}", e)),
    }
}

async fn fetch_and_parse_list(url: &str) -> Result<Vec<String>, String> {
    let resp = reqwest::get(url).await.map_err(|e| format!("Gagal ambil {}: {}", url, e))?;
    let text = resp.text().await.map_err(|e| e.to_string())?;
    
    let mut domains = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
            if parts[1] != "0.0.0.0" && parts[1] != "localhost" {
                domains.push(parts[1].to_string());
            }
        } 
        else if parts.len() == 1 {
            domains.push(parts[0].to_string());
        }
    }
    Ok(domains)
}

#[tauri::command]
async fn update_blocklist_from_github() -> Result<String, String> {
    let base_url = "https://raw.githubusercontent.com/oktamatija/oktamagenerator/main";
    
    let url_ads      = format!("{}/ads.txt", base_url);
    let url_adult    = format!("{}/adult.txt", base_url);
    let url_gambling = format!("{}/gambling.txt", base_url);
    let url_malware  = format!("{}/malware.txt", base_url);
    let url_phishing = format!("{}/phishing.txt", base_url);
    let url_drugs    = format!("{}/drugs.txt", base_url);
    let url_violence = format!("{}/violence.txt", base_url);
    let url_scam     = format!("{}/scam.txt", base_url);

    let ads_list      = fetch_and_parse_list(&url_ads).await.unwrap_or_default();
    let adult_list    = fetch_and_parse_list(&url_adult).await.unwrap_or_default();
    let gambling_list = fetch_and_parse_list(&url_gambling).await.unwrap_or_default();
    let malware_list  = fetch_and_parse_list(&url_malware).await.unwrap_or_default();
    let phishing_list = fetch_and_parse_list(&url_phishing).await.unwrap_or_default();
    let drugs_list    = fetch_and_parse_list(&url_drugs).await.unwrap_or_default();
    let violence_list = fetch_and_parse_list(&url_violence).await.unwrap_or_default();
    let scam_list     = fetch_and_parse_list(&url_scam).await.unwrap_or_default();

    let total_domains = ads_list.len() 
        + adult_list.len() 
        + gambling_list.len()
        + malware_list.len()
        + phishing_list.len()
        + drugs_list.len()
        + violence_list.len()
        + scam_list.len();

    let config_arc = get_global_config();
    let mut config = config_arc.write().unwrap();
    config.cloud_blocklist = ads_list;
    config.adult_blocklist = adult_list;
    config.gambling_blocklist = gambling_list;
    config.malware_blocklist = malware_list;
    config.phishing_blocklist = phishing_list;
    config.drugs_blocklist = drugs_list;
    config.violence_blocklist = violence_list;
    config.scam_blocklist = scam_list;
    
    save_config(&config).map_err(|e| format!("Gagal menyimpan: {}", e))?;
    
    Ok(format!("✅ Berhasil menyinkronkan {} total domain!", total_domains.to_string().replace("\"", "")))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _cleanup = CleanupHandler; 

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            if let Ok(app_dir) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&app_dir);
                let _ = std::env::set_current_dir(&app_dir);
                
                std::env::set_var("HOME", &app_dir);
                std::env::set_var("XDG_CONFIG_HOME", &app_dir);
                std::env::set_var("XDG_DATA_HOME", &app_dir);
                std::env::set_var("XDG_CACHE_HOME", &app_dir);
            }

            let _ = get_global_config();

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_configuration, 
            update_configuration, 
            apply_engine_state, 
            check_doh_connection, 
            update_blocklist_from_github
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}