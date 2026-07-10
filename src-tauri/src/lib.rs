// PREVENT CONSOLE WINDOW ON WINDOWS IN RELEASE
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

#[cfg(target_os = "android")]
use std::sync::{Arc, Mutex, OnceLock};

use tauri::{Manager, AppHandle, Emitter};
use dns_core::storage::AppConfig;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use futures_util::future::join_all;

#[cfg(target_os = "android")]
use jni::{JavaVM, JNIEnv};
#[cfg(target_os = "android")]
use jni::objects::{JObject, GlobalRef, JValue};

#[cfg(target_os = "android")]
static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

#[cfg(target_os = "android")]
static MAIN_ACTIVITY: Mutex<Option<Arc<GlobalRef>>> = Mutex::new(None);


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
        std::thread::sleep(std::time::Duration::from_millis(1000)); 
        let should_enable = {
            let config_arc = dns_core::storage::GLOBAL_APP_CONFIG.read().unwrap();
            config_arc.doh_enabled || config_arc.filtering_enabled
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
    let mut env = vm.attach_current_thread_permanently().map_err(|e| format!("Gagal attach thread: {}", e))?;
    let result = env.call_method(
        activity_arc.as_ref(),
        "toggleVpnFromRust",
        "(Z)V",
        &[JValue::Bool(if enable { 1 } else { 0 })],
    );
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        return Err("JNI membuang Exception".to_string());
    }
    result.map_err(|e| format!("JNI Call Failed: {:?}", e))?;
    Ok(())
}

struct CleanupHandler;
impl Drop for CleanupHandler {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        { dns_core::tunnel::stop_windivert_interface(); }
    }
}

#[tauri::command]
fn get_configuration() -> AppConfig {
    let config_arc = dns_core::storage::GLOBAL_APP_CONFIG.read().unwrap();
    config_arc.as_ref().clone()
}

#[tauri::command]
fn update_configuration(new_config: AppConfig) -> Result<(), String> {
    dns_core::storage::save_config(&new_config).map_err(|e| e.to_string())?;
    dns_core::storage::reload_global_config(); 
    Ok(())
}

#[tauri::command]
fn apply_engine_state() -> Result<String, String> {
    let should_enable = {
        let config_arc = dns_core::storage::GLOBAL_APP_CONFIG.read().unwrap();
        config_arc.doh_enabled || config_arc.filtering_enabled
    };
    
    if should_enable {
        #[cfg(target_os = "windows")]
        {
            let config = dns_core::storage::GLOBAL_APP_CONFIG.read().unwrap().as_ref().clone();
            let config_store = std::sync::Arc::new(std::sync::RwLock::new(config));
            std::thread::spawn(move || { dns_core::tunnel::start_windivert_interface(config_store); });
        }
        #[cfg(target_os = "android")]
        {
            if let Err(e) = toggle_android_vpn(true) { eprintln!("⚠️ Gagal memanggil VPN: {}", e); }
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
        Ok("⚙️ Mesin Intersepsi Aktif.".to_string())
    } else {
        #[cfg(target_os = "windows")]
        { dns_core::tunnel::stop_windivert_interface(); }
        #[cfg(target_os = "android")]
        {
            if let Err(e) = toggle_android_vpn(false) { eprintln!("⚠️ Gagal mematikan VPN: {}", e); }
        }
        Ok("🛑 Mesin Intersepsi Mati.".to_string())
    }
}

fn build_raw_dns_query(domain: &str, id: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes()); 
    query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); 
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); 
    query
}

#[tauri::command]
async fn check_doh_connection(url: String) -> Result<String, String> {
    let raw = url.trim().to_lowercase();
    let safe_url = if raw.contains("1.1.1.1") { "https://cloudflare-dns.com/dns-query".to_string() } else { raw };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .resolve("cloudflare-dns.com", std::net::SocketAddr::from(([1, 0, 0, 1], 443)))
        .build().map_err(|e| e.to_string())?;

    let dns_query = build_raw_dns_query("google.com", rand::random::<u16>());
    match client.post(&safe_url).header("Accept", "application/dns-message").header("Content-Type", "application/dns-message").body(dns_query).send().await {
        Ok(resp) => if resp.status().is_success() { Ok("Tersambung".to_string()) } else { Err("Gagal".to_string()) },
        Err(_) => Err("Gagal".to_string()),
    }
}

#[derive(Clone, serde::Serialize)]
struct ProgressPayload { category: String, percentage: f64 }
static ACTIVE_DOWNLOADS: AtomicUsize = AtomicUsize::new(0);

async fn download_and_save_category(app: &tauri::AppHandle, url: &str, category: &str) -> Result<usize, String> {
    while ACTIVE_DOWNLOADS.load(Ordering::SeqCst) >= 2 { thread::sleep(std::time::Duration::from_millis(100)); }
    ACTIVE_DOWNLOADS.fetch_add(1, Ordering::SeqCst);
    
    let result = async {
        let _ = app.emit("download_progress", ProgressPayload { category: category.to_string(), percentage: 10.0 });
        let res = reqwest::Client::new().get(url).send().await.map_err(|e| format!("Koneksi terputus: {}", e))?;
        if !res.status().is_success() { return Err("Ditolak".to_string()); }
        let _ = app.emit("download_progress", ProgressPayload { category: category.to_string(), percentage: 40.0 });
        
        let full_text = res.text().await.map_err(|e| e.to_string())?;
        let _ = app.emit("download_progress", ProgressPayload { category: category.to_string(), percentage: 70.0 });
        
        let mut valid_domains = String::with_capacity(full_text.len());
        let mut line_count = 0;
        for line in full_text.lines() {
            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") && parts[1] != "0.0.0.0" && parts[1] != "localhost" {
                valid_domains.push_str(parts[1]); valid_domains.push('\n'); line_count += 1;
            } else if parts.len() == 1 && !parts[0].starts_with('#') {
                valid_domains.push_str(parts[0]); valid_domains.push('\n'); line_count += 1;
            }
        }
        
        let mut path = app.path().app_local_data_dir().unwrap();
        std::fs::create_dir_all(&path).unwrap();
        path.push(format!("{}.txt", category));
        File::create(&path).unwrap().write_all(valid_domains.as_bytes()).unwrap();
        let _ = app.emit("download_progress", ProgressPayload { category: category.to_string(), percentage: 100.0 });
        Ok(line_count)
    }.await;
    
    ACTIVE_DOWNLOADS.fetch_sub(1, Ordering::SeqCst);
    result
}

#[tauri::command]
async fn update_blocklist_from_github(app: AppHandle) -> Result<String, String> {
    let base = "https://raw.githubusercontent.com/oktamatija/oktamagenerator/main";
    let categories = [("ads", format!("{}/ads.txt", base)), ("adult", format!("{}/adult.txt", base)), ("gambling", format!("{}/gambling.txt", base)), ("malware", format!("{}/malware.txt", base)), ("phishing", format!("{}/phishing.txt", base)), ("drugs", format!("{}/drugs.txt", base)), ("violence", format!("{}/violence.txt", base)), ("scam", format!("{}/scam.txt", base))];
    let mut total = 0;
    
    let mut i = 0;
    while i < categories.len() {
        let batch = &categories[i..(i + 2).min(categories.len())];
        let futures = batch.iter().map(|(cat, url)| { let app = app.clone(); async move { download_and_save_category(&app, url, cat).await } });
        for res in join_all(futures).await { if let Ok(c) = res { total += c; } }
        i += 2;
    }
    dns_core::storage::reload_blocklists();
    Ok(format!("✅ Mengunduh ~{} domain!", total))
}

#[tauri::command]
fn get_blocklist_counts(app: tauri::AppHandle) -> std::collections::HashMap<String, usize> {
    let mut counts = std::collections::HashMap::new();
    if let Ok(dir) = app.path().app_local_data_dir() {
        for cat in ["ads", "adult", "gambling", "malware", "phishing", "drugs", "violence", "scam"] {
            let count = File::open(dir.join(format!("{}.txt", cat))).map(|f| BufReader::new(f).lines().count()).unwrap_or(0);
            counts.insert(cat.to_string(), count);
        }
    }
    counts
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _cleanup = CleanupHandler; 
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            if let Ok(dir) = app.path().app_local_data_dir() {
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::env::set_current_dir(&dir);
            }
            
            // 🌟 MEMISAHKAN BEBAN KE BACKGROUND THREAD AGAR UI INSTAN
            std::thread::spawn(|| {
                // Menggunakan drop() agar Rust tahu kita sengaja "membuang" nilainya 
                // setelah berhasil menyentuh variabel lazy_static
                drop(dns_core::storage::GLOBAL_BLOCKLISTS.read().unwrap());
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_configuration, update_configuration, apply_engine_state, check_doh_connection, update_blocklist_from_github, get_blocklist_counts])
        .run(tauri::generate_context!())
        .expect("error");
}