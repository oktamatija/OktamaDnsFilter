use std::sync::{Arc, RwLock};
use tauri::State;
use dns_core::storage::{AppConfig, load_config, save_config};

struct CleanupHandler;

impl Drop for CleanupHandler {
    fn drop(&mut self) {
        dns_core::tunnel::stop_windivert_interface();
        println!("⚠️ Aplikasi berhenti, koneksi WinDivert terputus dengan aman.");
    }
}

struct AppState {
    config: Arc<RwLock<AppConfig>>,
}

#[tauri::command]
fn get_configuration(state: State<'_, AppState>) -> AppConfig {
    let config = state.config.read().unwrap();
    config.clone()
}

#[tauri::command]
fn update_configuration(new_config: AppConfig, state: State<'_, AppState>) -> Result<(), String> {
    let mut config = state.config.write().unwrap();
    *config = new_config.clone();
    save_config(&new_config).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn apply_engine_state(state: State<'_, AppState>) -> Result<String, String> {
    let config = state.config.read().unwrap();
    
    if config.doh_enabled || config.filtering_enabled {
        let config_clone = Arc::clone(&state.config);
        std::thread::spawn(move || {
            dns_core::tunnel::start_windivert_interface(config_clone);
        });
        Ok("⚙️ Mesin Intersepsi Aktif.".to_string())
    } else {
        dns_core::tunnel::stop_windivert_interface();
        Ok("🛑 Mesin Intersepsi Mati.".to_string())
    }
}

#[tauri::command]
async fn check_doh_connection(url: String) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3)) // Timeout 3 detik agar UI tidak hang
        .build()
        .map_err(|e| e.to_string())?;

    // Melakukan PING (HTTP GET) ke server DoH
    match client.get(&url).send().await {
        Ok(_) => Ok("Tersambung".to_string()),
        Err(e) => Err(format!("Gagal/Diblokir ISP: {}", e)),
    }
}

// ==========================================
// FUNGSI PEMBANTU: Ekstraktor Domain Cerdas
// ==========================================
async fn fetch_and_parse_list(url: &str) -> Result<Vec<String>, String> {
    let resp = reqwest::get(url).await.map_err(|e| format!("Gagal ambil {}: {}", url, e))?;
    let text = resp.text().await.map_err(|e| e.to_string())?;
    
    let mut domains = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Lewati baris kosong atau komentar
        if line.is_empty() || line.starts_with('#') { continue; }
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format standar StevenBlack: "0.0.0.0 domain.com"
        if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
            if parts[1] != "0.0.0.0" && parts[1] != "localhost" {
                domains.push(parts[1].to_string());
            }
        } 
        // Format Raw Domain (seperti repo Anda): "domain.com"
        else if parts.len() == 1 {
            domains.push(parts[0].to_string());
        }
    }
    Ok(domains)
}

// ==========================================
// MENGUNDUH 3 KATEGORI SEKALIGUS
// ==========================================
#[tauri::command]
async fn update_blocklist_from_github(state: State<'_, AppState>) -> Result<String, String> {
    // 1. Master List (Iklan & Telemetri)
    let url_ads = "https://raw.githubusercontent.com/oktamatija/ad-blocker/main/master-blocklist.txt";
    // 2. StevenBlack Porn List
    let url_adult = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts";
    // 3. StevenBlack Gambling List
    let url_gambling = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts";

    // Eksekusi pengunduhan (Bisa memakan waktu 3-10 detik tergantung koneksi)
    let ads_list = fetch_and_parse_list(url_ads).await.unwrap_or_default();
    let adult_list = fetch_and_parse_list(url_adult).await.unwrap_or_default();
    let gambling_list = fetch_and_parse_list(url_gambling).await.unwrap_or_default();

    let total_domains = ads_list.len() + adult_list.len() + gambling_list.len();

    // Menyuntikkan array ke memori Rust
    let mut config = state.config.write().unwrap();
    config.cloud_blocklist = ads_list;
    config.adult_blocklist = adult_list;
    config.gambling_blocklist = gambling_list;
    
    save_config(&config).map_err(|e| format!("Gagal menyimpan konfigurasi: {}", e))?;
    
    Ok(format!("✅ Berhasil menyinkronkan {} total domain ke dalam mesin!", total_domains))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _cleanup = CleanupHandler; 
    let current_config = Arc::new(RwLock::new(load_config()));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState { config: current_config })
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