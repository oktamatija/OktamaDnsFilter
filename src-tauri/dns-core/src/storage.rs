use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, RwLock};
use lazy_static::lazy_static;

lazy_static! {
    // OTAK: Konfigurasi Ringan untuk UI (Sangat Cepat)
    pub static ref GLOBAL_APP_CONFIG: RwLock<Arc<AppConfig>> = RwLock::new(Arc::new(load_config()));
    // OTOT: Brankas Baja 1.1 Juta Domain (TIDAK PERNAH DI-CLONE)
    pub static ref GLOBAL_BLOCKLISTS: RwLock<Arc<Blocklists>> = RwLock::new(Arc::new(load_blocklists()));
}

pub fn reload_global_config() {
    let new_config = load_config();
    if let Ok(mut lock) = GLOBAL_APP_CONFIG.write() {
        *lock = Arc::new(new_config);
    }
}

pub fn reload_blocklists() {
    let new_lists = load_blocklists();
    if let Ok(mut lock) = GLOBAL_BLOCKLISTS.write() {
        *lock = Arc::new(new_lists);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub upstream_dns: String,
    pub regex_rules: Vec<String>,
    pub whitelist: Vec<String>,
    pub doh_enabled: bool,
    pub filtering_enabled: bool,
    pub block_adult: bool,
    pub block_gambling: bool,
    pub block_violence: bool,
    pub block_drugs: bool,
    pub block_malware: bool,
    pub block_phishing: bool,
    pub block_scam: bool,
    pub language: String,
    #[serde(default)] pub doh_url: String, 
    #[serde(default)] pub isp_dns_servers: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            upstream_dns: "https://cloudflare-dns.com/dns-query".to_string(),
            regex_rules: vec![],
            whitelist: vec![],
            doh_enabled: false,
            filtering_enabled: false,
            block_adult: false,
            block_gambling: false,
            block_violence: false,
            block_drugs: false,
            block_malware: false,
            block_phishing: false,
            block_scam: false,
            language: "id".to_string(),
            doh_url: "".to_string(),
            isp_dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
        }
    }
}

// STRUKTUR BARU KHUSUS UNTUK MESIN PEMBLOKIR
pub struct Blocklists {
    pub cloud: Vec<String>,
    pub adult: Vec<String>,
    pub gambling: Vec<String>,
    pub violence: Vec<String>,
    pub drugs: Vec<String>,
    pub malware: Vec<String>,
    pub phishing: Vec<String>,
    pub scam: Vec<String>,
}

pub fn get_config_path() -> PathBuf {
    let mut path = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
    path.push("dns_filter_config.json");
    path
}

pub fn load_config() -> AppConfig {
    let path = get_config_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(parsed) = serde_json::from_str(&data) {
            return parsed;
        }
    }
    AppConfig::default()
}

pub fn load_blocklists() -> Blocklists {
    let path = get_config_path();
    let base_dir = path.parent().unwrap_or(std::path::Path::new("."));
    
    let load_txt = |filename: &str| -> Vec<String> {
        let mut list = Vec::new();
        if let Ok(file) = fs::File::open(base_dir.join(filename)) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if !trimmed.is_empty() { list.push(trimmed.to_string()); }
            }
        }
        list
    };

    Blocklists {
        cloud: load_txt("ads.txt"),
        adult: load_txt("adult.txt"),
        gambling: load_txt("gambling.txt"),
        malware: load_txt("malware.txt"),
        phishing: load_txt("phishing.txt"),
        drugs: load_txt("drugs.txt"),
        violence: load_txt("violence.txt"),
        scam: load_txt("scam.txt"),
    }
}

pub fn save_config(config: &AppConfig) -> Result<(), String> {
    let path = get_config_path();
    let data = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())?;
    Ok(())
}