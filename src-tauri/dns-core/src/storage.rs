use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub upstream_dns: String,
    pub regex_rules: Vec<String>,
    pub whitelist: Vec<String>,
    
    // Daftar Blokir Utama
    pub cloud_blocklist: Vec<String>,
    pub adult_blocklist: Vec<String>,
    pub gambling_blocklist: Vec<String>,
    
    // 🌟 5 Kategori Blokir Ekstra
    pub violence_blocklist: Vec<String>,
    pub drugs_blocklist: Vec<String>,
    pub malware_blocklist: Vec<String>,
    pub phishing_blocklist: Vec<String>,
    pub scam_blocklist: Vec<String>,

    // Setelan Saklar (Toggle) Utama
    pub doh_enabled: bool,
    pub filtering_enabled: bool,
    
    // Setelan Saklar Kategori
    pub block_adult: bool,
    pub block_gambling: bool,
    pub block_violence: bool,
    pub block_drugs: bool,
    pub block_malware: bool,
    pub block_phishing: bool,
    pub block_scam: bool,

    pub language: String,

    // Menyimpan field lama agar tidak error saat membaca file config versi sebelumnya
    #[serde(default)]
    pub doh_url: String, 
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            upstream_dns: "https://cloudflare-dns.com/dns-query".to_string(),
            regex_rules: vec![],
            whitelist: vec![],
            
            cloud_blocklist: vec![],
            adult_blocklist: vec![],
            gambling_blocklist: vec![],
            violence_blocklist: vec![],
            drugs_blocklist: vec![],
            malware_blocklist: vec![],
            phishing_blocklist: vec![],
            scam_blocklist: vec![],

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
        }
    }
}

pub fn get_config_path() -> PathBuf {
    let mut path = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
    path.push("dns_filter_config.json");
    path
}

pub fn load_config() -> AppConfig {
    let path = get_config_path();
    if let Ok(data) = fs::read_to_string(path) {
        // Jika file ada, coba parsing
        if let Ok(config) = serde_json::from_str(&data) {
            return config;
        }
    }
    // Jika file tidak ada atau rusak, gunakan default bawaan pabrik
    AppConfig::default()
}

pub fn save_config(config: &AppConfig) -> Result<(), String> {
    let path = get_config_path();
    let data = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())?;
    Ok(())
}