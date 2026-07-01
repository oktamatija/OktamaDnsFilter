use serde::{Serialize, Deserialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub upstream_dns: String,
    pub regex_rules: Vec<String>,
    pub whitelist: Vec<String>,
    pub cloud_blocklist: Vec<String>,
    #[serde(default)]
    pub adult_blocklist: Vec<String>,
    #[serde(default)]
    pub gambling_blocklist: Vec<String>,
    
    // Saklar Utama
    #[serde(default)] 
    pub doh_enabled: bool,
    #[serde(default)] 
    pub filtering_enabled: bool,

    // Saklar Kategori
    #[serde(default)]
    pub block_adult: bool,
    #[serde(default)]
    pub block_gambling: bool,

    // --- FITUR BARU: LOKALISASI BAHASA ---
    #[serde(default = "default_lang")]
    pub language: String,
}

// Fungsi pembantu untuk memberikan nilai default jika key tidak ditemukan saat parsing
fn default_lang() -> String {
    "id".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            upstream_dns: "https://cloudflare-dns.com/dns-query".to_string(),
            regex_rules: Vec::new(),
            whitelist: Vec::new(),
            cloud_blocklist: Vec::new(),
            adult_blocklist: Vec::new(),
            gambling_blocklist: Vec::new(),
            doh_enabled: false,
            filtering_enabled: false,
            block_adult: false,
            block_gambling: false,
            language: "id".to_string(), // Default awal memakai Bahasa Indonesia
        }
    }
}

fn get_config_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    path.pop();
    path.push("dns_config.json");
    path
}

pub fn load_config() -> AppConfig {
    let path = get_config_path();
    if let Ok(content) = fs::read_to_string(&path) {
        if let Ok(config) = serde_json::from_str(&content) {
            return config;
        }
    }
    let default_config = AppConfig::default();
    let _ = save_config(&default_config);
    default_config
}

pub fn save_config(config: &AppConfig) -> Result<(), std::io::Error> {
    let path = get_config_path();
    let content = serde_json::to_string_pretty(config)?;
    fs::write(path, content)
}