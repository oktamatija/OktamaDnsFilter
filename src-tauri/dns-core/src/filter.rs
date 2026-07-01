use crate::storage::AppConfig;
use regex::Regex;

pub fn is_blocked(domain: &str, config: &AppConfig) -> bool {
    // ==========================================
    // PRIORITAS 1: CEK WHITELIST (BYPASS)
    // Jika domain ada di whitelist, LANGSUNG LOLOS
    // ==========================================
    for w in &config.whitelist {
        // Cocokkan persis (misal: "api.internal.com") 
        // ATAU subdomainnya (misal: "v1.api.internal.com")
        if domain == w || domain.ends_with(&format!(".{}", w)) {
            return false; 
        }
    }

    // ==========================================
    // PRIORITAS 2: CEK REGEX / MANUAL RULES
    // ==========================================
    for rule in &config.regex_rules {
        // Mencoba memproses teks dari UI sebagai pola Regex sejati
        if let Ok(re) = Regex::new(rule) {
            if re.is_match(domain) {
                return true; // Terblokir oleh Regex!
            }
        } else {
            // FALLBACK AMAN: Jika user mengetik regex yang salah/tidak valid, 
            // Rust tidak akan error, melainkan menganggapnya sebagai kata kunci biasa.
            if domain.contains(rule) {
                return true;
            }
        }
    }

    // ==========================================
    // PRIORITAS 3: CEK KATEGORI IKLAN & TELEMETRI (Master)
    // Menggunakan pencocokan persis agar sangat cepat
    // ==========================================
    for blocked_domain in &config.cloud_blocklist {
        if domain == blocked_domain {
            return true;
        }
    }

    // ==========================================
    // PRIORITAS 4: CEK KATEGORI KONTEN DEWASA (Pornografi)
    // Hanya dieksekusi jika saklar di UI dinyalakan
    // ==========================================
    if config.block_adult {
        for blocked_domain in &config.adult_blocklist {
            if domain == blocked_domain {
                return true;
            }
        }
    }

    // ==========================================
    // PRIORITAS 5: CEK KATEGORI JUDI ONLINE (Gambling)
    // Hanya dieksekusi jika saklar di UI dinyalakan
    // ==========================================
    if config.block_gambling {
        for blocked_domain in &config.gambling_blocklist {
            if domain == blocked_domain {
                return true;
            }
        }
    }

    // Jika tidak ada yang cocok satupun dari lapisan di atas, loloskan paketnya!
    false
}