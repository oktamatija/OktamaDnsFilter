use crate::storage::AppConfig;
use regex::Regex;

// 🌟 FUNGSI PENDETEKSI DOMAIN (CASE-INSENSITIVE & ZERO-ALLOCATION)
// Mengabaikan huruf besar/kecil dan mendeteksi sub-domain tanpa membebani RAM
#[inline(always)]
fn match_domain_case_insensitive(domain: &str, blocked: &str) -> bool {
    // 1. Cek kecocokan persis (misal: "Google.com" == "google.com")
    if domain.eq_ignore_ascii_case(blocked) {
        return true;
    }
    
    let d_len = domain.len();
    let b_len = blocked.len();
    
    // 2. Cek sub-domain (misal: "www.google.com" berakhiran ".google.com")
    if d_len > b_len && domain.as_bytes()[d_len - b_len - 1] == b'.' {
        let suffix = &domain[d_len - b_len..];
        if suffix.eq_ignore_ascii_case(blocked) {
            return true;
        }
    }
    
    false
}

pub fn is_blocked(domain: &str, config: &AppConfig) -> bool {
    // 1: CEK WHITELIST (Bypass Utama)
    for w in &config.whitelist {
        if match_domain_case_insensitive(domain, w) { return false; }
    }

    // 2: CEK REGEX / MANUAL RULES
    for rule in &config.regex_rules {
        // (?i) membuat Regex otomatis mengabaikan Case-Sensitive
        let regex_pattern = format!("(?i){}", rule);
        if let Ok(re) = Regex::new(&regex_pattern) {
            if re.is_match(domain) { return true; }
        } else {
            if domain.to_lowercase().contains(&rule.to_lowercase()) { return true; }
        }
    }

    // 3: CEK IKLAN & TELEMETRI (Master)
    for blocked_domain in &config.cloud_blocklist {
        if match_domain_case_insensitive(domain, blocked_domain) { return true; }
    }

    // 4: KONTEN DEWASA
    if config.block_adult {
        for blocked_domain in &config.adult_blocklist {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    // 5: JUDI ONLINE
    if config.block_gambling {
        for blocked_domain in &config.gambling_blocklist {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    // 6: KEKERASAN (Violence)
    if config.block_violence {
        for blocked_domain in &config.violence_blocklist {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    // 7: OBAT TERLARANG (Drugs)
    if config.block_drugs {
        for blocked_domain in &config.drugs_blocklist {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    // 8: MALWARE
    if config.block_malware {
        for blocked_domain in &config.malware_blocklist {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    // 9: PHISHING
    if config.block_phishing {
        for blocked_domain in &config.phishing_blocklist {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    // 10: PENIPUAN (Scam)
    if config.block_scam {
        for blocked_domain in &config.scam_blocklist {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    false
}