use crate::storage::{AppConfig, Blocklists};
use regex::Regex;

#[inline(always)]
fn match_domain_case_insensitive(domain: &str, blocked: &str) -> bool {
    if domain.eq_ignore_ascii_case(blocked) { return true; }
    let d_len = domain.len();
    let b_len = blocked.len();
    if d_len > b_len && domain.as_bytes()[d_len - b_len - 1] == b'.' {
        let suffix = &domain[d_len - b_len..];
        if suffix.eq_ignore_ascii_case(blocked) { return true; }
    }
    false
}

pub fn is_blocked(domain: &str, config: &AppConfig, lists: &Blocklists) -> bool {
    println!("🔎 [FILTER FORENSIK] Menginvestigasi domain: '{}'", domain);

    if !config.filtering_enabled { return false; }

    for w in &config.whitelist {
        if match_domain_case_insensitive(domain, w) { return false; }
    }

    for rule in &config.regex_rules {
        let regex_pattern = format!("(?i){}", rule);
        if let Ok(re) = Regex::new(&regex_pattern) {
            if re.is_match(domain) { 
                println!("   🚫 [BLOKIR] Terjegat oleh Regex Rule: {}", rule);
                return true; 
            }
        } else {
            if domain.to_lowercase().contains(&rule.to_lowercase()) { 
                println!("   🚫 [BLOKIR] Terjegat oleh Keyword Rule: {}", rule);
                return true; 
            }
        }
    }

    for blocked_domain in &lists.cloud {
        if match_domain_case_insensitive(domain, blocked_domain) { 
            println!("   🚫 [BLOKIR] Terjegat Iklan/Tracker: {}", blocked_domain);
            return true; 
        }
    }

    if config.block_adult {
        for blocked_domain in &lists.adult {
            if match_domain_case_insensitive(domain, blocked_domain) { 
                println!("   🔞 [BLOKIR] Terjegat Database Dewasa: {}", blocked_domain);
                return true; 
            }
        }
    }

    if config.block_gambling {
        for blocked_domain in &lists.gambling {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    if config.block_violence {
        for blocked_domain in &lists.violence {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    if config.block_drugs {
        for blocked_domain in &lists.drugs {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    if config.block_malware {
        for blocked_domain in &lists.malware {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    if config.block_phishing {
        for blocked_domain in &lists.phishing {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    if config.block_scam {
        for blocked_domain in &lists.scam {
            if match_domain_case_insensitive(domain, blocked_domain) { return true; }
        }
    }

    println!("   ✅ [LOLOS] Domain bersih.");
    false
}