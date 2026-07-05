// ----------------------------------------------------------------
// MODUL KHUSUS TARGET ANDROID
// ----------------------------------------------------------------
#[cfg(target_os = "android")]
pub mod android;

// ----------------------------------------------------------------
// MODUL UTAMA ENGINE (Berjalan di Semua Platform)
// ----------------------------------------------------------------
pub mod filter;
pub mod upstream;
pub mod storage;

// ----------------------------------------------------------------
// MODUL INTERCEPTOR & TUNNEL KHUSUS WINDOWS
// ----------------------------------------------------------------
#[cfg(target_os = "windows")]
pub mod intercept;

#[cfg(target_os = "windows")]
pub mod tunnel; // <-- Dipindahkan ke sini agar Android tidak membacanya

#[cfg(target_os = "windows")]
pub use intercept::start_dns_listener;

pub fn init_core_engine() {
    // Inisialisasi engine global
}