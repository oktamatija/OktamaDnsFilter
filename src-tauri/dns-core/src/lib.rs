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
pub mod tunnel;

#[cfg(target_os = "windows")]
pub use intercept::start_dns_listener;

use once_cell::sync::Lazy;

// 🌟 MESIN ASINKRON GLOBAL (Solusi OOM & Panic)
pub static TOKIO_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Runtime::new().expect("Gagal membuat Tokio Runtime Global")
});

pub fn init_core_engine() {
    // Memastikan Tokio Runtime menyala saat engine diinisialisasi pertama kali
    let _ = &*TOKIO_RUNTIME;
}