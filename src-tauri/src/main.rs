// Menyembunyikan jendela konsol (Command Prompt) di Windows saat aplikasi berjalan dalam mode Release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Memanggil fungsi utama run() dari pustaka oktama_dns_filter untuk menyalakan Tauri v2
    oktama_dns_filter::run();
}