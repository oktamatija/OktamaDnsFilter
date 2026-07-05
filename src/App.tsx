import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface AppConfig {
  upstream_dns: string;
  regex_rules: string[];
  whitelist: string[];
  cloud_blocklist: string[]; // Ini adalah wadah utama untuk daftar Iklan & Telemetri
  adult_blocklist: string[];
  gambling_blocklist: string[];
  violence_blocklist: string[];
  drugs_blocklist: string[];
  malware_blocklist: string[];
  phishing_blocklist: string[];
  scam_blocklist: string[];

  doh_enabled: boolean;
  filtering_enabled: boolean; // Ini adalah saklar utama (Master Switch) untuk Ad-Blocker
  block_adult: boolean;
  block_gambling: boolean;
  block_violence: boolean;
  block_drugs: boolean;
  block_malware: boolean;
  block_phishing: boolean;
  block_scam: boolean;
  
  language: string;
}

type DohStatus = "idle" | "checking" | "connected" | "error";

const translations: Record<string, Record<string, string>> = {
  id: {
    title: "🛡️ Privacy Shield",
    statusActive: "● Intersepsi Kernel Aktif",
    statusIdle: "● Kernel Idle",
    adBlocker: "Ad-Blocker (Iklan & Tracker)",
    dohTunnel: "DoH Tunnel",
    dohProvider: "🌍 Penyedia DNS over HTTPS (DoH)",
    dohSubtitle: "Pilih server selain Cloudflare jika diblokir oleh ISP Anda.",
    checkingRoute: "⏳ Mengecek Rute...",
    connected: "✅ Tersambung",
    errorRoute: "❌ Gagal (Rute Diblokir)",
    extraCategories: "☁️ Kategori Keamanan Ekstra",
    adultContent: "🔞 Konten Dewasa",
    gambling: "🎲 Perjudian",
    violence: "🥊 Kekerasan",
    drugs: "💊 Obat Terlarang",
    malware: "🦠 Malware",
    phishing: "🎣 Phishing",
    scam: "🤥 Penipuan (Scam)",
    totalActive: "Total Domain Aktif",
    manualBlock: "🚫 Intersepsi Manual (Block)",
    placeholderBlock: "contoh: ads, telemetry...",
    whitelist: "✅ Pengecualian Blokir (Whitelist)",
    placeholderWhitelist: "contoh: web-penting.com...",
    btnUpdate: "🔄 Perbarui Daftar dari Cloud",
    btnUpdating: "⏳ Mengunduh Jutaan Aturan Baru...",
    connecting: "⚙️ Menghubungkan ke Mesin Kernel..."
  },
  en: {
    title: "🛡️ Privacy Shield",
    statusActive: "● Kernel Interception Active",
    statusIdle: "● Kernel Idle",
    adBlocker: "Ad-Blocker (Ads & Trackers)",
    dohTunnel: "DoH Tunnel",
    dohProvider: "🌍 DNS over HTTPS (DoH) Provider",
    dohSubtitle: "Select a server other than Cloudflare if blocked.",
    checkingRoute: "⏳ Checking Route...",
    connected: "✅ Connected",
    errorRoute: "❌ Failed (Blocked)",
    extraCategories: "☁️ Extra Security Categories",
    adultContent: "🔞 Adult Content",
    gambling: "🎲 Gambling",
    violence: "🥊 Violence",
    drugs: "💊 Illegal Drugs",
    malware: "🦠 Malware",
    phishing: "🎣 Phishing",
    scam: "🤥 Fraud & Scam",
    totalActive: "Total Active Domains",
    manualBlock: "🚫 Manual Interception (Block)",
    placeholderBlock: "e.g., ads, telemetry...",
    whitelist: "✅ Block Exception (Whitelist)",
    placeholderWhitelist: "e.g., important-web.com...",
    btnUpdate: "🔄 Update Lists from Cloud",
    btnUpdating: "⏳ Downloading Rules...",
    connecting: "⚙️ Connecting to Kernel Engine..."
  }
};

export default function App() {
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [newRule, setNewRule] = useState("");
  const [newWhitelist, setNewWhitelist] = useState("");
  const [isUpdating, setIsUpdating] = useState(false);
  const [dohStatus, setDohStatus] = useState<DohStatus>("idle");

  const t = (key: string): string => {
    const lang = config?.language || "id";
    return translations[lang]?.[key] || translations["id"][key] || key;
  };

  const verifyDohConnection = async (url: string) => {
    setDohStatus("checking");
    try {
      await invoke("check_doh_connection", { url });
      setDohStatus("connected");
    } catch (error) {
      console.error("DoH Connection Error:", error);
      setDohStatus("error");
    }
  };

  useEffect(() => {
    invoke<AppConfig>("get_configuration")
      .then((data) => {
        // Fallback untuk array agar tidak undefined
        if (!data.whitelist) data.whitelist = [];
        if (!data.cloud_blocklist) data.cloud_blocklist = [];
        if (!data.adult_blocklist) data.adult_blocklist = [];
        if (!data.gambling_blocklist) data.gambling_blocklist = [];
        if (!data.violence_blocklist) data.violence_blocklist = [];
        if (!data.drugs_blocklist) data.drugs_blocklist = [];
        if (!data.malware_blocklist) data.malware_blocklist = [];
        if (!data.phishing_blocklist) data.phishing_blocklist = [];
        if (!data.scam_blocklist) data.scam_blocklist = [];

        // Fallback untuk boolean
        if (typeof data.doh_enabled === 'undefined') data.doh_enabled = false;
        if (typeof data.filtering_enabled === 'undefined') data.filtering_enabled = false;
        if (typeof data.block_adult === 'undefined') data.block_adult = false;
        if (typeof data.block_gambling === 'undefined') data.block_gambling = false;
        if (typeof data.block_violence === 'undefined') data.block_violence = false;
        if (typeof data.block_drugs === 'undefined') data.block_drugs = false;
        if (typeof data.block_malware === 'undefined') data.block_malware = false;
        if (typeof data.block_phishing === 'undefined') data.block_phishing = false;
        if (typeof data.block_scam === 'undefined') data.block_scam = false;

        if (!data.language) data.language = "id";
        if (!data.upstream_dns) data.upstream_dns = "https://cloudflare-dns.com/dns-query";
        
        setConfig(data);
        if (data.doh_enabled) verifyDohConnection(data.upstream_dns);
      })
      .catch((err) => console.error("Gagal memuat konfigurasi:", err));
  }, []);

  const saveAndApplyState = async (newConfig: AppConfig, triggerDohCheck = false) => {
    setConfig(newConfig);
    try {
      await invoke("update_configuration", { newConfig });
      await invoke("apply_engine_state");

      if (triggerDohCheck && newConfig.doh_enabled) {
        verifyDohConnection(newConfig.upstream_dns);
      } else if (!newConfig.doh_enabled) {
        setDohStatus("idle");
      }
    } catch (err) {
      console.error(err);
    }
  };

  const toggleDoH = () => {
    if (config) saveAndApplyState({ ...config, doh_enabled: !config.doh_enabled }, true);
  };

  const toggleFiltering = () => {
    if (config) saveAndApplyState({ ...config, filtering_enabled: !config.filtering_enabled });
  };

  const handleDohServerChange = (newUrl: string) => {
    if (config) saveAndApplyState({ ...config, upstream_dns: newUrl }, true);
  };

  const handleLanguageChange = (lang: "id" | "en") => {
    if (config) saveAndApplyState({ ...config, language: lang }, config.doh_enabled);
  };

  const handleUpdateList = async () => {
    setIsUpdating(true);
    try {
      const msg = await invoke<string>("update_blocklist_from_github");
      const successMsg = config?.language === "en" ? "✅ Cloud synchronization successful!" : msg;
      alert(successMsg);
      const data = await invoke<AppConfig>("get_configuration");
      setConfig(data);
    } catch (err) {
      alert("❌ Error: " + err);
    } finally {
      setIsUpdating(false);
    }
  };

  const handleAddRule = () => {
    if (newRule.trim() && config) {
      saveAndApplyState({ ...config, regex_rules: [...config.regex_rules, newRule.trim().toLowerCase()] });
      setNewRule("");
    }
  };

  const handleRemoveRule = (indexToRemove: number) => {
    if (config) {
      const updatedRules = config.regex_rules.filter((_, idx) => idx !== indexToRemove);
      saveAndApplyState({ ...config, regex_rules: updatedRules });
    }
  };

  const handleAddWhitelist = () => {
    if (newWhitelist.trim() && config) {
      saveAndApplyState({ ...config, whitelist: [...config.whitelist, newWhitelist.trim().toLowerCase()] });
      setNewWhitelist("");
    }
  };

  const handleRemoveWhitelist = (indexToRemove: number) => {
    if (config) {
      const updatedWhitelist = config.whitelist.filter((_, idx) => idx !== indexToRemove);
      saveAndApplyState({ ...config, whitelist: updatedWhitelist });
    }
  };

  // Komponen untuk saklar kategori sekunder
  const CategoryToggle = ({ label, prop, color }: { label: string, prop: keyof AppConfig, color: string }) => {
    if (!config) return null;
    const isActive = config[prop] as boolean;
    const arrayProp = prop.replace('block_', '') + '_blocklist' as keyof AppConfig;
    const count = (config[arrayProp] as string[])?.length || 0;

    return (
      <label onClick={() => saveAndApplyState({ ...config, [prop]: !isActive })} style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: config.filtering_enabled ? 'pointer' : 'not-allowed', opacity: config.filtering_enabled ? 1 : 0.5, padding: "4px 0" }}>
        <div style={{ position: 'relative', width: '32px', height: '18px', backgroundColor: isActive ? color : '#333', borderRadius: '20px', transition: '0.3s' }}>
          <div style={{ position: 'absolute', top: '2px', left: isActive ? '16px' : '2px', width: '14px', height: '14px', backgroundColor: '#fff', borderRadius: '50%', transition: '0.3s' }} />
        </div>
        <span style={{ fontSize: '12px', fontWeight: 600, color: isActive ? color : '#94a3b8', display: 'flex', alignItems: 'center', gap: '6px' }}>
          {t(label)}
          <span style={{ backgroundColor: isActive ? `${color}33` : '#333', color: isActive ? color : '#888', padding: '2px 6px', borderRadius: '10px', fontSize: '10px' }}>
            {count.toLocaleString("id-ID")}
          </span>
        </span>
      </label>
    );
  };

  if (!config) return <div style={{ padding: "40px", textAlign: "center", color: "#888", fontFamily: "system-ui" }}>{t("connecting")}</div>;

  const isEngineActive = config.doh_enabled || config.filtering_enabled;
  
  // Kalkulasi total seluruh domain yang diblokir, TERMASUK iklan (cloud_blocklist)
  const totalBlocked = config.cloud_blocklist.length 
    + (config.block_adult ? config.adult_blocklist.length : 0) 
    + (config.block_gambling ? config.gambling_blocklist.length : 0)
    + (config.block_violence ? config.violence_blocklist.length : 0)
    + (config.block_drugs ? config.drugs_blocklist.length : 0)
    + (config.block_malware ? config.malware_blocklist.length : 0)
    + (config.block_phishing ? config.phishing_blocklist.length : 0)
    + (config.block_scam ? config.scam_blocklist.length : 0);

  return (
    <div style={{ backgroundColor: "#121212", minHeight: "100vh", color: "#e0e0e0", fontFamily: "system-ui, -apple-system, sans-serif" }}>
      
      {/* HEADER & GLOBAL TOGGLES */}
      <div style={{ backgroundColor: "#1e1e1e", padding: "15px 20px", borderBottom: "1px solid #2d2d2d", display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", position: "sticky", top: 0, zIndex: 10, gap: "15px" }}>
        <div>
          <h2 style={{ margin: 0, color: "#3b82f6", display: "flex", alignItems: "center", gap: "10px", fontSize: "18px" }}>
            {t("title")}
          </h2>
          <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: isEngineActive ? "#10b981" : "#64748b", fontWeight: "500" }}>
            {isEngineActive ? t("statusActive") : t("statusIdle")}
          </p>
        </div>

        <div style={{ display: "flex", gap: "15px", alignItems: "center", flexWrap: "wrap" }}>
          
          {/* SAKLAR UTAMA AD-BLOCKER & INDIKATOR JUMLAH IKLAN */}
          <label onClick={toggleFiltering} style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: config.filtering_enabled ? '#f59e0b' : '#666', transition: '0.3s', display: 'flex', alignItems: 'center', gap: '6px' }}>
              {t("adBlocker")}
              <span style={{ backgroundColor: config.filtering_enabled ? 'rgba(245, 158, 11, 0.2)' : '#333', color: config.filtering_enabled ? '#f59e0b' : '#888', padding: '2px 6px', borderRadius: '10px', fontSize: '10px' }}>
                {config.cloud_blocklist.length.toLocaleString("id-ID")}
              </span>
            </span>
            <div style={{ position: 'relative', width: '32px', height: '18px', backgroundColor: config.filtering_enabled ? '#f59e0b' : '#333', borderRadius: '20px', transition: '0.3s' }}>
               <div style={{ position: 'absolute', top: '2px', left: config.filtering_enabled ? '16px' : '2px', width: '14px', height: '14px', backgroundColor: '#fff', borderRadius: '50%', transition: '0.3s' }} />
            </div>
          </label>

          {/* SAKLAR DOH */}
          <label onClick={toggleDoH} style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: config.doh_enabled ? '#3b82f6' : '#666', transition: '0.3s' }}>{t("dohTunnel")}</span>
            <div style={{ position: 'relative', width: '32px', height: '18px', backgroundColor: config.doh_enabled ? '#3b82f6' : '#333', borderRadius: '20px', transition: '0.3s' }}>
               <div style={{ position: 'absolute', top: '2px', left: config.doh_enabled ? '16px' : '2px', width: '14px', height: '14px', backgroundColor: '#fff', borderRadius: '50%', transition: '0.3s' }} />
            </div>
          </label>

          {/* BAHASA */}
          <div style={{ display: "flex", backgroundColor: "#0f0f0f", padding: "4px", borderRadius: "20px", border: "1px solid #333" }}>
            <button onClick={() => handleLanguageChange("id")} style={{ border: "none", background: config.language === "id" ? "#3b82f6" : "none", color: config.language === "id" ? "#fff" : "#666", padding: "4px 10px", borderRadius: "15px", fontSize: "11px", fontWeight: "bold", cursor: "pointer", transition: "0.2s" }}>ID</button>
            <button onClick={() => handleLanguageChange("en")} style={{ border: "none", background: config.language === "en" ? "#3b82f6" : "none", color: config.language === "en" ? "#fff" : "#666", padding: "4px 10px", borderRadius: "15px", fontSize: "11px", fontWeight: "bold", cursor: "pointer", transition: "0.2s" }}>EN</button>
          </div>
        </div>
      </div>

      <div style={{ padding: "20px", maxWidth: "100%", margin: "0 auto", paddingBottom: "50px", overflowX: "hidden" }}>
        
        {/* PANEL DOH */}
        <div style={{ marginBottom: "20px", padding: "15px", backgroundColor: "#1a1a1a", borderRadius: "10px", border: "1px solid #2d2d2d" }}>
          <h3 style={{ margin: "0 0 10px 0", color: "#e0e0e0", fontSize: "14px", display: "flex", alignItems: "center", flexWrap: "wrap", gap: "8px" }}>
            {t("dohProvider")}
            {config.doh_enabled && (
              <span style={{ 
                marginLeft: "auto", fontSize: "11px", padding: "4px 8px", borderRadius: "20px", fontWeight: "bold",
                backgroundColor: dohStatus === "checking" ? "#f59e0b" : dohStatus === "connected" ? "#059669" : "#dc2626", 
                color: "#fff", transition: "0.3s"
              }}>
                {dohStatus === "checking" ? t("checkingRoute") : dohStatus === "connected" ? t("connected") : t("errorRoute")}
              </span>
            )}
          </h3>
          <p style={{ margin: "0 0 15px 0", fontSize: "12px", color: "#888" }}>{t("dohSubtitle")}</p>
          
          <select 
            value={config.upstream_dns}
            onChange={(e) => handleDohServerChange(e.target.value)}
            disabled={!config.doh_enabled}
            style={{ width: "100%", padding: "10px", borderRadius: "6px", backgroundColor: config.doh_enabled ? "#0f0f0f" : "#1a1a1a", color: config.doh_enabled ? "#fff" : "#666", border: "1px solid #333", outline: "none", cursor: config.doh_enabled ? "pointer" : "not-allowed", fontSize: "13px" }}
          >
            <option value="https://cloudflare-dns.com/dns-query">Cloudflare (1.1.1.1) - Tercepat</option>
            <option value="https://dns.google/dns-query">Google DNS (8.8.8.8) - Paling Stabil</option>
            <option value="https://dns.quad9.net/dns-query">Quad9 (9.9.9.9) - Privasi Tinggi</option>
          </select>
        </div>

        {/* PANEL KATEGORI EKSTRA */}
        <div style={{ marginBottom: "20px", padding: "15px", backgroundColor: "#1e293b", borderRadius: "10px", border: "1px solid #334155", display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: "15px" }}>
          <div style={{ flex: 1 }}>
            <h4 style={{ margin: "0 0 10px 0", color: "#f8fafc", fontSize: "14px" }}>{t("extraCategories")}</h4>
            
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "10px" }}>
              <CategoryToggle label="adultContent" prop="block_adult" color="#ef4444" />
              <CategoryToggle label="gambling" prop="block_gambling" color="#d946ef" />
              <CategoryToggle label="violence" prop="block_violence" color="#f97316" />
              <CategoryToggle label="drugs" prop="block_drugs" color="#14b8a6" />
              <CategoryToggle label="malware" prop="block_malware" color="#dc2626" />
              <CategoryToggle label="phishing" prop="block_phishing" color="#3b82f6" />
              <CategoryToggle label="scam" prop="block_scam" color="#eab308" />
            </div>
          </div>
          
          {/* TOTAL SELURUH DOMAIN (Termasuk Iklan) */}
          <div style={{ textAlign: "right", paddingLeft: "10px", alignSelf: "flex-end" }}>
            <div style={{ fontSize: "28px", fontWeight: "800", color: "#38bdf8" }}>
              {totalBlocked.toLocaleString("id-ID")} 
            </div>
            <div style={{ fontSize: "11px", color: "#94a3b8", fontWeight: "bold", textTransform: "uppercase" }}>{t("totalActive")}</div>
          </div>
        </div>

        {/* INPUT MANUAL & WHITELIST */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "20px" }}>
          <div style={{ backgroundColor: "#1a1a1a", padding: "15px", borderRadius: "10px", border: "1px solid #2d2d2d", opacity: config.filtering_enabled ? 1 : 0.5 }}>
            <h3 style={{ margin: "0 0 10px 0", color: config.filtering_enabled ? "#f59e0b" : "#666", fontSize: "14px" }}>
              {t("manualBlock")}
            </h3>
            <div style={{ display: "flex", gap: "10px", marginBottom: "15px" }}>
              <input 
                type="text" placeholder={t("placeholderBlock")} value={newRule} onChange={(e) => setNewRule(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleAddRule()}
                disabled={!config.filtering_enabled}
                style={{ flex: 1, padding: "8px 10px", borderRadius: "6px", border: "1px solid #333", backgroundColor: "#0f0f0f", color: "#fff", fontSize: "13px" }}
              />
              <button onClick={handleAddRule} disabled={!config.filtering_enabled} style={{ padding: "0 14px", backgroundColor: config.filtering_enabled ? "#d97706" : "#444", color: "white", border: "none", borderRadius: "6px" }}>+</button>
            </div>
            
            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", maxHeight: "150px", overflowY: "auto" }}>
              {config.regex_rules.map((rule, idx) => (
                <div key={idx} style={{ display: "flex", alignItems: "center", backgroundColor: config.filtering_enabled ? "#261706" : "#222", padding: "4px 10px", borderRadius: "20px", fontSize: "12px", border: config.filtering_enabled ? "1px solid #452605" : "1px solid #333" }}>
                  <span style={{ marginRight: "8px", color: config.filtering_enabled ? "#fcd34d" : "#888" }}>{rule}</span>
                  <button onClick={() => handleRemoveRule(idx)} disabled={!config.filtering_enabled} style={{ background: "none", border: "none", color: config.filtering_enabled ? "#ef4444" : "#666", fontSize: "14px" }}>&times;</button>
                </div>
              ))}
            </div>
          </div>

          <div style={{ backgroundColor: "#1a1a1a", padding: "15px", borderRadius: "10px", border: "1px solid #2d2d2d", opacity: isEngineActive ? 1 : 0.5 }}>
            <h3 style={{ margin: "0 0 10px 0", color: isEngineActive ? "#10b981" : "#666", fontSize: "14px" }}>
              {t("whitelist")}
            </h3>
            <div style={{ display: "flex", gap: "10px", marginBottom: "15px" }}>
              <input 
                type="text" placeholder={t("placeholderWhitelist")} value={newWhitelist} onChange={(e) => setNewWhitelist(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleAddWhitelist()}
                disabled={!isEngineActive}
                style={{ flex: 1, padding: "8px 10px", borderRadius: "6px", border: "1px solid #333", backgroundColor: "#0f0f0f", color: "#fff", fontSize: "13px" }}
              />
              <button onClick={handleAddWhitelist} disabled={!isEngineActive} style={{ padding: "0 14px", backgroundColor: isEngineActive ? "#059669" : "#444", color: "white", border: "none", borderRadius: "6px" }}>+</button>
            </div>
            
            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", maxHeight: "150px", overflowY: "auto" }}>
              {config.whitelist.map((domain, idx) => (
                <div key={idx} style={{ display: "flex", alignItems: "center", backgroundColor: isEngineActive ? "#062618" : "#222", padding: "4px 10px", borderRadius: "20px", fontSize: "12px", border: isEngineActive ? "1px solid #05452a" : "1px solid #333" }}>
                  <span style={{ marginRight: "8px", color: isEngineActive ? "#6ee7b7" : "#888" }}>{domain}</span>
                  <button onClick={() => handleRemoveWhitelist(idx)} disabled={!isEngineActive} style={{ background: "none", border: "none", color: isEngineActive ? "#fff" : "#666", fontSize: "14px" }}>&times;</button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* TOMBOL PERBARUI */}
        <div style={{ marginTop: "20px" }}>
          <button onClick={handleUpdateList} disabled={isUpdating} style={{ width: "100%", padding: "12px", backgroundColor: isUpdating ? "#1e293b" : "#2d2d2d", color: isUpdating ? "#64748b" : "#e0e0e0", border: "1px solid #444", borderRadius: "8px", fontWeight: "bold", fontSize: "13px", cursor: isUpdating ? "not-allowed" : "pointer" }}>
            {isUpdating ? t("btnUpdating") : t("btnUpdate")}
          </button>
        </div>

      </div>
    </div>
  );
}