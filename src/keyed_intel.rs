use std::cmp::Ordering;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RECORD_LEN: u64 = 17;
const UPDATE_INTERVAL_SECS: u64 = 6 * 60 * 60;

#[derive(Clone, Copy)]
struct KeyedSource {
    id: &'static str,
    label: &'static str,
    category: &'static str,
}

const SOURCES: &[KeyedSource] = &[
    KeyedSource { id: "threatfox", label: "ThreatFox", category: "recent malware IOC / payload delivery / C2" },
    KeyedSource { id: "urlhaus", label: "URLhaus", category: "recent malware distribution URLs" },
];

#[derive(Clone, Debug)]
pub struct KeyedIntelHit {
    pub source: &'static str,
    pub category: &'static str,
    pub matched_domain: String,
}

pub fn update_keyed_feeds(force: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(16);
    out.push("QuietGuard 선택형 abuse.ch DB 업데이트".into());

    let Some(key) = abusech_key() else {
        out.push("[정보] abuse.ch Auth-Key가 없어 ThreatFox/URLhaus는 건너뜁니다. 기본 공개 DB는 계속 정상 사용됩니다.".into());
        return out;
    };

    let dir = keyed_dir();
    let raw = dir.join("raw");
    if let Err(e) = fs::create_dir_all(&raw) {
        out.push(format!("[오류] 선택형 DB 폴더 생성 실패: {}", e));
        return out;
    }

    let mut any_success = false;

    if force || !dir.join("threatfox.f64").is_file() || source_due("threatfox") {
        match update_threatfox(&key, &raw) {
            Ok(count) => {
                any_success = true;
                let _ = mark_source_updated("threatfox");
                out.push(format!("[완료] ThreatFox 최근 IOC 도메인 {}개", count));
            }
            Err(e) => out.push(format!("[경고] ThreatFox 업데이트 실패: {} (기존 캐시 유지)", e)),
        }
    } else {
        out.push("[최신] ThreatFox 로컬 캐시는 6시간 이내에 갱신되었습니다.".into());
    }

    if force || !dir.join("urlhaus.f64").is_file() || source_due("urlhaus") {
        match update_urlhaus(&key, &raw) {
            Ok(count) => {
                any_success = true;
                let _ = mark_source_updated("urlhaus");
                out.push(format!("[완료] URLhaus 최근 URL 도메인 {}개", count));
            }
            Err(e) => out.push(format!("[경고] URLhaus 업데이트 실패: {} (기존 캐시 유지)", e)),
        }
    } else {
        out.push("[최신] URLhaus 로컬 캐시는 6시간 이내에 갱신되었습니다.".into());
    }

    if any_success { let _ = fs::write(dir.join("last-update.txt"), format!("{}\n", unix_now())); }
    let _ = fs::remove_dir_all(raw);
    out.extend(status_lines());
    out
}

pub fn keyed_ready() -> bool {
    SOURCES.iter().any(|s| keyed_dir().join(format!("{}.f64", s.id)).is_file())
}

pub fn status_lines() -> Vec<String> {
    let dir = keyed_dir();
    let mut out = Vec::new();
    if abusech_key().is_none() {
        out.push("[DB] ThreatFox/URLhaus: 비활성 (Auth-Key 없음, 선택 사항)".into());
        return out;
    }
    for source in SOURCES {
        let path = dir.join(format!("{}.f64", source.id));
        if let Ok(meta) = fs::metadata(path) {
            let age = source_age_secs(source.id).map(|s| format!(" / 약 {}시간 전 갱신", s / 3600)).unwrap_or_default();
            out.push(format!("[DB] {}: {}개 / {}{}", source.label, meta.len() / RECORD_LEN, source.category, age));
        }
    }
    out
}

pub fn lookup_domain(input: &str) -> Vec<KeyedIntelHit> {
    let Some(host) = extract_host(input) else { return Vec::new(); };
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 { return Vec::new(); }

    let mut hits = Vec::new();
    for start in 0..labels.len().saturating_sub(1) {
        let candidate = labels[start..].join(".");
        if candidate.split('.').count() < 2 { continue; }
        let hash = fnv1a64(candidate.as_bytes());
        for source in SOURCES {
            let path = keyed_dir().join(format!("{}.f64", source.id));
            if binary_search_hash(&path, hash).unwrap_or(false)
                && !hits.iter().any(|h: &KeyedIntelHit| h.source == source.label && h.matched_domain == candidate)
            {
                hits.push(KeyedIntelHit { source: source.label, category: source.category, matched_domain: candidate.clone() });
            }
        }
    }
    hits
}

pub fn abusech_config_status() -> String {
    if abusech_key().is_some() { "abuse.ch Auth-Key: 설정됨 (ThreatFox/URLhaus 활성)".into() }
    else { "abuse.ch Auth-Key: 없음 (선택형 ThreatFox/URLhaus 비활성)".into() }
}

fn update_threatfox(key: &str, raw_dir: &Path) -> Result<usize, String> {
    let destination = raw_dir.join("threatfox.json");
    let dest = ps_quote(&destination.to_string_lossy());
    let script = format!(
        "$ErrorActionPreference='Stop';$h=@{{'Auth-Key'=$env:QUIETGUARD_ABUSECH_AUTH_KEY}};$b='{{\"query\":\"get_iocs\",\"days\":7}}';Invoke-WebRequest -UseBasicParsing -TimeoutSec 45 -Method POST -ContentType 'application/json' -Headers $h -Body $b -Uri 'https://threatfox-api.abuse.ch/api/v1/' -OutFile '{}';",
        dest
    );
    run_powershell_with_key(&script, key)?;
    let text = fs::read_to_string(&destination).map_err(|e| e.to_string())?;
    if text.contains("\"query_status\":\"auth_key_invalid\"") || text.contains("\"query_status\": \"auth_key_invalid\"") {
        return Err("Auth-Key가 거부되었습니다.".into());
    }
    let mut domains = Vec::new();
    let mut offset = 0usize;
    while let Some(pos) = text[offset..].find("\"ioc\"") {
        let start = offset + pos + 5;
        let Some(colon) = text[start..].find(':') else { break; };
        let after = text[start + colon + 1..].trim_start();
        if let Some(after_quote) = after.strip_prefix('"') {
            if let Some(end) = json_string_end(after_quote) {
                let value = unescape_json_basic(&after_quote[..end]);
                if let Some(domain) = extract_host(&value) { domains.push(domain); }
            }
        }
        offset = start + colon + 1;
        if offset >= text.len() { break; }
    }
    install_domains("threatfox", &domains)
}

fn update_urlhaus(key: &str, raw_dir: &Path) -> Result<usize, String> {
    let destination = raw_dir.join("urlhaus.csv");
    let dest = ps_quote(&destination.to_string_lossy());
    let script = format!(
        "$ErrorActionPreference='Stop';$u='https://urlhaus-api.abuse.ch/v2/files/exports/'+$env:QUIETGUARD_ABUSECH_AUTH_KEY+'/recent.csv';Invoke-WebRequest -UseBasicParsing -TimeoutSec 45 -Uri $u -OutFile '{}';",
        dest
    );
    run_powershell_with_key(&script, key)?;
    let text = fs::read_to_string(&destination).map_err(|e| e.to_string())?;
    let mut domains = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') { continue; }
        for url in urls_in_text(line) {
            if let Some(domain) = extract_host(&url) { domains.push(domain); }
        }
    }
    install_domains("urlhaus", &domains)
}

fn run_powershell_with_key(script: &str, key: &str) -> Result<(), String> {
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]);
    cmd.env("QUIETGUARD_ABUSECH_AUTH_KEY", key);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let output = cmd.output().map_err(|e| format!("PowerShell 실행 실패: {}", e))?;
    if output.status.success() { Ok(()) }
    else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err(if err.trim().is_empty() { "HTTPS/API 요청 실패".into() } else { compact(err.trim(), 180) })
    }
}

fn install_domains(id: &str, domains: &[String]) -> Result<usize, String> {
    let dir = keyed_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut hashes: Vec<u64> = domains.iter().map(|d| fnv1a64(d.as_bytes())).collect();
    hashes.sort_unstable();
    hashes.dedup();
    if hashes.is_empty() { return Err("파싱된 도메인이 없습니다.".into()); }

    let temp = dir.join(format!("{}.f64.download", id));
    let final_path = dir.join(format!("{}.f64", id));
    let mut file = File::create(&temp).map_err(|e| e.to_string())?;
    for hash in &hashes { writeln!(file, "{:016x}", hash).map_err(|e| e.to_string())?; }
    file.flush().map_err(|e| e.to_string())?;
    replace_file(&temp, &final_path).map_err(|e| e.to_string())?;
    Ok(hashes.len())
}

fn abusech_key() -> Option<String> {
    if let Ok(value) = env::var("QUIETGUARD_ABUSECH_AUTH_KEY") {
        let value = value.trim();
        if valid_key(value) { return Some(value.to_string()); }
    }
    let text = fs::read_to_string(data_dir().join("secrets.conf")).ok()?;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim().eq_ignore_ascii_case("abusech_auth_key") {
                let value = value.trim();
                if valid_key(value) { return Some(value.to_string()); }
            }
        }
    }
    None
}

fn valid_key(value: &str) -> bool {
    value.len() >= 16 && value.len() <= 256 && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn source_due(id: &str) -> bool {
    source_age_secs(id).map(|age| age >= UPDATE_INTERVAL_SECS).unwrap_or(true)
}

fn source_age_secs(id: &str) -> Option<u64> {
    let dir = keyed_dir();
    let ts = fs::read_to_string(dir.join(format!("{}-last-update.txt", id))).ok().and_then(|s| s.trim().parse::<u64>().ok())
        .or_else(|| fs::read_to_string(dir.join("last-update.txt")).ok().and_then(|s| s.trim().parse::<u64>().ok()))?;
    Some(unix_now().saturating_sub(ts))
}

fn mark_source_updated(id: &str) -> std::io::Result<()> {
    fs::write(keyed_dir().join(format!("{}-last-update.txt", id)), format!("{}\n", unix_now()))
}

fn urls_in_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for scheme in ["http://", "https://"] {
        let mut offset = 0usize;
        while let Some(pos) = text[offset..].find(scheme) {
            let start = offset + pos;
            let rest = &text[start..];
            let end = rest.find(|c: char| matches!(c, ',' | '"' | '\'' | ' ' | '\t' | '\r' | '\n')).unwrap_or(rest.len());
            if end > scheme.len() { out.push(rest[..end].to_string()); }
            offset = start + scheme.len();
            if offset >= text.len() { break; }
        }
    }
    out
}

fn extract_host(input: &str) -> Option<String> {
    let mut value = input.trim().trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';'));
    if let Some(pos) = value.find("://") { value = &value[pos + 3..]; }
    if let Some(pos) = value.rfind('@') { value = &value[pos + 1..]; }
    value = value.split(&['/', '?', '#'][..]).next().unwrap_or(value);
    if let Some((host, port)) = value.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !host.contains(':') { value = host; }
    }
    let value = value.trim_matches('.').to_ascii_lowercase();
    if value.len() < 4 || value.len() > 253 || !value.contains('.') { return None; }
    if value.parse::<std::net::IpAddr>().is_ok() { return None; }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') { return None; }
    if value.split('.').any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-')) { return None; }
    Some(value)
}

fn binary_search_hash(path: &Path, target: u64) -> std::io::Result<bool> {
    let mut file = File::open(path)?;
    let count = file.metadata()?.len() / RECORD_LEN;
    let target_hex = format!("{:016x}", target);
    let target_bytes = target_hex.as_bytes();
    let mut low = 0u64;
    let mut high = count;
    let mut buf = [0u8; 16];
    while low < high {
        let mid = low + (high - low) / 2;
        file.seek(SeekFrom::Start(mid * RECORD_LEN))?;
        file.read_exact(&mut buf)?;
        match buf.as_slice().cmp(target_bytes) {
            Ordering::Less => low = mid + 1,
            Ordering::Greater => high = mid,
            Ordering::Equal => return Ok(true),
        }
    }
    Ok(false)
}

fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    let backup = destination.with_extension("f64.bak");
    if backup.exists() { let _ = fs::remove_file(&backup); }
    let had_destination = destination.exists();
    if had_destination { move_file(destination, &backup)?; }
    match move_file(source, destination) {
        Ok(()) => Ok(()),
        Err(error) => {
            if had_destination && backup.exists() && !destination.exists() { let _ = move_file(&backup, destination); }
            Err(error)
        }
    }
}

fn move_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(_) => { fs::copy(source, destination)?; fs::remove_file(source)?; Ok(()) }
    }
}

fn keyed_dir() -> PathBuf { data_dir().join("intel").join("keyed") }
fn data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") { return PathBuf::from(local).join("QuietGuard"); }
    PathBuf::from("QuietGuardData")
}
fn unix_now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for &b in bytes { hash ^= b as u64; hash = hash.wrapping_mul(0x100000001b3); }
    hash
}
fn ps_quote(text: &str) -> String { text.replace('\'', "''") }
fn json_string_end(text: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in text.char_indices() {
        if escaped { escaped = false; continue; }
        if c == '\\' { escaped = true; continue; }
        if c == '"' { return Some(i); }
    }
    None
}
fn unescape_json_basic(text: &str) -> String {
    text.replace("\\/", "/").replace("\\\\", "\\").replace("\\\"", "\"")
}
fn compact(text: &str, max: usize) -> String {
    let flat = text.replace(['\r', '\n'], " ");
    if flat.chars().count() <= max { flat } else { flat.chars().take(max).collect::<String>() + "..." }
}
