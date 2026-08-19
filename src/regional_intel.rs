use std::cmp::Ordering;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RECORD_LEN: u64 = 17;
const UPDATE_INTERVAL_SECS: u64 = 24 * 60 * 60;
const YOULIST_URL: &str = "https://raw.githubusercontent.com/yous/YousList/master/hosts.txt";

pub fn update(force: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(6);
    out.push("QuietGuard 한국 광고 참고 DB 업데이트".into());
    let dir = regional_dir();
    let final_path = dir.join("youslist.f64");
    if !force && final_path.is_file() && !update_due() {
        let count = fs::metadata(&final_path).map(|m| m.len() / RECORD_LEN).unwrap_or(0);
        out.push(format!("[최신] YousList {}개 도메인", count));
        return out;
    }
    if let Err(e) = fs::create_dir_all(&dir) {
        out.push(format!("[오류] 지역 DB 폴더 생성 실패: {}", e));
        return out;
    }
    let raw = dir.join("youslist.download");
    let tmp = dir.join("youslist.f64.download");
    if let Err(e) = download(YOULIST_URL, &raw) {
        out.push(format!("[경고] YousList 다운로드 실패: {} (기존 DB 유지)", e));
        return out;
    }
    match build_index(&raw, &tmp) {
        Ok(count) => {
            if let Err(e) = replace_file(&tmp, &final_path) {
                out.push(format!("[경고] YousList 적용 실패: {}", e));
            } else {
                let _ = fs::write(dir.join("last-update.txt"), format!("{}\n", unix_now()));
                out.push(format!("[완료] YousList {}개 도메인 (한국 광고 참고/저신뢰)", count));
            }
        }
        Err(e) => out.push(format!("[경고] YousList 파싱 실패: {}", e)),
    }
    let _ = fs::remove_file(raw);
    out
}

pub fn lookup_domain(input: &str) -> Option<String> {
    let host = extract_host(input)?;
    let labels: Vec<&str> = host.split('.').collect();
    for start in 0..labels.len().saturating_sub(1) {
        let candidate = labels[start..].join(".");
        if binary_search_hash(&regional_dir().join("youslist.f64"), fnv1a64(candidate.as_bytes())).unwrap_or(false) {
            return Some(candidate);
        }
    }
    None
}

pub fn status_line() -> String {
    let path = regional_dir().join("youslist.f64");
    match fs::metadata(path) {
        Ok(meta) => format!("[DB] YousList: {}개 / 한국 광고 참고 (저신뢰)", meta.len() / RECORD_LEN),
        Err(_) => "[DB] YousList: 아직 없음 (자동 업데이트 예정)".into(),
    }
}

fn update_due() -> bool {
    let Some(ts) = fs::read_to_string(regional_dir().join("last-update.txt")).ok()
        .and_then(|s| s.trim().parse::<u64>().ok()) else { return true; };
    unix_now().saturating_sub(ts) >= UPDATE_INTERVAL_SECS
}

fn build_index(raw: &Path, destination: &Path) -> Result<usize, String> {
    let reader = BufReader::new(File::open(raw).map_err(|e| e.to_string())?);
    let mut hashes = Vec::with_capacity(2_000);
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let clean = line.split('#').next().unwrap_or("").trim();
        if clean.is_empty() { continue; }
        let tokens: Vec<&str> = clean.split_whitespace().collect();
        let start = if tokens.first().map(|v| looks_like_ip(v)).unwrap_or(false) { 1 } else { 0 };
        for token in &tokens[start..] {
            if let Some(domain) = normalize_domain(token) { hashes.push(fnv1a64(domain.as_bytes())); }
        }
    }
    hashes.sort_unstable();
    hashes.dedup();
    let mut file = File::create(destination).map_err(|e| e.to_string())?;
    for hash in &hashes { writeln!(file, "{:016x}", hash).map_err(|e| e.to_string())?; }
    file.flush().map_err(|e| e.to_string())?;
    Ok(hashes.len())
}

fn normalize_domain(input: &str) -> Option<String> {
    let value = input.trim().trim_matches('.').to_ascii_lowercase();
    if value.len() < 4 || value.len() > 253 || !value.contains('.') { return None; }
    if looks_like_ip(&value) { return None; }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') { return None; }
    Some(value)
}

fn extract_host(input: &str) -> Option<String> {
    let mut value = input.trim().trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';'));
    if let Some(pos) = value.find("://") { value = &value[pos + 3..]; }
    if let Some(pos) = value.rfind('@') { value = &value[pos + 1..]; }
    value = value.split(&['/', '?', '#'][..]).next().unwrap_or(value);
    if let Some((host, port)) = value.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !host.contains(':') { value = host; }
    }
    normalize_domain(value)
}

fn looks_like_ip(value: &str) -> bool {
    let v = value.trim();
    v == "0.0.0.0" || v == "127.0.0.1" || v == "::" || v == "::1" || v.parse::<std::net::IpAddr>().is_ok()
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

fn download(url: &str, destination: &Path) -> Result<(), String> {
    let dest = destination.to_string_lossy().to_string();
    let output = hidden_output("curl.exe", &[
        "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--tlsv1.2",
        "--connect-timeout", "10", "--max-time", "60", "--output", &dest, url,
    ]).map_err(|e| e.to_string())?;
    if output.status.success() && destination.is_file() { Ok(()) } else { Err("HTTPS 다운로드 실패".into()) }
}

fn hidden_output(program: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output()
}

fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    if destination.exists() { let _ = fs::copy(destination, destination.with_extension("f64.bak")); fs::remove_file(destination)?; }
    fs::rename(source, destination).or_else(|_| { fs::copy(source, destination)?; fs::remove_file(source) })
}

fn regional_dir() -> PathBuf { data_dir().join("intel").join("regional") }
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
