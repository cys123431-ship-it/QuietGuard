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

#[derive(Clone, Copy)]
struct FeedSource {
    id: &'static str,
    label: &'static str,
    category: &'static str,
    license: &'static str,
    url: &'static str,
}

const FEEDS: &[FeedSource] = &[
    FeedSource { id: "unchecky_ads", label: "UncheckyAds", category: "Windows installer ads/PUP", license: "MIT", url: "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts" },
    FeedSource { id: "fademind_risk", label: "FadeMind add.Risk", category: "risk domains", license: "MIT", url: "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts" },
    FeedSource { id: "kadhosts", label: "KADhosts", category: "fraud/adware/scam", license: "CC BY-SA 4.0", url: "https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt" },
    FeedSource { id: "stevenblack", label: "StevenBlack Unified Hosts", category: "adware/malware aggregate", license: "aggregated upstream licenses; runtime cache only", url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" },
];

#[derive(Clone, Debug)]
pub struct IntelHit {
    pub source: &'static str,
    pub category: &'static str,
    pub matched_domain: String,
}

pub fn update_public_feeds(force: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(28);
    out.push("QuietGuard 공개 PUP/도메인 DB 업데이트".into());

    let dir = intel_dir();
    let raw_dir = dir.join("raw");
    if let Err(e) = fs::create_dir_all(&raw_dir) {
        out.push(format!("[오류] 공개 DB 폴더 생성 실패: {}", e));
        return out;
    }

    let mut all_ok = true;
    let mut refreshed = 0usize;
    let mut total_entries = 0usize;

    for source in FEEDS {
        let raw = raw_dir.join(format!("{}.download", source.id));
        let index_tmp = dir.join(format!("{}.f64.download", source.id));
        let index_final = dir.join(format!("{}.f64", source.id));

        if !force && index_final.is_file() && !source_update_due(source.id) {
            let count = fs::metadata(&index_final).map(|m| m.len() / RECORD_LEN).unwrap_or(0);
            out.push(format!("[최신] {}: {}개 / 24시간 이내 갱신", source.label, count));
            total_entries += count as usize;
            continue;
        }

        if let Err(e) = download(source.url, &raw) {
            all_ok = false;
            out.push(format!("[경고] {} 다운로드 실패: {} (기존 DB 유지)", source.label, e));
            let _ = fs::remove_file(&raw);
            continue;
        }

        match build_index(&raw, &index_tmp) {
            Ok(count) => {
                if let Err(e) = replace_file(&index_tmp, &index_final) {
                    all_ok = false;
                    out.push(format!("[경고] {} 인덱스 적용 실패: {}", source.label, e));
                } else {
                    refreshed += 1;
                    total_entries += count;
                    let _ = write_source_meta(source, count);
                    let _ = write_source_update_time(source.id);
                    out.push(format!("[완료] {}: {}개 도메인 인덱스", source.label, count));
                }
            }
            Err(e) => {
                all_ok = false;
                out.push(format!("[경고] {} 파싱 실패: {} (기존 DB 유지)", source.label, e));
                let _ = fs::remove_file(&index_tmp);
            }
        }
        let _ = fs::remove_file(&raw);
    }

    if all_ok {
        let _ = fs::write(dir.join("last-update.txt"), format!("{}\n", unix_now()));
        if refreshed > 0 {
            out.push(format!("[완료] 공개 DB 갱신 완료 (갱신 소스 {}개 / 현재 소스 합계 {}개 항목)", refreshed, total_entries));
        } else {
            out.push("[최신] 공개 DB 모든 소스가 각 24시간 주기 이내입니다.".into());
        }
    } else {
        out.push("[정보] 실패한 소스만 다음 예약 주기에 다시 시도합니다. 성공한 소스의 개별 갱신 시각은 유지됩니다.".into());
    }
    out
}

pub fn indexes_ready() -> bool {
    FEEDS.iter().any(|s| intel_dir().join(format!("{}.f64", s.id)).is_file())
}

pub fn status_lines() -> Vec<String> {
    let dir = intel_dir();
    let mut out = Vec::with_capacity(FEEDS.len() + 2);
    if !indexes_ready() {
        out.push("[정보] 공개 도메인 DB가 아직 없습니다. DB 업데이트 또는 예약 업데이트로 생성할 수 있습니다.".into());
        return out;
    }

    for source in FEEDS {
        let path = dir.join(format!("{}.f64", source.id));
        if let Ok(meta) = fs::metadata(&path) {
            let count = meta.len() / RECORD_LEN;
            let age = source_age_secs(source.id).map(|s| format!(" / 약 {}시간 전 갱신", s / 3600)).unwrap_or_default();
            out.push(format!("[DB] {}: {}개 / {}{}", source.label, count, source.category, age));
        }
    }
    out
}

pub fn lookup_domain(input: &str) -> Vec<IntelHit> {
    let Some(host) = extract_host(input) else { return Vec::new(); };
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 { return Vec::new(); }

    let mut hits = Vec::new();
    for start in 0..labels.len().saturating_sub(1) {
        let candidate = labels[start..].join(".");
        if candidate.split('.').count() < 2 { continue; }
        let hash = fnv1a64(candidate.as_bytes());
        for source in FEEDS {
            let path = intel_dir().join(format!("{}.f64", source.id));
            if binary_search_hash(&path, hash).unwrap_or(false)
                && !hits.iter().any(|h: &IntelHit| h.source == source.label && h.matched_domain == candidate)
            {
                hits.push(IntelHit { source: source.label, category: source.category, matched_domain: candidate.clone() });
            }
        }
    }
    hits
}

fn source_update_due(id: &str) -> bool {
    source_age_secs(id).map(|age| age >= UPDATE_INTERVAL_SECS).unwrap_or(true)
}

fn source_age_secs(id: &str) -> Option<u64> {
    let dir = intel_dir();
    let per_source = dir.join(format!("{}-last-update.txt", id));
    let ts = fs::read_to_string(&per_source).ok().and_then(|s| s.trim().parse::<u64>().ok())
        .or_else(|| fs::read_to_string(dir.join("last-update.txt")).ok().and_then(|s| s.trim().parse::<u64>().ok()))?;
    Some(unix_now().saturating_sub(ts))
}

fn write_source_update_time(id: &str) -> std::io::Result<()> {
    fs::write(intel_dir().join(format!("{}-last-update.txt", id)), format!("{}\n", unix_now()))
}

fn build_index(raw: &Path, destination: &Path) -> Result<usize, String> {
    let file = File::open(raw).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    let mut hashes: Vec<u64> = Vec::with_capacity(64_000);
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        for domain in domains_from_line(&line) { hashes.push(fnv1a64(domain.as_bytes())); }
    }
    hashes.sort_unstable();
    hashes.dedup();
    let mut file = File::create(destination).map_err(|e| e.to_string())?;
    for hash in &hashes { writeln!(file, "{:016x}", hash).map_err(|e| e.to_string())?; }
    file.flush().map_err(|e| e.to_string())?;
    Ok(hashes.len())
}

fn domains_from_line(raw: &str) -> Vec<String> {
    let line = raw.split('#').next().unwrap_or("").trim();
    if line.is_empty() { return Vec::new(); }
    if let Some(rest) = line.strip_prefix("||") {
        let end = rest.find(|c: char| matches!(c, '^' | '/' | '$' | '|' | ':' )).unwrap_or(rest.len());
        return normalize_domain(&rest[..end]).into_iter().collect();
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() { return Vec::new(); }
    let start = if looks_like_ip(tokens[0]) { 1 } else { 0 };
    let mut out = Vec::new();
    for token in &tokens[start..] {
        for part in token.split(|c| matches!(c, ',' | ';' | '|')) {
            if let Some(domain) = normalize_domain(part) { out.push(domain); }
        }
    }
    out
}

fn normalize_domain(input: &str) -> Option<String> {
    let mut value = input.trim().trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>'));
    if value.is_empty() { return None; }
    if let Some(pos) = value.find("://") { value = &value[pos + 3..]; }
    if let Some(pos) = value.rfind('@') { value = &value[pos + 1..]; }
    value = value.split(&['/', '?', '#'][..]).next().unwrap_or(value);
    if let Some((host, port)) = value.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !host.contains(':') { value = host; }
    }
    let value = value.trim_matches('.').to_ascii_lowercase();
    if value.len() < 4 || value.len() > 253 || !value.contains('.') { return None; }
    if value == "localhost" || looks_like_ip(&value) { return None; }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') { return None; }
    if value.split('.').any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-')) { return None; }
    Some(value)
}

fn extract_host(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';'));
    normalize_domain(trimmed).or_else(|| {
        for token in trimmed.split_whitespace() {
            if let Some(host) = normalize_domain(token) { return Some(host); }
            for part in token.split(|c| matches!(c, ';' | ',' | '=')) {
                if let Some(host) = normalize_domain(part) { return Some(host); }
            }
        }
        None
    })
}

fn looks_like_ip(value: &str) -> bool {
    let v = value.trim_matches(|c: char| c == '[' || c == ']');
    v == "0.0.0.0" || v == "127.0.0.1" || v == "::" || v == "::1" || v.parse::<std::net::IpAddr>().is_ok()
}

fn binary_search_hash(path: &Path, target: u64) -> std::io::Result<bool> {
    let mut file = File::open(path)?;
    let count = file.metadata()?.len() / RECORD_LEN;
    if count == 0 { return Ok(false); }
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

fn write_source_meta(source: &FeedSource, entries: usize) -> std::io::Result<()> {
    let text = format!("source={}\ncategory={}\nlicense={}\nurl={}\nentries={}\nupdated_unix={}\n",
        source.label, source.category, source.license, source.url, entries, unix_now());
    fs::write(intel_dir().join(format!("{}.meta", source.id)), text)
}

fn download(url: &str, destination: &Path) -> Result<(), String> {
    let dest = destination.to_string_lossy().to_string();
    if let Ok(output) = hidden_output("curl.exe", &[
        "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--tlsv1.2",
        "--connect-timeout", "10", "--max-time", "90", "--output", &dest, url,
    ]) {
        if output.status.success() && destination.is_file() { return Ok(()); }
    }
    let safe_url = url.replace('\'', "''");
    let safe_dest = dest.replace('\'', "''");
    let script = format!("$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -TimeoutSec 90 -Uri '{}' -OutFile '{}'", safe_url, safe_dest);
    let output = hidden_output("powershell.exe", &["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .map_err(|e| format!("curl/PowerShell 실행 실패: {}", e))?;
    if output.status.success() && destination.is_file() { Ok(()) } else { Err("HTTPS 다운로드 실패".into()) }
}

fn hidden_output(program: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output()
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

fn intel_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") { return PathBuf::from(local).join("QuietGuard").join("intel"); }
    PathBuf::from("QuietGuardData").join("intel")
}

fn unix_now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for &b in bytes { hash ^= b as u64; hash = hash.wrapping_mul(0x100000001b3); }
    hash
}
