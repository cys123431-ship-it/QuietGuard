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
const THREATFOX_INTERVAL_SECS: u64 = 6 * 60 * 60;

pub fn update_all(force_public_intel: bool) -> Vec<String> {
    let mut out = crate::updater::update_rules();
    out.push(String::new());
    out.extend(crate::intel::update_public_feeds(force_public_intel));
    out.push(String::new());
    out.extend(crate::regional_intel::update(force_public_intel));
    out.push(String::new());

    let mut keyed = crate::keyed_intel::update_keyed_feeds(force_public_intel);
    match update_threatfox_compat(force_public_intel) {
        Ok(Some(count)) => {
            keyed.retain(|line| !line.starts_with("[경고] ThreatFox 업데이트 실패:"));
            keyed.push(format!("[완료] ThreatFox 최근 IOC 도메인 {}개", count));
            keyed.retain(|line| !line.starts_with("[DB] ThreatFox:"));
            keyed.push(format!("[DB] ThreatFox: {}개 / recent malware IOC / payload delivery / C2", count));
        }
        Ok(None) => {}
        Err(e) => {
            if !keyed.iter().any(|line| line.starts_with("[경고] ThreatFox 업데이트 실패:")) {
                keyed.push(format!("[경고] ThreatFox 업데이트 실패: {} (기존 캐시 유지)", e));
            }
        }
    }
    out.extend(keyed);

    out.push(String::new());
    out.extend(crate::clam_bridge::update_if_present(force_public_intel));
    out
}

pub fn spawn_background_update() -> String {
    let exe = match env::current_exe() {
        Ok(v) => v,
        Err(e) => return format!("[정보] 자동 DB 업데이트 시작 실패: {}", e),
    };
    let mut cmd = Command::new(exe);
    cmd.arg("--update-data-silent");
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.spawn() {
        Ok(_) => "[정보] QuietGuard/공개/지역/선택형 DB 업데이트 확인을 백그라운드에서 시작했습니다.".into(),
        Err(e) => format!("[정보] 자동 DB 업데이트 시작 실패: {}", e),
    }
}

pub fn update_silent() {
    let lines = update_all(false);
    let dir = data_dir();
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(dir.join("update.log"), lines.join("\n") + "\n");
}

fn update_threatfox_compat(force: bool) -> Result<Option<usize>, String> {
    let Some(key) = abusech_key() else { return Ok(None); };
    let final_path = keyed_dir().join("threatfox.f64");
    if !force && final_path.is_file() && !threatfox_due() { return Ok(None); }

    let raw_dir = keyed_dir().join("raw-compat");
    fs::create_dir_all(&raw_dir).map_err(|e| e.to_string())?;
    let destination = raw_dir.join("threatfox.json");
    let dest = ps_quote(&destination.to_string_lossy());

    // ThreatFox's documented Community API uses an Auth-Key header and a
    // POST body {"query":"get_iocs","days":7}. Invoke-RestMethod avoids
    // the Windows PowerShell Invoke-WebRequest/OutFile failure seen on some PCs.
    let script = format!(
        "$ErrorActionPreference='Stop';$h=@{{'Auth-Key'=$env:QUIETGUARD_ABUSECH_AUTH_KEY}};$b='{{\"query\":\"get_iocs\",\"days\":7}}';$r=Invoke-RestMethod -Method POST -Headers $h -ContentType 'application/json' -Body $b -Uri 'https://threatfox-api.abuse.ch/api/v1/';$r|ConvertTo-Json -Depth 20 -Compress|Set-Content -LiteralPath '{}' -Encoding UTF8;",
        dest
    );
    run_powershell_with_key(&script, &key)?;

    let text = fs::read_to_string(&destination).map_err(|e| e.to_string())?;
    if !text.contains("\"query_status\":\"ok\"") {
        let status = json_value(&text, "query_status").unwrap_or_else(|| "unknown response".into());
        let _ = fs::remove_dir_all(&raw_dir);
        return Err(format!("ThreatFox API 상태: {}", status));
    }

    let mut domains = Vec::new();
    let mut cursor = text.as_str();
    while let Some(pos) = cursor.find("\"ioc\"") {
        cursor = &cursor[pos + 5..];
        let Some(colon) = cursor.find(':') else { break; };
        let after = cursor[colon + 1..].trim_start();
        let Some(quoted) = after.strip_prefix('"') else { cursor = after; continue; };
        let Some(end) = json_string_end(quoted) else { break; };
        let value = unescape_json_basic(&quoted[..end]);
        if let Some(domain) = extract_host(&value) { domains.push(domain); }
        cursor = &quoted[end + 1..];
    }

    let count = install_threatfox_domains(&domains)?;
    let _ = fs::write(keyed_dir().join("threatfox-last-update.txt"), format!("{}\n", unix_now()));
    let _ = fs::remove_dir_all(&raw_dir);
    Ok(Some(count))
}

fn run_powershell_with_key(script: &str, key: &str) -> Result<(), String> {
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]);
    cmd.env("QUIETGUARD_ABUSECH_AUTH_KEY", key);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let output = cmd.output().map_err(|e| format!("PowerShell 실행 실패: {}", e))?;
    if output.status.success() { return Ok(()); }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let compact = stderr.replace(['\r', '\n'], " ");
    Err(if compact.trim().is_empty() { "HTTPS/API 요청 실패".into() } else { compact.chars().take(220).collect() })
}

fn install_threatfox_domains(domains: &[String]) -> Result<usize, String> {
    fs::create_dir_all(keyed_dir()).map_err(|e| e.to_string())?;
    let mut hashes: Vec<u64> = domains.iter().map(|d| fnv1a64(d.as_bytes())).collect();
    hashes.sort_unstable();
    hashes.dedup();
    if hashes.is_empty() { return Err("ThreatFox 응답에서 도메인 IOC를 찾지 못했습니다.".into()); }

    let temp = keyed_dir().join("threatfox.f64.download");
    let final_path = keyed_dir().join("threatfox.f64");
    let mut file = File::create(&temp).map_err(|e| e.to_string())?;
    for hash in &hashes { writeln!(file, "{:016x}", hash).map_err(|e| e.to_string())?; }
    file.flush().map_err(|e| e.to_string())?;

    if final_path.exists() {
        let _ = fs::copy(&final_path, keyed_dir().join("threatfox.f64.bak"));
        fs::remove_file(&final_path).map_err(|e| e.to_string())?;
    }
    fs::rename(&temp, &final_path).or_else(|_| {
        fs::copy(&temp, &final_path)?;
        fs::remove_file(&temp)
    }).map_err(|e| e.to_string())?;
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
        if let Some((name, value)) = line.split_once('=') {
            if name.trim().eq_ignore_ascii_case("abusech_auth_key") && valid_key(value.trim()) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn valid_key(value: &str) -> bool {
    value.len() >= 16 && value.len() <= 256 && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn threatfox_due() -> bool {
    let path = keyed_dir().join("threatfox-last-update.txt");
    let Some(ts) = fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u64>().ok()) else { return true; };
    unix_now().saturating_sub(ts) >= THREATFOX_INTERVAL_SECS
}

fn json_value(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let rest = &text[text.find(&needle)? + needle.len()..];
    let after = rest[rest.find(':')? + 1..].trim_start().strip_prefix('"')?;
    let end = json_string_end(after)?;
    Some(unescape_json_basic(&after[..end]))
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

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for &b in bytes { hash ^= b as u64; hash = hash.wrapping_mul(0x100000001b3); }
    hash
}

#[allow(dead_code)]
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

fn keyed_dir() -> PathBuf { data_dir().join("intel").join("keyed") }

fn data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("QuietGuard");
    }
    PathBuf::from("QuietGuardData")
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn ps_quote(text: &str) -> String { text.replace('\'', "''") }
