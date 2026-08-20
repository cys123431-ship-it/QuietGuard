use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const BASELINE_SCHEMA: u32 = 2;

pub fn save_baseline() -> Vec<String> {
    let mut out = Vec::with_capacity(10);
    out.push("QuietGuard 기준 상태 저장".into());
    let normalized = normalize(&collect_scan_lines());
    let path = baseline_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            out.push(format!("[오류] 데이터 폴더 생성 실패: {}", e));
            return out;
        }
    }

    if path.exists() {
        let backup = baseline_backup_path();
        let _ = fs::copy(&path, &backup);
    }

    let mut body = String::new();
    body.push_str(&format!("# quietguard_baseline_schema={}\n", BASELINE_SCHEMA));
    body.push_str(&format!("# app_version={}\n", env!("CARGO_PKG_VERSION")));
    body.push_str(&format!("# created_unix={}\n", unix_now()));
    body.push_str("# comparison_only=1\n");
    for line in &normalized {
        body.push_str(line);
        body.push('\n');
    }

    match fs::write(&path, body) {
        Ok(()) => {
            out.push(format!("[완료] 기준 항목 {}개 저장", normalized.len()));
            out.push(format!("위치: {}", path.display()));
            if baseline_backup_path().exists() {
                out.push(format!("이전 기준 백업: {}", baseline_backup_path().display()));
            }
            out.push("이 파일은 변화 비교용 스냅샷일 뿐 정상/악성 승인이나 탐지 예외로 사용되지 않습니다.".into());
        }
        Err(e) => out.push(format!("[오류] 기준 상태 저장 실패: {}", e)),
    }
    out
}

pub fn compare_baseline() -> Vec<String> {
    let mut out = Vec::with_capacity(64);
    out.push("QuietGuard 기준 상태 비교".into());
    let path = baseline_path();
    let baseline_text = match fs::read_to_string(&path) {
        Ok(v) => v,
        Err(_) => {
            out.push("[정보] 저장된 기준 상태가 없습니다. 먼저 '기준 저장'을 실행하세요.".into());
            return out;
        }
    };

    let schema = baseline_text.lines()
        .find_map(|line| line.strip_prefix("# quietguard_baseline_schema="))
        .and_then(|v| v.trim().parse::<u32>().ok());
    if let Some(schema) = schema {
        if schema > BASELINE_SCHEMA {
            out.push(format!("[정보] 현재 프로그램보다 새로운 기준 파일 형식(schema {})입니다. 비교를 중단합니다.", schema));
            return out;
        }
    }

    let baseline: BTreeSet<String> = baseline_text.lines().map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(ToOwned::to_owned).collect();
    let current = normalize(&collect_scan_lines());
    let added: Vec<&String> = current.difference(&baseline).collect();
    let removed: Vec<&String> = baseline.difference(&current).collect();
    if added.is_empty() && removed.is_empty() {
        out.push("[정상] 저장된 기준 상태와 의미 있는 차이가 없습니다.".into());
        return out;
    }
    out.push(format!("[변경] 새 항목 {}개 / 사라진 항목 {}개", added.len(), removed.len()));
    for line in added.iter().take(30) { out.push(format!("[추가] {}", line)); }
    if added.len() > 30 { out.push(format!("[정보] 추가 항목 {}개 더 있음", added.len() - 30)); }
    for line in removed.iter().take(20) { out.push(format!("[삭제/변경] {}", line)); }
    if removed.len() > 20 { out.push(format!("[정보] 삭제/변경 항목 {}개 더 있음", removed.len() - 20)); }
    out
}

pub fn recent_events(max_lines: usize) -> Vec<String> {
    let path = data_dir().join("events.log");
    let text = match fs::read_to_string(&path) {
        Ok(v) => v,
        Err(_) => return vec!["[정보] 아직 실시간 감시 로그가 없습니다.".into()],
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    let mut out = Vec::with_capacity(lines.len().saturating_sub(start) + 1);
    out.push(format!("최근 실시간 감시 로그 (최대 {}줄)", max_lines));
    for line in &lines[start..] { out.push((*line).to_string()); }
    out
}

fn collect_scan_lines() -> Vec<String> {
    let mut all = Vec::new();
    all.extend(crate::scanner::run_quick_scan());
    all.extend(crate::scanner_extra::run_extra_scan());
    all.extend(crate::scanner_extra2::run_extra_scan2());
    all.extend(crate::scanner_extra3::run_extra_scan3());
    all.extend(crate::scanner_extra4::run_extra_scan4());
    all.extend(crate::scanner_extra5::run_extra_scan5());
    all.extend(crate::scanner_extra6::run_extra_scan6());
    all.extend(crate::scanner_extra7::run_extra_scan7());
    all.extend(crate::scanner_extra8::run_extra_scan8());
    all
}

fn normalize(lines: &[String]) -> BTreeSet<String> {
    lines.iter().map(|s| s.trim()).filter(|s| !s.is_empty())
        .filter(|s| !s.starts_with("QuietGuard "))
        .filter(|s| !s.starts_with("점검 완료"))
        .filter(|s| !s.starts_with("---"))
        .filter(|s| !s.starts_with("[DB] "))
        .filter(|s| !s.starts_with("[최신] "))
        .filter(|s| !s.starts_with("[정보] 공개 DB 마지막 갱신:"))
        .filter(|s| !s.contains("도메인 DB가 아직 없습니다"))
        .map(ToOwned::to_owned).collect()
}

fn data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") { return PathBuf::from(local).join("QuietGuard"); }
    PathBuf::from("QuietGuardData")
}

fn baseline_path() -> PathBuf { data_dir().join("baseline.txt") }
fn baseline_backup_path() -> PathBuf { data_dir().join("baseline.prev.txt") }
fn unix_now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
