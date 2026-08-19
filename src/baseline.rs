use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;

pub fn save_baseline() -> Vec<String> {
    let mut out = Vec::with_capacity(8);
    out.push("QuietGuard 기준 상태 저장".into());
    let current = collect_scan_lines();
    let normalized = normalize(&current);
    let path = baseline_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            out.push(format!("[오류] 데이터 폴더 생성 실패: {}", e));
            return out;
        }
    }
    let body = normalized.iter().cloned().collect::<Vec<_>>().join("\n") + "\n";
    match fs::write(&path, body) {
        Ok(()) => {
            out.push(format!("[완료] 기준 항목 {}개 저장", normalized.len()));
            out.push(format!("위치: {}", path.display()));
            out.push("이 기준은 사용자가 현재 PC 상태를 정상으로 확인한 뒤 저장하는 용도입니다.".into());
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

    let baseline: BTreeSet<String> = baseline_text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let current = normalize(&collect_scan_lines());

    let added: Vec<&String> = current.difference(&baseline).collect();
    let removed: Vec<&String> = baseline.difference(&current).collect();

    if added.is_empty() && removed.is_empty() {
        out.push("[정상] 저장된 기준 상태와 의미 있는 차이가 없습니다.".into());
        return out;
    }

    out.push(format!("[변경] 새 항목 {}개 / 사라진 항목 {}개", added.len(), removed.len()));
    for line in added.iter().take(30) {
        out.push(format!("[추가] {}", line));
    }
    if added.len() > 30 {
        out.push(format!("[정보] 추가 항목 {}개 더 있음", added.len() - 30));
    }
    for line in removed.iter().take(20) {
        out.push(format!("[삭제/변경] {}", line));
    }
    if removed.len() > 20 {
        out.push(format!("[정보] 삭제/변경 항목 {}개 더 있음", removed.len() - 20));
    }
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
    for line in &lines[start..] {
        out.push((*line).to_string());
    }
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
    all
}

fn normalize(lines: &[String]) -> BTreeSet<String> {
    lines.iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter(|s| !s.starts_with("QuietGuard 0."))
        .filter(|s| !s.starts_with("점검 완료"))
        .filter(|s| !s.starts_with("---"))
        .map(ToOwned::to_owned)
        .collect()
}

fn data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("QuietGuard");
    }
    PathBuf::from("QuietGuardData")
}

fn baseline_path() -> PathBuf {
    data_dir().join("baseline.txt")
}
