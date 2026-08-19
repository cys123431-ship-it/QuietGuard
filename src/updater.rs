use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MANIFEST_URL: &str = "https://raw.githubusercontent.com/cys123431-ship-it/QuietGuard/main/rules/version.json";
const RULES_URL: &str = "https://raw.githubusercontent.com/cys123431-ship-it/QuietGuard/main/rules/heuristics.conf";

pub fn update_rules() -> Vec<String> {
    let mut out = Vec::with_capacity(12);
    out.push("QuietGuard 규칙 DB 업데이트 확인".to_string());

    let dir = local_rules_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        out.push(format!("[오류] 규칙 폴더 생성 실패: {}", e));
        return out;
    }

    let manifest_tmp = dir.join("version.download.json");
    let rules_tmp = dir.join("heuristics.download.conf");

    if let Err(e) = download(MANIFEST_URL, &manifest_tmp) {
        out.push(format!("[오류] 버전 정보 다운로드 실패: {}", e));
        cleanup(&manifest_tmp, &rules_tmp);
        return out;
    }

    let manifest = match fs::read_to_string(&manifest_tmp) {
        Ok(v) => v,
        Err(e) => {
            out.push(format!("[오류] 버전 정보 읽기 실패: {}", e));
            cleanup(&manifest_tmp, &rules_tmp);
            return out;
        }
    };

    let remote_version = json_string(&manifest, "rules_version").unwrap_or_else(|| "unknown".into());
    let expected_sha = match json_string(&manifest, "sha256") {
        Some(v) if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) => v.to_ascii_lowercase(),
        _ => {
            out.push("[오류] 원격 매니페스트에 올바른 SHA-256이 없습니다.".into());
            cleanup(&manifest_tmp, &rules_tmp);
            return out;
        }
    };

    let local_version_path = dir.join("version.json");
    let local_rules_path = dir.join("heuristics.conf");
    let local_version = fs::read_to_string(&local_version_path)
        .ok()
        .and_then(|s| json_string(&s, "rules_version"));

    if local_rules_path.exists() && local_version.as_deref() == Some(remote_version.as_str()) {
        out.push(format!("[최신] 규칙 DB {}", remote_version));
        let _ = fs::remove_file(&manifest_tmp);
        return out;
    }

    out.push(format!(
        "[정보] 규칙 DB {} -> {}",
        local_version.as_deref().unwrap_or("초기/동봉"),
        remote_version
    ));

    if let Err(e) = download(RULES_URL, &rules_tmp) {
        out.push(format!("[오류] 규칙 DB 다운로드 실패: {}", e));
        cleanup(&manifest_tmp, &rules_tmp);
        return out;
    }

    let actual_sha = match sha256_file(&rules_tmp) {
        Ok(v) => v,
        Err(e) => {
            out.push(format!("[오류] SHA-256 계산 실패: {}", e));
            cleanup(&manifest_tmp, &rules_tmp);
            return out;
        }
    };

    if actual_sha != expected_sha {
        out.push("[차단] 다운로드한 규칙 DB의 SHA-256이 매니페스트와 다릅니다.".into());
        out.push(format!("  예상: {}", expected_sha));
        out.push(format!("  실제: {}", actual_sha));
        cleanup(&manifest_tmp, &rules_tmp);
        return out;
    }

    if let Err(e) = install_verified(&rules_tmp, &local_rules_path) {
        out.push(format!("[오류] 규칙 DB 적용 실패: {}", e));
        cleanup(&manifest_tmp, &rules_tmp);
        return out;
    }
    if let Err(e) = install_verified(&manifest_tmp, &local_version_path) {
        out.push(format!("[오류] 버전 정보 적용 실패: {}", e));
        cleanup(&manifest_tmp, &rules_tmp);
        return out;
    }

    out.push(format!("[완료] 규칙 DB {} 적용", remote_version));
    out.push("[검증] SHA-256 일치 확인 완료".into());
    out.push("다음 시스템 점검부터 새 규칙이 적용됩니다.".into());
    cleanup(&manifest_tmp, &rules_tmp);
    out
}

pub fn local_rules_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("QuietGuard").join("rules");
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.join("rules");
        }
    }
    PathBuf::from("rules")
}

fn download(url: &str, destination: &Path) -> Result<(), String> {
    let dest = destination.to_string_lossy().to_string();
    let curl = hidden_output("curl.exe", &[
        "--fail", "--silent", "--show-error", "--location",
        "--connect-timeout", "10", "--max-time", "30",
        "--output", &dest, url,
    ]);
    if let Ok(output) = curl {
        if output.status.success() && destination.exists() {
            return Ok(());
        }
    }

    let safe_url = url.replace('\'', "''");
    let safe_dest = dest.replace('\'', "''");
    let script = format!(
        "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri '{}' -OutFile '{}'",
        safe_url, safe_dest
    );
    let output = hidden_output("powershell.exe", &[
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script,
    ]).map_err(|e| format!("curl/PowerShell 실행 실패: {}", e))?;

    if output.status.success() && destination.exists() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err(if err.trim().is_empty() { "HTTP 다운로드 실패".into() } else { err.trim().into() })
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let p = path.to_string_lossy().to_string();
    let output = hidden_output("certutil.exe", &["-hashfile", &p, "SHA256"])
        .map_err(|e| format!("certutil 실행 실패: {}", e))?;
    if !output.status.success() {
        return Err("certutil이 해시를 계산하지 못했습니다.".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let candidate: String = line.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if candidate.len() == 64 {
            return Ok(candidate.to_ascii_lowercase());
        }
    }
    Err("SHA-256 결과를 해석하지 못했습니다.".into())
}

fn hidden_output(program: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output()
}

fn install_verified(source: &Path, destination: &Path) -> std::io::Result<()> {
    let backup = destination.with_extension("bak");
    if destination.exists() {
        let _ = fs::copy(destination, &backup);
        fs::remove_file(destination)?;
    }
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(source, destination)?;
            fs::remove_file(source)?;
            Ok(())
        }
    }
}

fn json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)? + needle.len();
    let rest = text.get(start..)?;
    let colon = rest.find(':')?;
    let after = rest.get(colon + 1..)?.trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn cleanup(a: &Path, b: &Path) {
    let _ = fs::remove_file(a);
    let _ = fs::remove_file(b);
}
