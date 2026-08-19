use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn update_all(force_public_intel: bool) -> Vec<String> {
    let mut out = crate::updater::update_rules();
    out.push(String::new());
    out.extend(crate::intel::update_public_feeds(force_public_intel));
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
        Ok(_) => "[정보] 규칙/PUP 공개 DB 자동 업데이트 확인을 백그라운드에서 시작했습니다.".into(),
        Err(e) => format!("[정보] 자동 DB 업데이트 시작 실패: {}", e),
    }
}

pub fn update_silent() {
    let lines = update_all(false);
    let dir = data_dir();
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(dir.join("update.log"), lines.join("\n") + "\n");
}

fn data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("QuietGuard");
    }
    PathBuf::from("QuietGuardData")
}
