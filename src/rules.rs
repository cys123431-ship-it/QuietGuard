use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Rules {
    pub suspicious_paths: Vec<String>,
    pub suspicious_commands: Vec<String>,
    pub script_extensions: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            suspicious_paths: vec![
                "\\appdata\\local\\temp\\".into(),
                "\\windows\\temp\\".into(),
                "\\temp\\".into(),
                "\\downloads\\".into(),
                "\\recycle.bin\\".into(),
            ],
            suspicious_commands: vec![
                "powershell.exe".into(),
                "pwsh.exe".into(),
                "wscript.exe".into(),
                "cscript.exe".into(),
                "mshta.exe".into(),
                "regsvr32.exe".into(),
                "rundll32.exe".into(),
            ],
            script_extensions: vec![
                ".bat".into(), ".cmd".into(), ".vbs".into(), ".vbe".into(),
                ".js".into(), ".jse".into(), ".wsf".into(), ".ps1".into(), ".hta".into(),
            ],
        }
    }
}

impl Rules {
    pub fn load() -> Self {
        let mut rules = Self::default();
        for path in candidate_paths() {
            if path.exists() {
                if let Ok(text) = fs::read_to_string(&path) {
                    rules.apply_text(&text);
                    break;
                }
            }
        }
        rules
    }

    fn apply_text(&mut self, text: &str) {
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let Some((key, value)) = line.split_once('=') else { continue; };
            let key = key.trim();
            let mut value = value.trim().to_ascii_lowercase();
            if value.is_empty() { continue; }

            // Older QuietGuard rule files wrote doubled backslashes literally.
            // Accept both old and normal Windows path separators so a rule such as
            // \\users\\public\\ still matches C:\Users\Public\... as intended.
            if key == "suspicious_path" {
                value = collapse_legacy_backslashes(&value);
            }

            match key {
                "suspicious_path" => push_unique(&mut self.suspicious_paths, value),
                "suspicious_command" => push_unique(&mut self.suspicious_commands, value),
                "script_extension" => push_unique(&mut self.script_extensions, value),
                _ => {}
            }
        }
    }

    pub fn path_is_suspicious(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.suspicious_paths.iter().any(|p| lower.contains(p))
    }

    pub fn command_is_suspicious(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.suspicious_commands.iter().any(|p| lower.contains(p))
            || self.script_extensions.iter().any(|ext| lower.contains(ext))
    }

    pub fn autorun_is_suspicious(&self, text: &str) -> bool {
        self.path_is_suspicious(text) || self.command_is_suspicious(text)
    }
}

fn collapse_legacy_backslashes(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'\\') {
            out.push('\\');
            let _ = chars.next();
        } else {
            out.push(ch);
        }
    }
    out
}

fn push_unique(items: &mut Vec<String>, value: String) {
    if !items.iter().any(|x| x.eq_ignore_ascii_case(&value)) {
        items.push(value);
    }
}

fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        paths.push(PathBuf::from(local).join("QuietGuard").join("rules").join("heuristics.conf"));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            paths.push(parent.join("rules").join("heuristics.conf"));
        }
    }

    paths.push(Path::new("rules").join("heuristics.conf"));
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_doubled_path_rule_matches_normal_windows_path() {
        let mut rules = Rules::default();
        rules.apply_text("suspicious_path=\\\\users\\\\public\\\\\n");
        assert!(rules.path_is_suspicious(r"C:\Users\Public\payload.exe"));
    }

    #[test]
    fn normal_path_rule_is_kept_compatible() {
        let mut rules = Rules::default();
        rules.apply_text("suspicious_path=\\users\\public\\\n");
        assert!(rules.path_is_suspicious(r"C:\Users\Public\payload.exe"));
    }
}
