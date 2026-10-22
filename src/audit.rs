use anyhow::{Context, Result};
use chrono::{Local, SecondsFormat};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const DEFAULT_QUERY_LIMIT: usize = 100;
pub const MAX_QUERY_LIMIT: usize = 1000;

/// One audit event, stored as a JSON line in the audit log file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub time: String,
    pub user: String,
    pub ip: String,
    pub op: String,
    pub path: String,
    pub status: u16,
}

impl AuditEvent {
    pub fn new(user: Option<&str>, ip: &str, op: &str, path: String, status: u16) -> Self {
        Self {
            time: Local::now().to_rfc3339_opts(SecondsFormat::Secs, false),
            user: user.unwrap_or("-").to_string(),
            ip: ip.to_string(),
            op: op.to_string(),
            path,
            status,
        }
    }
}

/// Filters for querying the audit log. user/ip/keyword match by substring,
/// op matches exactly, from/to compare lexicographically against the ISO8601
/// timestamp (valid because all timestamps share the same local offset).
#[derive(Debug, Default)]
pub struct AuditQuery {
    pub user: Option<String>,
    pub ip: Option<String>,
    pub op: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub keyword: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

impl AuditQuery {
    pub fn from_params(params: &HashMap<String, String>) -> Self {
        let get = |key: &str| params.get(key).filter(|v| !v.is_empty()).cloned();
        let offset = params
            .get("offset")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let limit = params
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_QUERY_LIMIT)
            .min(MAX_QUERY_LIMIT);
        Self {
            user: get("user"),
            ip: get("ip"),
            op: get("op"),
            from: get("from"),
            to: get("to"),
            keyword: get("keyword"),
            offset,
            limit,
        }
    }

    fn matches(&self, ev: &AuditEvent) -> bool {
        if let Some(user) = &self.user {
            if !ev.user.contains(user.as_str()) {
                return false;
            }
        }
        if let Some(ip) = &self.ip {
            if !ev.ip.contains(ip.as_str()) {
                return false;
            }
        }
        if let Some(op) = &self.op {
            if ev.op != *op {
                return false;
            }
        }
        if let Some(from) = &self.from {
            if ev.time.as_str() < from.as_str() {
                return false;
            }
        }
        if let Some(to) = &self.to {
            // datetime-local yields "YYYY-MM-DDTHH:MM"; include the whole minute
            let to = if to.len() == 16 {
                format!("{to}:59")
            } else {
                to.clone()
            };
            if ev.time.as_str() > to.as_str() {
                return false;
            }
        }
        if let Some(keyword) = &self.keyword {
            if !ev.path.contains(keyword.as_str()) {
                return false;
            }
        }
        true
    }
}

/// Append-only audit log. The file must live outside the served directory,
/// and the server exposes no mutation API, so records can only be read.
pub struct AuditLogger {
    file: Mutex<File>,
    path: PathBuf,
}

impl AuditLogger {
    pub fn new(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open audit log file {}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
        })
    }

    pub fn record(&self, event: &AuditEvent) {
        if let Ok(mut line) = serde_json::to_string(event) {
            line.push('\n');
            if let Ok(mut file) = self.file.lock() {
                let _ = file.write_all(line.as_bytes());
            }
        }
    }

    /// Returns (total_matched, events page), newest first.
    pub fn query(&self, q: &AuditQuery) -> (usize, Vec<AuditEvent>) {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(_) => return (0, Vec::new()),
        };
        let mut matched: Vec<AuditEvent> = BufReader::new(file)
            .lines()
            .filter_map(|line| line.ok())
            .filter_map(|line| serde_json::from_str::<AuditEvent>(&line).ok())
            .filter(|ev| q.matches(ev))
            .collect();
        matched.reverse();
        let total = matched.len();
        let events = matched.into_iter().skip(q.offset).take(q.limit).collect();
        (total, events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(time: &str, user: &str, ip: &str, op: &str, path: &str, status: u16) -> AuditEvent {
        AuditEvent {
            time: time.to_string(),
            user: user.to_string(),
            ip: ip.to_string(),
            op: op.to_string(),
            path: path.to_string(),
            status,
        }
    }

    #[test]
    fn query_filters() {
        let events = vec![
            ev("2026-10-22T09:00:00+08:00", "alice", "10.0.0.1", "登录", "/", 200),
            ev("2026-10-22T10:00:00+08:00", "bob", "10.0.0.2", "上传", "/a.zip", 201),
            ev("2026-10-22T11:00:00+08:00", "alice", "10.0.0.3", "删除", "/a.zip", 204),
        ];
        let dir = std::env::temp_dir().join(format!("dufs-audit-test-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        {
            let logger = AuditLogger::new(&path).unwrap();
            for e in &events {
                logger.record(e);
            }
        }
        let logger = AuditLogger::new(&path).unwrap();

        let (total, page) = logger.query(&AuditQuery {
            limit: 10,
            ..Default::default()
        });
        assert_eq!(total, 3);
        assert_eq!(page[0].op, "删除"); // newest first

        let (total, _) = logger.query(&AuditQuery {
            user: Some("ali".to_string()),
            limit: 10,
            ..Default::default()
        });
        assert_eq!(total, 2);

        let (total, _) = logger.query(&AuditQuery {
            op: Some("上传".to_string()),
            limit: 10,
            ..Default::default()
        });
        assert_eq!(total, 1);

        let (total, _) = logger.query(&AuditQuery {
            from: Some("2026-10-22T09:30".to_string()),
            to: Some("2026-10-22T10:30".to_string()),
            limit: 10,
            ..Default::default()
        });
        assert_eq!(total, 1);

        let (total, _) = logger.query(&AuditQuery {
            keyword: Some("a.zip".to_string()),
            limit: 10,
            ..Default::default()
        });
        assert_eq!(total, 2);

        std::fs::remove_dir_all(&dir).ok();
    }
}
