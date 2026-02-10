use std::collections::HashMap;
use std::fs;

use anyhow::Result;

/// Container runtime information for a process.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub name: String,
    pub runtime: ContainerRuntime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    Podman,
    Unknown,
}

/// Cache of cgroup path -> container name mappings.
#[derive(Debug, Default)]
pub struct ContainerResolver {
    cache: HashMap<String, Option<ContainerInfo>>,
}

impl ContainerResolver {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Resolve the container name for a given PID by reading its cgroup.
    pub fn resolve(&mut self, pid: u32) -> Option<ContainerInfo> {
        let cgroup_path = read_cgroup(pid).unwrap_or_default();
        if cgroup_path.is_empty() {
            return None;
        }

        if let Some(cached) = self.cache.get(&cgroup_path) {
            return cached.clone();
        }

        let info = parse_container_from_cgroup(&cgroup_path);
        self.cache.insert(cgroup_path, info.clone());
        info
    }

    /// Clear the cache (call periodically to pick up new containers).
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

/// Read the cgroup path for a PID from /proc/[pid]/cgroup.
fn read_cgroup(pid: u32) -> Result<String> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    // For cgroup v2, there's a single "0::/path" line.
    // For cgroup v1, look for the "name=systemd" or first entry.
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            // cgroup v2: hierarchy-ID = 0, controller = empty
            if parts[0] == "0" {
                return Ok(parts[2].to_string());
            }
        }
    }
    // Fallback: return the path from the first line
    if let Some(line) = content.lines().next() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            return Ok(parts[2].to_string());
        }
    }
    Ok(String::new())
}

/// Parse container ID/name from a cgroup path.
///
/// Docker:     /system.slice/docker-<id>.scope
/// Containerd: /system.slice/containerd-<id>.scope
/// Podman:     /user.slice/user-1000.slice/.../libpod-<id>.scope
/// k8s:        /kubepods/burstable/pod<uid>/<container-id>
fn parse_container_from_cgroup(cgroup_path: &str) -> Option<ContainerInfo> {
    // Docker pattern
    if let Some(id) = extract_scope_id(cgroup_path, "docker-") {
        return Some(ContainerInfo {
            name: short_id(&id),
            runtime: ContainerRuntime::Docker,
        });
    }

    // Containerd pattern
    if let Some(id) = extract_scope_id(cgroup_path, "containerd-") {
        return Some(ContainerInfo {
            name: short_id(&id),
            runtime: ContainerRuntime::Containerd,
        });
    }

    // Podman pattern
    if let Some(id) = extract_scope_id(cgroup_path, "libpod-") {
        return Some(ContainerInfo {
            name: short_id(&id),
            runtime: ContainerRuntime::Podman,
        });
    }

    // Kubernetes pattern: /kubepods/.../pod<uid>/<container-id>
    if cgroup_path.contains("kubepods") {
        let parts: Vec<&str> = cgroup_path.split('/').collect();
        if let Some(last) = parts.last() {
            if !last.is_empty() && !last.starts_with("pod") {
                return Some(ContainerInfo {
                    name: short_id(last),
                    runtime: ContainerRuntime::Containerd,
                });
            }
        }
    }

    None
}

fn extract_scope_id(path: &str, prefix: &str) -> Option<String> {
    for segment in path.split('/') {
        if let Some(rest) = segment.strip_prefix(prefix) {
            let id = rest.trim_end_matches(".scope");
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}

fn short_id(id: &str) -> String {
    if id.len() > 12 {
        id[..12].to_string()
    } else {
        id.to_string()
    }
}
