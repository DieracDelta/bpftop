use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{DirEntryExt, MetadataExt};
use std::path::Path;
use std::time::{Duration, Instant};

use super::process::Text;

/// Container runtime information for a process.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub name: String,
    #[allow(dead_code)]
    pub runtime: ContainerRuntime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    Podman,
    Unknown,
}

/// Which systemd unit display mode to use for the SERVICE column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceDisplayMode {
    /// Show only `.service` unit names, suffix stripped (e.g. `sshd`).
    ServiceOnly,
    /// Show the deepest systemd unit of any type (e.g. `sshd.service`, `session-2.scope`).
    AllUnits,
    /// Show the full cgroup path (e.g. `system.slice/sshd.service`).
    FullSlice,
}

const UNIT_SUFFIXES: &[&str] = &[".service", ".scope", ".slice", ".timer", ".socket"];

/// Minimum time between cgroupfs walks triggered by unknown cgroup IDs.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

/// Resolves cgroup inode IDs to container names.
///
/// BPF provides `cgroup_id` (the inode number of the cgroup directory
/// in cgroupfs). We walk /sys/fs/cgroup/ to build a mapping from
/// inode ID → cgroup path, then parse container info from the path.
///
/// Cgroup IDs are never reused and cgroup v2 directories can't be
/// renamed, so a mapping stays valid for the cgroup's lifetime. The tree
/// is only re-walked when a task shows up in a cgroup we haven't seen.
pub struct CgroupResolver {
    /// cgroup inode ID → cgroup path (e.g. "/system.slice/docker-abc.scope")
    id_to_path: HashMap<u64, Text>,
    /// cgroup path → container name (cache)
    path_to_container: HashMap<Text, Option<Text>>,
    /// Returned for unknown cgroup IDs.
    empty: Text,
    last_refresh: Instant,
}

impl CgroupResolver {
    pub fn new() -> Self {
        let mut resolver = Self::empty();
        resolver.refresh_inode_map();
        resolver
    }

    /// A resolver that knows no cgroups (and doesn't walk cgroupfs).
    pub fn empty() -> Self {
        Self {
            id_to_path: HashMap::new(),
            path_to_container: HashMap::new(),
            last_refresh: Instant::now(),
            empty: Text::from(""),
        }
    }

    /// Call once per collect cycle with every task's cgroup ID. Re-walks
    /// cgroupfs if any ID is unknown, rate-limited so IDs that never
    /// resolve (e.g. a foreign cgroup namespace) don't cause a walk per cycle.
    pub fn ensure_known(&mut self, mut ids: impl Iterator<Item = u64>) {
        if self.last_refresh.elapsed() < MIN_REFRESH_INTERVAL {
            return;
        }
        if ids.any(|id| id != 0 && !self.id_to_path.contains_key(&id)) {
            self.refresh_inode_map();
        }
    }

    /// Resolve a cgroup inode ID (from BPF) to a container name.
    /// Returns None for non-container cgroups.
    pub fn resolve(&mut self, cgroup_id: u64) -> Option<Text> {
        if cgroup_id == 0 {
            return None;
        }

        let path = self.id_to_path.get(&cgroup_id)?;

        if let Some(cached) = self.path_to_container.get(path) {
            return cached.clone();
        }

        let name = parse_container_from_cgroup(path).map(|c| Text::from(c.name));
        self.path_to_container.insert(path.clone(), name.clone());
        name
    }

    /// Also return the cgroup path string for a given cgroup_id.
    pub fn resolve_path(&self, cgroup_id: u64) -> Text {
        self.id_to_path
            .get(&cgroup_id)
            .unwrap_or(&self.empty)
            .clone()
    }

    /// Walk /sys/fs/cgroup/ and map inode numbers to cgroup paths.
    fn refresh_inode_map(&mut self) {
        self.id_to_path.clear();
        self.last_refresh = Instant::now();
        let base = Path::new("/sys/fs/cgroup");
        if let Ok(meta) = fs::metadata(base) {
            self.id_to_path.insert(meta.ino(), Text::from("/"));
            self.walk_cgroup_tree(base, "");
        }
    }

    /// Uses d_type and d_ino from getdents, so the walk costs one
    /// open/getdents/close per cgroup and no stat calls. (kernfs reports
    /// the node ID as the inode number on 64-bit.)
    fn walk_cgroup_tree(&mut self, dir: &Path, rel: &str) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let name = entry.file_name();
            let child_rel = format!("{rel}/{}", name.to_string_lossy());
            self.id_to_path.insert(entry.ino(), Text::from(child_rel.as_str()));
            self.walk_cgroup_tree(&entry.path(), &child_rel);
        }
    }
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

/// Resolve a systemd unit name from a cgroup path string.
pub fn resolve_service_from_path(path: &str, mode: ServiceDisplayMode) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    match mode {
        ServiceDisplayMode::ServiceOnly => {
            path.rsplit('/')
                .find(|seg| seg.ends_with(".service"))
                .map(|seg| seg.strip_suffix(".service").unwrap().to_string())
        }
        ServiceDisplayMode::AllUnits => {
            path.rsplit('/')
                .find(|seg| UNIT_SUFFIXES.iter().any(|suf| seg.ends_with(suf)))
                .map(|seg| seg.to_string())
        }
        ServiceDisplayMode::FullSlice => {
            let trimmed = path.trim_start_matches('/');
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
    }
}

fn short_id(id: &str) -> String {
    if id.len() > 12 {
        id[..12].to_string()
    } else {
        id.to_string()
    }
}
