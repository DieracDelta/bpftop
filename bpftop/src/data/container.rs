use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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

/// Resolves cgroup inode IDs to container names.
///
/// BPF provides `cgroup_id` (the inode number of the cgroup directory
/// in cgroupfs). We walk /sys/fs/cgroup/ to build a mapping from
/// inode ID → cgroup path, then parse container info from the path.
///
/// No per-PID /proc reads are needed.
pub struct CgroupResolver {
    /// cgroup inode ID → cgroup path (e.g. "/system.slice/docker-abc.scope")
    id_to_path: HashMap<u64, String>,
    /// cgroup path → parsed container info (cache)
    path_to_container: HashMap<String, Option<ContainerInfo>>,
    /// Counter to trigger periodic refresh of the inode map.
    cycles_since_refresh: u32,
}

impl CgroupResolver {
    pub fn new() -> Self {
        let mut resolver = Self {
            id_to_path: HashMap::new(),
            path_to_container: HashMap::new(),
            cycles_since_refresh: 0,
        };
        resolver.refresh_inode_map();
        resolver
    }

    /// Call once per collect cycle to periodically refresh the cgroup inode map.
    pub fn tick(&mut self) {
        self.cycles_since_refresh += 1;
        if self.cycles_since_refresh >= 10 {
            self.refresh_inode_map();
            self.cycles_since_refresh = 0;
        }
    }

    /// Resolve a cgroup inode ID (from BPF) to container info.
    /// Returns None for non-container cgroups.
    pub fn resolve(&mut self, cgroup_id: u64) -> Option<ContainerInfo> {
        if cgroup_id == 0 {
            return None;
        }

        let path = self.id_to_path.get(&cgroup_id)?;

        if let Some(cached) = self.path_to_container.get(path) {
            return cached.clone();
        }

        let info = parse_container_from_cgroup(path);
        self.path_to_container.insert(path.clone(), info.clone());
        info
    }

    /// Also return the cgroup path string for a given cgroup_id.
    pub fn resolve_path(&self, cgroup_id: u64) -> String {
        self.id_to_path
            .get(&cgroup_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Walk /sys/fs/cgroup/ and map inode numbers to cgroup paths.
    fn refresh_inode_map(&mut self) {
        self.id_to_path.clear();
        let base = Path::new("/sys/fs/cgroup");
        if base.exists() {
            self.walk_cgroup_tree(base, base);
        }
    }

    fn walk_cgroup_tree(&mut self, dir: &Path, base: &Path) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        // Record this directory's inode
        if let Ok(meta) = fs::metadata(dir) {
            let ino = meta.ino();
            let relative = dir
                .strip_prefix(base)
                .map(|p| format!("/{}", p.display()))
                .unwrap_or_else(|_| "/".to_string());
            self.id_to_path.insert(ino, relative);
        }

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.is_dir() {
                self.walk_cgroup_tree(&path, base);
            }
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

fn short_id(id: &str) -> String {
    if id.len() > 12 {
        id[..12].to_string()
    } else {
        id.to_string()
    }
}
