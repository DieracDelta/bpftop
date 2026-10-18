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
    let runtimes = [
        ("docker-", ContainerRuntime::Docker),
        ("containerd-", ContainerRuntime::Containerd),
        ("libpod-", ContainerRuntime::Podman),
    ];
    for (prefix, runtime) in runtimes {
        if let Some(id) = extract_scope_id(cgroup_path, prefix) {
            // Podman's conmon monitor runs in libpod-conmon-<id>.scope.
            let id = id.strip_prefix("conmon-").unwrap_or(&id);
            return Some(ContainerInfo {
                name: container_name(runtime, id, cgroup_path).unwrap_or_else(|| short_id(id)),
                runtime,
            });
        }
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

/// Docker's default data root; each container's config.v2.json has its name.
const DOCKER_ROOT: &str = "/var/lib/docker";
/// Podman's default storage root for rootful containers.
const PODMAN_ROOT: &str = "/var/lib/containers/storage";

/// Look up a container's name in its runtime's on-disk state. Called once
/// per container cgroup (results are cached by path); None falls back to
/// the short ID, e.g. for non-default data roots or containerd.
fn container_name(runtime: ContainerRuntime, id: &str, cgroup_path: &str) -> Option<String> {
    match runtime {
        ContainerRuntime::Docker => {
            let config = fs::read_to_string(format!("{DOCKER_ROOT}/containers/{id}/config.v2.json")).ok()?;
            docker_name(&config)
        }
        ContainerRuntime::Podman => {
            let root = match rootless_uid(cgroup_path) {
                Some(uid) => nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                    .ok()
                    .flatten()?
                    .dir
                    .join(".local/share/containers/storage"),
                None => PODMAN_ROOT.into(),
            };
            let containers = fs::read_to_string(root.join("overlay-containers/containers.json")).ok()?;
            podman_name(&containers, id)
        }
        _ => None,
    }
}

/// `"Name": "/web"` in Docker's config.v2.json.
fn docker_name(config_json: &str) -> Option<String> {
    let config: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let name = config.get("Name")?.as_str()?.trim_start_matches('/');
    (!name.is_empty()).then(|| name.to_string())
}

/// First name of the container with `id` in podman's containers.json.
fn podman_name(containers_json: &str, id: &str) -> Option<String> {
    let containers: Vec<serde_json::Value> = serde_json::from_str(containers_json).ok()?;
    let container = containers.iter().find(|c| c.get("id").and_then(|v| v.as_str()) == Some(id))?;
    container.get("names")?.get(0)?.as_str().map(str::to_string)
}

/// Rootless podman containers live under the user's systemd manager:
/// .../user@<uid>.service/.../libpod-<id>.scope
fn rootless_uid(cgroup_path: &str) -> Option<u32> {
    cgroup_path
        .split('/')
        .find_map(|seg| seg.strip_prefix("user@")?.strip_suffix(".service")?.parse().ok())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_name_from_config() {
        assert_eq!(docker_name(r#"{"ID":"abc","Name":"/web","State":{}}"#).as_deref(), Some("web"));
        assert_eq!(docker_name(r#"{"Name":""}"#), None);
        assert_eq!(docker_name("not json"), None);
    }

    #[test]
    fn podman_name_from_containers_json() {
        let json = r#"[{"id":"aaa","names":["db"]},{"id":"bbb","names":["web","alias"]}]"#;
        assert_eq!(podman_name(json, "bbb").as_deref(), Some("web"));
        assert_eq!(podman_name(json, "ccc"), None);
    }

    #[test]
    fn rootless_uid_from_cgroup() {
        let path = "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-abc.scope";
        assert_eq!(rootless_uid(path), Some(1000));
        assert_eq!(rootless_uid("/machine.slice/libpod-abc.scope"), None);
    }

    #[test]
    fn conmon_scope_maps_to_container() {
        let info = parse_container_from_cgroup("/machine.slice/libpod-conmon-0123456789abcdef.scope").unwrap();
        assert_eq!(info.runtime, ContainerRuntime::Podman);
        assert_eq!(info.name, "0123456789ab");
    }
}
