use std::fs;
use std::io;
use std::path::Path;

const CGROUP_BASE: &str = "/sys/fs/cgroup";
const BPFTOP_CGROUP_DIR: &str = "bpftop.freeze";

const PERMS_HINT: &str =
    "insufficient permissions: add cap_dac_override,cap_sys_admin or run as root";

/// Wrap an io::Result, replacing PermissionDenied with a helpful message.
fn check_perms<T>(result: io::Result<T>) -> io::Result<T> {
    result.map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(io::ErrorKind::PermissionDenied, PERMS_HINT)
        } else {
            e
        }
    })
}

/// Read all PIDs from a cgroup's cgroup.procs file.
pub fn read_cgroup_pids(cgroup_path: &str) -> io::Result<Vec<u32>> {
    let path = format!("{CGROUP_BASE}{cgroup_path}/cgroup.procs");
    let contents = fs::read_to_string(&path)?;
    Ok(contents
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect())
}

/// Check if a cgroup is currently frozen (reads cgroup.freeze).
pub fn is_frozen(cgroup_path: &str) -> bool {
    let path = format!("{CGROUP_BASE}{cgroup_path}/cgroup.freeze");
    fs::read_to_string(&path)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Freeze a cgroup (write "1" to cgroup.freeze).
pub fn freeze_cgroup(cgroup_path: &str) -> io::Result<()> {
    let path = format!("{CGROUP_BASE}{cgroup_path}/cgroup.freeze");
    check_perms(fs::write(&path, "1"))
}

/// Unfreeze a cgroup (write "0" to cgroup.freeze).
pub fn thaw_cgroup(cgroup_path: &str) -> io::Result<()> {
    let path = format!("{CGROUP_BASE}{cgroup_path}/cgroup.freeze");
    check_perms(fs::write(&path, "0"))
}

/// Create a bpftop-managed cgroup for a root-cgroup process and move it there.
/// Returns the new cgroup relative path (e.g. "/bpftop.freeze/1234").
pub fn create_and_move(pid: u32) -> io::Result<String> {
    let dir = format!("{CGROUP_BASE}/{BPFTOP_CGROUP_DIR}/{pid}");
    let rel_path = format!("/{BPFTOP_CGROUP_DIR}/{pid}");

    // Create the cgroup directory (and parent if needed)
    let parent = format!("{CGROUP_BASE}/{BPFTOP_CGROUP_DIR}");
    if !Path::new(&parent).exists() {
        check_perms(fs::create_dir(&parent))?;
    }
    if !Path::new(&dir).exists() {
        check_perms(fs::create_dir(&dir))?;
    }

    // Move the process into the new cgroup
    let procs_path = format!("{dir}/cgroup.procs");
    check_perms(fs::write(&procs_path, pid.to_string()))?;

    Ok(rel_path)
}
