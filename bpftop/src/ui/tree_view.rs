use std::collections::HashMap;

use crate::data::process::ProcessInfo;

/// A flattened tree entry with indentation info for rendering.
#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub pid: u32,
    pub depth: u16,
    pub prefix: String, // e.g., "├─" or "└─"
    pub is_last: bool,
}

/// Build a flat list of tree entries from the process list.
/// The tree is rooted at init (pid 1) or the earliest ancestor.
pub fn build_tree(processes: &[ProcessInfo]) -> Vec<TreeEntry> {
    let proc_map: HashMap<u32, &ProcessInfo> = processes.iter().map(|p| (p.pid, p)).collect();

    // Find root processes (ppid == 0 or ppid not in our process list)
    let mut roots: Vec<u32> = processes
        .iter()
        .filter(|p| p.ppid == 0 || !proc_map.contains_key(&p.ppid))
        .map(|p| p.pid)
        .collect();
    roots.sort();

    // Build children map
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for proc in processes {
        if proc.ppid != 0 && proc.ppid != proc.pid {
            children_map
                .entry(proc.ppid)
                .or_default()
                .push(proc.pid);
        }
    }
    // Sort children by PID
    for children in children_map.values_mut() {
        children.sort();
    }

    let mut entries = Vec::new();
    for (i, &root) in roots.iter().enumerate() {
        let is_last = i == roots.len() - 1;
        build_subtree(
            root,
            0,
            is_last,
            String::new(),
            &children_map,
            &mut entries,
        );
    }

    entries
}

fn build_subtree(
    pid: u32,
    depth: u16,
    is_last: bool,
    indent_prefix: String,
    children_map: &HashMap<u32, Vec<u32>>,
    entries: &mut Vec<TreeEntry>,
) {
    let prefix = if depth == 0 {
        String::new()
    } else if is_last {
        format!("{indent_prefix}\u{2514}\u{2500}") // └─
    } else {
        format!("{indent_prefix}\u{251c}\u{2500}") // ├─
    };

    entries.push(TreeEntry {
        pid,
        depth,
        prefix,
        is_last,
    });

    if let Some(children) = children_map.get(&pid) {
        for (i, &child) in children.iter().enumerate() {
            let child_is_last = i == children.len() - 1;
            let child_indent = if depth == 0 {
                String::new()
            } else if is_last {
                format!("{indent_prefix}  ")
            } else {
                format!("{indent_prefix}\u{2502} ") // │
            };
            build_subtree(child, depth + 1, child_is_last, child_indent, children_map, entries);
        }
    }
}

/// Reorder processes according to tree order, returning the reordered list.
pub fn tree_ordered_processes(
    processes: &[ProcessInfo],
    tree: &[TreeEntry],
) -> Vec<ProcessInfo> {
    let proc_map: HashMap<u32, &ProcessInfo> = processes.iter().map(|p| (p.pid, p)).collect();
    tree.iter()
        .filter_map(|entry| proc_map.get(&entry.pid).map(|p| (*p).clone()))
        .collect()
}
