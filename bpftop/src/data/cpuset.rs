//! CPUs reserved by cgroup v2 cpuset partitions (or `isolcpus`), and the
//! kernel's CPU list format ("0-3,8").

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use super::system::StatFile;

/// A set of CPU numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CpuSet {
    words: Vec<u64>,
}

impl CpuSet {
    /// Parse a kernel CPU list. Whitespace around it is ignored; an empty
    /// list is the empty set.
    pub fn parse(text: &str) -> Option<Self> {
        let mut set = Self::default();
        for part in text.trim().split(',').filter(|p| !p.is_empty()) {
            let (first, last) = match part.split_once('-') {
                Some((a, b)) => (a.parse().ok()?, b.parse().ok()?),
                None => {
                    let cpu = part.parse().ok()?;
                    (cpu, cpu)
                }
            };
            if first > last {
                return None;
            }
            (first..=last).for_each(|cpu| set.insert(cpu));
        }
        Some(set)
    }

    /// The set with bit `n % 64` of word `n / 64` for CPU n.
    pub fn from_words(words: &[u64]) -> Self {
        let mut set = Self { words: words.to_vec() };
        set.trim();
        set
    }

    pub fn insert(&mut self, cpu: usize) {
        let word = cpu / 64;
        if self.words.len() <= word {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= 1 << (cpu % 64);
    }

    pub fn contains(&self, cpu: usize) -> bool {
        self.words.get(cpu / 64).is_some_and(|w| w & (1 << (cpu % 64)) != 0)
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(i, &w)| {
            (0..64).filter(move |bit| w & (1 << bit) != 0).map(move |bit| i * 64 + bit)
        })
    }

    pub fn union(&self, other: &Self) -> Self {
        let n = self.words.len().max(other.words.len());
        let word = |s: &Self, i: usize| s.words.get(i).copied().unwrap_or(0);
        Self::from_words(&(0..n).map(|i| word(self, i) | word(other, i)).collect::<Vec<_>>())
    }

    pub fn intersection(&self, other: &Self) -> Self {
        let word = |i: usize| other.words.get(i).copied().unwrap_or(0);
        Self::from_words(&self.words.iter().enumerate().map(|(i, &w)| w & word(i)).collect::<Vec<_>>())
    }

    pub fn difference(&self, other: &Self) -> Self {
        let word = |i: usize| other.words.get(i).copied().unwrap_or(0);
        Self::from_words(&self.words.iter().enumerate().map(|(i, &w)| w & !word(i)).collect::<Vec<_>>())
    }

    /// Drop trailing zero words, so equal sets compare (and hash) equal.
    fn trim(&mut self) {
        while self.words.last() == Some(&0) {
            self.words.pop();
        }
    }
}

/// Formats as a kernel CPU list ("0-3,8"); the empty set as "".
impl fmt::Display for CpuSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut cpus = self.iter().peekable();
        let mut first = true;
        while let Some(start) = cpus.next() {
            let mut end = start;
            while cpus.peek() == Some(&(end + 1)) {
                end = cpus.next().unwrap();
            }
            if !first {
                f.write_str(",")?;
            }
            first = false;
            if end == start {
                write!(f, "{start}")?;
            } else {
                write!(f, "{start}-{end}")?;
            }
        }
        Ok(())
    }
}

/// A cgroup that is a valid cpuset partition root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    /// cgroup path below the cgroup2 mount, e.g. "bench.slice".
    pub cgroup: String,
    /// An `isolated` partition (no load balancing) rather than `root`.
    pub isolated: bool,
    pub cpus: CpuSet,
}

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Tracks which CPUs are reserved: taken out of the root cgroup's CPUs by
/// partitions, or isolated (isolated partitions and `isolcpus`). Costs one
/// or two `pread`s per refresh; cgroupfs is only walked, to name the
/// partitions, when the reserved CPUs change.
pub struct ReservedCpus {
    root: PathBuf,
    /// `cpuset.cpus.effective` of the root cgroup.
    root_effective: Option<StatFile>,
    /// `cpuset.cpus.isolated` of the root cgroup (Linux 6.9+).
    root_isolated: Option<StatFile>,
    /// Contents of the two files at the last refresh.
    last_raw: (String, String),
    reserved: CpuSet,
    partitions: Vec<Partition>,
}

impl ReservedCpus {
    pub fn new() -> Self {
        Self::at(Path::new(CGROUP_ROOT))
    }

    fn at(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            root_effective: StatFile::open(root.join("cpuset.cpus.effective")).ok(),
            root_isolated: StatFile::open(root.join("cpuset.cpus.isolated")).ok(),
            last_raw: Default::default(),
            reserved: CpuSet::default(),
            partitions: Vec::new(),
        }
    }

    /// Re-read the root cgroup's CPUs. Returns true when the reserved CPUs
    /// changed since the last call.
    pub fn refresh(&mut self) -> bool {
        let read = |file: &mut Option<StatFile>| {
            file.as_mut().and_then(|f| f.read().ok()).map(str::to_owned).unwrap_or_default()
        };
        let raw = (read(&mut self.root_effective), read(&mut self.root_isolated));
        if raw == self.last_raw {
            return false;
        }
        self.last_raw = raw;

        let online = fs::read_to_string("/sys/devices/system/cpu/online")
            .ok()
            .and_then(|s| CpuSet::parse(&s))
            .unwrap_or_default();
        let effective = CpuSet::parse(&self.last_raw.0).unwrap_or_else(|| online.clone());
        let isolated = CpuSet::parse(&self.last_raw.1).unwrap_or_default();
        // No cpuset controller: nothing can be reserved this way.
        let taken = if self.root_effective.is_some() { online.difference(&effective) } else { CpuSet::default() };
        let reserved = taken.union(&isolated);

        self.partitions.clear();
        if !reserved.is_empty() {
            find_partitions(&self.root, &self.root, &mut self.partitions);
        }
        let changed = reserved != self.reserved;
        self.reserved = reserved;
        changed
    }

    pub fn cpus(&self) -> &CpuSet {
        &self.reserved
    }

    pub fn partitions(&self) -> &[Partition] {
        &self.partitions
    }
}

/// Collect the valid partition roots below `dir`. Only cgroups holding
/// exclusive CPUs are descended into: a partition's ancestors (other than
/// the root) all hold the partition's CPUs in `cpuset.cpus.exclusive`.
fn find_partitions(root: &Path, dir: &Path, out: &mut Vec<Partition>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let path = entry.path();
        let read = |name: &str| fs::read_to_string(path.join(name)).ok();
        let Some(exclusive) = read("cpuset.cpus.exclusive.effective").and_then(|s| CpuSet::parse(&s)) else {
            continue;
        };
        if exclusive.is_empty() {
            continue;
        }
        let state = read("cpuset.cpus.partition").unwrap_or_default();
        let state = state.trim();
        if state == "root" || state == "isolated" {
            let cgroup = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            out.push(Partition { cgroup, isolated: state == "isolated", cpus: exclusive });
        }
        find_partitions(root, &path, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_cpu_lists() {
        let set = CpuSet::parse("12-15,28-31\n").unwrap();
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![12, 13, 14, 15, 28, 29, 30, 31]);
        assert_eq!(set.to_string(), "12-15,28-31");
        assert_eq!(CpuSet::parse("0,2-3,5").unwrap().to_string(), "0,2-3,5");
        assert_eq!(CpuSet::parse("63-65").unwrap().to_string(), "63-65");
        assert!(CpuSet::parse("").unwrap().is_empty());
        assert!(CpuSet::parse("\n").unwrap().is_empty());
        assert_eq!(CpuSet::parse("3-1"), None);
        assert_eq!(CpuSet::parse("x"), None);
    }

    #[test]
    fn set_operations() {
        let all = CpuSet::parse("0-31").unwrap();
        let rest = CpuSet::parse("0-11,16-27").unwrap();
        let reserved = all.difference(&rest);
        assert_eq!(reserved.to_string(), "12-15,28-31");
        assert_eq!(reserved.union(&CpuSet::parse("100").unwrap()).to_string(), "12-15,28-31,100");
        // Equal sets compare equal whatever their storage length.
        assert_eq!(all.difference(&all), CpuSet::default());
        assert_eq!(CpuSet::from_words(&[0b1010, 0, 0, 0]), CpuSet::parse("1,3").unwrap());
        assert!(reserved.contains(28) && !reserved.contains(16) && !reserved.contains(1000));
        assert_eq!(CpuSet::parse("3,64-255").unwrap().intersection(&CpuSet::parse("0-3").unwrap()).to_string(), "3");
    }

    #[test]
    fn finds_partitions_in_a_cgroup_tree() {
        let dir = std::env::temp_dir().join(format!("bpftop-cpuset-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let write = |rel: &str, content: &str| {
            let path = dir.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        };
        // Root: 32 CPUs, 12-15 and 28-31 handed to bench.slice.
        write("cpuset.cpus.effective", "0-11,16-27\n");
        write("cpuset.cpus.isolated", "\n");
        write("bench.slice/cpuset.cpus.exclusive.effective", "12-15,28-31\n");
        write("bench.slice/cpuset.cpus.partition", "root\n");
        write("bench.slice/run.scope/cpuset.cpus.exclusive.effective", "\n");
        write("system.slice/cpuset.cpus.exclusive.effective", "\n");
        write("system.slice/cpuset.cpus.partition", "member\n");
        write("user.slice/cpuset.cpus.partition", "member\n");

        let mut reserved = ReservedCpus::at(&dir);
        // Uses this machine's online CPUs; only check when it has 32.
        let online = fs::read_to_string("/sys/devices/system/cpu/online").unwrap_or_default();
        if online.trim() == "0-31" {
            assert!(reserved.refresh());
            assert_eq!(reserved.cpus().to_string(), "12-15,28-31");
            assert!(!reserved.refresh(), "unchanged files: no change");
        } else {
            reserved.refresh();
        }
        let mut found = Vec::new();
        find_partitions(&dir, &dir, &mut found);
        assert_eq!(
            found,
            vec![Partition {
                cgroup: "bench.slice".into(),
                isolated: false,
                cpus: CpuSet::parse("12-15,28-31").unwrap(),
            }]
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
