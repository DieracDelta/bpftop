use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::config::Config;
use crate::data::collector::Collector;
use crate::data::container::{resolve_service_from_path, ServiceDisplayMode};
use crate::data::process::{
    compare_processes, matches_filter, ProcessInfo, SortColumn, YankField,
};
use crate::data::system::SystemInfo;
use crate::ebpf::loader::EbpfLoader;
use crate::input;
use crate::theme::Theme;
use crate::ui::dialogs::{HelpDialog, KillDialog};
use crate::ui::filter_bar::{FilterBarWidget, FilterMode};
use crate::ui::header::HeaderWidget;
use crate::ui::layout::main_layout;
use crate::ui::process_table::{self, ProcessTableWidget};
use crate::ui::status_bar::StatusBarWidget;
use crate::ui::tree_view;

/// Current interaction mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Normal,
    Search,
    Filter,
    Help,
    Kill,
    SortSelect,
    Visual,
}

/// Main application state.
pub struct App {
    pub mode: AppMode,
    pub config: Config,
    pub theme: Theme,

    // Process data
    pub sys_info: SystemInfo,
    pub all_processes: Vec<ProcessInfo>,
    pub filtered_processes: Vec<ProcessInfo>,

    // Table state
    pub selected: usize,
    pub scroll_offset: usize,
    pub visible_rows: usize,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,

    // View toggles
    pub tree_view: bool,
    pub show_threads: bool,
    pub show_kernel_threads: bool,

    // Tree collapse/expand
    pub collapsed_pids: HashSet<u32>,

    // Service display mode
    pub service_display_mode: ServiceDisplayMode,

    // Filter/search
    pub filter_query: String,
    pub active_filter: String,
    pub user_filter: Option<String>,

    // Kill dialog
    pub kill_signal_idx: usize,
    pub kill_pid_scroll: usize,
    pub pre_kill_mode: AppMode,

    // Vim multi-key sequences
    pub pending_key: Option<char>,

    // Jump list
    pub jump_list: Vec<u32>,
    pub jump_pos: usize,

    // Visual mode
    pub visual_anchor: Option<usize>,

    // Flash message (transient status bar text)
    pub flash_message: Option<(String, Instant)>,

    // Dynamic header height (set during draw)
    pub header_height: u16,

    // Redraw control
    pub dirty: bool,

    // Data collection
    collector: Collector,
    ebpf_loaded: bool,
    pub ebpf_error: Option<String>,
}

impl App {
    pub fn new(config: Config) -> Self {
        let theme = Theme::from_config(&config.theme.preset, &config.theme.overrides);
        let tree_view = config.general.tree_view;
        let show_threads = config.general.show_threads;
        let show_kernel_threads = config.general.show_kernel_threads;
        let (ebpf, ebpf_error) = match EbpfLoader::load() {
            Ok(loader) => {
                log::info!("eBPF programs loaded successfully");
                (loader, None)
            }
            Err(e) => {
                log::warn!("eBPF not available: {e}");
                let msg = format!(
                    "eBPF failed to load: {e:#}\n\n\
                     Run as root (sudo bpftop) or use the NixOS wrapper:\n\
                     programs.bpftop.enable = true  ->  /run/wrappers/bin/bpftop"
                );
                (EbpfLoader::noop(), Some(msg))
            }
        };
        let ebpf_loaded = ebpf.is_loaded();
        let collector = Collector::new(ebpf);

        Self {
            mode: AppMode::Normal,
            config,
            theme,
            sys_info: SystemInfo::default(),
            all_processes: Vec::new(),
            filtered_processes: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            visible_rows: 0,
            sort_column: SortColumn::Pid,
            sort_ascending: true,
            tree_view,
            show_threads,
            show_kernel_threads,
            collapsed_pids: HashSet::new(),
            service_display_mode: ServiceDisplayMode::ServiceOnly,
            filter_query: String::new(),
            active_filter: String::new(),
            user_filter: None,
            kill_signal_idx: 0,
            kill_pid_scroll: 0,
            pre_kill_mode: AppMode::Normal,
            pending_key: None,
            jump_list: Vec::new(),
            jump_pos: 0,
            visual_anchor: None,
            flash_message: None,
            header_height: 4,
            dirty: true,
            collector,
            ebpf_loaded,
            ebpf_error,
        }
    }

    /// Run the main event loop.
    pub fn run(&mut self) -> Result<()> {
        // Set up terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        crossterm::execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let tick_rate = Duration::from_millis(self.config.general.refresh_rate_ms);

        // Move collector to background thread
        let (data_tx, data_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let mut collector = std::mem::replace(&mut self.collector, Collector::noop());

        // Initial collect on main thread so first frame has data
        if let Ok(data) = collector.collect() {
            self.merge_data(data.0, data.1);
        }

        let tick_rate_clone = tick_rate;
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(tick_rate_clone);
                match collector.collect() {
                    Ok(data) => {
                        if data_tx.send(data).is_err() {
                            break;
                        }
                    }
                    Err(e) => log::error!("Collection error: {e}"),
                }
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
            }
        });

        // Short poll timeout so UI stays responsive
        let poll_timeout = Duration::from_millis(50);

        loop {
            // Drain any available data (use freshest)
            while let Ok((sys_info, processes)) = data_rx.try_recv() {
                self.merge_data(sys_info, processes);
            }

            // Expire flash message (forces redraw to clear it)
            if self.active_flash().is_some() {
                self.dirty = true;
            }

            // Only redraw when something changed
            if self.dirty {
                terminal.draw(|frame| self.draw(frame))?;
                self.dirty = false;
            }

            // Handle events with short timeout
            if event::poll(poll_timeout)? {
                let evt = event::read()?;
                if input::handle_event(self, evt) {
                    break;
                }
                self.dirty = true;
            }
        }

        // Signal the background thread to exit
        drop(shutdown_tx);

        // Restore terminal
        disable_raw_mode()?;
        crossterm::execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        Ok(())
    }

    fn draw(&mut self, frame: &mut ratatui::Frame) {
        let area = frame.area();

        // Fill background
        let bg_style = ratatui::style::Style::default().bg(self.theme.bg);
        frame.render_widget(ratatui::widgets::Clear, area);
        let bg = ratatui::widgets::Block::default().style(bg_style);
        frame.render_widget(bg, area);

        let filter_active = self.mode == AppMode::Search || self.mode == AppMode::Filter;
        let num_cpus = self.sys_info.cpus.len().max(1);
        let num_gpus = self.sys_info.gpus.len();
        let has_gpu = num_gpus > 0;
        let (header_area, table_area, status_area, filter_area) =
            main_layout(area, filter_active, num_cpus, num_gpus);
        self.header_height = header_area.height;

        // Header meters
        let header = HeaderWidget {
            sys: &self.sys_info,
            theme: &self.theme,
        };
        frame.render_widget(header, header_area);

        // Process table
        self.visible_rows = process_table::visible_rows(table_area);
        let has_container = self.filtered_processes.iter().any(|p| p.container.is_some());
        let has_service = self.filtered_processes.iter().any(|p| p.service.is_some());
        let table = ProcessTableWidget {
            processes: &self.filtered_processes,
            selected: self.selected,
            scroll_offset: self.scroll_offset,
            sort_column: self.sort_column,
            sort_ascending: self.sort_ascending,
            theme: &self.theme,
            show_container: has_container,
            show_service: has_service,
            service_display_mode: self.service_display_mode,
            show_gpu: has_gpu,
            visual_range: self.visual_range(),
            error_message: self.ebpf_error.as_deref(),
        };
        frame.render_widget(table, table_area);

        // Filter bar
        if let Some(filter_area) = filter_area {
            let mode = match self.mode {
                AppMode::Search => FilterMode::Search,
                _ => FilterMode::Filter,
            };
            let filter_bar = FilterBarWidget {
                query: &self.filter_query,
                mode,
                theme: &self.theme,
            };
            frame.render_widget(filter_bar, filter_area);
        }

        // Status bar
        let status = StatusBarWidget {
            theme: &self.theme,
            ebpf_loaded: self.ebpf_loaded,
            flash: self.active_flash(),
        };
        frame.render_widget(status, status_area);

        // Overlays
        match self.mode {
            AppMode::Help => {
                let help = HelpDialog { theme: &self.theme };
                frame.render_widget(help, area);
            }
            AppMode::Kill => {
                let pids: Vec<u32> = if self.filtered_processes.iter().any(|p| p.tagged) {
                    self.filtered_processes.iter().filter(|p| p.tagged).map(|p| p.pid).collect()
                } else if let Some(proc) = self.filtered_processes.get(self.selected) {
                    vec![proc.pid]
                } else {
                    vec![]
                };
                if !pids.is_empty() {
                    let kill = KillDialog {
                        pids: &pids,
                        pid_scroll: self.kill_pid_scroll,
                        selected_signal: self.kill_signal_idx,
                        theme: &self.theme,
                    };
                    frame.render_widget(kill, area);
                }
            }
            _ => {}
        }
    }

    /// Resolve service names on all processes based on current display mode.
    pub fn resolve_services(&mut self) {
        let mode = self.service_display_mode;
        for p in &mut self.all_processes {
            p.service = resolve_service_from_path(&p.cgroup_path, mode);
        }
        for p in &mut self.filtered_processes {
            p.service = resolve_service_from_path(&p.cgroup_path, mode);
        }
    }

    fn merge_data(&mut self, sys_info: SystemInfo, processes: Vec<ProcessInfo>) {
        self.sys_info = sys_info;

        let new_map: HashMap<u32, ProcessInfo> =
            processes.into_iter().map(|p| (p.pid, p)).collect();
        let old_pids: HashSet<u32> = self.all_processes.iter().map(|p| p.pid).collect();
        let new_pids: HashSet<u32> = new_map.keys().copied().collect();
        let structure_changed = old_pids != new_pids;

        if structure_changed {
            // PIDs appeared or disappeared — full rebuild required
            let tagged_pids: HashSet<u32> = self
                .all_processes
                .iter()
                .chain(self.filtered_processes.iter())
                .filter(|p| p.tagged)
                .map(|p| p.pid)
                .collect();

            self.all_processes = new_map.into_values().collect();
            let mode = self.service_display_mode;
            for p in &mut self.all_processes {
                if tagged_pids.contains(&p.pid) {
                    p.tagged = true;
                }
                p.service = resolve_service_from_path(&p.cgroup_path, mode);
            }
            self.update_filtered_processes();
        } else {
            // Same PIDs — update values in-place, no re-sort, no tree rebuild
            let mode = self.service_display_mode;
            for p in &mut self.all_processes {
                if let Some(np) = new_map.get(&p.pid) {
                    p.update_dynamic_fields(np);
                    p.service = resolve_service_from_path(&np.cgroup_path, mode);
                }
            }
            for p in &mut self.filtered_processes {
                if let Some(np) = new_map.get(&p.pid) {
                    p.update_dynamic_fields(np);
                    p.service = resolve_service_from_path(&np.cgroup_path, mode);
                }
            }
        }
        self.dirty = true;
    }

    pub fn update_filtered_processes(&mut self) {
        let mut procs: Vec<ProcessInfo> = self
            .all_processes
            .iter()
            .filter(|p| {
                // Thread filter
                if !self.show_threads && p.is_thread {
                    return false;
                }
                // Kernel thread filter
                if !self.show_kernel_threads && p.is_kernel_thread {
                    return false;
                }
                // User filter
                if let Some(ref user) = self.user_filter {
                    if p.user != *user {
                        return false;
                    }
                }
                // Text filter
                matches_filter(p, &self.active_filter)
            })
            .cloned()
            .collect();

        if self.tree_view {
            let tree = tree_view::build_tree(&procs, &self.collapsed_pids);
            procs = tree_view::tree_ordered_processes(&procs, &tree);
        } else {
            procs.sort_by(|a, b| compare_processes(a, b, self.sort_column, self.sort_ascending));
        }

        self.filtered_processes = procs;

        // Keep cursor at same visual position, just clamp to new bounds
        if !self.filtered_processes.is_empty() {
            self.selected = self.selected.min(self.filtered_processes.len() - 1);
        } else {
            self.selected = 0;
        }

        // Clamp scroll offset
        let max_offset = if self.visible_rows > 0 {
            self.filtered_processes.len().saturating_sub(self.visible_rows)
        } else {
            self.filtered_processes.len().saturating_sub(1)
        };
        self.scroll_offset = self.scroll_offset.min(max_offset);
    }

    pub fn move_selection(&mut self, delta: i32) {
        if self.filtered_processes.is_empty() {
            return;
        }
        let new = self.selected as i32 + delta;
        self.selected = new.clamp(0, self.filtered_processes.len() as i32 - 1) as usize;
        self.adjust_scroll();
    }

    pub fn select_first(&mut self) {
        self.selected = 0;
        self.adjust_scroll();
    }

    pub fn select_last(&mut self) {
        if !self.filtered_processes.is_empty() {
            self.selected = self.filtered_processes.len() - 1;
        }
        self.adjust_scroll();
    }

    pub fn toggle_tag(&mut self) {
        if let Some(proc) = self.filtered_processes.get_mut(self.selected) {
            proc.tagged = !proc.tagged;
            // Also toggle in all_processes
            let pid = proc.pid;
            let tagged = proc.tagged;
            if let Some(ap) = self.all_processes.iter_mut().find(|p| p.pid == pid) {
                ap.tagged = tagged;
            }
        }
        self.move_selection(1);
    }

    pub fn untag_all(&mut self) {
        for p in &mut self.filtered_processes {
            p.tagged = false;
        }
        for p in &mut self.all_processes {
            p.tagged = false;
        }
    }

    // --- Jump list ---

    /// Push the current PID as a jump mark, truncating forward history.
    pub fn push_jump_mark(&mut self) {
        let pid = match self.filtered_processes.get(self.selected) {
            Some(p) => p.pid,
            None => return,
        };
        // Truncate forward history
        self.jump_list.truncate(self.jump_pos);
        self.jump_list.push(pid);
        // Cap at 100 entries
        if self.jump_list.len() > 100 {
            let excess = self.jump_list.len() - 100;
            self.jump_list.drain(..excess);
        }
        self.jump_pos = self.jump_list.len();
    }

    /// Jump backward in the jump list.
    pub fn jump_back(&mut self) {
        if self.jump_list.is_empty() {
            return;
        }
        // If at end, push current position first
        if self.jump_pos == self.jump_list.len() {
            self.push_jump_mark();
            // push_jump_mark increments jump_pos, so we need to go back 2
            if self.jump_pos >= 2 {
                self.jump_pos -= 2;
            } else {
                return;
            }
        } else if self.jump_pos > 0 {
            self.jump_pos -= 1;
        } else {
            return;
        }
        self.navigate_to_jump_pid();
    }

    /// Jump forward in the jump list.
    pub fn jump_forward(&mut self) {
        if self.jump_pos + 1 < self.jump_list.len() {
            self.jump_pos += 1;
            self.navigate_to_jump_pid();
        }
    }

    fn navigate_to_jump_pid(&mut self) {
        if let Some(&pid) = self.jump_list.get(self.jump_pos) {
            if let Some(pos) = self.filtered_processes.iter().position(|p| p.pid == pid) {
                self.selected = pos;
                self.adjust_scroll();
            }
        }
    }

    // --- Visual mode ---

    /// Returns the visual selection range as (start, end) inclusive indices.
    pub fn visual_range(&self) -> Option<(usize, usize)> {
        let anchor = self.visual_anchor?;
        let lo = anchor.min(self.selected);
        let hi = anchor.max(self.selected);
        Some((lo, hi))
    }

    /// Tag all processes in the visual range (both filtered and all_processes).
    pub fn tag_visual_range(&mut self) {
        if let Some((lo, hi)) = self.visual_range() {
            for i in lo..=hi {
                if let Some(proc) = self.filtered_processes.get_mut(i) {
                    proc.tagged = true;
                    let pid = proc.pid;
                    if let Some(ap) = self.all_processes.iter_mut().find(|p| p.pid == pid) {
                        ap.tagged = true;
                    }
                }
            }
        }
    }

    pub fn expand_tree_node(&mut self) {
        if let Some(proc) = self.filtered_processes.get(self.selected) {
            self.collapsed_pids.remove(&proc.pid);
            self.update_filtered_processes();
        }
    }

    pub fn collapse_tree_node(&mut self) {
        if let Some(proc) = self.filtered_processes.get(self.selected) {
            if !proc.children.is_empty() {
                self.collapsed_pids.insert(proc.pid);
                self.update_filtered_processes();
            }
        }
    }

    pub fn toggle_tree_node(&mut self) {
        if let Some(proc) = self.filtered_processes.get(self.selected) {
            let pid = proc.pid;
            let has_children = !proc.children.is_empty();
            if self.collapsed_pids.contains(&pid) {
                self.collapsed_pids.remove(&pid);
                self.update_filtered_processes();
            } else if has_children {
                self.collapsed_pids.insert(pid);
                self.update_filtered_processes();
            }
        }
    }

    pub fn expand_tree_recursive(&mut self) {
        if let Some(proc) = self.filtered_processes.get(self.selected) {
            let pid = proc.pid;
            self.collapsed_pids.remove(&pid);
            for desc in self.descendant_pids(pid) {
                self.collapsed_pids.remove(&desc);
            }
            self.update_filtered_processes();
        }
    }

    pub fn collapse_tree_recursive(&mut self) {
        if let Some(proc) = self.filtered_processes.get(self.selected) {
            let pid = proc.pid;
            if !proc.children.is_empty() {
                self.collapsed_pids.insert(pid);
            }
            for anc in self.ancestor_pids(pid) {
                self.collapsed_pids.insert(anc);
            }
            self.update_filtered_processes();
        }
    }

    pub fn expand_all_tree(&mut self) {
        self.collapsed_pids.clear();
        self.update_filtered_processes();
    }

    pub fn collapse_all_tree(&mut self) {
        let parent_pids: Vec<u32> = self
            .all_processes
            .iter()
            .filter(|p| !p.children.is_empty())
            .map(|p| p.pid)
            .collect();
        for pid in parent_pids {
            self.collapsed_pids.insert(pid);
        }
        self.update_filtered_processes();
    }

    fn descendant_pids(&self, pid: u32) -> Vec<u32> {
        let child_map: HashMap<u32, &Vec<u32>> = self
            .all_processes
            .iter()
            .map(|p| (p.pid, &p.children))
            .collect();
        let mut result = Vec::new();
        let mut stack = vec![pid];
        while let Some(current) = stack.pop() {
            if let Some(children) = child_map.get(&current) {
                for &child in children.iter() {
                    result.push(child);
                    stack.push(child);
                }
            }
        }
        result
    }

    fn ancestor_pids(&self, pid: u32) -> Vec<u32> {
        let ppid_map: HashMap<u32, u32> = self
            .all_processes
            .iter()
            .map(|p| (p.pid, p.ppid))
            .collect();
        let mut result = Vec::new();
        let mut current = pid;
        while let Some(&parent) = ppid_map.get(&current) {
            if parent == 0 || parent == current {
                break;
            }
            result.push(parent);
            current = parent;
        }
        result
    }

    // --- Flash message ---

    pub fn flash(&mut self, msg: String) {
        self.flash_message = Some((msg, Instant::now()));
    }

    pub fn active_flash(&self) -> Option<&str> {
        if let Some((ref msg, when)) = self.flash_message {
            if when.elapsed() < Duration::from_secs(2) {
                return Some(msg.as_str());
            }
        }
        None
    }

    // --- Yank to clipboard ---

    /// Yank the given field from the visual range (if active) or current row.
    /// Returns a description for the flash message.
    pub fn yank(&mut self, field: YankField) -> Option<String> {
        let indices: Vec<usize> = if let Some((lo, hi)) = self.visual_range() {
            (lo..=hi).collect()
        } else {
            vec![self.selected]
        };

        let texts: Vec<String> = indices
            .iter()
            .filter_map(|&i| self.filtered_processes.get(i))
            .map(|p| p.yank_text(field))
            .collect();

        if texts.is_empty() {
            return None;
        }

        let joined = texts.join("\n");
        if crate::clipboard::yank(&joined).is_err() {
            return Some("Clipboard write failed".to_string());
        }

        let desc = match field {
            YankField::Row => {
                if texts.len() == 1 {
                    "Yanked row".to_string()
                } else {
                    format!("Yanked {} rows", texts.len())
                }
            }
            YankField::Pid => {
                if texts.len() == 1 {
                    format!("Yanked PID {}", texts[0])
                } else {
                    format!("Yanked {} PIDs", texts.len())
                }
            }
            YankField::User => {
                if texts.len() == 1 {
                    format!("Yanked user {}", texts[0])
                } else {
                    format!("Yanked {} users", texts.len())
                }
            }
            YankField::Container => {
                if texts.len() == 1 {
                    format!("Yanked container {}", texts[0])
                } else {
                    format!("Yanked {} containers", texts.len())
                }
            }
            YankField::Service => {
                if texts.len() == 1 {
                    format!("Yanked service {}", texts[0])
                } else {
                    format!("Yanked {} services", texts.len())
                }
            }
            YankField::Name => {
                if texts.len() == 1 {
                    format!("Yanked name {}", texts[0])
                } else {
                    format!("Yanked {} names", texts.len())
                }
            }
            YankField::Cmdline => {
                if texts.len() == 1 {
                    "Yanked cmdline".to_string()
                } else {
                    format!("Yanked {} cmdlines", texts.len())
                }
            }
            YankField::GpuPercent => {
                if texts.len() == 1 {
                    format!("Yanked GPU% {}", texts[0])
                } else {
                    format!("Yanked {} GPU%", texts.len())
                }
            }
            YankField::GpuMem => {
                if texts.len() == 1 {
                    format!("Yanked GMEM {}", texts[0])
                } else {
                    format!("Yanked {} GMEM", texts.len())
                }
            }
        };
        Some(desc)
    }

    pub fn cycle_user_filter(&mut self) {
        if self.user_filter.is_some() {
            self.user_filter = None;
        } else if let Some(proc) = self.filtered_processes.get(self.selected) {
            self.user_filter = Some(proc.user.clone());
        }
        self.update_filtered_processes();
    }

    pub fn send_signal(&self, signal: i32) {
        let pids: Vec<u32> = if self.filtered_processes.iter().any(|p| p.tagged) {
            self.filtered_processes
                .iter()
                .filter(|p| p.tagged)
                .map(|p| p.pid)
                .collect()
        } else if let Some(proc) = self.filtered_processes.get(self.selected) {
            vec![proc.pid]
        } else {
            return;
        };

        let sig = match nix::sys::signal::Signal::try_from(signal) {
            Ok(s) => s,
            Err(_) => return,
        };

        for pid in pids {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                sig,
            );
        }
    }

    fn adjust_scroll(&mut self) {
        if self.visible_rows == 0 {
            return;
        }
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        }
        if self.selected >= self.scroll_offset + self.visible_rows {
            self.scroll_offset = self.selected - self.visible_rows + 1;
        }
    }
}
