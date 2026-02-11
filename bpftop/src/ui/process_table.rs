use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::Widget;

use crate::data::container::ServiceDisplayMode;
use crate::data::process::{format_bytes, format_time, ProcessInfo, ProcessState, SortColumn};
use crate::theme::Theme;

/// Renders the scrollable, sortable process table.
pub struct ProcessTableWidget<'a> {
    pub processes: &'a [ProcessInfo],
    pub selected: usize,
    pub scroll_offset: usize,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub theme: &'a Theme,
    pub show_container: bool,
    pub show_service: bool,
    pub service_display_mode: ServiceDisplayMode,
    pub show_gpu: bool,
    pub visual_range: Option<(usize, usize)>,
    pub error_message: Option<&'a str>,
}

impl<'a> Widget for ProcessTableWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 2 {
            return;
        }

        // Render column headers
        let header_area = Rect {
            height: 1,
            ..area
        };
        self.render_header(header_area, buf);

        // Render process rows
        let rows_area = Rect {
            y: area.y + 1,
            height: area.height.saturating_sub(1),
            ..area
        };

        // Show error message if BPF failed and there are no processes
        if self.processes.is_empty() {
            if let Some(msg) = self.error_message {
                let err_style = Style::default()
                    .fg(self.theme.proc_zombie)
                    .add_modifier(Modifier::BOLD);
                let normal_style = Style::default().fg(self.theme.fg);
                let mut y = rows_area.y + 1;
                for line in msg.lines() {
                    if y >= rows_area.y + rows_area.height {
                        break;
                    }
                    let style = if y == rows_area.y + 1 { err_style } else { normal_style };
                    buf.set_string(rows_area.x + 2, y, line, style);
                    y += 1;
                }
                return;
            }
        }

        let visible_rows = rows_area.height as usize;
        let end = (self.scroll_offset + visible_rows).min(self.processes.len());

        for (i, proc) in self.processes[self.scroll_offset..end].iter().enumerate() {
            let row_y = rows_area.y + i as u16;
            let abs_index = self.scroll_offset + i;
            let is_selected = abs_index == self.selected;
            self.render_row(
                Rect {
                    y: row_y,
                    height: 1,
                    ..rows_area
                },
                buf,
                proc,
                is_selected,
                abs_index,
            );
        }
    }
}

impl<'a> ProcessTableWidget<'a> {
    fn render_header(&self, area: Rect, buf: &mut Buffer) {
        let style = Style::default()
            .fg(self.theme.column_header_fg)
            .bg(self.theme.column_header_bg)
            .add_modifier(Modifier::BOLD);

        // Fill background
        for x in area.x..area.x + area.width {
            buf[(x, area.y)].set_style(style);
        }

        let columns = self.column_layout(area.width);
        let mut x = area.x;
        for (col, width) in &columns {
            let label = col.label();
            let styled = if *col == self.sort_column {
                let arrow = if self.sort_ascending { "^" } else { "v" };
                format!("{label}{arrow}")
            } else {
                label.to_string()
            };
            let display = if *width > 0 {
                format!("{:<width$}", styled, width = *width as usize)
            } else {
                styled
            };
            buf.set_string(x, area.y, &display, style);
            x += *width;
            if x < area.x + area.width {
                buf.set_string(x, area.y, " ", style);
                x += 1;
            }
        }
    }

    fn render_row(&self, area: Rect, buf: &mut Buffer, proc: &ProcessInfo, selected: bool, abs_index: usize) {
        let in_visual = self.visual_range.is_some_and(|(lo, hi)| abs_index >= lo && abs_index <= hi);

        let bg = if selected {
            self.theme.selection_bg
        } else if in_visual || proc.tagged {
            self.theme.visual_bg
        } else {
            self.theme.bg
        };

        let fg = if selected {
            self.theme.selection_fg
        } else {
            match proc.state {
                ProcessState::Running => self.theme.proc_running,
                ProcessState::Zombie => self.theme.proc_zombie,
                ProcessState::Stopped | ProcessState::TracingStop => self.theme.proc_stopped,
                _ => self.theme.fg,
            }
        };

        let style = Style::default().fg(fg).bg(bg);

        // Fill background
        for x in area.x..area.x + area.width {
            buf[(x, area.y)].set_style(style);
        }

        let columns = self.column_layout(area.width);
        let mut x = area.x;
        for (col, width) in &columns {
            let text = self.format_column(proc, col, *width);
            buf.set_string(x, area.y, &text, style);
            x += *width;
            if x < area.x + area.width {
                buf.set_string(x, area.y, " ", style);
                x += 1;
            }
        }
    }

    fn format_column(&self, proc: &ProcessInfo, col: &SortColumn, width: u16) -> String {
        let w = width as usize;
        match col {
            SortColumn::Pid => format!("{:>w$}", proc.pid),
            SortColumn::User => {
                let u = &proc.user;
                if u.len() > w {
                    u[..w].to_string()
                } else {
                    format!("{:<w$}", u)
                }
            }
            SortColumn::Priority => format!("{:>w$}", proc.priority),
            SortColumn::Nice => format!("{:>w$}", proc.nice),
            SortColumn::Virt => format!("{:>w$}", format_bytes(proc.virt_bytes)),
            SortColumn::Res => format!("{:>w$}", format_bytes(proc.res_bytes)),
            SortColumn::Shr => format!("{:>w$}", format_bytes(proc.shr_bytes)),
            SortColumn::State => format!("{:>w$}", proc.state.as_char()),
            SortColumn::CpuPercent => format!("{:>w$.1}", proc.cpu_percent),
            SortColumn::MemPercent => format!("{:>w$.1}", proc.mem_percent),
            SortColumn::GpuPercent => format!("{:>w$.1}", proc.gpu_percent),
            SortColumn::GpuMem => format!("{:>w$}", format_bytes(proc.gpu_mem_bytes)),
            SortColumn::Time => {
                let t = format_time(proc.cpu_time_secs);
                format!("{:>w$}", t)
            }
            SortColumn::Container => {
                let name = proc.container.as_deref().unwrap_or("-");
                if name.len() > w {
                    name[..w].to_string()
                } else {
                    format!("{:<w$}", name)
                }
            }
            SortColumn::Service => {
                let name = proc.service.as_deref().unwrap_or("-");
                if name.len() > w {
                    name[..w].to_string()
                } else {
                    format!("{:<w$}", name)
                }
            }
            SortColumn::Command => {
                let display = format!("{}{}", proc.tree_prefix, proc.cmdline);
                if w > 0 && display.len() > w {
                    display[..w].to_string()
                } else {
                    display
                }
            }
        }
    }

    fn column_layout(&self, total_width: u16) -> Vec<(SortColumn, u16)> {
        let mut cols: Vec<(SortColumn, u16)> = SortColumn::all()
            .iter()
            .filter(|c| **c != SortColumn::Container || self.show_container)
            .filter(|c| **c != SortColumn::Service || self.show_service)
            .filter(|c| (**c != SortColumn::GpuPercent && **c != SortColumn::GpuMem) || self.show_gpu)
            .map(|c| (*c, c.width()))
            .collect();

        // Size UNIT column to fit content, capped per display mode
        if let Some(entry) = cols.iter_mut().find(|(c, _)| *c == SortColumn::Service) {
            let max_len = self.processes.iter()
                .filter_map(|p| p.service.as_deref())
                .map(|s| s.len())
                .max()
                .unwrap_or(4) as u16;
            let cap = match self.service_display_mode {
                ServiceDisplayMode::ServiceOnly => 20,
                ServiceDisplayMode::AllUnits => 28,
                ServiceDisplayMode::FullSlice => 40,
            };
            // At least wide enough for the header label, at most the cap
            entry.1 = max_len.clamp(5, cap);
        }

        // Calculate remaining width for Command column
        let fixed_width: u16 = cols.iter().filter(|(c, _)| *c != SortColumn::Command).map(|(_, w)| w + 1).sum();
        let cmd_width = total_width.saturating_sub(fixed_width);
        if let Some(entry) = cols.iter_mut().find(|(c, _)| *c == SortColumn::Command) {
            entry.1 = cmd_width;
        }

        cols
    }
}

/// Calculate visible row count for the process table area.
pub fn visible_rows(area: Rect) -> usize {
    area.height.saturating_sub(1) as usize // minus header row
}
