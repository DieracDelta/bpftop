use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;

use crate::data::system::{format_uptime, CpuStats, MemoryInfo, SwapInfo, SystemInfo};
use crate::theme::Theme;
use crate::ui::layout::cpu_grid_dims;

/// Renders the header area with CPU grid, memory bar, swap, and info line.
pub struct HeaderWidget<'a> {
    pub sys: &'a SystemInfo,
    pub theme: &'a Theme,
}

impl<'a> Widget for HeaderWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 2 {
            return;
        }

        let num_cpus = self.sys.cpus.len();
        if num_cpus == 0 {
            return;
        }
        let (grid_cols, grid_rows) = cpu_grid_dims(num_cpus, area.width);

        // Vertical layout: cpu_rows + mem + swap + info
        let mut constraints: Vec<Constraint> = (0..grid_rows)
            .map(|_| Constraint::Length(1))
            .collect();
        constraints.push(Constraint::Length(1)); // mem
        constraints.push(Constraint::Length(1)); // swap
        constraints.push(Constraint::Length(1)); // info line

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area);

        // CPU grid: column-major fill like htop
        for grid_row in 0..grid_rows {
            let row_area = rows[grid_row];
            // Split this row into grid_cols columns
            let col_constraints: Vec<Constraint> = (0..grid_cols)
                .map(|_| Constraint::Ratio(1, grid_cols as u32))
                .collect();
            let col_areas = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(col_constraints)
                .split(row_area);

            for grid_col in 0..grid_cols {
                let cpu_idx = grid_col * grid_rows + grid_row;
                if cpu_idx < num_cpus {
                    let label = format!("{cpu_idx}");
                    // Shrink area by 1 on the right to leave a gap between columns
                    let mut bar_area = col_areas[grid_col];
                    if grid_col + 1 < grid_cols && bar_area.width > 1 {
                        bar_area.width -= 1;
                    }
                    render_cpu_bar(buf, bar_area, &self.sys.cpus[cpu_idx], &label, self.theme);
                }
            }
        }

        // Mem bar (full width)
        let mem_row = grid_rows;
        if mem_row < rows.len() {
            render_mem_bar(buf, rows[mem_row], &self.sys.memory, self.theme);
        }

        // Swap bar (full width)
        let swap_row = grid_rows + 1;
        if swap_row < rows.len() {
            render_swap_bar(buf, rows[swap_row], &self.sys.swap, self.theme);
        }

        // Info line (full width): Tasks: N, N running  Load: x.xx x.xx x.xx  Uptime: Xd HH:MM:SS
        let info_row = grid_rows + 2;
        if info_row < rows.len() {
            let info_area = rows[info_row];
            let line = Line::from(vec![
                Span::styled("Tasks: ", Style::default().fg(self.theme.fg)),
                Span::styled(
                    format!("{}", self.sys.total_tasks),
                    Style::default().fg(self.theme.fg),
                ),
                Span::styled(
                    format!(", {} thr, {} kthr", self.sys.user_threads, self.sys.kernel_threads),
                    Style::default().fg(self.theme.fg),
                ),
                Span::styled("; ", Style::default().fg(self.theme.fg)),
                Span::styled(
                    format!("{} running", self.sys.running_tasks),
                    Style::default().fg(self.theme.proc_running),
                ),
                Span::styled("  ", Style::default().fg(self.theme.fg)),
                Span::styled("Load: ", Style::default().fg(self.theme.fg)),
                Span::styled(
                    format!(
                        "{:.2} {:.2} {:.2}",
                        self.sys.load_avg[0], self.sys.load_avg[1], self.sys.load_avg[2]
                    ),
                    Style::default().fg(self.theme.fg),
                ),
                Span::styled("  ", Style::default().fg(self.theme.fg)),
                Span::styled("Uptime: ", Style::default().fg(self.theme.fg)),
                Span::styled(
                    format_uptime(self.sys.uptime_secs),
                    Style::default().fg(self.theme.fg),
                ),
            ]);
            buf.set_line(info_area.x, info_area.y, &line, info_area.width);
        }
    }
}

fn render_cpu_bar(buf: &mut Buffer, area: Rect, cpu: &CpuStats, label: &str, theme: &Theme) {
    if area.width < 10 {
        return;
    }

    let prefix = format!("{label}[");
    let suffix = format!("{:4.1}%]", cpu.total_pct);
    let bar_width = (area.width as usize).saturating_sub(prefix.len() + suffix.len());
    if bar_width == 0 {
        return;
    }

    // Bar fill matches total_pct: all busy components (excludes idle and iowait)
    // irq + softirq + steal are folded into system color since they're kernel-side
    let irq_pct = 100.0 - cpu.user_pct - cpu.nice_pct - cpu.system_pct - cpu.iowait_pct - cpu.idle_pct;
    let irq_pct = irq_pct.max(0.0);
    let user_chars = ((cpu.user_pct / 100.0) * bar_width as f64) as usize;
    let sys_chars = (((cpu.system_pct + irq_pct) / 100.0) * bar_width as f64) as usize;
    let nice_chars = ((cpu.nice_pct / 100.0) * bar_width as f64) as usize;
    let empty_chars = bar_width.saturating_sub(user_chars + sys_chars + nice_chars);

    let mut spans = vec![Span::styled(prefix, Style::default().fg(theme.fg))];
    if user_chars > 0 {
        spans.push(Span::styled(
            "|".repeat(user_chars),
            Style::default().fg(theme.cpu_user),
        ));
    }
    if sys_chars > 0 {
        spans.push(Span::styled(
            "|".repeat(sys_chars),
            Style::default().fg(theme.cpu_system),
        ));
    }
    if nice_chars > 0 {
        spans.push(Span::styled(
            "|".repeat(nice_chars),
            Style::default().fg(theme.cpu_nice),
        ));
    }
    if empty_chars > 0 {
        spans.push(Span::styled(
            " ".repeat(empty_chars),
            Style::default().fg(theme.fg),
        ));
    }
    spans.push(Span::styled(suffix, Style::default().fg(theme.fg)));

    let line = Line::from(spans);
    buf.set_line(area.x, area.y, &line, area.width);
}

fn render_mem_bar(buf: &mut Buffer, area: Rect, mem: &MemoryInfo, theme: &Theme) {
    if area.width < 10 {
        return;
    }

    let total_gb = mem.total as f64 / (1024.0 * 1024.0 * 1024.0);
    let used_gb = mem.used as f64 / (1024.0 * 1024.0 * 1024.0);
    let prefix = "Mem[";
    let suffix = format!("{used_gb:.1}G/{total_gb:.1}G]");
    let bar_width = (area.width as usize).saturating_sub(prefix.len() + suffix.len());
    if bar_width == 0 {
        return;
    }

    let used_pct = if mem.total > 0 { mem.used as f64 / mem.total as f64 } else { 0.0 };
    let cached_pct = if mem.total > 0 { mem.cached as f64 / mem.total as f64 } else { 0.0 };
    let buffers_pct = if mem.total > 0 { mem.buffers as f64 / mem.total as f64 } else { 0.0 };

    let used_chars = (used_pct * bar_width as f64) as usize;
    let cached_chars = (cached_pct * bar_width as f64) as usize;
    let buf_chars = (buffers_pct * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(used_chars + cached_chars + buf_chars);

    let mut spans = vec![Span::styled(prefix, Style::default().fg(theme.fg))];
    if used_chars > 0 {
        spans.push(Span::styled("|".repeat(used_chars), Style::default().fg(theme.mem_used)));
    }
    if buf_chars > 0 {
        spans.push(Span::styled("|".repeat(buf_chars), Style::default().fg(theme.mem_buffers)));
    }
    if cached_chars > 0 {
        spans.push(Span::styled("|".repeat(cached_chars), Style::default().fg(theme.mem_cached)));
    }
    if empty > 0 {
        spans.push(Span::styled(" ".repeat(empty), Style::default().fg(theme.fg)));
    }
    spans.push(Span::styled(suffix, Style::default().fg(theme.fg)));

    let line = Line::from(spans);
    buf.set_line(area.x, area.y, &line, area.width);
}

fn render_swap_bar(buf: &mut Buffer, area: Rect, swap: &SwapInfo, theme: &Theme) {
    if area.width < 10 || swap.total == 0 {
        let line = Line::from(Span::styled("Swp[N/A]", Style::default().fg(theme.fg)));
        buf.set_line(area.x, area.y, &line, area.width);
        return;
    }

    let total_gb = swap.total as f64 / (1024.0 * 1024.0 * 1024.0);
    let used_gb = swap.used as f64 / (1024.0 * 1024.0 * 1024.0);
    let prefix = "Swp[";
    let suffix = format!("{used_gb:.1}G/{total_gb:.1}G]");
    let bar_width = (area.width as usize).saturating_sub(prefix.len() + suffix.len());
    if bar_width == 0 {
        return;
    }

    let used_pct = swap.used as f64 / swap.total as f64;
    let used_chars = (used_pct * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(used_chars);

    let mut spans = vec![Span::styled(prefix, Style::default().fg(theme.fg))];
    if used_chars > 0 {
        spans.push(Span::styled("|".repeat(used_chars), Style::default().fg(theme.swap_used)));
    }
    if empty > 0 {
        spans.push(Span::styled(" ".repeat(empty), Style::default().fg(theme.fg)));
    }
    spans.push(Span::styled(suffix, Style::default().fg(theme.fg)));

    let line = Line::from(spans);
    buf.set_line(area.x, area.y, &line, area.width);
}
