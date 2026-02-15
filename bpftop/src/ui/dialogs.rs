use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap};

use crate::app::FreezeTarget;
use crate::theme::Theme;

/// Help overlay showing all keybindings.
pub struct HelpDialog<'a> {
    pub theme: &'a Theme,
}

impl<'a> Widget for HelpDialog<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog = centered_rect(60, 80, area);

        // Clear the area behind the dialog
        Clear.render(dialog, buf);

        let block = Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border))
            .style(Style::default().bg(self.theme.bg));

        let inner = block.inner(dialog);
        block.render(dialog, buf);

        let key_style = Style::default()
            .fg(self.theme.status_key)
            .add_modifier(Modifier::BOLD);
        let desc_style = Style::default().fg(self.theme.fg);

        let bindings = [
            ("q", "Quit"),
            ("?", "This help"),
            ("/", "Incremental search"),
            ("\\", "Filter processes"),
            ("t", "Toggle tree view"),
            ("> <", "Sort column select"),
            ("x", "Kill process (send signal)"),
            ("f", "Freeze cgroup"),
            ("u / U", "Thaw (dialog / instant)"),
            ("j / k", "Navigate down / up"),
            ("gg", "Jump to top"),
            ("G", "Jump to bottom"),
            ("Ctrl+O", "Jump back"),
            ("Tab", "Jump forward"),
            ("V", "Visual mode"),
            ("yy", "Yank row to clipboard"),
            ("yp", "Yank PID"),
            ("yu", "Yank user"),
            ("yc", "Yank container"),
            ("ys", "Yank service/unit"),
            ("yn", "Yank command name"),
            ("yl", "Yank full cmdline"),
            ("yg", "Yank GPU%"),
            ("yv", "Yank VRAM usage"),
            ("Space", "Tag process"),
            ("H", "Toggle user threads"),
            ("K", "Toggle kernel threads"),
            ("P", "Sort by CPU%"),
            ("M", "Sort by MEM%"),
            ("T", "Sort by TIME"),
            ("N", "Sort by GPU%"),
            ("W", "Sort by GPU MEM"),
            ("I", "Invert sort order"),
            ("S", "Toggle full slice path"),
            ("A", "Toggle all unit types"),
            ("+ / -", "Expand/Collapse tree node"),
            ("zo / zc", "Open/Close fold (vim)"),
            ("za", "Toggle fold"),
            ("zO / zC", "Open/Close fold recursive"),
            ("zR / zM", "Open/Close all folds"),
        ];

        let lines: Vec<Line> = bindings
            .iter()
            .map(|(key, desc)| {
                Line::from(vec![
                    Span::styled(format!("{:<18}", key), key_style),
                    Span::styled(*desc, desc_style),
                ])
            })
            .collect();

        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        para.render(inner, buf);
    }
}

/// Kill signal picker dialog.
pub struct KillDialog<'a> {
    pub pids: &'a [u32],
    pub pid_scroll: usize,
    pub selected_signal: usize,
    pub theme: &'a Theme,
}

impl<'a> Widget for KillDialog<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let multi = self.pids.len() > 1;
        let dialog = centered_rect(if multi { 55 } else { 40 }, 60, area);
        Clear.render(dialog, buf);

        let title = if self.pids.len() == 1 {
            format!(" Send signal to PID {} ", self.pids[0])
        } else {
            format!(" Send signal to {} PIDs ", self.pids.len())
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border))
            .style(Style::default().bg(self.theme.bg));

        let inner = block.inner(dialog);
        block.render(dialog, buf);

        let signals = signal_list();

        // Build signal lines (shared by both paths)
        let signal_lines: Vec<Line> = signals
            .iter()
            .enumerate()
            .map(|(i, (num, name))| {
                let style = if i == self.selected_signal {
                    Style::default()
                        .fg(self.theme.selection_fg)
                        .bg(self.theme.selection_bg)
                } else {
                    Style::default().fg(self.theme.fg)
                };
                Line::styled(format!("{:>2}) {}", num, name), style)
            })
            .collect();

        if !multi {
            Paragraph::new(signal_lines).render(inner, buf);
            return;
        }

        // Horizontal split: signals on left, PID list on right
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(16), // signal column
                Constraint::Length(1),  // divider
                Constraint::Min(8),    // PID list
            ])
            .split(inner);

        // Left: signal list
        Paragraph::new(signal_lines).render(chunks[0], buf);

        // Divider
        let dim_style = Style::default().fg(self.theme.border);
        let divider_lines: Vec<Line> = (0..chunks[1].height)
            .map(|_| Line::styled("\u{2502}", dim_style))
            .collect();
        Paragraph::new(divider_lines).render(chunks[1], buf);

        // Right: scrollable PID list
        let pid_style = Style::default()
            .fg(self.theme.status_key)
            .add_modifier(Modifier::BOLD);

        let pid_area = chunks[2];
        // Reserve 1 row for scroll indicator if needed
        let visible = if self.pids.len() > pid_area.height as usize {
            (pid_area.height as usize).saturating_sub(1)
        } else {
            pid_area.height as usize
        };
        let scroll = self.pid_scroll.min(self.pids.len().saturating_sub(visible));

        let mut pid_lines: Vec<Line> = self.pids
            .iter()
            .skip(scroll)
            .take(visible)
            .map(|pid| Line::styled(format!(" {pid}"), pid_style))
            .collect();

        // Scroll indicator at bottom if list overflows
        if self.pids.len() > visible {
            let showing_end = (scroll + visible).min(self.pids.len());
            pid_lines.push(Line::styled(
                format!(" h/l {}-{}/{}", scroll + 1, showing_end, self.pids.len()),
                dim_style,
            ));
        }

        Paragraph::new(pid_lines).render(pid_area, buf);
    }
}

/// Freeze/thaw confirmation dialog.
pub struct FreezeDialog<'a> {
    pub targets: &'a [FreezeTarget],
    pub is_thaw: bool,
    pub scroll: usize,
    pub theme: &'a Theme,
}

impl<'a> Widget for FreezeDialog<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog = centered_rect(55, 50, area);
        Clear.render(dialog, buf);

        // Build title based on targets
        let title = if self.targets.len() == 1 {
            let t = &self.targets[0];
            let action = if self.is_thaw { "Thaw" } else { "Freeze" };
            if t.is_root && !self.is_thaw {
                format!(" Create cgroup and freeze PID {} ", t.pids.first().unwrap_or(&0))
            } else {
                format!(" {action} cgroup {} ", t.cgroup_path)
            }
        } else {
            let action = if self.is_thaw { "Thaw" } else { "Freeze" };
            format!(" {action} {} cgroups ", self.targets.len())
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border))
            .style(Style::default().bg(self.theme.bg));

        let inner = block.inner(dialog);
        block.render(dialog, buf);

        let pid_style = Style::default()
            .fg(self.theme.status_key)
            .add_modifier(Modifier::BOLD);
        let label_style = Style::default()
            .fg(self.theme.fg)
            .add_modifier(Modifier::BOLD);
        let dim_style = Style::default().fg(self.theme.border);
        let footer_style = Style::default().fg(self.theme.fg);

        // Build lines: for each target, show cgroup path header then PIDs
        let mut all_lines: Vec<Line> = Vec::new();
        for target in self.targets {
            if self.targets.len() > 1 {
                all_lines.push(Line::styled(
                    format!("  {}", target.cgroup_path),
                    label_style,
                ));
            }
            let total = target.pids.len();
            all_lines.push(Line::styled(
                format!("  {} process(es) affected:", total),
                dim_style,
            ));
            for pid in &target.pids {
                all_lines.push(Line::styled(format!("    {pid}"), pid_style));
            }
        }

        // Reserve 2 rows for footer
        let content_height = inner.height.saturating_sub(2) as usize;
        let total_lines = all_lines.len();
        let scroll = self.scroll.min(total_lines.saturating_sub(content_height));

        let visible_lines: Vec<Line> = all_lines
            .into_iter()
            .skip(scroll)
            .take(content_height)
            .collect();

        let content_area = Rect {
            height: inner.height.saturating_sub(2),
            ..inner
        };
        Paragraph::new(visible_lines).render(content_area, buf);

        // Scroll indicator
        if total_lines > content_height {
            let showing_end = (scroll + content_height).min(total_lines);
            let indicator = Line::styled(
                format!("  j/k {}-{}/{}", scroll + 1, showing_end, total_lines),
                dim_style,
            );
            let indicator_area = Rect {
                y: inner.y + inner.height.saturating_sub(2),
                height: 1,
                ..inner
            };
            Paragraph::new(vec![indicator]).render(indicator_area, buf);
        }

        // Footer: [Enter] Confirm  [Esc] Cancel
        let footer = Line::from(vec![
            Span::styled("[Enter]", pid_style),
            Span::styled(" Confirm  ", footer_style),
            Span::styled("[Esc]", pid_style),
            Span::styled(" Cancel", footer_style),
        ]);
        let footer_area = Rect {
            y: inner.y + inner.height.saturating_sub(1),
            height: 1,
            ..inner
        };
        Paragraph::new(vec![footer]).render(footer_area, buf);
    }
}

/// Returns the list of common signals for the kill dialog.
pub fn signal_list() -> Vec<(i32, &'static str)> {
    vec![
        (15, "SIGTERM"),
        (9, "SIGKILL"),
        (1, "SIGHUP"),
        (2, "SIGINT"),
        (3, "SIGQUIT"),
        (6, "SIGABRT"),
        (10, "SIGUSR1"),
        (12, "SIGUSR2"),
        (18, "SIGCONT"),
        (19, "SIGSTOP"),
    ]
}

/// Center a rectangle within an area by percentage.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
