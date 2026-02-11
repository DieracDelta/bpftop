use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap};

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
            ("yn", "Yank command name"),
            ("yl", "Yank full cmdline"),
            ("yg", "Yank GPU%"),
            ("yv", "Yank VRAM usage"),
            ("Space", "Tag process"),
            ("u", "Filter by user"),
            ("H", "Toggle user threads"),
            ("K", "Toggle kernel threads"),
            ("P", "Sort by CPU%"),
            ("M", "Sort by MEM%"),
            ("T", "Sort by TIME"),
            ("I", "Invert sort order"),
            ("+ / -", "Expand/Collapse tree node"),
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
