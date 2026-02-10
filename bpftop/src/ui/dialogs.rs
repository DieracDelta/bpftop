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
    pub pid: u32,
    pub selected_signal: usize,
    pub theme: &'a Theme,
}

impl<'a> Widget for KillDialog<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog = centered_rect(40, 60, area);
        Clear.render(dialog, buf);

        let title = format!(" Send signal to PID {} ", self.pid);
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border))
            .style(Style::default().bg(self.theme.bg));

        let inner = block.inner(dialog);
        block.render(dialog, buf);

        let signals = signal_list();

        let lines: Vec<Line> = signals
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

        let para = Paragraph::new(lines);
        para.render(inner, buf);
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
