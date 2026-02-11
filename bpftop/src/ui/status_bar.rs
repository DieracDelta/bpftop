use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;

use crate::theme::Theme;

/// Renders the bottom status bar with F-key hints.
pub struct StatusBarWidget<'a> {
    pub theme: &'a Theme,
    pub ebpf_loaded: bool,
    pub flash: Option<&'a str>,
}

impl<'a> Widget for StatusBarWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let bg_style = Style::default()
            .fg(self.theme.status_fg)
            .bg(self.theme.status_bg);

        // Fill background
        for x in area.x..area.x + area.width {
            buf[(x, area.y)].set_style(bg_style);
        }

        let key_style = Style::default()
            .fg(self.theme.status_key)
            .bg(self.theme.status_bg);
        let label_style = bg_style;

        let keys = [
            ("?", "Help"),
            ("/", "Search"),
            ("\\", "Filter"),
            ("t", "Tree"),
            ("><", "Sort"),
            ("x", "Kill"),
            ("q", "Quit"),
        ];

        let mut spans = Vec::new();
        for (key, label) in &keys {
            spans.push(Span::styled(*key, key_style));
            spans.push(Span::styled(*label, label_style));
            spans.push(Span::styled(" ", label_style));
        }

        // Add eBPF indicator
        if self.ebpf_loaded {
            spans.push(Span::styled(
                " [eBPF]",
                Style::default()
                    .fg(self.theme.proc_running)
                    .bg(self.theme.status_bg),
            ));
        }

        // Flash message (transient yank feedback etc.)
        if let Some(flash) = self.flash {
            spans.push(Span::styled(
                format!("  {flash}"),
                Style::default()
                    .fg(self.theme.status_key)
                    .bg(self.theme.status_bg)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ));
        }

        let line = Line::from(spans);
        buf.set_line(area.x, area.y, &line, area.width);
    }
}
