use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;

use crate::theme::Theme;

/// Renders the incremental search/filter input bar.
pub struct FilterBarWidget<'a> {
    pub query: &'a str,
    pub mode: FilterMode,
    pub theme: &'a Theme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// F3 search - highlights matching process, moves selection to it.
    Search,
    /// F4 filter - hides non-matching processes.
    Filter,
}

impl<'a> Widget for FilterBarWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let bg_style = Style::default()
            .fg(self.theme.fg)
            .bg(self.theme.status_bg);

        // Fill background
        for x in area.x..area.x + area.width {
            buf[(x, area.y)].set_style(bg_style);
        }

        let label = match self.mode {
            FilterMode::Search => "Search: ",
            FilterMode::Filter => "Filter: ",
        };

        let line = Line::from(vec![
            Span::styled(
                label,
                Style::default()
                    .fg(self.theme.status_key)
                    .bg(self.theme.status_bg),
            ),
            Span::styled(
                self.query,
                Style::default()
                    .fg(self.theme.selection_fg)
                    .bg(self.theme.status_bg),
            ),
            Span::styled(
                "_",
                Style::default()
                    .fg(self.theme.selection_fg)
                    .bg(self.theme.status_bg),
            ),
        ]);

        buf.set_line(area.x, area.y, &line, area.width);
    }
}
