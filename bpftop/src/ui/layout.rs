use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Compute the number of columns and rows for the CPU grid.
pub fn cpu_grid_dims(num_cpus: usize, terminal_width: u16) -> (usize, usize) {
    let min_col_width: u16 = 20;
    let max_cols = (terminal_width / min_col_width).max(1) as usize;
    let cols = max_cols.min(num_cpus).max(1);
    let rows = (num_cpus + cols - 1) / cols;
    (cols, rows)
}

/// Main screen layout: header | process_table | status_bar.
/// Returns (header_area, table_area, status_area, filter_area).
pub fn main_layout(area: Rect, filter_active: bool, num_cpus: usize) -> (Rect, Rect, Rect, Option<Rect>) {
    let (_, cpu_rows) = cpu_grid_dims(num_cpus, area.width);
    let header_height = (cpu_rows + 3) as u16; // cpu grid + mem + swap + info line
    let status_height = 1;
    let filter_height = if filter_active { 1 } else { 0 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height),
            Constraint::Min(5),
            Constraint::Length(filter_height),
            Constraint::Length(status_height),
        ])
        .split(area);

    let filter_area = if filter_active {
        Some(chunks[2])
    } else {
        None
    };

    (chunks[0], chunks[1], chunks[3], filter_area)
}
