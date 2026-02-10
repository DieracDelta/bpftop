use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};

use crate::app::{App, AppMode};
use crate::data::process::SortColumn;
use crate::ui::dialogs::signal_list;
use crate::ui::filter_bar::FilterMode;

/// Handle a crossterm event, returning true if the app should quit.
pub fn handle_event(app: &mut App, event: Event) -> bool {
    match event {
        Event::Key(key) => handle_key(app, key),
        Event::Mouse(mouse) => {
            handle_mouse(app, mouse);
            false
        }
        Event::Resize(_, _) => false,
        _ => false,
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }

    match app.mode {
        AppMode::Normal => handle_normal_key(app, key),
        AppMode::Search => handle_filter_key(app, key, FilterMode::Search),
        AppMode::Filter => handle_filter_key(app, key, FilterMode::Filter),
        AppMode::Help => handle_help_key(app, key),
        AppMode::Kill => handle_kill_key(app, key),
        AppMode::SortSelect => handle_sort_key(app, key),
        AppMode::Visual => handle_visual_key(app, key),
    }
}

fn handle_normal_key(app: &mut App, key: KeyEvent) -> bool {
    // Handle pending multi-key sequences (e.g. gg)
    if let Some(pending) = app.pending_key.take() {
        match (pending, key.code) {
            ('g', KeyCode::Char('g')) => {
                               app.push_jump_mark();
                app.select_first();
                return false;
            }
            _ => { /* cancel pending, fall through to handle current key */ }
        }
    }

    // Ctrl+O = jump back, Tab = jump forward (Ctrl+I = Tab in terminals)
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('o') {
        app.jump_back();
        return false;
    }

    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::F(10) => return true,

        // Help
        KeyCode::F(1) | KeyCode::Char('?') => app.mode = AppMode::Help,

        // Search
        KeyCode::F(3) | KeyCode::Char('/') => {
            app.mode = AppMode::Search;
            app.filter_query.clear();
        }

        // Filter
        KeyCode::F(4) | KeyCode::Char('\\') => {
            app.mode = AppMode::Filter;
            app.filter_query.clear();
        }

        // Tree view
        KeyCode::F(5) | KeyCode::Char('t') => {
            app.tree_view = !app.tree_view;

            app.update_filtered_processes();
        }

        // Sort column select
        KeyCode::F(6) | KeyCode::Char('>') | KeyCode::Char('<') => {
            app.mode = AppMode::SortSelect;
        }

        // Kill (F9 only - 'k' is reserved for vi-nav)
        KeyCode::F(9) => {
            if !app.filtered_processes.is_empty() {
                app.kill_signal_idx = 0;
                app.mode = AppMode::Kill;
            }
        }

        // Navigation (vi-style j/k + arrows)
        KeyCode::Up | KeyCode::Char('k') => { app.move_selection(-1); }
        KeyCode::Down | KeyCode::Char('j') => { app.move_selection(1); }
        KeyCode::Home => { app.push_jump_mark(); app.select_first(); }
        KeyCode::End => { app.push_jump_mark(); app.select_last(); }
        KeyCode::PageUp => { app.push_jump_mark(); app.move_selection(-(app.visible_rows as i32)); }
        KeyCode::PageDown => { app.push_jump_mark(); app.move_selection(app.visible_rows as i32); }

        // gg / G vim motions
        KeyCode::Char('g') => app.pending_key = Some('g'),
        KeyCode::Char('G') => { app.push_jump_mark(); app.select_last(); }

        // Jump forward (Tab = Ctrl+I in terminals)
        KeyCode::Tab => app.jump_forward(),

        // Visual mode (Shift+V)
        KeyCode::Char('V') => {
            app.visual_anchor = Some(app.selected);
            app.mode = AppMode::Visual;
        }

        // Tag process
        KeyCode::Char(' ') => app.toggle_tag(),

        // User filter
        KeyCode::Char('u') => app.cycle_user_filter(),

        // Toggle threads
        KeyCode::Char('H') => {
            app.show_threads = !app.show_threads;

            app.update_filtered_processes();
        }
        KeyCode::Char('K') => {
            app.show_kernel_threads = !app.show_kernel_threads;

            app.update_filtered_processes();
        }

        // Quick sort
        KeyCode::Char('P') => {
            app.sort_column = SortColumn::CpuPercent;
            app.sort_ascending = false;

            app.update_filtered_processes();
        }
        KeyCode::Char('M') => {
            app.sort_column = SortColumn::MemPercent;
            app.sort_ascending = false;

            app.update_filtered_processes();
        }
        KeyCode::Char('T') => {
            app.sort_column = SortColumn::Time;
            app.sort_ascending = false;

            app.update_filtered_processes();
        }
        KeyCode::Char('I') => {
            app.sort_ascending = !app.sort_ascending;

            app.update_filtered_processes();
        }

        // Tree collapse/expand
        KeyCode::Char('+') | KeyCode::Char('=') => {
            if app.tree_view {
                app.expand_tree_node();
            }
        }
        KeyCode::Char('-') => {
            if app.tree_view {
                app.collapse_tree_node();
            }
        }

        _ => {}
    }

    false
}

fn handle_visual_key(app: &mut App, key: KeyEvent) -> bool {
    // Handle pending multi-key sequences in visual mode too
    if let Some(pending) = app.pending_key.take() {
        match (pending, key.code) {
            ('g', KeyCode::Char('g')) => {
                               app.select_first();
                return false;
            }
            _ => { /* cancel pending, fall through */ }
        }
    }

    match key.code {
        KeyCode::Esc => {
            app.visual_anchor = None;
            app.mode = AppMode::Normal;
        }
        KeyCode::Up | KeyCode::Char('k') => { app.move_selection(-1); }
        KeyCode::Down | KeyCode::Char('j') => { app.move_selection(1); }
        KeyCode::Char('g') => app.pending_key = Some('g'),
        KeyCode::Char('G') => { app.select_last(); }
        KeyCode::PageUp => { app.move_selection(-(app.visible_rows as i32)); }
        KeyCode::PageDown => { app.move_selection(app.visible_rows as i32); }

        // Space: tag the visual range and exit visual mode
        KeyCode::Char(' ') => {
            app.tag_visual_range();
            app.visual_anchor = None;
            app.mode = AppMode::Normal;
        }

        // F9: tag the visual range, open kill dialog, exit visual mode
        KeyCode::F(9) => {
            app.tag_visual_range();
            app.visual_anchor = None;
            app.kill_signal_idx = 0;
            app.mode = AppMode::Kill;
        }

        _ => {}
    }
    false
}

fn handle_filter_key(app: &mut App, key: KeyEvent, _mode: FilterMode) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.mode = AppMode::Normal;
            app.filter_query.clear();
            app.active_filter.clear();

            app.update_filtered_processes();
        }
        KeyCode::Enter => {
            app.push_jump_mark();
            app.active_filter = app.filter_query.clone();
            app.mode = AppMode::Normal;

            app.update_filtered_processes();
        }
        KeyCode::Backspace => {
            app.filter_query.pop();
            app.active_filter = app.filter_query.clone();

            app.update_filtered_processes();
        }
        KeyCode::Char(c) => {
            app.filter_query.push(c);
            app.active_filter = app.filter_query.clone();

            app.update_filtered_processes();
        }
        _ => {}
    }
    false
}

fn handle_help_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::F(1) | KeyCode::Char('q') | KeyCode::Char('?') => {
            app.mode = AppMode::Normal;
        }
        _ => {}
    }
    false
}

fn handle_kill_key(app: &mut App, key: KeyEvent) -> bool {
    let signals = signal_list();
    match key.code {
        KeyCode::Esc => app.mode = AppMode::Normal,
        KeyCode::Up | KeyCode::Char('k') => {
            if app.kill_signal_idx > 0 {
                app.kill_signal_idx -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.kill_signal_idx < signals.len() - 1 {
                app.kill_signal_idx += 1;
            }
        }
        KeyCode::Enter => {
            if let Some((sig_num, _)) = signals.get(app.kill_signal_idx) {
                app.send_signal(*sig_num);
            }
            app.mode = AppMode::Normal;
        }
        _ => {}
    }
    false
}

fn handle_sort_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => app.mode = AppMode::Normal,
        KeyCode::Up | KeyCode::Char('k') => {
            let cols = SortColumn::all();
            if let Some(pos) = cols.iter().position(|c| *c == app.sort_column) {
                if pos > 0 {
                    app.sort_column = cols[pos - 1];
        
                    app.update_filtered_processes();
                }
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let cols = SortColumn::all();
            if let Some(pos) = cols.iter().position(|c| *c == app.sort_column) {
                if pos < cols.len() - 1 {
                    app.sort_column = cols[pos + 1];
        
                    app.update_filtered_processes();
                }
            }
        }
        KeyCode::Enter => app.mode = AppMode::Normal,
        _ => {}
    }
    false
}

fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => app.move_selection(-3),
        MouseEventKind::ScrollDown => app.move_selection(3),
        MouseEventKind::Down(_) => {
            // Click to select a process row
            // header_height rows + 1 column header row
            let header_offset = app.header_height + 1;
            if mouse.row >= header_offset {
                let row = (mouse.row - header_offset) as usize + app.scroll_offset;
                if row < app.filtered_processes.len() {
                    app.selected = row;
                }
            }
        }
        _ => {}
    }
}
