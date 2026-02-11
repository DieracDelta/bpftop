pub mod gruvbox;
pub mod palette;

use ratatui::style::Color;
use serde::{Deserialize, Serialize};

/// Semantic color roles for the TUI. Each field maps to a specific
/// UI element purpose rather than a raw color name.
#[derive(Debug, Clone)]
pub struct Theme {
    // Layout
    pub bg: Color,
    pub fg: Color,
    pub border: Color,
    pub header_bg: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,

    // Meters
    pub cpu_user: Color,
    pub cpu_system: Color,
    pub cpu_nice: Color,
    pub cpu_iowait: Color,
    pub mem_used: Color,
    pub mem_cached: Color,
    pub mem_buffers: Color,
    pub swap_used: Color,
    pub gpu_util: Color,
    pub gpu_mem: Color,

    // Process states
    pub proc_running: Color,
    pub proc_sleeping: Color,
    pub proc_zombie: Color,
    pub proc_stopped: Color,

    // Status bar
    pub status_bg: Color,
    pub status_fg: Color,
    pub status_key: Color,

    // Column headers
    pub column_header_fg: Color,
    pub column_header_bg: Color,

    // Visual mode
    pub visual_bg: Color,
}

impl Default for Theme {
    fn default() -> Self {
        gruvbox::dark()
    }
}

impl Theme {
    /// Create a theme from a preset name, with optional color overrides.
    pub fn from_config(preset: &str, overrides: &ThemeOverrides) -> Self {
        let mut theme = match preset {
            "gruvbox-light" => gruvbox::light(),
            _ => gruvbox::dark(),
        };
        theme.apply_overrides(overrides);
        theme
    }

    fn apply_overrides(&mut self, ov: &ThemeOverrides) {
        if let Some(c) = ov.bg.as_deref().and_then(parse_hex_color) { self.bg = c; }
        if let Some(c) = ov.fg.as_deref().and_then(parse_hex_color) { self.fg = c; }
        if let Some(c) = ov.border.as_deref().and_then(parse_hex_color) { self.border = c; }
        if let Some(c) = ov.header_bg.as_deref().and_then(parse_hex_color) { self.header_bg = c; }
        if let Some(c) = ov.selection_bg.as_deref().and_then(parse_hex_color) { self.selection_bg = c; }
        if let Some(c) = ov.selection_fg.as_deref().and_then(parse_hex_color) { self.selection_fg = c; }
        if let Some(c) = ov.cpu_user.as_deref().and_then(parse_hex_color) { self.cpu_user = c; }
        if let Some(c) = ov.cpu_system.as_deref().and_then(parse_hex_color) { self.cpu_system = c; }
        if let Some(c) = ov.cpu_nice.as_deref().and_then(parse_hex_color) { self.cpu_nice = c; }
        if let Some(c) = ov.cpu_iowait.as_deref().and_then(parse_hex_color) { self.cpu_iowait = c; }
        if let Some(c) = ov.mem_used.as_deref().and_then(parse_hex_color) { self.mem_used = c; }
        if let Some(c) = ov.mem_cached.as_deref().and_then(parse_hex_color) { self.mem_cached = c; }
        if let Some(c) = ov.mem_buffers.as_deref().and_then(parse_hex_color) { self.mem_buffers = c; }
        if let Some(c) = ov.swap_used.as_deref().and_then(parse_hex_color) { self.swap_used = c; }
        if let Some(c) = ov.gpu_util.as_deref().and_then(parse_hex_color) { self.gpu_util = c; }
        if let Some(c) = ov.gpu_mem.as_deref().and_then(parse_hex_color) { self.gpu_mem = c; }
        if let Some(c) = ov.status_key.as_deref().and_then(parse_hex_color) { self.status_key = c; }
        if let Some(c) = ov.visual_bg.as_deref().and_then(parse_hex_color) { self.visual_bg = c; }
    }
}

/// Deserializable theme override section from config TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThemeOverrides {
    pub bg: Option<String>,
    pub fg: Option<String>,
    pub border: Option<String>,
    pub header_bg: Option<String>,
    pub selection_bg: Option<String>,
    pub selection_fg: Option<String>,
    pub cpu_user: Option<String>,
    pub cpu_system: Option<String>,
    pub cpu_nice: Option<String>,
    pub cpu_iowait: Option<String>,
    pub mem_used: Option<String>,
    pub mem_cached: Option<String>,
    pub mem_buffers: Option<String>,
    pub swap_used: Option<String>,
    pub gpu_util: Option<String>,
    pub gpu_mem: Option<String>,
    pub status_key: Option<String>,
    pub visual_bg: Option<String>,
}

/// Parse a hex color string like "#fb4934" into a ratatui Color.
fn parse_hex_color(s: &str) -> Option<Color> {
    let s = s.strip_prefix('#')?;
    if s.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&s[0..2], 16).ok()?;
    let g = u8::from_str_radix(&s[2..4], 16).ok()?;
    let b = u8::from_str_radix(&s[4..6], 16).ok()?;
    Some(Color::Rgb(r, g, b))
}
