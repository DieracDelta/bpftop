use super::palette::*;
use super::Theme;

/// Returns the gruvbox dark theme.
pub fn dark() -> Theme {
    Theme {
        // Layout
        bg: DARK_BG,
        fg: DARK_FG,
        border: DARK_BG3,
        header_bg: DARK_BG,
        selection_bg: DARK_BG2,
        selection_fg: BR_YELLOW,

        // Meters
        cpu_user: BR_GREEN,
        cpu_system: BR_RED,
        cpu_nice: BR_BLUE,
        cpu_iowait: BR_YELLOW,
        mem_used: BR_GREEN,
        mem_cached: BR_BLUE,
        mem_buffers: BR_AQUA,
        swap_used: BR_ORANGE,
        gpu_util: BR_PURPLE,
        gpu_mem: BR_AQUA,

        // Process states
        proc_running: BR_GREEN,
        proc_sleeping: DARK_FG,
        proc_zombie: BR_RED,
        proc_stopped: BR_YELLOW,
        proc_frozen: BR_BLUE,

        // Status bar
        status_bg: DARK_BG2,
        status_fg: DARK_FG,
        status_key: BR_ORANGE,

        // Column headers
        column_header_fg: DARK_BG,
        column_header_bg: BR_GREEN,

        // Visual mode
        visual_bg: DARK_BG3,
    }
}

/// Returns the gruvbox light theme.
pub fn light() -> Theme {
    Theme {
        // Layout
        bg: LIGHT_BG,
        fg: LIGHT_FG,
        border: LIGHT_BG3,
        header_bg: LIGHT_BG,
        selection_bg: LIGHT_BG2,
        selection_fg: ORANGE,

        // Meters
        cpu_user: GREEN,
        cpu_system: RED,
        cpu_nice: BLUE,
        cpu_iowait: YELLOW,
        mem_used: GREEN,
        mem_cached: BLUE,
        mem_buffers: AQUA,
        swap_used: ORANGE,
        gpu_util: PURPLE,
        gpu_mem: AQUA,

        // Process states
        proc_running: GREEN,
        proc_sleeping: LIGHT_FG,
        proc_zombie: RED,
        proc_stopped: YELLOW,
        proc_frozen: BLUE,

        // Status bar
        status_bg: LIGHT_BG2,
        status_fg: LIGHT_FG,
        status_key: ORANGE,

        // Column headers
        column_header_fg: LIGHT_BG,
        column_header_bg: GREEN,

        // Visual mode
        visual_bg: LIGHT_BG3,
    }
}
