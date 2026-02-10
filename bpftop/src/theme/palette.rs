use ratatui::style::Color;

/// Gruvbox color palette definitions.
/// See: https://github.com/morhetz/gruvbox

// === Dark background shades ===
pub const DARK_BG: Color = Color::Rgb(40, 40, 40);       // #282828 bg
pub const DARK_BG0_H: Color = Color::Rgb(29, 32, 33);    // #1d2021 bg0_h (hard)
pub const DARK_BG0_S: Color = Color::Rgb(50, 48, 47);    // #32302f bg0_s (soft)
pub const DARK_BG1: Color = Color::Rgb(60, 56, 54);      // #3c3836
pub const DARK_BG2: Color = Color::Rgb(80, 73, 69);      // #504945
pub const DARK_BG3: Color = Color::Rgb(102, 92, 84);     // #665c54
pub const DARK_BG4: Color = Color::Rgb(124, 111, 100);   // #7c6f64

// === Light background shades ===
pub const LIGHT_BG: Color = Color::Rgb(251, 241, 199);   // #fbf1c7 bg
pub const LIGHT_BG0_H: Color = Color::Rgb(249, 245, 215);// #f9f5d7 bg0_h (hard)
pub const LIGHT_BG0_S: Color = Color::Rgb(242, 229, 188);// #f2e5bc bg0_s (soft)
pub const LIGHT_BG1: Color = Color::Rgb(235, 219, 178);  // #ebdbb2
pub const LIGHT_BG2: Color = Color::Rgb(213, 196, 161);  // #d5c4a1
pub const LIGHT_BG3: Color = Color::Rgb(189, 174, 147);  // #bdae93
pub const LIGHT_BG4: Color = Color::Rgb(168, 153, 132);  // #a89984

// === Dark foreground shades ===
pub const DARK_FG: Color = Color::Rgb(235, 219, 178);    // #ebdbb2 fg
pub const DARK_FG1: Color = Color::Rgb(235, 219, 178);   // #ebdbb2
pub const DARK_FG2: Color = Color::Rgb(213, 196, 161);   // #d5c4a1
pub const DARK_FG3: Color = Color::Rgb(189, 174, 147);   // #bdae93
pub const DARK_FG4: Color = Color::Rgb(168, 153, 132);   // #a89984

// === Light foreground shades ===
pub const LIGHT_FG: Color = Color::Rgb(60, 56, 54);      // #3c3836 fg
pub const LIGHT_FG1: Color = Color::Rgb(60, 56, 54);     // #3c3836
pub const LIGHT_FG2: Color = Color::Rgb(80, 73, 69);     // #504945
pub const LIGHT_FG3: Color = Color::Rgb(102, 92, 84);    // #665c54
pub const LIGHT_FG4: Color = Color::Rgb(124, 111, 100);  // #7c6f64

// === Normal accent colors ===
pub const RED: Color = Color::Rgb(204, 36, 29);          // #cc241d
pub const GREEN: Color = Color::Rgb(152, 151, 26);       // #98971a
pub const YELLOW: Color = Color::Rgb(215, 153, 33);      // #d79921
pub const BLUE: Color = Color::Rgb(69, 133, 136);        // #458588
pub const PURPLE: Color = Color::Rgb(177, 98, 134);      // #b16286
pub const AQUA: Color = Color::Rgb(104, 157, 106);       // #689d6a
pub const ORANGE: Color = Color::Rgb(214, 93, 14);       // #d65d0e

// === Bright accent colors ===
pub const BR_RED: Color = Color::Rgb(251, 73, 52);       // #fb4934
pub const BR_GREEN: Color = Color::Rgb(184, 187, 38);    // #b8bb26
pub const BR_YELLOW: Color = Color::Rgb(250, 189, 47);   // #fabd2f
pub const BR_BLUE: Color = Color::Rgb(131, 165, 152);    // #83a598
pub const BR_PURPLE: Color = Color::Rgb(211, 134, 155);  // #d3869b
pub const BR_AQUA: Color = Color::Rgb(142, 192, 124);    // #8ec07c
pub const BR_ORANGE: Color = Color::Rgb(254, 128, 25);   // #fe8019
