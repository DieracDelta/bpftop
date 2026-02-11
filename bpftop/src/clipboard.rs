use std::fs::OpenOptions;
use std::io::{self, Write};

use base64::Engine;

/// Copy text to the system clipboard via OSC-52 escape sequence.
///
/// Writes directly to `/dev/tty` so it bypasses ratatui's stdout ownership.
/// If `$TMUX` is set, wraps in a DCS passthrough so tmux forwards it to the
/// outer terminal.
pub fn yank(text: &str) -> io::Result<()> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let osc = format!("\x1b]52;c;{encoded}\x07");

    let payload = if std::env::var("TMUX").is_ok() {
        // Tmux DCS passthrough: escape every \x1b inside the payload
        let escaped = osc.replace('\x1b', "\x1b\x1b");
        format!("\x1bPtmux;{escaped}\x1b\\")
    } else {
        osc
    };

    let mut tty = OpenOptions::new().write(true).open("/dev/tty")?;
    tty.write_all(payload.as_bytes())?;
    tty.flush()
}
