mod app;
mod config;
mod data;
mod ebpf;
mod input;
mod theme;
mod ui;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "bpftop", about = "eBPF-powered interactive process monitor")]
struct Cli {
    /// Refresh rate in milliseconds
    #[arg(short = 'd', long, default_value_t = 1000)]
    delay: u64,

    /// Start in tree view mode
    #[arg(short = 't', long)]
    tree: bool,

    /// Filter processes by user
    #[arg(short = 'u', long)]
    user: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config
    let mut config = config::Config::load().unwrap_or_default();

    // CLI overrides
    if cli.delay != 1000 {
        config.general.refresh_rate_ms = cli.delay;
    }
    if cli.tree {
        config.general.tree_view = true;
    }

    // Create and run app
    let mut app = app::App::new(config);

    if let Some(user) = cli.user {
        app.user_filter = Some(user);
    }

    app.run()
}
