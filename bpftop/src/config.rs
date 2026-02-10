use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::theme::ThemeOverrides;

/// Application configuration loaded from ~/.config/bpftop/config.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub theme: ThemeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Refresh rate in milliseconds.
    #[serde(default = "default_refresh_rate")]
    pub refresh_rate_ms: u64,
    /// Start in tree view mode.
    #[serde(default)]
    pub tree_view: bool,
    /// Show individual threads.
    #[serde(default)]
    pub show_threads: bool,
    /// Show kernel threads.
    #[serde(default)]
    pub show_kernel_threads: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            refresh_rate_ms: default_refresh_rate(),
            tree_view: false,
            show_threads: false,
            show_kernel_threads: false,
        }
    }
}

fn default_refresh_rate() -> u64 {
    1000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeConfig {
    /// Theme preset name: "gruvbox-dark" or "gruvbox-light".
    #[serde(default = "default_preset")]
    pub preset: String,
    /// Optional per-color overrides.
    #[serde(default)]
    pub overrides: ThemeOverrides,
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            preset: default_preset(),
            overrides: ThemeOverrides::default(),
        }
    }
}

fn default_preset() -> String {
    "gruvbox-dark".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            theme: ThemeConfig::default(),
        }
    }
}

impl Config {
    /// Load config from the default path, or return defaults if not found.
    pub fn load() -> Result<Self> {
        let path = config_path();
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("reading config from {}", path.display()))?;
            let config: Config = toml::from_str(&content)
                .with_context(|| format!("parsing config from {}", path.display()))?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    /// Save config to the default path.
    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating config directory {}", parent.display()))?;
        }
        let content = toml::to_string_pretty(self).context("serializing config")?;
        fs::write(&path, content)
            .with_context(|| format!("writing config to {}", path.display()))?;
        Ok(())
    }
}

fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("bpftop")
        .join("config.toml")
}
