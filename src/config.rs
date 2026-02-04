//! Configuration for AMAI Identity Service

use std::env;
use std::path::PathBuf;
use std::time::Duration;

/// Service configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Data directory for persistence
    pub data_dir: PathBuf,
    /// How often to persist state to disk
    pub persist_interval: Duration,
    /// Maximum clock skew allowed for signatures (seconds)
    pub max_clock_skew: u64,
    /// Nonce expiry time (seconds)
    pub nonce_expiry: u64,
    /// Rate limit: requests per window
    pub rate_limit_requests: u32,
    /// Rate limit: window duration
    pub rate_limit_window: Duration,
    /// Service version
    pub version: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            data_dir: env::var("DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("./data")),
            persist_interval: Duration::from_secs(
                env::var("PERSIST_INTERVAL_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30),
            ),
            max_clock_skew: env::var("MAX_CLOCK_SKEW_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300), // 5 minutes
            nonce_expiry: env::var("NONCE_EXPIRY_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600), // 10 minutes
            rate_limit_requests: env::var("RATE_LIMIT_REQUESTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            rate_limit_window: Duration::from_secs(
                env::var("RATE_LIMIT_WINDOW_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60),
            ),
            version: env::var("SERVICE_VERSION").unwrap_or_else(|_| "1.0.0".into()),
        }
    }

    /// Path to state file
    pub fn state_file_path(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }

    /// Path to sigchain storage
    pub fn sigchain_dir(&self) -> PathBuf {
        self.data_dir.join("sigchains")
    }

    /// Path to nonce store
    pub fn nonce_file_path(&self) -> PathBuf {
        self.data_dir.join("nonces.json")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.max_clock_skew, 300);
        assert_eq!(config.nonce_expiry, 600);
    }

    #[test]
    fn test_paths() {
        let config = Config {
            data_dir: PathBuf::from("/tmp/test"),
            ..Config::default()
        };
        assert_eq!(
            config.state_file_path(),
            PathBuf::from("/tmp/test/state.json")
        );
        assert_eq!(config.sigchain_dir(), PathBuf::from("/tmp/test/sigchains"));
    }
}
