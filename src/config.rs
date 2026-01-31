use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub persist_interval: Duration,
    pub chain_id: u64,
    pub rpc_url: String,
    pub identity_contract: String,
    pub rate_limit_requests: u32,
    pub rate_limit_window: Duration,
    pub api_key_prefix: String,
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
            chain_id: env::var("CHAIN_ID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(84532), // Base Sepolia
            rpc_url: env::var("RPC_URL")
                .unwrap_or_else(|_| "https://sepolia.base.org".into()),
            identity_contract: env::var("IDENTITY_CONTRACT")
                .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".into()),
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
            api_key_prefix: env::var("API_KEY_PREFIX")
                .unwrap_or_else(|_| "amai_sk_".into()),
        }
    }

    pub fn state_file_path(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}
