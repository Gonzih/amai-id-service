use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

use crate::types::Chain;

/// Contract configuration for a specific chain
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain: Chain,
    pub rpc_url: String,
    pub contract_address: String,
    pub contract_version: u64,
}

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
    /// Chain-specific configurations
    pub chains: HashMap<Chain, ChainConfig>,
    /// Current contract version
    pub contract_version: u64,
}

impl Config {
    pub fn from_env() -> Self {
        // Parse contract version from string like "1.0.0" to 1_000_000
        let contract_version = env::var("CONTRACT_VERSION")
            .ok()
            .and_then(|v| parse_version_string(&v))
            .unwrap_or(1_000_000); // Default 1.0.0

        // Build chain configs from environment
        let mut chains = HashMap::new();

        // Base Sepolia
        if let Ok(contract) = env::var("BASE_SEPOLIA_CONTRACT") {
            chains.insert(
                Chain::BaseSepolia,
                ChainConfig {
                    chain: Chain::BaseSepolia,
                    rpc_url: env::var("BASE_SEPOLIA_RPC")
                        .unwrap_or_else(|_| "https://sepolia.base.org".into()),
                    contract_address: contract,
                    contract_version,
                },
            );
        }

        // Base Mainnet
        if let Ok(contract) = env::var("BASE_MAINNET_CONTRACT") {
            chains.insert(
                Chain::BaseMainnet,
                ChainConfig {
                    chain: Chain::BaseMainnet,
                    rpc_url: env::var("BASE_MAINNET_RPC")
                        .unwrap_or_else(|_| "https://mainnet.base.org".into()),
                    contract_address: contract,
                    contract_version,
                },
            );
        }

        // Solana Devnet
        if let Ok(contract) = env::var("SOLANA_DEVNET_PROGRAM") {
            chains.insert(
                Chain::SolanaDevnet,
                ChainConfig {
                    chain: Chain::SolanaDevnet,
                    rpc_url: env::var("SOLANA_DEVNET_RPC")
                        .unwrap_or_else(|_| "https://api.devnet.solana.com".into()),
                    contract_address: contract,
                    contract_version,
                },
            );
        }

        // Solana Mainnet
        if let Ok(contract) = env::var("SOLANA_MAINNET_PROGRAM") {
            chains.insert(
                Chain::SolanaMainnet,
                ChainConfig {
                    chain: Chain::SolanaMainnet,
                    rpc_url: env::var("SOLANA_MAINNET_RPC")
                        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into()),
                    contract_address: contract,
                    contract_version,
                },
            );
        }

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
            chains,
            contract_version,
        }
    }

    pub fn state_file_path(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }

    pub fn action_log_path(&self) -> PathBuf {
        self.data_dir.join("action_log.json")
    }

    /// Get chain config for a specific chain
    pub fn get_chain_config(&self, chain: Chain) -> Option<&ChainConfig> {
        self.chains.get(&chain)
    }

    /// Check if a contract address is valid for a chain
    pub fn validate_contract(&self, chain: Chain, contract_address: &str) -> bool {
        self.chains
            .get(&chain)
            .map(|c| c.contract_address.eq_ignore_ascii_case(contract_address))
            .unwrap_or(false)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Parse version string like "1.0.0" to numeric 1_000_000
fn parse_version_string(version: &str) -> Option<u64> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let major: u64 = parts[0].parse().ok()?;
    let minor: u64 = parts[1].parse().ok()?;
    let patch: u64 = parts[2].parse().ok()?;

    Some(major * 1_000_000 + minor * 1_000 + patch)
}

/// Format version number to string
pub fn format_version(version: u64) -> String {
    let major = version / 1_000_000;
    let minor = (version % 1_000_000) / 1_000;
    let patch = version % 1_000;
    format!("{}.{}.{}", major, minor, patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_string() {
        assert_eq!(parse_version_string("1.0.0"), Some(1_000_000));
        assert_eq!(parse_version_string("1.2.3"), Some(1_002_003));
        assert_eq!(parse_version_string("2.0.0"), Some(2_000_000));
        assert_eq!(parse_version_string("invalid"), None);
    }

    #[test]
    fn test_format_version() {
        assert_eq!(format_version(1_000_000), "1.0.0");
        assert_eq!(format_version(1_002_003), "1.2.3");
        assert_eq!(format_version(2_000_000), "2.0.0");
    }
}
