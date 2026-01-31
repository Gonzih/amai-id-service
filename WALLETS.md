# AMAI Identity Service - Wallet Configuration

## Wallets

### Base (EVM) - Chain ID: 84532 (Sepolia) / 8453 (Mainnet)

| Field | Value |
|-------|-------|
| Address | `0x4476ac2E3E0a03d3FE953D95e2C311eF1E66b043` |
| Local Key File | `.keys/base-wallet.json` |
| Created | 2026-01-31 |

### Solana

| Field | Value |
|-------|-------|
| Address | `DaGqKhv3Tymup8e2Z3aAmWkchAmTvE3STYEj4hCAtLGz` |
| Local Key File | `.keys/solana-wallet.json` |
| Created | 2026-01-31 |

## Environment Variables

### Local Development (`.env.local`)

```bash
# Base (EVM)
BASE_WALLET_ADDRESS=0x4476ac2E3E0a03d3FE953D95e2C311eF1E66b043
BASE_WALLET_PRIVATE_KEY=<in .env.local>
BASE_SEPOLIA_RPC=https://sepolia.base.org
BASE_MAINNET_RPC=https://mainnet.base.org

# Solana
SOLANA_WALLET_ADDRESS=DaGqKhv3Tymup8e2Z3aAmWkchAmTvE3STYEj4hCAtLGz
SOLANA_WALLET_KEYPAIR_PATH=.keys/solana-wallet.json
SOLANA_DEVNET_RPC=https://api.devnet.solana.com
SOLANA_MAINNET_RPC=https://api.mainnet-beta.solana.com
```

### Production (Railway)

All wallet environment variables are configured in Railway:

| Variable | Set | Description |
|----------|-----|-------------|
| `BASE_WALLET_ADDRESS` | ✅ | Public address |
| `BASE_WALLET_PRIVATE_KEY` | ✅ | Private key (encrypted in Railway) |
| `BASE_SEPOLIA_RPC` | ✅ | RPC endpoint |
| `SOLANA_WALLET_ADDRESS` | ✅ | Public address |
| `SOLANA_WALLET_KEYPAIR` | ✅ | Full keypair JSON |
| `SOLANA_DEVNET_RPC` | ✅ | RPC endpoint |
| `CONTRACT_VERSION` | ✅ | Current contract version |

## Smart Contracts

### Base (EVM) - `contracts/base/AMAIIdentity.sol`

- **Version**: 1.0.0 (1_000_000)
- **Type**: Soulbound ERC-721 NFT
- **Features**:
  - On-chain trust score (0-100, scaled to 10000)
  - Action/confirmation counting
  - Oracle authorization system
  - Logistic curve trust delta
  - Version tracking per agent

**Key Functions**:
- `mintAgent(to, name, serviceEndpoint)` - Mint new identity
- `getContractInfo()` - Get version, chain, address
- `getAgentWithVersionInfo(tokenId)` - Get agent + version delta
- `isLatestVersion(tokenId)` - Check if agent on current version

**Deploy**:
```bash
source .env.local
cd contracts/base
forge script script/Deploy.s.sol --rpc-url $BASE_SEPOLIA_RPC --broadcast
```

### Solana - `contracts/solana/amai_identity/lib.rs`

- **Version**: 1.0.0 (1_000_000)
- **Framework**: Anchor
- **Features**:
  - PDA-based agent accounts
  - Same trust mechanics as Base
  - Oracle authorization
  - Version tracking per agent

**Deploy**:
```bash
cd contracts/solana
anchor build
anchor deploy --provider.cluster devnet
```

## Security

### Local Keys
- Stored in `.keys/` directory (700 permissions)
- Files have 600 permissions (owner read/write only)
- Directory is in `.gitignore`

### Production Keys
- Stored as Railway environment variables
- Encrypted at rest
- Never logged or exposed in builds

## Funding

Before deploying contracts, wallets need testnet funds:

**Base Sepolia**:
- Faucet: https://www.alchemy.com/faucets/base-sepolia
- Or bridge from Sepolia ETH

**Solana Devnet**:
```bash
solana airdrop 2 DaGqKhv3Tymup8e2Z3aAmWkchAmTvE3STYEj4hCAtLGz --url devnet
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-31 | Initial release with trust scoring and versioning |

---

*Last Updated: 2026-01-31*
