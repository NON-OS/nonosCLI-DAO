# nonosCLI-DAO

<NØNOS DAO CLI>

**Zero-Trust Multi-Chain Governance Framework**


[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


Overview

NØNOS DAO is an enterprise-grade, zero-trust governance framework engineered for cross-chain decentralized decision-making. Built with Rust for maximum performance and security, it supports both Ethereum (EVM) and Solana ecosystems through a unified interface.


Key Features
• **Zero-Trust Architecture**: No central servers or points of failure
• **Multi-Chain Support**: Works with both Ethereum and Solana
• **Encrypted Voting**: ChaCha20-Poly1305 for ballot privacy
• **Automated Dashboard**: Terminal UI and mobile interfaces
• **Open Source**: Fully auditable codebase


Prerequisites

System Requirements
• **Rust**: Version 1.70 or higher
• **OpenSSL**: For cryptographic operations
• **Git**: For cloning the repository


Rust Installation

# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Configure current shell
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version


API Configuration

Before using NØNOS DAO, you'll need API keys from blockchain providers:


Helius (Solana - Recommended)
1. Visit [Helius Dashboard](https://dashboard.helius.xyz/)
2. Create a new project
3. Copy your API key
4. Use endpoint: `https://mainnet.helius-rpc.com/?api-key=YOUR_KEY`


Alchemy (Ethereum - Recommended)
1. Visit [Alchemy Dashboard](https://dashboard.alchemy.com/)
2. Create a new app (Ethereum Mainnet)
3. Copy your API key
4. Use endpoints:
- RPC: `https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY`
- NFT API: `https://eth-mainnet.g.alchemy.com/nft/v2/YOUR_KEY`


Wallet Setup

Eligibility Requirements

To participate in NØNOS DAO governance, your wallet must hold one of the following:

• **N0NOS Token (Solana)**
- Minimum Balance: 1 N0NOS token
- Network: Solana Mainnet

• **ZeroState NFT (Ethereum)**
- Minimum: 1 NFT
- Network: Ethereum Mainnet


Installation

Step 1: Clone Repository

git clone https://github.com/NON-OS/nonosCLI-DAO.git
cd nonosCLI-DAO


Step 2: Build Binaries

# Build optimized binaries
cargo build --release

# Verify installation
./target/release/n0nos-dao-cli --version
./target/release/n0nos-dashboard --version


Step 3: Configure Environment

Create a `.env` file in the project root:


# Ethereum Configuration
EVM_RPC=https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY
EVM_INDEXER_URL=https://eth-mainnet.g.alchemy.com/nft/v2/YOUR_ALCHEMY_KEY
EVM_CHAIN_ID=1

# Solana Configuration  
SOL_RPC=https://mainnet.helius-rpc.com/?api-key=YOUR_HELIUS_KEY
SOL_CLUSTER=mainnet-beta

# Ballot Encryption
BALLOT_KEY=your_secure_encryption_key_here

# Developer Settings
DEVELOPER_MODE=true
DEVELOPER_WALLET=your_wallet_address


Step 4: Generate Encryption Key

# Generate a secure random key for ballot encryption
openssl rand -hex 32


Dashboard Guide

NØNOS provides both a terminal-based dashboard and a mobile interface for governance operations.


Terminal Dashboard

Launch the dashboard:


./target/release/n0nos-dashboard


Dashboard Features
• **Setup Wizard**: Configure API keys and wallet connections
• **System Doctor**: Verify connections and system health
• **Create Proposal**: Create new governance proposals
• **Vote**: Cast votes on active proposals
• **Tally**: Count votes and determine results
• **Configuration**: Manage system settings


CLI Reference

Command Structure

./target/release/n0nos-dao-cli <COMMAND> [OPTIONS]


Core Commands

Create Proposal

./target/release/n0nos-dao-cli new \
  --title "Treasury Diversification" \
  --description "Move 10% to ETH staking" \
  --evm_rpc $EVM_RPC \
  --sol_rpc $SOL_RPC \
  --evm_chain_id 1 \
  --evm_nft_contract 0xZEROSTATE_CONTRACT \
  --sol_token_mint N0NOS_TOKEN_MINT \
  --min_balance 1 \
  --start_utc "2025-08-20T00:00:00Z" \
  --end_utc "2025-08-25T00:00:00Z" \
  --created_by "anon.eth" \
  --options "YES,NO,ABSTAIN"


Cast Vote

./target/release/n0nos-dao-cli vote \
  --proposal_id PROPOSAL_ID \
  --choices YES \
  --wallet_path ~/.config/solana/id.json \
  --encrypt true


Tally Results

./target/release/n0nos-dao-cli tally \
  --proposal_id PROPOSAL_ID \
  --decrypt_key $BALLOT_KEY


Security Model
• **No Central Authority**: All operations verifiable by participants
• **Cryptographic Verification**: Every step secured with cryptography
• **Open Source**: All code publicly auditable
• **Local-First**: Data stored locally, not on central servers


Development

Local Development Setup

# Clone repository
git clone https://github.com/NON-OS/nonosCLI-DAO.git
cd nonosCLI-DAO

# Install dependencies
cargo check

# Run tests
cargo test

# Format code
cargo fmt

# Lint code
cargo clippy


Contributing

We welcome contributions from the community! Here's how to get involved:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature`
3. **Commit** your changes: `git commit -m 'Add feature'`
4. **Push** to the branch: `git push origin feature`
5. **Open** a Pull Request


License

MIT License - See [LICENSE](LICENSE) for details.


Contact

**Developer Contact:** [eK@nonos-tech.xyz](mailto:eK@nonos-tech.xyz)


**Built with ❤️ 4 the NØNOS community**
