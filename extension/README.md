# zWallet Chrome Extension

A minimalist Ethereum wallet browser extension built for DeFi operations.

## Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked" and select the `extension` folder
4. The zWallet icon should appear in your extensions bar

## Features

- **Secure Wallet Management**: Create, import, and manage multiple Ethereum wallets
- **Token Support**: ETH, USDC, DAI, USDT, ENS, and custom ERC20/ERC6909 tokens
- **DeFi Integration**: Direct interaction with smart contracts
- **Transaction History**: View your recent transactions
- **Multiple RPC Endpoints**: Choose from various Ethereum nodes
- **Dark Mode**: Toggle between light and dark themes
- **Encrypted Storage**: Private keys are encrypted with PBKDF2 + AES-GCM

## Security

- Private keys are encrypted with user passwords (PBKDF2, 210k iterations)
- AES-GCM encryption with authenticated encryption
- Keys never leave your device
- Restricted host permissions (only necessary RPC endpoints)
- Content Security Policy enforced

## Development

The extension consists of:
- `manifest.json` - Chrome extension configuration
- `popup.html/js` - Main wallet interface
- `background.js` - Service worker for handling external links
- `ethers.umd.min.js` - Ethereum library for Web3 operations

## Version

v0.0.3

## License

MIT