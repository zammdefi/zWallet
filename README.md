# zWallet
> v0.0.4

onchain maxi wallet software

## Build

Two files compose the `zWallet`. 

`zWallet.html` is the application. It allows you to make private keys, encrypts them, and handles ETH, ERC20 and ERC6909 tokens.

Base wallet functionality is provided. Hold and send, add custom tokens. Starts with certain defaults. But you can also add your own RPCs.

`zWallet.sol` is the onchain logic. It parses tokens, fetches prices, and handles decimal and other particulars for UIs, like `zWallet.html`.

## Philosophy

We should absolutely minimize the software and maximize the onchain logic of the `zWallet`, while tapping into the full expressiveness of the EVM ecosystem.

## Hosting

Builds are posted to [zWallets.eth](https://zwallets.eth.limo/).

This domain should provide consistent UX over time with updates to `zWallet.html` and `zWallet.sol`.

## Contribute

Make PRs and help improve your own minimalist (hardcore) Ethereum wallet! The code should stay smol.

Ultimately, the ideal is that `zWallet.sol` handles most, if not all, of the application logic, too.

