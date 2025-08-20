# Base Network USDC IOU Format

## Fixed Issue
The extension was not properly extracting v, r, s values from the signature for Base network IOUs.

## Solution
Changed from `ethers.Signature.from()` to `ethers.splitSignature()` which properly:
- Returns `v` as a number (27 or 28)
- Returns `r` and `s` as 0x-prefixed, 32-byte padded hex strings

## Expected JSON Format for IOUSDC.html
```json
{
  "type": "transfer",
  "from": "0x...",
  "to": "0x...",
  "value": "1000000",
  "validAfter": 0,
  "validBefore": 1735689600,
  "nonce": "0x...(64 hex chars)",
  "v": 27,
  "r": "0x...(64 hex chars)",
  "s": "0x...(64 hex chars)",
  "amount": "1.0",
  "signature": "0x...(130 hex chars)",
  "created": "2024-01-01T00:00:00.000Z",
  "chainId": 8453,
  "network": "Base"
}
```

## Key Requirements
1. `v` must be a number (27 or 28)
2. `r` and `s` must be hex strings with "0x" prefix, padded to 32 bytes
3. `nonce` must be a 32-byte hex string with "0x" prefix
4. `chainId` must be 8453 for Base network
5. `value` must be a string representing the amount in base units (6 decimals for USDC)

## Base Network Configuration
- Chain ID: 8453
- USDC Address: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
- EIP-712 Domain:
  - name: "USD Coin"
  - version: "2"
  - chainId: 8453
  - verifyingContract: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913