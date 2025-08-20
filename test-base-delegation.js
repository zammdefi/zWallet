// Test script to verify Base network delegation setup
const ethers = require('ethers');

async function testBaseDelegation() {
  const BASE_RPC = 'https://mainnet.base.org';
  const EXECUTOR_ADDRESS = '0x00000000BEBEDB7C30ee418158e26E31a5A8f3E2';
  
  console.log('Testing EIP-7702 delegation setup on Base network...\n');
  
  try {
    // Connect to Base
    const provider = new ethers.JsonRpcProvider(BASE_RPC);
    
    // Check network
    const network = await provider.getNetwork();
    console.log('✓ Connected to Base network');
    console.log('  Chain ID:', network.chainId.toString());
    console.log('  Expected: 8453\n');
    
    // Check if executor contract is deployed
    const code = await provider.getCode(EXECUTOR_ADDRESS);
    
    if (code && code !== '0x' && code !== '0x0') {
      console.log('✓ BasicEOABatchExecutor is deployed on Base');
      console.log('  Address:', EXECUTOR_ADDRESS);
      console.log('  Code length:', code.length, 'chars\n');
      console.log('✅ Base network is ready for EIP-7702 delegations!');
    } else {
      console.log('✗ BasicEOABatchExecutor NOT found on Base');
      console.log('  The contract needs to be deployed first\n');
      console.log('⚠️  Base network is NOT ready for delegations');
    }
    
  } catch (error) {
    console.error('Error testing Base delegation:', error.message);
  }
}

testBaseDelegation();
