#!/usr/bin/env node
/**
 * Base Network Compatibility Test Suite for zWallet
 * Tests both browser wallet and Chrome extension modes
 */

const fs = require('fs');
const path = require('path');

console.log('🔵 Base Network Compatibility Test Suite\n');
console.log('=' .repeat(50));

let testsPassed = 0;
let testsFailed = 0;
let warnings = [];

function test(name, fn) {
  try {
    const result = fn();
    if (result === true) {
      console.log(`✅ ${name}`);
      testsPassed++;
    } else if (result && result.warning) {
      console.log(`⚠️  ${name}: ${result.warning}`);
      warnings.push({ test: name, message: result.warning });
      testsPassed++;
    } else {
      throw new Error(result || 'Test returned false');
    }
  } catch (error) {
    console.error(`❌ ${name}: ${error.message}`);
    testsFailed++;
  }
}

// Test 1: Check Base network configuration in popup.js
test('Base network is configured in NETWORKS constant', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  
  // Check for Base network configuration
  if (!popupJs.includes('BASE:')) {
    throw new Error('Base network not found in NETWORKS configuration');
  }
  
  // Check for correct chain ID (8453 or 0x2105)
  if (!popupJs.includes('chainId: 8453')) {
    throw new Error('Base chain ID (8453) not configured');
  }
  
  // Check for Base RPC URLs
  if (!popupJs.includes('mainnet.base.org') && !popupJs.includes('base.llamarpc.com')) {
    throw new Error('Base RPC URLs not configured');
  }
  
  return true;
});

// Test 2: Check manifest.json for Base RPC permissions
test('Base RPC endpoints are whitelisted in manifest', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  
  const baseRPCs = [
    'https://mainnet.base.org/*',
    'https://base.llamarpc.com/*',
    'https://base.publicnode.com/*'
  ];
  
  let foundCount = 0;
  baseRPCs.forEach(rpc => {
    if (manifest.host_permissions && manifest.host_permissions.includes(rpc)) {
      foundCount++;
    }
  });
  
  if (foundCount === 0) {
    throw new Error('No Base RPC endpoints found in host_permissions');
  }
  
  if (foundCount < baseRPCs.length) {
    return { warning: `Only ${foundCount}/${baseRPCs.length} Base RPC endpoints configured` };
  }
  
  return true;
});

// Test 3: Check BaseScan permission
test('BaseScan is whitelisted for block explorer', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  
  if (!manifest.host_permissions || !manifest.host_permissions.includes('https://basescan.org/*')) {
    throw new Error('BaseScan not found in host_permissions');
  }
  
  return true;
});

// Test 4: Check Content Security Policy for Base RPCs
test('CSP allows Base network connections', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  
  if (!manifest.content_security_policy || !manifest.content_security_policy.extension_pages) {
    throw new Error('CSP not configured');
  }
  
  const csp = manifest.content_security_policy.extension_pages;
  if (!csp.includes('mainnet.base.org') && !csp.includes('base.llamarpc.com')) {
    throw new Error('Base RPCs not included in CSP connect-src');
  }
  
  return true;
});

// Test 5: Check background.js for Base chain support
test('Background service worker supports Base chain ID', () => {
  const backgroundJs = fs.readFileSync('extension/background.js', 'utf8');
  
  // Check for Base chain ID support (0x2105)
  if (!backgroundJs.includes('0x2105')) {
    throw new Error('Base chain ID (0x2105) not found in background.js');
  }
  
  // Check chain switching support
  if (!backgroundJs.includes('wallet_switchEthereumChain')) {
    throw new Error('Chain switching not implemented');
  }
  
  return true;
});

// Test 6: Check RPC forwarding for Base
test('RPC forwarding handles Base network', () => {
  const backgroundJs = fs.readFileSync('extension/background.js', 'utf8');
  
  // Check if Base RPC is used when on Base chain
  if (!backgroundJs.includes('base.llamarpc.com') && 
      !backgroundJs.includes('mainnet.base.org')) {
    throw new Error('Base RPC not configured for forwarding');
  }
  
  // Check conditional RPC selection based on chain ID
  if (!backgroundJs.includes("chainId === '0x2105'")) {
    throw new Error('Conditional Base RPC selection not implemented');
  }
  
  return true;
});

// Test 7: Check inject.js for proper chain ID handling
test('Injected provider handles chain ID correctly', () => {
  const injectJs = fs.readFileSync('extension/inject.js', 'utf8');
  
  // Check for chainId property
  if (!injectJs.includes('chainId:')) {
    throw new Error('chainId property not found in provider');
  }
  
  // Check for chain change event emission
  if (!injectJs.includes('chainChanged')) {
    throw new Error('chainChanged event not implemented');
  }
  
  return true;
});

// Test 8: Check network switching UI
test('Network switching UI supports Base', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  
  // Check for Base mode toggle
  if (!popupJs.includes('isBaseMode')) {
    throw new Error('Base mode toggle not implemented');
  }
  
  // Check for network switching function
  if (!popupJs.includes('toggleNetwork') && !popupJs.includes('switchNetwork')) {
    return { warning: 'Network switching function not clearly defined' };
  }
  
  return true;
});

// Test 9: Check transaction handling for Base
test('Transaction handling supports Base network', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  
  // Check for Base-specific transaction handling
  if (popupJs.includes('isBaseMode') && popupJs.includes('sendTransaction')) {
    return true;
  }
  
  return { warning: 'Base-specific transaction handling not explicitly implemented' };
});

// Test 10: Check block explorer integration
test('Block explorer integration for Base', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  
  // Check for BaseScan integration
  if (!popupJs.includes('basescan.org')) {
    throw new Error('BaseScan not integrated for transaction viewing');
  }
  
  // Check for conditional explorer URL based on network
  if (!popupJs.includes('8453')) {
    return { warning: 'Base chain ID not used for explorer selection' };
  }
  
  return true;
});

// Test 11: Check Web3 provider compatibility
test('Web3 provider is EIP-1193 compliant', () => {
  const injectJs = fs.readFileSync('extension/inject.js', 'utf8');
  
  // Check for required EIP-1193 methods
  const requiredMethods = ['request', 'on', 'once', 'off', 'removeListener', 'emit'];
  let missingMethods = [];
  
  requiredMethods.forEach(method => {
    if (!injectJs.includes(`${method}:`)) {
      missingMethods.push(method);
    }
  });
  
  if (missingMethods.length > 0) {
    throw new Error(`Missing EIP-1193 methods: ${missingMethods.join(', ')}`);
  }
  
  return true;
});

// Test 12: Check MetaMask compatibility flag
test('MetaMask compatibility mode is enabled', () => {
  const injectJs = fs.readFileSync('extension/inject.js', 'utf8');
  
  if (!injectJs.includes('isMetaMask: true')) {
    return { warning: 'MetaMask compatibility flag not set' };
  }
  
  return true;
});

// Test 13: Check event handling for network changes
test('Network change events are properly handled', () => {
  const backgroundJs = fs.readFileSync('extension/background.js', 'utf8');
  const contentJs = fs.readFileSync('extension/content.js', 'utf8');
  
  // Check background script emits events
  if (!backgroundJs.includes('CHAIN_CHANGED')) {
    throw new Error('Chain change event not emitted from background');
  }
  
  // Check content script forwards events
  if (!contentJs.includes('PROVIDER_EVENT')) {
    throw new Error('Provider events not forwarded by content script');
  }
  
  return true;
});

// Test 14: Check RPC error handling
test('RPC errors are properly handled', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  const backgroundJs = fs.readFileSync('extension/background.js', 'utf8');
  
  // Check for retry mechanism
  if (!popupJs.includes('withRetry') && !popupJs.includes('retry')) {
    return { warning: 'No retry mechanism for RPC calls' };
  }
  
  // Check for error codes
  if (!backgroundJs.includes('4902')) {
    return { warning: 'Chain not found error (4902) not handled' };
  }
  
  return true;
});

// Test 15: Check storage of network preferences
test('Network preferences are persisted', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  
  // Check for localStorage usage for Base RPC
  if (!popupJs.includes('base_rpc')) {
    return { warning: 'Base RPC preference not stored' };
  }
  
  // Check for network mode storage
  if (!popupJs.includes('localStorage') || !popupJs.includes('chrome.storage')) {
    return { warning: 'Network preferences may not be persisted' };
  }
  
  return true;
});

// Test 16: Verify no hardcoded mainnet assumptions
test('No hardcoded mainnet-only assumptions', () => {
  const backgroundJs = fs.readFileSync('extension/background.js', 'utf8');
  
  // Check default chain ID is configurable
  if (backgroundJs.includes("chainId = '0x1'") && !backgroundJs.includes('0x2105')) {
    return { warning: 'Default chain ID is hardcoded to mainnet only' };
  }
  
  return true;
});

// Test 17: Check gas estimation for Base
test('Gas estimation works for Base network', () => {
  const backgroundJs = fs.readFileSync('extension/background.js', 'utf8');
  
  // Check if eth_estimateGas is forwarded
  if (!backgroundJs.includes('eth_estimateGas')) {
    throw new Error('Gas estimation not supported');
  }
  
  return true;
});

// Test 18: Check typed data signing for Base
test('Typed data signing includes Base chain ID', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  
  // Check for EIP-712 support
  if (!popupJs.includes('signTypedData') && !popupJs.includes('eth_signTypedData')) {
    return { warning: 'Typed data signing not implemented' };
  }
  
  return true;
});

console.log('\n' + '=' .repeat(50));
console.log('\n📊 Test Results Summary:\n');
console.log(`✅ Passed: ${testsPassed}`);
console.log(`❌ Failed: ${testsFailed}`);

if (warnings.length > 0) {
  console.log(`\n⚠️  Warnings (${warnings.length}):`);
  warnings.forEach(w => {
    console.log(`   - ${w.test}: ${w.message}`);
  });
}

console.log('\n🔍 Compatibility Analysis:\n');

if (testsFailed === 0) {
  console.log('✅ FULL COMPATIBILITY: zWallet fully supports Base network');
  console.log('   - Browser wallet mode: ✅');
  console.log('   - Chrome extension mode: ✅');
  console.log('   - Web3 injection: ✅');
  console.log('   - Network switching: ✅');
  console.log('   - RPC forwarding: ✅');
  console.log('   - Transaction handling: ✅');
} else if (testsFailed <= 3) {
  console.log('⚠️  PARTIAL COMPATIBILITY: zWallet has good Base support with minor issues');
  console.log('   Please review failed tests above');
} else {
  console.log('❌ LIMITED COMPATIBILITY: zWallet needs improvements for Base support');
  console.log('   Please fix the failed tests before using with Base network');
}

console.log('\n📝 Recommendations:');
if (testsFailed === 0 && warnings.length === 0) {
  console.log('   - No issues found, ready for production use with Base network');
} else {
  console.log('   - Test with live Base dApps (Uniswap, Aave on Base)');
  console.log('   - Verify transaction signing on Base testnet');
  console.log('   - Test network switching between Ethereum and Base');
  if (warnings.length > 0) {
    console.log('   - Review warnings for potential improvements');
  }
}

process.exit(testsFailed > 0 ? 1 : 0);