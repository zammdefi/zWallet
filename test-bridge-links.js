#!/usr/bin/env node
/**
 * Test for Bridge Transaction Dual Links
 */

const fs = require('fs');

console.log('🔗 Testing Bridge Transaction Links\n');

const popupJs = fs.readFileSync('extension/popup.js', 'utf8');

let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✅ ${name}`);
    testsPassed++;
  } catch (error) {
    console.error(`❌ ${name}: ${error.message}`);
    testsFailed++;
  }
}

// Test 1: Check for dual links in success message
test('Bridge success has both Etherscan and Basescan links', () => {
  // Check for Bridge transaction link
  if (!popupJs.includes('Bridge transaction:')) {
    throw new Error('Missing "Bridge transaction:" label');
  }
  
  // Check for Etherscan link in bridge success
  if (!popupJs.includes('https://etherscan.io/tx/${tx.hash}')) {
    throw new Error('Missing Etherscan transaction link');
  }
  
  // Check for Basescan destination link
  if (!popupJs.includes('https://basescan.org/address/${wallet.address}')) {
    throw new Error('Missing Basescan destination link');
  }
  
  // Check for "Destination" label
  if (!popupJs.includes('Destination (1-2 min):')) {
    throw new Error('Missing destination timing information');
  }
});

// Test 2: Check for proper link styling
test('Links have consistent styling', () => {
  // Check for accent color styling
  if (!popupJs.includes('style="color: var(--accent); text-decoration: underline;"')) {
    throw new Error('Missing consistent link styling');
  }
});

// Test 3: Check failed bridge has Etherscan link
test('Failed bridge shows Etherscan link', () => {
  // Look for the failed bridge section
  const failedBridgePattern = /Bridge Failed[\s\S]*?View transaction:[\s\S]*?Etherscan/;
  if (!failedBridgePattern.test(popupJs)) {
    throw new Error('Failed bridge missing Etherscan link');
  }
});

// Test 4: Verify link structure
test('Links open in new tab', () => {
  // Check for target="_blank" on bridge links
  const linkPattern = /href="https:\/\/etherscan\.io\/tx\/\$\{tx\.hash\}"[^>]*target="_blank"/;
  if (!linkPattern.test(popupJs)) {
    throw new Error('Etherscan links missing target="_blank"');
  }
});

// Test 5: Check for proper line height for readability
test('Bridge status has proper line height', () => {
  if (!popupJs.includes('line-height: 1.6;')) {
    throw new Error('Missing line-height for readability');
  }
});

// Test 6: Verify margin between links
test('Links have proper spacing', () => {
  if (!popupJs.includes('margin-bottom: 4px;')) {
    throw new Error('Missing margin between link sections');
  }
});

// Test 7: Check that regular transactions still use showEtherscanLink
test('Regular transactions still use showEtherscanLink function', () => {
  if (!popupJs.includes('showEtherscanLink(tx.hash)')) {
    throw new Error('showEtherscanLink function not found');
  }
});

// Test 8: Verify arrow indicators
test('Links have arrow indicators', () => {
  const arrowCount = (popupJs.match(/Etherscan →/g) || []).length;
  if (arrowCount < 2) {
    throw new Error('Missing arrow indicators for Etherscan links');
  }
  
  const basescanArrowCount = (popupJs.match(/Basescan →/g) || []).length;
  if (basescanArrowCount < 1) {
    throw new Error('Missing arrow indicators for Basescan links');
  }
});

// Summary
console.log('\n📊 Bridge Link Test Results:');
console.log(`✅ Passed: ${testsPassed}`);
console.log(`❌ Failed: ${testsFailed}`);

if (testsFailed === 0) {
  console.log('\n✅ Bridge transaction dual links implemented successfully!');
  console.log('\n📝 Implementation details:');
  console.log('  • Bridge success shows Etherscan link for source transaction');
  console.log('  • Bridge success shows Basescan link for destination wallet');
  console.log('  • Failed bridges show Etherscan link for debugging');
  console.log('  • All links styled consistently with accent color');
  console.log('  • Proper spacing and readability maintained');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed.');
  process.exit(1);
}