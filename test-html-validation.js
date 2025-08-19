#!/usr/bin/env node
/**
 * Validation of test HTML files
 */

const fs = require('fs');

console.log('🧪 Validating Test HTML Files\n');

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

// Test test-7702.html
console.log('📄 test-7702.html:');
test('File exists', () => {
  if (!fs.existsSync('test-7702.html')) {
    throw new Error('test-7702.html not found');
  }
});

test('Has EIP-7702 module import', () => {
  const content = fs.readFileSync('test-7702.html', 'utf8');
  if (!content.includes('extension/eip7702.js')) {
    throw new Error('Missing EIP-7702 module import');
  }
});

test('Has ethers.js library', () => {
  const content = fs.readFileSync('test-7702.html', 'utf8');
  if (!content.includes('ethers.umd.min.js')) {
    throw new Error('Missing ethers.js library');
  }
});

test('Has wallet connection button', () => {
  const content = fs.readFileSync('test-7702.html', 'utf8');
  if (!content.includes('connectBtn')) {
    throw new Error('Missing connect button');
  }
});

test('Has delegation check functionality', () => {
  const content = fs.readFileSync('test-7702.html', 'utf8');
  if (!content.includes('checkDelegation')) {
    throw new Error('Missing delegation check');
  }
});

// Test test-app.html
console.log('\n📄 test-app.html:');
test('File exists', () => {
  if (!fs.existsSync('test-app.html')) {
    throw new Error('test-app.html not found');
  }
});

test('Has library test', () => {
  const content = fs.readFileSync('test-app.html', 'utf8');
  if (!content.includes('testLibraries')) {
    throw new Error('Missing library test function');
  }
});

test('Has EIP-7702 module test', () => {
  const content = fs.readFileSync('test-app.html', 'utf8');
  if (!content.includes('testEIP7702Module')) {
    throw new Error('Missing EIP-7702 module test');
  }
});

test('Has wallet generation test', () => {
  const content = fs.readFileSync('test-app.html', 'utf8');
  if (!content.includes('testWalletGeneration')) {
    throw new Error('Missing wallet generation test');
  }
});

test('Has logging functionality', () => {
  const content = fs.readFileSync('test-app.html', 'utf8');
  if (!content.includes('test-log')) {
    throw new Error('Missing test logging');
  }
});

// Test for security issues in test files
console.log('\n🔒 Security Checks:');
test('No hardcoded private keys in test files', () => {
  const files = ['test-7702.html', 'test-app.html'];
  files.forEach(file => {
    const content = fs.readFileSync(file, 'utf8');
    const privateKeyPattern = /0x[a-fA-F0-9]{64}/g;
    const matches = content.match(privateKeyPattern);
    if (matches && matches.some(m => !m.includes('0000000000'))) {
      throw new Error(`Potential private key in ${file}`);
    }
  });
});

test('No external script sources except CDN', () => {
  const files = ['test-7702.html', 'test-app.html'];
  files.forEach(file => {
    const content = fs.readFileSync(file, 'utf8');
    const scriptPattern = /<script[^>]*src=["']([^"']+)["']/g;
    let match;
    while ((match = scriptPattern.exec(content)) !== null) {
      const src = match[1];
      if (!src.includes('cdnjs.cloudflare.com') && !src.startsWith('extension/')) {
        throw new Error(`Unsafe script source in ${file}: ${src}`);
      }
    }
  });
});

// Functionality validation
console.log('\n⚙️ Functionality Checks:');
test('test-7702.html supports all networks', () => {
  const content = fs.readFileSync('test-7702.html', 'utf8');
  const networks = ['Ethereum Mainnet', 'Base', 'Sepolia', 'Base Sepolia'];
  networks.forEach(network => {
    if (!content.includes(network)) {
      throw new Error(`Missing network support: ${network}`);
    }
  });
});

test('test-app.html has all test sections', () => {
  const content = fs.readFileSync('test-app.html', 'utf8');
  const sections = [
    'Library Loading Test',
    'EIP-7702 Module Test',
    'Wallet Generation Test',
    'Password Modal Test'
  ];
  sections.forEach(section => {
    if (!content.includes(section)) {
      throw new Error(`Missing test section: ${section}`);
    }
  });
});

// Summary
console.log('\n📊 HTML Test File Validation Results:');
console.log(`✅ Passed: ${testsPassed}`);
console.log(`❌ Failed: ${testsFailed}`);

if (testsFailed === 0) {
  console.log('\n✅ All test HTML files are valid and ready for use!');
  console.log('\n📝 To use the test files:');
  console.log('1. Start a local server: python3 -m http.server 8080');
  console.log('2. Open http://localhost:8080/test-7702.html for EIP-7702 testing');
  console.log('3. Open http://localhost:8080/test-app.html for general extension testing');
  console.log('4. Make sure the extension is installed in Chrome first');
  process.exit(0);
} else {
  console.log('\n❌ Some validations failed.');
  process.exit(1);
}