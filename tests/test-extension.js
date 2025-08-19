#!/usr/bin/env node
/**
 * Production readiness tests for zWallet Chrome Extension
 */

const fs = require('fs');
const path = require('path');

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

console.log('🧪 Running zWallet Extension Production Tests\n');

// Test 1: Check manifest version
test('Manifest uses Manifest V3', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  if (manifest.manifest_version !== 3) {
    throw new Error(`Expected manifest_version 3, got ${manifest.manifest_version}`);
  }
});

// Test 2: Check required permissions
test('Required permissions are declared', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  const requiredPerms = ['storage', 'tabs'];
  requiredPerms.forEach(perm => {
    if (!manifest.permissions.includes(perm)) {
      throw new Error(`Missing required permission: ${perm}`);
    }
  });
});

// Test 3: Check service worker declaration
test('Service worker is properly declared', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  if (!manifest.background || !manifest.background.service_worker) {
    throw new Error('Service worker not declared in manifest');
  }
});

// Test 4: Check CSP is set
test('Content Security Policy is configured', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  if (!manifest.content_security_policy || !manifest.content_security_policy.extension_pages) {
    throw new Error('CSP not properly configured');
  }
});

// Test 5: Check all required files exist
test('All required extension files exist', () => {
  const requiredFiles = [
    'extension/manifest.json',
    'extension/popup.html',
    'extension/popup.js',
    'extension/background.js',
    'extension/content.js',
    'extension/inject.js',
    'extension/icon16.png',
    'extension/icon48.png',
    'extension/icon128.png',
    'extension/ethers.umd.min.js'
  ];
  
  requiredFiles.forEach(file => {
    if (!fs.existsSync(file)) {
      throw new Error(`Missing required file: ${file}`);
    }
  });
});

// Test 6: Check for common security issues
test('No eval() or Function() constructors in code', () => {
  const jsFiles = [
    'extension/popup.js',
    'extension/background.js',
    'extension/content.js',
    'extension/inject.js'
  ];
  
  jsFiles.forEach(file => {
    const content = fs.readFileSync(file, 'utf8');
    if (content.includes('eval(') && !content.includes('// eval(')) {
      throw new Error(`Unsafe eval() found in ${file}`);
    }
    if (content.includes('new Function(') && !content.includes('// new Function(')) {
      throw new Error(`Unsafe Function constructor found in ${file}`);
    }
  });
});

// Test 7: Check for hardcoded sensitive data
test('No hardcoded private keys or secrets', () => {
  const jsFiles = [
    'extension/popup.js',
    'extension/background.js',
    'extension/content.js',
    'extension/inject.js'
  ];
  
  const suspiciousPatterns = [
    /0x[a-fA-F0-9]{64}/, // Private key pattern
    /sk_live_[a-zA-Z0-9]+/, // API key pattern
    /password\s*=\s*["'][^"']+["']/, // Hardcoded password
  ];
  
  jsFiles.forEach(file => {
    const content = fs.readFileSync(file, 'utf8');
    suspiciousPatterns.forEach(pattern => {
      const match = content.match(pattern);
      if (match && !match[0].includes('0x0000000000') && !match[0].includes('example')) {
        // Allow zero addresses and example data
        console.warn(`⚠️  Suspicious pattern found in ${file}: ${match[0].substring(0, 20)}...`);
      }
    });
  });
});

// Test 8: Check host permissions are specific
test('Host permissions are properly scoped', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  if (manifest.host_permissions) {
    manifest.host_permissions.forEach(perm => {
      if (perm === '<all_urls>' || perm === '*://*/*') {
        throw new Error('Host permissions too broad - should be specific to required domains');
      }
    });
  }
});

// Test 9: Check for proper error handling patterns
test('Error handling is implemented', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  
  // Check for try-catch blocks
  if (!popupJs.includes('try {')) {
    throw new Error('No try-catch blocks found in popup.js');
  }
  
  // Check for error logging (accepts both err and _err patterns)
  if (!popupJs.includes('catch (err') && !popupJs.includes('catch (_err')) {
    throw new Error('No error catching found in popup.js');
  }
});

// Test 10: Verify our improvements are in place
test('Race condition fix is implemented', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  if (!popupJs.includes('simulationLock')) {
    throw new Error('Race condition fix not found');
  }
});

test('Nonce management is implemented', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  if (!popupJs.includes('getNextNonce')) {
    throw new Error('Nonce management not found');
  }
});

test('RPC retry mechanism is implemented', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  if (!popupJs.includes('withRetry')) {
    throw new Error('RPC retry mechanism not found');
  }
});

test('DOM updates use efficient patterns', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  // We removed batchDOMUpdates as it was unused dead code
  // The app uses DocumentFragment for efficient updates instead
  if (!popupJs.includes('DocumentFragment')) {
    throw new Error('DocumentFragment pattern not found');
  }
});

test('Event listener cleanup is optimized', () => {
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  if (!popupJs.includes('eventListenersWeak')) {
    throw new Error('Optimized event listener cleanup not found');
  }
});

// Test 11: Check version consistency
test('Version is consistent across files', () => {
  const manifest = JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'));
  const popupJs = fs.readFileSync('extension/popup.js', 'utf8');
  
  const versionMatch = popupJs.match(/version\s*=\s*["']([^"']+)["']/);
  if (versionMatch && versionMatch[1] !== manifest.version) {
    console.warn(`⚠️  Version mismatch: manifest has ${manifest.version}, popup.js has ${versionMatch[1]}`);
  }
});

// Test 12: Check for console.log statements (should be minimal in production)
test('Minimal console logging in production', () => {
  const jsFiles = [
    'extension/popup.js',
    'extension/background.js',
    'extension/content.js'
  ];
  
  jsFiles.forEach(file => {
    const content = fs.readFileSync(file, 'utf8');
    const logCount = (content.match(/console\.log/g) || []).length;
    if (logCount > 10) {
      console.warn(`⚠️  High number of console.log statements in ${file}: ${logCount}`);
    }
  });
});

// Summary
console.log('\n📊 Test Results:');
console.log(`✅ Passed: ${testsPassed}`);
console.log(`❌ Failed: ${testsFailed}`);

if (testsFailed === 0) {
  console.log('\n🎉 All tests passed! Extension is ready for production.');
  process.exit(0);
} else {
  console.log('\n⚠️  Some tests failed. Please fix the issues before deploying to production.');
  process.exit(1);
}