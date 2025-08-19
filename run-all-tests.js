#!/usr/bin/env node
/**
 * Master Test Runner for zWallet
 * Runs all test suites and provides a comprehensive report
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Color codes for output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[36m',
  magenta: '\x1b[35m'
};

console.log(`${colors.magenta}${'='.repeat(60)}${colors.reset}`);
console.log(`${colors.magenta}🧪 zWallet Comprehensive Test Suite${colors.reset}`);
console.log(`${colors.magenta}${'='.repeat(60)}${colors.reset}\n`);

const testResults = [];
let totalPassed = 0;
let totalFailed = 0;

// Define all test files
const testFiles = [
  { name: 'Base Network Integration', file: 'tests/test-base-network.js' },
  { name: 'Bridge Links', file: 'tests/test-bridge-links.js' },
  { name: 'EIP-7702 Module', file: 'tests/test-eip7702-node.js' },
  { name: 'Extension Production Readiness', file: 'tests/test-extension.js' },
  { name: 'HTML File Validation', file: 'tests/test-html-validation.js', cwd: 'tests' }
];

// Run each test file
testFiles.forEach(({ name, file, cwd }) => {
  console.log(`${colors.blue}📝 Running: ${name}${colors.reset}`);
  console.log(`${'─'.repeat(40)}`);
  
  try {
    const options = cwd ? { cwd: path.join(__dirname, cwd), encoding: 'utf8' } : { cwd: __dirname, encoding: 'utf8' };
    const output = execSync(`node ${cwd ? path.basename(file) : file}`, options);
    
    // Parse test results from output
    const passMatch = output.match(/✅ Passed: (\d+)/);
    const failMatch = output.match(/❌ Failed: (\d+)/);
    
    const passed = passMatch ? parseInt(passMatch[1]) : 0;
    const failed = failMatch ? parseInt(failMatch[1]) : 0;
    
    totalPassed += passed;
    totalFailed += failed;
    
    testResults.push({
      name,
      passed,
      failed,
      status: failed === 0 ? 'PASSED' : 'FAILED'
    });
    
    // Show summary line
    if (failed === 0) {
      console.log(`${colors.green}✅ ${name}: All ${passed} tests passed${colors.reset}`);
    } else {
      console.log(`${colors.red}❌ ${name}: ${failed} tests failed (${passed} passed)${colors.reset}`);
    }
    
  } catch (error) {
    // Even if test fails, try to extract results
    const output = error.stdout ? error.stdout.toString() : '';
    const passMatch = output.match(/✅ Passed: (\d+)/);
    const failMatch = output.match(/❌ Failed: (\d+)/);
    
    const passed = passMatch ? parseInt(passMatch[1]) : 0;
    const failed = failMatch ? parseInt(failMatch[1]) : 1;
    
    totalPassed += passed;
    totalFailed += failed;
    
    testResults.push({
      name,
      passed,
      failed,
      status: 'FAILED'
    });
    
    console.log(`${colors.red}❌ ${name}: Test suite failed${colors.reset}`);
  }
  
  console.log();
});

// Print final summary
console.log(`${colors.magenta}${'='.repeat(60)}${colors.reset}`);
console.log(`${colors.magenta}📊 Test Results Summary${colors.reset}`);
console.log(`${colors.magenta}${'='.repeat(60)}${colors.reset}\n`);

// Print detailed results table
console.log(`${'Test Suite'.padEnd(35)} | ${'Status'.padEnd(10)} | Passed | Failed`);
console.log(`${'-'.repeat(35)}-+-${'-'.repeat(10)}-+--------+-------`);

testResults.forEach(result => {
  const statusColor = result.status === 'PASSED' ? colors.green : colors.red;
  console.log(
    `${result.name.padEnd(35)} | ` +
    `${statusColor}${result.status.padEnd(10)}${colors.reset} | ` +
    `${result.passed.toString().padStart(6)} | ` +
    `${result.failed.toString().padStart(6)}`
  );
});

console.log(`${'-'.repeat(35)}-+-${'-'.repeat(10)}-+--------+-------`);
console.log(
  `${'TOTAL'.padEnd(35)} | ` +
  `${' '.repeat(10)} | ` +
  `${colors.green}${totalPassed.toString().padStart(6)}${colors.reset} | ` +
  `${totalFailed > 0 ? colors.red : ''}${totalFailed.toString().padStart(6)}${colors.reset}`
);

console.log(`\n${colors.magenta}${'='.repeat(60)}${colors.reset}`);

// Final verdict
if (totalFailed === 0) {
  console.log(`${colors.green}🎉 SUCCESS: All ${totalPassed} tests passed!${colors.reset}`);
  console.log(`${colors.green}✅ zWallet is ready for production${colors.reset}`);
} else {
  console.log(`${colors.yellow}⚠️  WARNING: ${totalFailed} tests failed${colors.reset}`);
  console.log(`${colors.yellow}Please review and fix the failing tests${colors.reset}`);
}

console.log(`${colors.magenta}${'='.repeat(60)}${colors.reset}\n`);

// Exit with appropriate code
process.exit(totalFailed > 0 ? 1 : 0);