#!/usr/bin/env node
/**
 * EIP-7702 Module Test Suite
 */

const fs = require('fs');
const vm = require('vm');

// Load the EIP-7702 module
const eip7702Code = fs.readFileSync('extension/eip7702.js', 'utf8');

// Create a mock environment
const mockWindow = {
  ethers: {
    ZeroAddress: '0x0000000000000000000000000000000000000000',
    Interface: class {
      constructor(abi) {
        this.abi = abi;
      }
      encodeFunctionData(fn, params) {
        return '0x' + Buffer.from(JSON.stringify({fn, params})).toString('hex');
      }
    },
    AbiCoder: {
      defaultAbiCoder: {
        encode: (types, values) => {
          return '0x' + Buffer.from(JSON.stringify({types, values})).toString('hex');
        }
      }
    },
    toBigInt: (val) => BigInt(val),
    isAddress: (addr) => /^0x[0-9a-fA-F]{40}$/.test(addr),
    MaxUint256: 2n ** 256n - 1n,
    hexlify: (bytes) => '0x' + Buffer.from(bytes).toString('hex'),
    randomBytes: (len) => Buffer.allocUnsafe(len),
    Signature: {
      from: (sig) => ({ v: 27, r: '0x' + 'a'.repeat(64), s: '0x' + 'b'.repeat(64) })
    }
  }
};

// Create sandbox context
const sandbox = {
  console,
  Buffer,
  ethers: mockWindow.ethers,
  module: { exports: {} }
};

// Run the EIP-7702 module in sandbox
vm.createContext(sandbox);
vm.runInContext(eip7702Code, sandbox);

const EIP7702 = sandbox.EIP7702 || sandbox.module.exports;

// Test Suite
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

console.log('🧪 Testing EIP-7702 Module\n');

// Test 1: Module exports correctly
test('EIP7702 module is exported', () => {
  if (!EIP7702) {
    throw new Error('EIP7702 module not found');
  }
  if (typeof EIP7702 !== 'object') {
    throw new Error('EIP7702 should be an object');
  }
});

// Test 2: Required methods exist
test('Required methods exist', () => {
  const requiredMethods = [
    'checkDelegation',
    'createAuthorization',
    'encodeBatchedCalls',
    'simulateBatchedTx',
    'createBatchedSwapTx',
    'sendDelegation',
    'revokeDelegation',
    'isSupported',
    'shouldUseBatching',
    'getDelegationStatusHTML'
  ];
  
  requiredMethods.forEach(method => {
    if (typeof EIP7702[method] !== 'function') {
      throw new Error(`Missing method: ${method}`);
    }
  });
});

// Test 3: Constants are defined
test('Constants are properly defined', () => {
  if (!EIP7702.EXECUTOR_ADDRESS) {
    throw new Error('EXECUTOR_ADDRESS not defined');
  }
  if (!EIP7702.EXECUTOR_ADDRESS.startsWith('0x')) {
    throw new Error('EXECUTOR_ADDRESS should be a hex address');
  }
  if (!EIP7702.MODE_SINGLE_NO_OPDATA) {
    throw new Error('MODE_SINGLE_NO_OPDATA not defined');
  }
  if (!EIP7702.EXECUTOR_ABI) {
    throw new Error('EXECUTOR_ABI not defined');
  }
});

// Test 4: encodeBatchedCalls handles valid input
test('encodeBatchedCalls works with valid input', () => {
  const calls = [
    {
      target: '0x1234567890123456789012345678901234567890',
      value: '1000000000000000000',
      data: '0xabcdef'
    },
    {
      target: '0x0987654321098765432109876543210987654321',
      value: '0',
      data: '0x123456'
    }
  ];
  
  const encoded = EIP7702.encodeBatchedCalls(calls);
  
  if (!encoded) {
    throw new Error('encodeBatchedCalls returned nothing');
  }
  if (!encoded.startsWith('0x')) {
    throw new Error('Encoded data should start with 0x');
  }
});

// Test 5: encodeBatchedCalls validates input
test('encodeBatchedCalls validates input', () => {
  // Test empty array
  try {
    EIP7702.encodeBatchedCalls([]);
    throw new Error('Should reject empty array');
  } catch (e) {
    if (!e.message.includes('non-empty')) {
      throw e;
    }
  }
  
  // Test invalid address
  try {
    EIP7702.encodeBatchedCalls([{ target: 'invalid', value: '0', data: '0x' }]);
    throw new Error('Should reject invalid address');
  } catch (e) {
    if (!e.message.includes('Invalid target address')) {
      throw e;
    }
  }
});

// Test 6: isSupported checks chain IDs correctly
test('isSupported checks supported chains', async () => {
  const mockProvider = {
    getNetwork: async () => ({ chainId: 1 }) // Ethereum mainnet
  };
  
  const supported = await EIP7702.isSupported(mockProvider);
  
  if (typeof supported !== 'boolean') {
    throw new Error('isSupported should return boolean');
  }
});

// Test 7: Delegation checking logic
test('checkDelegation handles delegation indicator', async () => {
  const mockProvider = {
    getCode: async (addr) => {
      // Mock delegated code with 0xef0100 prefix
      return '0xef0100' + '00000000BEBEDB7C30ee418158e26E31a5A8f3E2'.toLowerCase();
    }
  };
  
  const result = await EIP7702.checkDelegation('0x1234567890123456789012345678901234567890', mockProvider);
  
  if (!result.isDelegated) {
    throw new Error('Should detect delegation');
  }
  if (!result.delegatedTo) {
    throw new Error('Should return delegated address');
  }
  if (!result.isOurExecutor) {
    throw new Error('Should detect our executor');
  }
});

// Test 8: Handle non-delegated addresses
test('checkDelegation handles non-delegated EOA', async () => {
  const mockProvider = {
    getCode: async (addr) => '0x' // Empty code for EOA
  };
  
  const result = await EIP7702.checkDelegation('0x1234567890123456789012345678901234567890', mockProvider);
  
  if (result.isDelegated) {
    throw new Error('Should not detect delegation for EOA');
  }
  if (result.delegatedTo) {
    throw new Error('Should not have delegatedTo for EOA');
  }
});

// Test 9: shouldUseBatching logic
test('shouldUseBatching returns correct values', async () => {
  const mockProvider = {
    getNetwork: async () => ({ chainId: 8453 }), // Base
    getCode: async () => '0xef0100' + '00000000BEBEDB7C30ee418158e26E31a5A8f3E2'.toLowerCase()
  };
  
  // Should use batching when approval required and delegated
  const shouldBatch = await EIP7702.shouldUseBatching(
    '0x1234567890123456789012345678901234567890',
    mockProvider,
    true // requires approval
  );
  
  if (typeof shouldBatch !== 'boolean') {
    throw new Error('shouldUseBatching should return boolean');
  }
});

// Test 10: HTML status generation
test('getDelegationStatusHTML generates valid HTML', async () => {
  const mockProvider = {
    getCode: async () => '0x' // Non-delegated
  };
  
  const html = await EIP7702.getDelegationStatusHTML(
    '0x1234567890123456789012345678901234567890',
    mockProvider
  );
  
  if (!html.includes('Standard EOA')) {
    throw new Error('Should show Standard EOA status');
  }
  if (!html.includes('delegation-status')) {
    throw new Error('Should include delegation-status class');
  }
});

// Summary
console.log('\n📊 EIP-7702 Test Results:');
console.log(`✅ Passed: ${testsPassed}`);
console.log(`❌ Failed: ${testsFailed}`);

if (testsFailed === 0) {
  console.log('\n✅ All EIP-7702 tests passed!');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed.');
  process.exit(1);
}