// EIP-7702 Delegation and Batching Module
// Supports Ethereum Mainnet, Base, and their testnets
// Uses CREATE2 deterministic deployment - same address on all chains

const EIP7702 = {
  // BasicEOABatchExecutor contract address (canonical singleton via CREATE2)
  // Same address on all supported chains (Ethereum, Base, testnets)
  EXECUTOR_ADDRESS: '0x00000000BEBEDB7C30ee418158e26E31a5A8f3E2',
  
  // ERC-7821 modes
  MODE_SINGLE_NO_OPDATA: '0x0100000000000000000000000000000000000000000000000000000000000000',
  
  // ERC-7821 ABI for batch executor
  EXECUTOR_ABI: [
    'function execute(bytes32 mode, bytes executionData) payable',
    'function supportsExecutionMode(bytes32 mode) view returns (bool)'
  ],
  
  /**
   * Check if an EOA has a 7702 delegation indicator
   * @param {string} address - EOA address to check
   * @param {ethers.Provider} provider - Ethers provider
   * @returns {Object} { isDelegated: boolean, delegatedTo: string|null }
   */
  async checkDelegation(address, provider) {
    try {
      const code = await provider.getCode(address);
      
      // Check for delegation indicator (0xef0100 prefix)
      if (code && code.startsWith('0xef0100')) {
        // Extract the delegated address (20 bytes after the 3-byte prefix)
        // 0xef0100 is 8 characters (including 0x), so address starts at position 8
        const delegatedTo = '0x' + code.slice(8, 48);
        
        // Check if it's delegated to our executor
        const isOurExecutor = delegatedTo.toLowerCase() === this.EXECUTOR_ADDRESS.toLowerCase();
        
        return {
          isDelegated: true,
          delegatedTo: delegatedTo,
          isOurExecutor: isOurExecutor
        };
      }
      
      return {
        isDelegated: false,
        delegatedTo: null,
        isOurExecutor: false
      };
    } catch (error) {
      console.error('Error checking delegation:', error);
      return {
        isDelegated: false,
        delegatedTo: null,
        isOurExecutor: false
      };
    }
  },
  
  /**
   * Create authorization for 7702 delegation
   * @param {ethers.Signer} signer - Ethers signer
   * @param {number} chainId - Chain ID
   * @param {string} delegateAddress - Address to delegate to (or 0x0 to revoke)
   * @param {boolean} isSelfSigned - Whether the signer is also the tx sender
   * @returns {Object} Authorization tuple
   */
  async createAuthorization(signer, chainId, delegateAddress = null, isSelfSigned = true) {
    const address = delegateAddress || this.EXECUTOR_ADDRESS;
    const currentNonce = await signer.provider.getTransactionCount(await signer.getAddress(), 'latest');
    
    // For self-delegation (sender == authorizer), use nonce + 1
    // This is because the sender's nonce increments before processing authorizations
    const authNonce = isSelfSigned ? currentNonce + 1 : currentNonce;
    
    const authorization = await signer.authorize({
      chainId: chainId,
      address: address,
      nonce: authNonce
    });
    
    return authorization;
  },
  
  /**
   * Encode batched calls for ERC-7821 executor
   * @param {Array} calls - Array of {target, value, data} objects
   * @returns {string} Encoded calldata for execute function
   */
  encodeBatchedCalls(calls) {
    // Validate input
    if (!Array.isArray(calls) || calls.length === 0) {
      throw new Error('Calls must be a non-empty array');
    }
    
    // Create interface for encoding
    const iface = new ethers.Interface(this.EXECUTOR_ABI);
    
    // Transform and validate calls to match ERC-7821 Call struct
    const formattedCalls = calls.map((call, index) => {
      const target = call.target || call.to;
      
      // Validate target address (allow address(0) as it becomes address(this))
      if (target === undefined || target === null) {
        throw new Error(`Call ${index}: Missing target address`);
      }
      
      if (target !== ethers.ZeroAddress && !ethers.isAddress(target)) {
        throw new Error(`Call ${index}: Invalid target address ${target}`);
      }
      
      // Validate and format value
      let value = call.value || '0';
      try {
        // Ensure value is a valid BigNumber string
        value = ethers.toBigInt(value).toString();
      } catch (e) {
        throw new Error(`Call ${index}: Invalid value ${call.value}`);
      }
      
      // Validate data
      const data = call.data || '0x';
      if (typeof data !== 'string' || !data.startsWith('0x')) {
        throw new Error(`Call ${index}: Invalid data - must be hex string starting with 0x`);
      }
      
      return {
        target: target,
        value: value,
        data: data
      };
    });
    
    // Encode the calls array according to ERC-7821 spec
    // The contract expects: abi.encode(Call[]) for mode without opData
    const coder = ethers.AbiCoder.defaultAbiCoder();
    const executionData = coder.encode(
      ['tuple(address target, uint256 value, bytes data)[]'],
      [formattedCalls]
    );
    
    // Encode the full execute call
    return iface.encodeFunctionData('execute', [this.MODE_SINGLE_NO_OPDATA, executionData]);
  },
  
  /**
   * Simulate a batched transaction using eth_call
   * @param {Object} params - Transaction parameters
   * @returns {Object} Simulation result
   */
  async simulateBatchedTx(params) {
    const { from, to, data, value = '0', provider } = params;
    
    try {
      // Use eth_call to simulate the transaction
      const result = await provider.call({
        from: from,
        to: to,
        data: data,
        value: value
      });
      
      return {
        success: true,
        result: result,
        error: null
      };
    } catch (error) {
      // Parse the error to get useful information
      let errorMessage = error.message || 'Unknown error';
      
      // Common error patterns
      if (errorMessage.includes('revert')) {
        errorMessage = 'Transaction would revert';
      } else if (errorMessage.includes('insufficient')) {
        errorMessage = 'Insufficient funds or allowance';
      }
      
      return {
        success: false,
        result: null,
        error: errorMessage
      };
    }
  },
  
  /**
   * Create a batched swap transaction (approve + swap in one tx)
   * @param {Object} params - Swap parameters
   * @returns {Object} Transaction object for type-4 transaction
   */
  async createBatchedSwapTx(params) {
    const {
      signer,
      tokenAddress,
      spenderAddress,
      approveAmount,
      approveData,
      swapData,
      swapTarget,
      swapValue = '0',
      gasSettings,
      simulate = true // Add option to simulate
    } = params;
    
    const account = await signer.getAddress();
    const chainId = Number((await signer.provider.getNetwork()).chainId);
    
    // Check if already delegated
    const delegation = await this.checkDelegation(account, signer.provider);
    
    const calls = [
      // Approve call
      {
        target: tokenAddress,
        value: '0',
        data: approveData
      },
      // Swap call
      {
        target: swapTarget,
        value: swapValue,
        data: swapData
      }
    ];
    
    // Encode the batched calls
    const batchedCalldata = this.encodeBatchedCalls(calls);
    
    // Simulate if requested and already delegated
    if (simulate && delegation.isOurExecutor) {
      const simulation = await this.simulateBatchedTx({
        from: account,
        to: account, // Call into EOA itself
        data: batchedCalldata,
        value: swapValue,
        provider: signer.provider
      });
      
      if (!simulation.success) {
        throw new Error(`Simulation failed: ${simulation.error}`);
      }
    }
    
    // Prepare transaction
    const tx = {
      type: 4, // EIP-7702 transaction type
      to: account, // Call into the EOA itself (executes delegated code)
      data: batchedCalldata,
      value: swapValue,
      ...gasSettings
    };
    
    // Add authorization list if not already delegated
    if (!delegation.isOurExecutor) {
        const authorization = await this.createAuthorization(signer, chainId);
      tx.authorizationList = [authorization];
    }
    
    return tx;
  },
  
  /**
   * Send a 7702 delegation transaction
   * @param {ethers.Signer} signer - Ethers signer
   * @param {string} delegateAddress - Address to delegate to (null for default executor)
   * @returns {Object} Transaction receipt
   */
  async sendDelegation(signer, delegateAddress = null) {
    const address = delegateAddress || this.EXECUTOR_ADDRESS;
    const chainId = Number((await signer.provider.getNetwork()).chainId);
    const account = await signer.getAddress();
    
    // Create authorization
    const authorization = await this.createAuthorization(signer, chainId, address);
    
    // Send type-4 transaction with authorization
    const tx = await signer.sendTransaction({
      type: 4,
      to: account,
      data: '0x', // No calldata needed for just delegation
      authorizationList: [authorization]
    });
    
    return await tx.wait();
  },
  
  /**
   * Revoke 7702 delegation
   * @param {ethers.Signer} signer - Ethers signer
   * @returns {Object} Transaction receipt
   */
  async revokeDelegation(signer) {
    const chainId = Number((await signer.provider.getNetwork()).chainId);
    const account = await signer.getAddress();
    const currentNonce = await signer.provider.getTransactionCount(account, 'latest');
    
    // Create revocation authorization (delegate to zero address)
    const revokeAuth = await signer.authorize({
      chainId: chainId,
      address: ethers.ZeroAddress,
      nonce: currentNonce + 1
    });
    
    // Send type-4 transaction to revoke
    const tx = await signer.sendTransaction({
      type: 4,
      to: account,
      data: '0x',
      authorizationList: [revokeAuth]
    });
    
    return await tx.wait();
  },
  
/**
   * Check if the current environment supports EIP-7702
   * @param {import('ethers').Provider} provider - Ethers provider
   * @returns {boolean} True if 7702 is supported
   */
  async isSupported(provider) {
    try {
      // Check if we're on a network that supports 7702
      const network = await provider.getNetwork();
      const chainId = Number(network.chainId);
      
      // List of chains that support 7702
      const supportedChains = [
        1,        // Ethereum Mainnet (after Pectra)
        8453,     // Base Mainnet (confirmed by user as live)
        11155111, // Sepolia testnet 
        84532,    // Base Sepolia testnet
        // Add more chains as they adopt 7702
      ];
      
      return supportedChains.includes(chainId);
    } catch (error) {
      console.error('Error checking 7702 support:', error);
      return false;
    }
  },
  
  /**
   * Helper to determine if we should use batching for a swap
   * @param {string} address - User's EOA address
   * @param {ethers.Provider} provider - Ethers provider
   * @param {boolean} requiresApproval - Whether the swap requires approval
   * @returns {boolean} True if we should use batched transaction
   */
  async shouldUseBatching(address, provider, requiresApproval) {
    // Only use batching if:
    // 1. 7702 is supported on this network
    // 2. The EOA has delegation to our executor
    // 3. The swap requires approval (otherwise no benefit)
    
    if (!requiresApproval) {
      return false;
    }
    
    const isSupported = await this.isSupported(provider);
    if (!isSupported) {
      return false;
    }
    
    const delegation = await this.checkDelegation(address, provider);
    return delegation.isOurExecutor;
  },
  
  /**
   * Create UI element to show delegation status
   * @param {string} address - User's EOA address
   * @param {ethers.Provider} provider - Ethers provider
   * @returns {string} HTML string for status display
   */
  async getDelegationStatusHTML(address, provider) {
    const delegation = await this.checkDelegation(address, provider);
    
    if (delegation.isDelegated) {
      if (delegation.isOurExecutor) {
        return `
          <div class="delegation-status active">
            <span class="status-icon">🔗</span>
            <span class="status-text">7702 Batching Active</span>
            <span class="status-address" title="${delegation.delegatedTo}">${delegation.delegatedTo.slice(0, 6)}...${delegation.delegatedTo.slice(-4)}</span>
          </div>
        `;
      } else {
        return `
          <div class="delegation-status other">
            <span class="status-icon">⚠️</span>
            <span class="status-text">Delegated to Other</span>
            <span class="status-address" title="${delegation.delegatedTo}">${delegation.delegatedTo.slice(0, 6)}...${delegation.delegatedTo.slice(-4)}</span>
          </div>
        `;
      }
    } else {
      return `
        <div class="delegation-status inactive">
          <span class="status-icon">⭕</span>
          <span class="status-text">Standard EOA</span>
        </div>
      `;
    }
  }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = EIP7702;
}

