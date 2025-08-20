// EIP-7702 Delegation and Batching Module
// Supports Ethereum Mainnet, Base, and their testnets
// Uses CREATE2 deterministic deployment - same address on all chains
const EIP7702 = {
  // BasicEOABatchExecutor contract address (canonical singleton via CREATE2)
  // Same address on all supported chains (Ethereum, Base, testnets)
  // This is a deterministic deployment ensuring same code across all chains
  // Per best practices: "Contracts should be deployed with CREATE2 to have some 
  // guarantees of what code is at a specific address"
  EXECUTOR_ADDRESS: "0x00000000BEBEDB7C30ee418158e26E31a5A8f3E2",
  
  // ERC-7821 execution mode for batch calls without opData
  // Per ERC-7821 spec: mode = 0x01000000000000000000... means:
  // - Byte 0: 0x01 = batch call
  // - Byte 1: 0x00 = revert on any failure
  // - Bytes 2-5: Reserved (0x00000000)
  // - Bytes 6-9: 0x00000000 = no opData support
  // - Bytes 10-31: Unused (all zeros)
  // When opData is empty, executor requires msg.sender == address(this)
  MODE_SINGLE_NO_OPDATA: "0x0100000000000000000000000000000000000000000000000000000000000000",
  
  // Cache for delegation status to reduce RPC calls
  // Key: address, Value: { status, timestamp }
  delegationCache: new Map(),
  CACHE_TTL: 30000, // 30 seconds cache
  
  // ERC-7821 ABI for batch executor
  EXECUTOR_ABI: [
    "function execute(bytes32 mode, bytes executionData) payable",
    "function supportsExecutionMode(bytes32 mode) view returns (bool)"
  ],
  
  /**
   * Check if an EOA has a 7702 delegation indicator
   * @param {string} address - EOA address to check
   * @param {ethers.Provider} provider - Ethers provider
   * @returns {Object} { isDelegated: boolean, delegatedTo: string|null }
   */
  async checkDelegation(address, provider, forceRefresh = false) {
    // Check cache first for better performance
    const cacheKey = address.toLowerCase();
    const cached = this.delegationCache.get(cacheKey);
    
    if (!forceRefresh && cached && (Date.now() - cached.timestamp < this.CACHE_TTL)) {
      return cached.status;
    }
    
    try {
      const code = await provider.getCode(address);
      
      let result;
      // Check for delegation indicator (0xef0100 prefix)
      // Per EIP-7702: delegation indicator is exactly 0xef0100 + 20-byte address
      if (code && code.startsWith("0xef0100") && code.length === 48) {
        // Extract the delegated address (20 bytes after the 3-byte prefix)
        // 0xef0100 is 8 characters (including 0x), so address starts at position 8
        // Position 8 to 48 = 40 hex chars = 20 bytes
        const delegatedTo = "0x" + code.slice(8, 48);
        
        // Check if it's delegated to our executor
        const isOurExecutor = delegatedTo.toLowerCase() === this.EXECUTOR_ADDRESS.toLowerCase();
        
        result = {
          isDelegated: true,
          delegatedTo: delegatedTo,
          isOurExecutor: isOurExecutor
        };
      } else {
        result = {
          isDelegated: false,
          delegatedTo: null,
          isOurExecutor: false
        };
      }
      
      // Cache the result
      this.delegationCache.set(cacheKey, {
        status: result,
        timestamp: Date.now()
      });
      
      return result;
    } catch (error) {
      console.error("Error checking delegation:", error);
      return {
        isDelegated: false,
        delegatedTo: null,
        isOurExecutor: false
      };
    }
  },
  
  /**
   * Clear delegation cache for an address
   */
  clearDelegationCache(address = null) {
    if (address) {
      // Ensure consistent lowercase for cache keys
      this.delegationCache.delete(address.toLowerCase());
    } else {
      this.delegationCache.clear();
    }
  },
  
  /**
   * Polyfill for signer.authorize if not available in ethers v6.15.0
   * Creates an EIP-7702 authorization signature
   * @param {ethers.Signer} signer - Ethers signer
   * @param {Object} authRequest - Authorization request
   * @returns {Object} Authorization tuple
   */
  /**
   * Simple RLP encoding for EIP-7702 authorization
   * @param {Array} input - Array to RLP encode
   * @returns {Uint8Array} RLP encoded bytes
   */
  rlpEncode(input) {
    // Simple RLP encoder for the specific case of [chainId, address, nonce]
    const encodeLength = (len, offset) => {
      if (len < 56) {
        return new Uint8Array([offset + len]);
      }
      const hexLen = len.toString(16);
      const lLength = Math.ceil(hexLen.length / 2);
      const firstByte = offset + 55 + lLength;
      const lenBytes = new Uint8Array(lLength);
      for (let i = 0; i < lLength; i++) {
        lenBytes[lLength - 1 - i] = len >> (i * 8);
      }
      return ethers.concat([new Uint8Array([firstByte]), lenBytes]);
    };
    
    const encodeElement = (item) => {
      if (typeof item === 'number' || typeof item === 'bigint') {
        // Convert number to minimal byte representation
        if (item === 0 || item === 0n) {
          return new Uint8Array([0x80]); // RLP encoding of 0
        }
        const hex = item.toString(16);
        const padded = hex.length % 2 ? '0' + hex : hex;
        const bytes = ethers.getBytes('0x' + padded);
        if (bytes.length === 1 && bytes[0] < 0x80) {
          return bytes;
        }
        return ethers.concat([encodeLength(bytes.length, 0x80), bytes]);
      } else if (typeof item === 'string' && item.startsWith('0x')) {
        // Address
        const bytes = ethers.getBytes(item);
        return ethers.concat([encodeLength(bytes.length, 0x80), bytes]);
      }
      throw new Error('Unsupported type for RLP encoding');
    };
    
    // Encode each element
    const encodedElements = input.map(encodeElement);
    const concatenated = ethers.concat(encodedElements);
    
    // Encode the list
    const listPrefix = encodeLength(concatenated.length, 0xc0);
    return ethers.concat([listPrefix, concatenated]);
  },

  async authorizePolyfill(signer, authRequest) {
    const { chainId, address, nonce } = authRequest;
    
    // Create the authorization payload per EIP-7702 spec
    // The message to sign is: keccak256(MAGIC || rlp([chain_id, address, nonce]))
    // MAGIC = 0x05
    
    // RLP encode [chainId, address, nonce]
    const rlpEncoded = this.rlpEncode([chainId, address, nonce]);
    
    // Create the message hash: keccak256(0x05 || rlp([chainId, address, nonce]))
    const messageHash = ethers.keccak256(
      ethers.concat([
        "0x05", // EIP-7702 magic byte
        rlpEncoded
      ])
    );
    
    // Sign the raw hash WITHOUT personal_sign prefix
    // In ethers v6, we need to use _signTypedData or create a raw signature
    // Since we need raw signing, we'll use the signer's private key if available
    let sig;
    
    if (signer._signingKey) {
      // If we have access to the signing key (like with Wallet instances)
      const signingKey = signer._signingKey();
      sig = signingKey.sign(messageHash);
    } else if (signer.signTypedData) {
      // Fallback: Try using signTypedData with minimal structure
      // This is not ideal but might work with some providers
      try {
        const rawSig = await signer.signTypedData(
          {}, // empty domain
          { Message: [{ name: 'hash', type: 'bytes32' }] },
          { hash: messageHash }
        );
        sig = ethers.Signature.from(rawSig);
      } catch (e) {
        // Final fallback: use signMessage (will have wrong prefix but might work)
        console.warn("[EIP7702] Using signMessage fallback - may not work correctly");
        const signature = await signer.signMessage(ethers.getBytes(messageHash));
        sig = ethers.Signature.from(signature);
      }
    } else {
      // Last resort: use signMessage
      console.warn("[EIP7702] Using signMessage fallback - may not work correctly");
      const signature = await signer.signMessage(ethers.getBytes(messageHash));
      sig = ethers.Signature.from(signature);
    }
    
    // Return authorization tuple format per spec
    return {
      chainId: chainId,
      address: address,
      nonce: nonce,
      r: sig.r,
      s: sig.s,
      yParity: sig.yParity !== undefined ? sig.yParity : (sig.v ? sig.v - 27 : 0)
    };
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
    const signerAddress = await signer.getAddress();
    
    // Validate chainId matches current network (unless chainId is 0 which means any chain)
    const currentChainId = Number((await signer.provider.getNetwork()).chainId);
    if (chainId !== 0 && chainId !== currentChainId) {
      throw new Error(`Chain ID mismatch: expected ${currentChainId}, got ${chainId}`);
    }
    
    const currentNonce = await signer.provider.getTransactionCount(signerAddress, "latest");
    
    // EIP-7702 Nonce Handling (per official spec):
    // The authorization list is processed AFTER the sender's nonce is incremented.
    // 
    // For self-delegation (tx.sender == authority):
    // 1. Before tx: sender's nonce = N
    // 2. Tx starts: sender's nonce increments to N+1
    // 3. Auth validation: checks if authority's nonce matches signed nonce
    // 4. Since sender IS the authority, their nonce is now N+1
    // 5. Therefore: must sign with nonce = N+1
    //
    // For cross-delegation (tx.sender != authority):
    // - Authority's nonce hasn't changed, use their current nonce
    const authNonce = isSelfSigned ? currentNonce + 1 : currentNonce;
    
    // Use native authorize method in ethers v6.15.0
    try {
      const authorization = await signer.authorize({
        chainId: chainId,
        address: address,
        nonce: authNonce
      });
      return authorization;
    } catch (error) {
      // If native method fails, try our polyfill as fallback
      console.warn("[EIP7702] Native authorize failed, using polyfill:", error.message);
      return await this.authorizePolyfill(signer, {
        chainId: chainId,
        address: address,
        nonce: authNonce
      });
    }
  },
  
  /**
   * Encode batched calls for ERC-7821 executor
   * @param {Array} calls - Array of {target, value, data} objects
   * @returns {string} Encoded calldata for execute function
   */
  encodeBatchedCalls(calls) {
    // Validate input
    if (!Array.isArray(calls) || calls.length === 0) {
      throw new Error("Calls must be a non-empty array");
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
      let value = call.value || "0";
      try {
        // Ensure value is a valid BigNumber string
        value = ethers.toBigInt(value).toString();
      } catch (e) {
        throw new Error(`Call ${index}: Invalid value ${call.value}`);
      }
      
      // Validate data
      const data = call.data || "0x";
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
    // For mode 0x01000000000000000000... (no opData), executionData = abi.encode(Call[])
    // Call struct matches BasicEOABatchExecutor's ERC7821.Call:
    // - address target: contract to call (or address(0) for self)
    // - uint256 value: ETH to send with call
    // - bytes data: calldata for the call
    // Auth requirement: msg.sender must be address(this) when opData is empty
    const coder = ethers.AbiCoder.defaultAbiCoder();
    const executionData = coder.encode(
      ["tuple(address target, uint256 value, bytes data)[]"],
      [formattedCalls]
    );
    
    // Encode the full execute call
    return iface.encodeFunctionData("execute", [this.MODE_SINGLE_NO_OPDATA, executionData]);
  },
  
  /**
   * Simulate a batched transaction using eth_call
   * @param {Object} params - Transaction parameters
   * @returns {Object} Simulation result
   */
  async simulateBatchedTx(params) {
    const { from, to, data, value = "0", provider } = params;
    
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
      let errorMessage = error.message || "Unknown error";
      
      // Common error patterns
      if (errorMessage.includes("revert")) {
        errorMessage = "Transaction would revert";
      } else if (errorMessage.includes("insufficient")) {
        errorMessage = "Insufficient funds or allowance";
      }
      
      return {
        success: false,
        result: null,
        error: errorMessage
      };
    }
  },
  
  /**
   * Send a type-4 transaction with authorization list
   * Uses modern ethers v6.15.0 methods for proper EIP-7702 support
   * @param {ethers.Signer} signer - Ethers signer
   * @param {Object} tx - Transaction object with authorizationList
   * @returns {Object} Transaction response
   */
  async sendType4Transaction(signer, tx) {
    try {
      // Use ethers v6.15.0's proper transaction preparation
      // This will handle authorizationList properly
      const provider = signer.provider;
      
      // Prepare the transaction with proper type-4 support
      // preparedTransactionRequest will have authorizationList field
      const prepared = await provider.prepareTransaction({
        ...tx,
        from: await signer.getAddress(),
        type: 4 // Ensure type-4
      });
      
      // Send the prepared transaction
      // The transactionRequest.authorizationList will be included
      const response = await signer.sendTransaction(prepared);
      
      // The transactionResponse.authorizationList will contain the authorizations
      console.log("[EIP7702] Type-4 tx sent with authorizations:", response.authorizationList);
      
      return response;
    } catch (error) {
      // If preparation fails, try direct send
      if (signer.sendTransaction) {
        try {
          const response = await signer.sendTransaction(tx);
          console.log("[EIP7702] Direct send successful");
          return response;
        } catch (sendError) {
          console.error("[EIP7702] Failed to send type-4 transaction:", sendError);
          throw sendError;
        }
      }
      throw error;
    }
  },

  /**
   * Manually serialize and send type-4 transaction
   * For providers that don't natively support EIP-7702
   * @param {ethers.Signer} signer - Ethers signer
   * @param {Object} tx - Transaction object
   * @returns {Object} Transaction response
   */
  async sendType4TransactionManual() {
    // Manual handling for type-4 transactions when not natively supported
    // This is a fallback that won't work with current ethers v6.15.0
    // but provides a clear error message
    throw new Error(
      "Type-4 transactions are not supported by your current provider. " +
      "Please use a provider that supports EIP-7702 (e.g., latest Ethereum nodes with Pectra upgrade)."
    );
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
      // spenderAddress, // Accept but don't require - for compatibility
      // approveAmount,  // Accept but don't require - for compatibility
      approveData,
      swapData,
      swapTarget,
      swapValue = "0",
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
        value: "0",
        data: approveData
      },
      // Swap call
      {
        target: swapTarget,
        value: swapValue,
        data: swapData
      }
    ];
    
    console.log("[EIP7702] Calls to batch:", {
      approve: {
        target: tokenAddress,
        value: "0",
        data: approveData ? approveData.slice(0, 100) + "..." : "no data"
      },
      swap: {
        target: swapTarget,
        value: swapValue,
        data: swapData ? swapData.slice(0, 100) + "..." : "no data"
      }
    });
    
    // Encode the batched calls
    const batchedCalldata = this.encodeBatchedCalls(calls);
    
    console.log("[EIP7702] Encoded batched calldata:", batchedCalldata ? batchedCalldata.slice(0, 100) + "..." : "no data");
    console.log("[EIP7702] Delegation status:", delegation);
    
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
    
    // Estimate gas for batched transaction
    // EIP-7702 specific gas costs per spec:
    // - PER_EMPTY_ACCOUNT_COST = 25000 per authorization (if account is empty)
    // - Authorization processing overhead
    // - Delegated code execution costs
    let gasLimit = 400000n; // Default for batched approve + swap
    
    try {
      if (delegation.isOurExecutor) {
        // Already delegated - can estimate actual execution cost
        const estimated = await signer.provider.estimateGas({
          from: account,
          to: account,
          data: batchedCalldata,
          value: swapValue
        });
        gasLimit = (estimated * 120n) / 100n; // 20% buffer
      } else {
        // Not delegated - need to account for authorization costs
        // Add 25000 for PER_EMPTY_ACCOUNT_COST + execution costs
        gasLimit = 425000n; // Higher default for initial delegation + execution
      }
    } catch (e) {
      console.warn("Gas estimation failed, using default:", e);
      // Use higher default if not delegated
      gasLimit = delegation.isOurExecutor ? 400000n : 425000n;
    }
    
    // Prepare base transaction
    // IMPORTANT: For ETH swaps, the value must be sent with the transaction
    // The executor will forward this value to the swap contract
    const baseTx = {
      to: account, // Call into the EOA itself (executes delegated code)
      data: batchedCalldata,
      value: swapValue, // This ETH will be forwarded by the executor to the swap
      gasLimit: gasLimit,
      ...gasSettings
    };
    
    // If already delegated, just send regular transaction to EOA
    if (delegation.isOurExecutor) {
      console.log("[EIP7702] Already delegated, sending regular tx to EOA");
      console.log("[EIP7702] Transaction details:", {
        to: account,
        data: batchedCalldata ? batchedCalldata.slice(0, 100) + "..." : "no data",
        value: swapValue,
        gasLimit: gasLimit.toString()
      });
      // When already delegated, send a REGULAR transaction (not type-4)
      // The EOA will execute the delegated contract code
      return {
        ...baseTx,
        // No type specified - this is a regular type-2 (EIP-1559) transaction
        // No authorizationList needed - already delegated
      };
    }
    
    // Need to delegate first - create type-4 transaction with authorization
    console.log("[EIP7702] Not delegated, creating type-4 tx with authorization");
    const authorization = await this.createAuthorization(signer, chainId);
    
    // IMPORTANT: Per EIP-7702 spec, if transaction execution fails,
    // the delegation is NOT rolled back. The account remains delegated.
    
    // Build the transactionRequest with authorizationList
    // This uses the proper ethers v6.15.0 format
    const transactionRequest = {
      type: 4, // EIP-7702 transaction type
      ...baseTx,
      authorizationList: [authorization] // Array<AuthorizationLike>
    };
    
    // Optionally prepare the transaction for better compatibility
    try {
      if (signer.provider.prepareTransaction) {
        const prepared = await signer.provider.prepareTransaction({
          ...transactionRequest,
          from: account
        });
        // preparedTransactionRequest.authorizationList will be properly formatted
        console.log("[EIP7702] Prepared transaction with authorizations");
        return prepared;
      }
    } catch (e) {
      console.warn("[EIP7702] Could not prepare transaction, returning raw request:", e.message);
    }
    
    return transactionRequest;
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
    
    // Check if address is a precompile (0x01 to 0x09)
    // Per spec: "When a precompile address is the target of a delegation, 
    // the retrieved code is considered empty"
    const addressBigInt = BigInt(address);
    if (addressBigInt >= 1n && addressBigInt <= 9n) {
      throw new Error("Cannot delegate to precompile addresses");
    }
    
    // Verify the executor contract exists (has code)
    const executorCode = await signer.provider.getCode(address);
    if (!executorCode || executorCode === '0x' || executorCode === '0x0') {
      throw new Error(`Executor contract not deployed at ${address} on this network`);
    }
    
    // Create authorization
    const authorization = await this.createAuthorization(signer, chainId, address);
    
    // Send type-4 transaction with authorization
    const tx = await this.sendType4Transaction(signer, {
      type: 4,
      to: account,
      value: 0, // Required field per spec
      data: "0x", // No calldata needed for just delegation
      authorizationList: [authorization]
    });
    
    const receipt = await tx.wait();
    
    // Clear cache after successful delegation
    if (receipt.status === 1) {
      this.clearDelegationCache(account);
    }
    
    return receipt;
  },
  
  /**
   * Revoke 7702 delegation
   * @param {ethers.Signer} signer - Ethers signer
   * @returns {Object} Transaction receipt
   */
  async revokeDelegation(signer) {
    const chainId = Number((await signer.provider.getNetwork()).chainId);
    const account = await signer.getAddress();
    const currentNonce = await signer.provider.getTransactionCount(account, "latest");
    
    // Create revocation authorization (delegate to zero address)
    // For self-signed revocation, nonce must be currentNonce + 1
    // because the sender's nonce increments before authorization processing
    let revokeAuth;
    try {
      // Use native authorize method in ethers v6.15.0
      revokeAuth = await signer.authorize({
        chainId: chainId,
        address: ethers.ZeroAddress,
        nonce: currentNonce + 1
      });
    } catch (error) {
      // Fallback to polyfill if native method fails
      console.warn("[EIP7702] Native authorize failed for revocation, using polyfill:", error.message);
      revokeAuth = await this.authorizePolyfill(signer, {
        chainId: chainId,
        address: ethers.ZeroAddress,
        nonce: currentNonce + 1
      });
    }
    
    // Send type-4 transaction to revoke
    const tx = await this.sendType4Transaction(signer, {
      type: 4,
      to: account,
      value: 0, // Required field per spec
      data: "0x",
      authorizationList: [revokeAuth]
    });
    
    const receipt = await tx.wait();
    
    // Clear cache after successful revocation
    if (receipt.status === 1) {
      this.clearDelegationCache(account);
    }
    
    return receipt;
  },
  
  /**
   * Check if the current environment supports EIP-7702
   * @param {ethers.Provider} provider - Ethers provider
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
      console.error("Error checking 7702 support:", error);
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
    
    // Check both conditions in parallel for better performance
    const [isSupported, delegation] = await Promise.all([
      this.isSupported(provider),
      this.checkDelegation(address, provider)
    ]);
    
    return isSupported && delegation.isOurExecutor;
  },
  
  /**
   * Check if a regular transaction can be sent (not batched)
   * EOAs with delegation can still send regular transactions
   * @returns {boolean} True if regular transactions are allowed
   */
  canSendRegularTx() {
    // Per EIP-7702: "Modify the restriction put in place by EIP-3607 to allow EOAs 
    // whose code is a valid delegation indicator to originate transactions"
    // This means delegated EOAs can still send regular transactions
    return true;
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

// No need for complex exports - this is just a regular JS object in the browser extension
// It will be available as EIP7702 when this script is loaded