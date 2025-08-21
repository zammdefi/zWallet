if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id) {
  document.documentElement.classList.add("is-extension");
}

// Performance optimizations and utilities
/**
 * Debounce utility for reducing function call frequency
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Throttle utility for limiting function execution rate
 * @param {Function} func - Function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

/**
 * Optimized formatters
 */
const formatBalance = (value, decimals = 18) => {
  if (!value) return "0";
  try {
    return ethers.formatUnits(value, decimals);
  } catch {
    return "0";
  }
};

const formatCurrency = (value, currency = 'USD') => {
  if (!value || isNaN(value)) return '$0.00';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  }).format(value);
};

const formatAddress = (address) => {
  if (!address) return '';
  return address.slice(0, 6) + '...' + address.slice(-4);
};

// BigInt JSON serialization support
if (!BigInt.prototype.toJSON) {
  BigInt.prototype.toJSON = function() {
    return this.toString();
  };
}

// Constants for magic numbers
const CONSTANTS = {
  PASSWORD_ITERATIONS: 600000,
  RPC_TIMEOUT: 5000,
  GAS_UPDATE_DELAY: 5000,
  ENS_RESOLVE_DELAY: 500,
  SWAP_SIMULATION_DELAY: 300,
  AUTO_REFRESH_INTERVAL: 15000,
  MIN_PASSWORD_LENGTH: 8,
  MAX_PASSWORD_LENGTH: 256,
  DEFAULT_GAS_LIMIT: 21000,
  SWAP_GAS_LIMIT: 250000,
  CACHE_TTL: 5 * 60 * 1000,
  DOM_CACHE_TTL: 10000,
  MAX_CACHE_SIZE: 100,
  TX_CONFIRMATION_DELAY: 3000, // 3 second delay before allowing confirmation
  MIN_TX_INTERVAL: 2000 // Minimum 2 seconds between transactions
};

// Network configuration
const NETWORKS = {
  MAINNET: {
    chainId: 1,
    name: 'Ethereum',
    rpcUrls: [
      'https://eth.llamarpc.com',
      'https://ethereum.publicnode.com',
      'https://cloudflare-eth.com'
    ],
    blockExplorer: 'https://etherscan.io',
    currency: 'ETH'
  },
  BASE: {
    chainId: 8453,
    name: 'Base',
    rpcUrls: [
      'https://mainnet.base.org',
      'https://base.llamarpc.com',
      'https://base.publicnode.com'
    ],
    blockExplorer: 'https://basescan.org',
    currency: 'ETH'
  }
};

// Current network state
let currentNetwork = 'MAINNET';
let isBaseMode = false;

// Secure password modal handler
let passwordModalCallback = null;
let passwordModalReject = null;

// Password caching for session (clears on extension close)
let sessionPasswordCache = new Map();
const PASSWORD_CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Transaction rate limiting
let lastTransactionTime = 0;
let pendingTransactionCount = 0;
const MAX_PENDING_TRANSACTIONS = 3;

function getCacheKey(method, ...args) {
  return `${method}:${args.join(':')}`;
}

// Gas price caching to reduce RPC calls
let gasPriceCache = { 
  data: null, 
  timestamp: 0,
  networkId: null 
};
const GAS_PRICE_CACHE_TTL = 10000; // 10 seconds


/**
 * Get cached gas price data to reduce redundant RPC calls
 * Automatically invalidates cache on network change
 * @returns {Promise<Object>} Fee data from provider
 */
async function getCachedGasPrice() {
  const currentNetworkId = currentNetwork;
  
  // Check if cache is valid (not expired and same network)
  if (gasPriceCache.data && 
      gasPriceCache.networkId === currentNetworkId &&
      Date.now() - gasPriceCache.timestamp < GAS_PRICE_CACHE_TTL) {
    return gasPriceCache.data;
  }
  
  // Fetch fresh gas price data
  try {
    const feeData = await provider.getFeeData();
    gasPriceCache = { 
      data: feeData, 
      timestamp: Date.now(),
      networkId: currentNetworkId
    };
    return feeData;
  } catch (error) {
    console.error('Failed to fetch gas price:', error);
    // Return cached data if available, even if expired
    if (gasPriceCache.data) {
      return gasPriceCache.data;
    }
    throw error;
  }
}

/**
 * Creates a confirmation button with countdown timer for security
 * @param {HTMLElement} button - The button element to add countdown to
 * @param {number} delayMs - Delay in milliseconds before enabling
 * @returns {Promise<boolean>} - Resolves to true if confirmed, false if cancelled
 */
function createSecureConfirmation(button, cancelButton, closeButton, delayMs = CONSTANTS.TX_CONFIRMATION_DELAY) {
  return new Promise(resolve => {
    // Store original state
    const originalText = button.textContent;
    const originalClass = button.className;
    
    // Disable button and add visual feedback
    button.disabled = true;
    button.style.opacity = '0.5';
    button.style.cursor = 'not-allowed';
    
    let countdown = Math.ceil(delayMs / 1000);
    
    // Update button with countdown
    const updateCountdown = () => {
      if (countdown > 0) {
        button.textContent = `Wait ${countdown}s...`;
        button.className = originalClass + ' counting';
      } else {
        button.textContent = originalText;
        button.disabled = false;
        button.style.opacity = '1';
        button.style.cursor = 'pointer';
        button.className = originalClass + ' ready';
        // Add pulse animation when ready
        button.style.animation = 'pulse 0.5s ease-in-out';
      }
    };
    
    updateCountdown();
    
    // Countdown interval
    const countdownInterval = setInterval(() => {
      countdown--;
      updateCountdown();
      if (countdown <= 0) {
        clearInterval(countdownInterval);
      }
    }, 1000);
    
    // Cleanup function
    const cleanup = () => {
      clearInterval(countdownInterval);
      button.textContent = originalText;
      button.disabled = false;
      button.style.opacity = '1';
      button.style.cursor = 'pointer';
      button.style.animation = '';
      button.className = originalClass;
      button.removeEventListener('click', handleConfirm);
      if (cancelButton) cancelButton.removeEventListener('click', handleCancel);
      if (closeButton) closeButton.removeEventListener('click', handleCancel);
    };
    
    const handleConfirm = () => {
      if (!button.disabled) {
        cleanup();
        resolve(true);
      }
    };
    
    const handleCancel = () => {
      cleanup();
      resolve(false);
    };
    
    button.addEventListener('click', handleConfirm);
    if (cancelButton) cancelButton.addEventListener('click', handleCancel);
    if (closeButton) closeButton.addEventListener('click', handleCancel);
  });
}

function initPasswordModal() {
  const modal = document.getElementById('passwordModal');
  const form = document.getElementById('passwordForm');
  const passwordInput = document.getElementById('passwordInput');
  const confirmPasswordInput = document.getElementById('confirmPasswordInput');
  const confirmGroup = document.getElementById('confirmPasswordGroup');
  const errorDiv = document.getElementById('passwordError');
  
  // Toggle password visibility
  document.getElementById('togglePassword')?.addEventListener('click', () => {
    const input = document.getElementById('passwordInput');
    const icon = document.getElementById('eyeIcon');
    if (input.type === 'password') {
      input.type = 'text';
      icon.setAttribute('d', 'M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24');
    } else {
      input.type = 'password';
      icon.setAttribute('d', 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z');
    }
  });
  
  document.getElementById('toggleConfirmPassword')?.addEventListener('click', () => {
    const input = document.getElementById('confirmPasswordInput');
    const icon = document.getElementById('confirmEyeIcon');
    if (input.type === 'password') {
      input.type = 'text';
      icon.setAttribute('d', 'M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24');
    } else {
      input.type = 'password';
      icon.setAttribute('d', 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z');
    }
  });
  
  // Password strength checker
  passwordInput?.addEventListener('input', (e) => {
    if (confirmGroup.style.display !== 'none') {
      const validation = InputValidator.validatePassword(e.target.value);
      const strength = validation.strength || 0;
      updatePasswordStrength(strength);
      checkPasswordMatch();
    }
  });
  
  // Password match checker
  confirmPasswordInput?.addEventListener('input', () => {
    checkPasswordMatch();
  });
  
  function checkPasswordMatch() {
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    const indicator = document.getElementById('passwordMatchIndicator');
    const icon = document.getElementById('matchIcon');
    const text = document.getElementById('matchText');
    
    if (!confirmPassword || confirmGroup.style.display === 'none') {
      indicator.style.display = 'none';
      return;
    }
    
    indicator.style.display = 'block';
    
    if (password === confirmPassword) {
      indicator.style.background = '#d4f4dd';
      indicator.style.color = '#1a7f37';
      indicator.style.border = '1px solid #1a7f37';
      icon.textContent = '✓ ';
      text.textContent = 'Passwords match';
    } else {
      indicator.style.background = '#ffd8d8';
      indicator.style.color = '#d1242f';
      indicator.style.border = '1px solid #d1242f';
      icon.textContent = '✗ ';
      text.textContent = 'Passwords do not match';
    }
  }
  
  // Form submission
  form?.addEventListener('submit', (e) => {
    e.preventDefault();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    
    // Clear inputs immediately for security
    passwordInput.value = '';
    confirmPasswordInput.value = '';
    
    // Validation
    if (confirmGroup.style.display !== 'none' && password !== confirmPassword) {
      showPasswordError("Passwords don't match");
      return;
    }
    
    if (confirmGroup.style.display !== 'none' && password.length < 8) {
      showPasswordError("Password must be at least 8 characters");
      return;
    }
    
    // Close modal
    modal.style.display = 'none';
    errorDiv.style.display = 'none';
    
    // Callback with password
    if (passwordModalCallback) {
      passwordModalCallback(password);
      passwordModalCallback = null;
      passwordModalReject = null;
    }
  });
  
  // Cancel button
  document.getElementById('cancelPassword')?.addEventListener('click', () => {
    passwordInput.value = '';
    confirmPasswordInput.value = '';
    modal.style.display = 'none';
    errorDiv.style.display = 'none';
    
    if (passwordModalReject) {
      passwordModalReject(new Error('User cancelled'));
      passwordModalCallback = null;
      passwordModalReject = null;
    }
  });
  
  // Close on background click (mobile-friendly)
  modal?.addEventListener('click', (e) => {
    if (e.target === modal) {
      document.getElementById('cancelPassword').click();
    }
  });
}

function updatePasswordStrength(strength) {
  const bar = document.getElementById('strengthBar');
  const text = document.getElementById('strengthText');
  const div = document.getElementById('passwordStrength');
  
  div.style.display = 'block';
  
  const colors = ['#ff4444', '#ff8844', '#ffaa44', '#88cc44', '#44cc44'];
  const texts = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
  
  bar.style.width = `${(strength / 5) * 100}%`;
  bar.style.background = colors[Math.min(strength - 1, 4)] || colors[0];
  text.textContent = texts[Math.min(strength - 1, 4)] || texts[0];
}

function showPasswordError(message) {
  const errorDiv = document.getElementById('passwordError');
  errorDiv.textContent = message;
  errorDiv.style.display = 'block';
  setManagedTimeout(() => {
    errorDiv.style.display = 'none';
  }, 3000);
}

// Input sanitization helper
function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  // Remove any HTML/script tags
  return input.replace(/<[^>]*>/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .trim();
}

// HTML escape for display
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Comprehensive Input Validation System
 */
class InputValidator {
  /**
   * Validate Ethereum address
   * @param {string} address - Address to validate
   * @returns {object} { valid: boolean, error?: string }
   */
  static validateAddress(address) {
    if (!address) {
      return { valid: false, error: 'Address is required' };
    }
    
    // Remove whitespace
    address = address.trim();
    
    // Check if it's an ENS name or Base name
    if (address.endsWith('.eth')) {
      return InputValidator.validateENS(address);
    }
    
    // Check basic format
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return { valid: false, error: 'Invalid address format' };
    }
    
    // Use ethers.js validation
    try {
      if (!ethers.isAddress(address)) {
        return { valid: false, error: 'Invalid Ethereum address' };
      }
    } catch (e) {
      return { valid: false, error: 'Invalid address' };
    }
    
    // Check for zero address
    if (address.toLowerCase() === '0x0000000000000000000000000000000000000000') {
      return { valid: false, error: 'Cannot send to zero address' };
    }
    
    return { valid: true, address: ethers.getAddress(address) }; // Return checksummed address
  }
  
  /**
   * Validate ENS name (including Base names)
   * @param {string} name - ENS/Base name to validate
   * @returns {object} { valid: boolean, error?: string }
   */
  static validateENS(name) {
    if (!name) {
      return { valid: false, error: 'Name is required' };
    }
    
    name = name.trim().toLowerCase();
    
    // Check format - support both .eth and .base.eth
    if (!name.endsWith('.eth')) {
      return { valid: false, error: 'Names must end with .eth or .base.eth' };
    }
    
    // Handle Base names (e.g., z0r0z.base.eth)
    let label;
    if (name.endsWith('.base.eth')) {
      // Base name format
      label = name.slice(0, -9); // Remove '.base.eth'
      if (label.length < 1) {
        return { valid: false, error: 'Base name must have at least 1 character' };
      }
    } else {
      // Standard ENS format
      label = name.slice(0, -4); // Remove '.eth'
      if (label.length < 3) {
        return { valid: false, error: 'ENS name must be at least 3 characters' };
      }
    }
    
    // Check for valid characters (alphanumeric, hyphens, and dots for subdomains)
    if (!/^[a-z0-9.-]+$/.test(label)) {
      return { valid: false, error: 'Names can only contain letters, numbers, dots, and hyphens' };
    }
    
    // Check for consecutive hyphens or starting/ending with hyphen/dot
    if (/--/.test(label) || /\.\./.test(label) || 
        label.startsWith('-') || label.endsWith('-') ||
        label.startsWith('.') || label.endsWith('.')) {
      return { valid: false, error: 'Invalid name format' };
    }
    
    return { valid: true, ens: name };
  }
  
  /**
   * Validate token amount
   * @param {string} amount - Amount to validate
   * @param {number} decimals - Token decimals
   * @param {string} balance - User's balance
   * @returns {object} { valid: boolean, error?: string, value?: bigint }
   */
  static validateAmount(amount, decimals = 18, balance = null) {
    if (!amount || amount === '') {
      return { valid: false, error: 'Amount is required' };
    }
    
    // Remove whitespace
    amount = amount.trim();
    
    // Check for valid number format
    if (!/^\d*\.?\d*$/.test(amount)) {
      return { valid: false, error: 'Invalid amount format' };
    }
    
    // Check for multiple decimal points
    if ((amount.match(/\./g) || []).length > 1) {
      return { valid: false, error: 'Invalid amount format' };
    }
    
    // Check decimal places
    const parts = amount.split('.');
    if (parts[1] && parts[1].length > decimals) {
      return { valid: false, error: `Maximum ${decimals} decimal places allowed` };
    }
    
    // Check for zero amount
    const numAmount = parseFloat(amount);
    if (numAmount <= 0) {
      return { valid: false, error: 'Amount must be greater than 0' };
    }
    
    // Check for very large amounts
    if (numAmount > 1e15) {
      return { valid: false, error: 'Amount too large' };
    }
    
    try {
      // Convert to wei/smallest unit
      const value = ethers.parseUnits(amount, decimals);
      
      // Check against balance if provided
      if (balance !== null) {
        const balanceWei = ethers.parseUnits(balance.toString(), decimals);
        if (value > balanceWei) {
          return { valid: false, error: 'Insufficient balance' };
        }
      }
      
      return { valid: true, value, formatted: amount };
    } catch (e) {
      return { valid: false, error: 'Invalid amount' };
    }
  }
  
  /**
   * Validate RPC URL
   * @param {string} url - RPC URL to validate
   * @returns {object} { valid: boolean, error?: string }
   */
  static validateRPCUrl(url) {
    if (!url) {
      return { valid: false, error: 'RPC URL is required' };
    }
    
    url = url.trim();
    
    // Check URL format
    try {
      const parsed = new URL(url);
      
      // Only allow HTTPS and WSS for security
      if (!['https:', 'wss:'].includes(parsed.protocol)) {
        return { valid: false, error: 'Only HTTPS and WSS protocols are allowed' };
      }
      
      // Block localhost/private IPs in production
      const hostname = parsed.hostname.toLowerCase();
      if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
        return { valid: false, error: 'Local/private RPC endpoints not allowed' };
      }
      
      // Check for common RPC endpoints patterns
      const validPatterns = [
        /infura\.io/,
        /alchemy\.com/,
        /quicknode\.com/,
        /ankr\.com/,
        /llamarpc\.com/,
        /publicnode\.com/,
        /cloudflare-eth\.com/,
        /chainstack\.com/,
        /polygon-rpc\.com/,
        /arbitrum\.io/,
        /optimism\.io/
      ];
      
      const isKnownProvider = validPatterns.some(pattern => pattern.test(hostname));
      
      // Warning for unknown providers
      if (!isKnownProvider) {
        // Unknown provider - handled silently in production
      }
      
      return { valid: true, url: parsed.href };
    } catch (e) {
      return { valid: false, error: 'Invalid URL format' };
    }
  }
  
  /**
   * Validate private key
   * @param {string} key - Private key to validate
   * @returns {object} { valid: boolean, error?: string }
   */
  static validatePrivateKey(key) {
    if (!key) {
      return { valid: false, error: 'Private key is required' };
    }
    
    // Remove whitespace and 0x prefix if present
    key = key.trim().replace(/^0x/i, '');
    
    // Check length (64 hex characters)
    if (key.length !== 64) {
      return { valid: false, error: 'Private key must be 64 characters (32 bytes)' };
    }
    
    // Check for valid hex characters
    if (!/^[a-fA-F0-9]{64}$/.test(key)) {
      return { valid: false, error: 'Private key must be hexadecimal' };
    }
    
    // Verify it can create a valid wallet
    try {
      const wallet = new ethers.Wallet('0x' + key);
      if (!wallet.address) {
        return { valid: false, error: 'Invalid private key' };
      }
      return { valid: true, key: '0x' + key };
    } catch (e) {
      return { valid: false, error: 'Invalid private key format' };
    }
  }
  
  /**
   * Validate token contract address using zWallet contract when available
   * @param {string} address - Contract address
   * @param {object} provider - Ethers provider
   * @returns {Promise<object>} { valid: boolean, error?: string, isContract?: boolean }
   */
  static async validateTokenContract(address, provider) {
    // First validate as address
    const addressValidation = InputValidator.validateAddress(address);
    if (!addressValidation.valid) {
      return addressValidation;
    }
    
    try {
      // If zWallet contract is available, use it for validation
      if (window.zWalletContract) {
        const contractType = await getCachedContractType(addressValidation.address);
        // Also check if it has code
        const code = await provider.getCode(address);
        const hasCode = code !== '0x' && code !== '0x0';
        
        if (!hasCode) {
          return { valid: false, error: 'Address is not a smart contract' };
        }
        
        return { 
          valid: true, 
          address: addressValidation.address, 
          isContract: true,
          isERC721: contractType.isERC721,
          isERC6909: contractType.isERC6909
        };
      }
      
      // Fallback to direct code check
      const code = await provider.getCode(address);
      if (code === '0x' || code === '0x0') {
        return { valid: false, error: 'Address is not a smart contract' };
      }
      
      return { valid: true, address: addressValidation.address, isContract: true };
    } catch (e) {
      return { valid: false, error: 'Failed to verify contract' };
    }
  }
  
  /**
   * Validate gas price
   * @param {string} gasPrice - Gas price in Gwei
   * @returns {object} { valid: boolean, error?: string, value?: bigint }
   */
  static validateGasPrice(gasPrice) {
    if (!gasPrice) {
      return { valid: false, error: 'Gas price is required' };
    }
    
    gasPrice = gasPrice.trim();
    
    // Check format
    if (!/^\d*\.?\d*$/.test(gasPrice)) {
      return { valid: false, error: 'Invalid gas price format' };
    }
    
    const numGasPrice = parseFloat(gasPrice);
    
    // Check reasonable bounds (0.1 to 1000 Gwei)
    if (numGasPrice < 0.1) {
      return { valid: false, error: 'Gas price too low (min 0.1 Gwei)' };
    }
    
    if (numGasPrice > 1000) {
      return { valid: false, error: 'Gas price too high (max 1000 Gwei)' };
    }
    
    try {
      const value = ethers.parseUnits(gasPrice, 'gwei');
      return { valid: true, value, gwei: numGasPrice };
    } catch (e) {
      return { valid: false, error: 'Invalid gas price' };
    }
  }
  
  /**
   * Validate slippage percentage
   * @param {string} slippage - Slippage percentage
   * @returns {object} { valid: boolean, error?: string, value?: number }
   */
  static validateSlippage(slippage) {
    if (!slippage) {
      return { valid: false, error: 'Slippage is required' };
    }
    
    slippage = slippage.trim();
    
    // Check format
    if (!/^\d*\.?\d*$/.test(slippage)) {
      return { valid: false, error: 'Invalid slippage format' };
    }
    
    const numSlippage = parseFloat(slippage);
    
    // Check bounds (0.01% to 50%)
    if (numSlippage < 0.01) {
      return { valid: false, error: 'Slippage too low (min 0.01%)' };
    }
    
    if (numSlippage > 50) {
      return { valid: false, error: 'Slippage too high (max 50%)' };
    }
    
    // Warning for high slippage
    if (numSlippage > 5) {
      // High slippage detected - UI will show warning
    }
    
    return { valid: true, value: numSlippage };
  }
  
  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {object} { valid: boolean, error?: string, strength?: number }
   */
  static validatePassword(password) {
    if (!password) {
      return { valid: false, error: 'Password is required' };
    }
    
    // Check minimum length
    if (password.length < 8) {
      return { valid: false, error: 'Password must be at least 8 characters' };
    }
    
    // Check maximum length
    if (password.length > 256) {
      return { valid: false, error: 'Password too long (max 256 characters)' };
    }
    
    // Calculate strength
    let strength = 0;
    if (password.length >= 12) strength++;
    if (password.length >= 16) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    
    // Require minimum strength
    if (strength < 2) {
      return { valid: false, error: 'Password too weak. Use uppercase, lowercase, numbers, and symbols' };
    }
    
    return { valid: true, strength };
  }
}

// Secure password prompt replacement
function securePasswordPrompt(title, message, requireConfirm = false, cacheKey = null) {
  // Check cache first for non-creation prompts
  if (!requireConfirm && cacheKey) {
    const cached = sessionPasswordCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < PASSWORD_CACHE_DURATION) {
      return Promise.resolve(cached.password);
    }
  }
  
  return new Promise((resolve, reject) => {
    const modal = document.getElementById('passwordModal');
    const titleEl = document.getElementById('passwordModalTitle');
    const messageEl = document.getElementById('passwordModalMessage');
    const confirmGroup = document.getElementById('confirmPasswordGroup');
    const strengthDiv = document.getElementById('passwordStrength');
    const passwordInput = document.getElementById('passwordInput');
    const confirmPasswordInput = document.getElementById('confirmPasswordInput');
    const submitBtn = document.getElementById('submitPassword');
    
    // Reset state
    passwordInput.value = '';
    confirmPasswordInput.value = '';
    document.getElementById('passwordError').style.display = 'none';
    submitBtn.textContent = requireConfirm ? 'Create' : 'Unlock';
    
    // Set content
    titleEl.textContent = title || 'Enter Password';
    messageEl.textContent = message || '';
    
    // Show/hide confirm field
    confirmGroup.style.display = requireConfirm ? 'block' : 'none';
    strengthDiv.style.display = requireConfirm ? 'block' : 'none';
    
    // Show modal with flex display for centering
    modal.style.display = 'flex';
    
    // Add escape key listener for better UX
    const escapeHandler = (e) => {
      if (e.key === 'Escape') {
        document.getElementById('cancelPassword').click();
        document.removeEventListener('keydown', escapeHandler);
      }
    };
    document.addEventListener('keydown', escapeHandler);
    
    // Focus input with slight delay for animation
    requestAnimationFrame(() => {
      passwordInput.focus();
      passwordInput.select();
    });
    
    // Set callbacks
    passwordModalCallback = (result) => {
      document.removeEventListener('keydown', escapeHandler);
      // Cache password for session if cacheKey provided
      if (!requireConfirm && cacheKey) {
        sessionPasswordCache.set(cacheKey, {
          password: result,
          timestamp: Date.now()
        });
        // Clear old cache entries
        for (const [key, value] of sessionPasswordCache.entries()) {
          if (Date.now() - value.timestamp > PASSWORD_CACHE_DURATION) {
            sessionPasswordCache.delete(key);
          }
        }
      }
      resolve(result);
    };
    passwordModalReject = (error) => {
      document.removeEventListener('keydown', escapeHandler);
      reject(error);
    };
  });
}

// Generate dynamic coin SVG
function generateCoinSVG(id) {
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  const textColor = isDark ? "#ffffff" : "#000000";
  const goldColor = isDark ? "#FFD700" : "#DAA520";
  const shadowColor = isDark ? "#B8860B" : "#996515";

  return `<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="coinGrad${id}" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:${goldColor};stop-opacity:1" />
              <stop offset="50%" style="stop-color:#FFA500;stop-opacity:1" />
              <stop offset="100%" style="stop-color:${shadowColor};stop-opacity:1" />
            </linearGradient>
          </defs>
          <circle cx="16" cy="16" r="14" fill="url(#coinGrad${id})" stroke="${shadowColor}" stroke-width="1"/>
          <circle cx="16" cy="16" r="11" fill="none" stroke="${shadowColor}" stroke-width="0.5" opacity="0.5"/>
          <text x="16" y="20" font-family="monospace" font-size="8" font-weight="bold" text-anchor="middle" fill="${textColor}">${id}</text>
        </svg>`;
}

// Token configuration with logos
const TOKEN_LOGOS = {
  ETH: '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><g fill="none" fill-rule="evenodd"><circle cx="16" cy="16" r="16" fill="#627EEA"/><g fill="#FFF" fill-rule="nonzero"><path fill-opacity=".602" d="M16.498 4v8.87l7.497 3.35z"/><path d="M16.498 4L9 16.22l7.498-3.35z"/><path fill-opacity=".602" d="M16.498 21.968v6.027L24 17.616z"/><path d="M16.498 27.995v-6.028L9 17.616z"/><path fill-opacity=".2" d="M16.498 20.573l7.497-4.353-7.497-3.348z"/><path fill-opacity=".602" d="M9 16.22l7.498 4.353v-7.701z"/></g></g></svg>',
  USDC: '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><g fill="none"><circle fill="#3E73C4" cx="16" cy="16" r="16"/><g fill="#FFF"><path d="M20.022 18.124c0-2.124-1.28-2.852-3.84-3.156-1.828-.243-2.193-.728-2.193-1.578 0-.85.61-1.396 1.828-1.396 1.097 0 1.707.364 2.011 1.275a.458.458 0 00.427.303h.975a.416.416 0 00.427-.425v-.06a3.04 3.04 0 00-2.743-2.489V9.142c0-.243-.183-.425-.487-.486h-.915c-.243 0-.426.182-.487.486v1.396c-1.829.242-2.986 1.456-2.986 2.974 0 2.002 1.218 2.791 3.778 3.095 1.707.303 2.255.668 2.255 1.639 0 .97-.853 1.638-2.011 1.638-1.585 0-2.133-.667-2.316-1.578-.06-.242-.244-.364-.427-.364h-1.036a.416.416 0 00-.426.425v.06c.243 1.518 1.219 2.61 3.23 2.914v1.457c0 .242.183.425.487.485h.915c.243 0 .426-.182.487-.485V21.34c1.829-.303 3.047-1.578 3.047-3.217z"/><path d="M12.892 24.497c-4.754-1.7-7.192-6.98-5.424-11.653.914-2.55 2.925-4.491 5.424-5.402.244-.121.365-.303.365-.607v-.85c0-.242-.121-.424-.365-.485-.061 0-.183 0-.244.06a10.895 10.895 0 00-7.13 13.717c1.096 3.4 3.717 6.01 7.13 7.102.244.121.488 0 .548-.243.061-.06.061-.122.061-.243v-.85c0-.182-.182-.424-.365-.546zm6.46-18.936c-.244-.122-.488 0-.548.242-.061.061-.061.122-.061.243v.85c0 .243.182.485.365.607 4.754 1.7 7.192 6.98 5.424 11.653-.914 2.55-2.925 4.491-5.424 5.402-.244.121-.365.303-.365.607v.85c0 .242.121.424.365.485.061 0 .183 0 .244-.06a10.895 10.895 0 007.13-13.717c-1.096-3.46-3.778-6.07-7.13-7.162z"/></g></g></svg>',
  DAI: '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><g fill="none" fill-rule="evenodd"><circle fill="#F4B731" fill-rule="nonzero" cx="16" cy="16" r="16"/><path d="M9.277 8h6.552c3.985 0 7.006 2.116 8.13 5.194H26v1.861h-1.611c.031.294.047.594.047.898v.046c0 .342-.02.68-.06 1.01H26v1.86h-2.08C22.767 21.905 19.77 24 15.83 24H9.277v-5.131H7v-1.86h2.277v-1.954H7v-1.86h2.277V8zm1.831 10.869v3.462h4.72c2.914 0 5.078-1.387 6.085-3.462H11.108zm11.366-1.86H11.108v-1.954h11.37c.041.307.063.622.063.944v.045c0 .329-.023.65-.067.964zM15.83 9.665c2.926 0 5.097 1.424 6.098 3.528h-10.82V9.666h4.72z" fill="#FFF"/></g></svg>',
  USDT: '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><g fill="none"><circle fill="#26A17B" cx="16" cy="16" r="16"/><path fill="#FFF" d="M17.922 17.383v-.002c-.11.008-.677.042-1.942.042-1.01 0-1.721-.03-1.971-.042v.003c-3.888-.171-6.79-.848-6.79-1.658 0-.809 2.902-1.486 6.79-1.66v2.644c.254.018.982.061 1.988.061 1.207 0 1.812-.05 1.925-.06v-2.643c3.88.173 6.775.85 6.775 1.658 0 .81-2.895 1.485-6.775 1.657m0-3.59v-2.366h5.414V7.819H8.595v3.608h5.414v2.365c-4.4.202-7.709 1.074-7.709 2.118 0 1.044 3.309 1.915 7.709 2.118v7.582h3.913v-7.584c4.393-.202 7.694-1.073 7.694-2.116 0-1.043-3.301-1.914-7.694-2.117"/></g></svg>',
  ENS: '<svg viewBox="0 0 202 231" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M98.3592 2.80337L34.8353 107.327C34.3371 108.147 33.1797 108.238 32.5617 107.505C26.9693 100.864 6.13478 72.615 31.9154 46.8673C55.4403 23.3726 85.4045 6.62129 96.5096 0.831705C97.7695 0.174847 99.0966 1.59007 98.3592 2.80337Z" fill="#0080BC"/><path d="M94.8459 230.385C96.1137 231.273 97.6758 229.759 96.8261 228.467C82.6374 206.886 35.4713 135.081 28.9559 124.302C22.5295 113.67 9.88976 96.001 8.83534 80.8842C8.7301 79.3751 6.64332 79.0687 6.11838 80.4879C5.27178 82.7767 4.37045 85.5085 3.53042 88.6292C-7.07427 128.023 8.32698 169.826 41.7753 193.238L94.8459 230.386V230.385Z" fill="#0080BC"/><path d="M103.571 228.526L167.095 124.003C167.593 123.183 168.751 123.092 169.369 123.825C174.961 130.465 195.796 158.715 170.015 184.463C146.49 207.957 116.526 224.709 105.421 230.498C104.161 231.155 102.834 229.74 103.571 228.526Z" fill="#0080BC"/><path d="M107.154 0.930762C105.886 0.0433954 104.324 1.5567 105.174 2.84902C119.363 24.4301 166.529 96.2354 173.044 107.014C179.471 117.646 192.11 135.315 193.165 150.432C193.27 151.941 195.357 152.247 195.882 150.828C196.728 148.539 197.63 145.808 198.47 142.687C209.074 103.293 193.673 61.4905 160.225 38.078L107.154 0.930762Z" fill="#0080BC"/></svg>',
  CULT: '<img src="https://assets.coingecko.com/coins/images/52583/standard/cult.jpg?1733712273" style="width: 100%; height: 100%; object-fit: contain;" />',
  ZAMM: '<img src="https://raw.githubusercontent.com/NaniDAO/coinchan/main/public/zammzamm.gif" style="width: 100%; height: 100%; object-fit: contain;" />',
};

// WETH address for ETH price
const WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

// zQuoter contract for finding best swap routes (includes V3 support)
const ZQUOTER_ADDRESS = "0xb474E11Dd4290d423d681a847475122d076D3b02";

// zQuoter ABI for getting best quotes (moved here to be defined before use)
const ZQUOTER_ABI = [
  "function getQuotes(bool exactOut, address tokenIn, address tokenOut, uint256 swapAmount) view returns ((uint8 source, uint256 feeBps, uint256 amountIn, uint256 amountOut) best, (uint8 source, uint256 feeBps, uint256 amountIn, uint256 amountOut)[] quotes)",
  "function buildBestSwap(address to, bool exactOut, address tokenIn, address tokenOut, uint256 swapAmount, uint256 slippageBps, uint256 deadline) view returns ((uint8 source, uint256 feeBps, uint256 amountIn, uint256 amountOut) best, bytes callData, uint256 amountLimit, uint256 msgValue)"
];

// ERC6909 addresses
const COINS_CONTRACT = "0x0000000000009710cd229bf635c4500029651ee8";
const ZAMM_ID = "1334160193485309697971829933264346612480800613613";

// ZAMM AMM Contracts for price fetching and swapping
const ZAMM_0_ADDRESS = "0x00000000000008882D72EfA6cCE4B6a40b24C860"; // Original ZAMM AMM for swapping ZAMM token
const ZAMM_1_ADDRESS = "0x000000000000040470635eb91b7ce4d132d616ed"; // New ZAMM AMM for all other ERC6909 ID swaps
const ZAMM_POOL_ID = "22979666169544372205220120853398704213623237650449182409187385558845249460832"; // ZAMM/ETH pool ID

// Price checking is now handled through zWallet contract which wraps CTC

const LS_WALLETS = "eth_wallets_v2";
const LS_LAST = "last_wallet_addr";

const KEY_VERSION = 1;
const DEFAULT_KDF = { kdf: "pbkdf2-sha256", iter: 600000 }; // OWASP 2024 recommended minimum

// Default tokens configuration for Mainnet
const DEFAULT_MAINNET_TOKENS = {
  ETH: { address: null, symbol: "ETH", name: "Ethereum", decimals: 18 },
  ZAMM: {
    address: COINS_CONTRACT,
    symbol: "ZAMM",
    name: "ZAMM",
    decimals: 18,
    isERC6909: true,
    id: ZAMM_ID,
  },
  USDT: {
    address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    symbol: "USDT",
    name: "Tether",
    decimals: 6,
  },
  DAI: {
    address: "0x6B175474E89094C44Da98b954EedeAC495271d0F",
    symbol: "DAI",
    name: "Dai",
    decimals: 18,
  },
  USDC: {
    address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    symbol: "USDC",
    name: "USD Coin",
    decimals: 6,
  },
  ENS: {
    address: "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72",
    symbol: "ENS",
    name: "ENS",
    decimals: 18,
  },
  CULT: {
    address: "0x0000000000c5dc95539589fbD24BE07c6C14eCa4",
    symbol: "CULT",
    name: "Milady Cult Coin",
    decimals: 18,
  },
};

// Base network tokens configuration
const DEFAULT_BASE_TOKENS = {
  ETH: { address: null, symbol: "ETH", name: "Ethereum", decimals: 18 },
  USDC: {
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    symbol: "USDC",
    name: "USD Coin",
    decimals: 6,
  },
  USDT: {
    address: "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2",
    symbol: "USDT",
    name: "Tether",
    decimals: 6,
  },
  DAI: {
    address: "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb",
    symbol: "DAI",
    name: "Dai",
    decimals: 18,
  },
};

const DEFAULT_TOKENS = DEFAULT_MAINNET_TOKENS;

// USDC EIP-3009 constants for IOU functionality  
const USDC_EIP712_DOMAIN_MAINNET = Object.freeze({
  name: "USD Coin",
  version: "2",
  chainId: 1,
  verifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
});

const USDC_EIP712_DOMAIN_BASE = Object.freeze({
  name: "USD Coin", 
  version: "2",
  chainId: 8453,
  verifyingContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
});

// Base USDC specific constants
const BASE_USDC_TRANSFER_AUTH_TYPEHASH = "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267";
const BASE_USDC_DOMAIN_SEPARATOR = "0x02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f";

const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" }
  ]
};

// zWallet contract addresses for Mainnet and Base
const ZWALLET_ADDRESS = "0x13e8874aB56f832C11e3Dfe748c0Ec22618c90B5"; // Mainnet
const BASE_ZWALLET_ADDRESS = "0xA64E4B7aCf500bB3D353299af1D15c9EEc9D2323"; // Base network backend contract
const ZWALLET_ABI = [
  // Enhanced batch view with ENS and token type detection
  "function batchView(address user, address[] calldata tokens, uint256[] calldata ids) view returns (string ensName, address[] tokensOut, uint256[] idsOut, uint8[] kinds, uint256[] rawBalances, uint256[] balances, string[] names, string[] symbols, uint8[] decimals, uint256[] pricesETH, string[] pricesETHStr, uint256[] pricesUSDC, string[] pricesUSDCStr)",
  // Individual getters
  "function getBalanceOf(address owner, address token, uint256 id) view returns (uint256 raw, uint256 bal)",
  "function getMetadata(address token) view returns (string name, string symbol, uint8 decimals)",
  "function getOwnerOf(address token, uint256 id) view returns (address owner)",
  // Payload preparation
  "function getERC20Transfer(address to, uint256 amount) pure returns (bytes)",
  "function getERC20Approve(address spender, uint256 amount) pure returns (bytes)",
  "function getERC6909Transfer(address to, uint256 id, uint256 amount) pure returns (bytes)",
  "function getERC6909SetOperator(address spender, bool approved) pure returns (bytes)",
  "function getERC721TransferFrom(address from, address to, uint256 tokenId) pure returns (bytes)",
  // Token type detection
  "function isERC721(address token) view returns (bool)",
  "function isERC6909(address token) view returns (bool)",
  // Allowance and operator checks
  "function getAllowanceOf(address owner, address token, address spender) view returns (uint256 raw, uint256 allow)",
  "function getIsOperatorOf(address owner, address token, address spender) view returns (bool)",
  // Router approval helpers
  "function checkERC20RouterApproval(address owner, address token, uint256 amount, bool max) view returns (bytes payload)",
  "function checkERC6909RouterIsOperator(address owner, address token) view returns (bytes payload)",
  // Price checking (via CTC)
  "function checkPrice(address token) view returns (uint256 price, string priceStr)",
  "function checkPriceInETH(address token) view returns (uint256 price, string priceStr)",
  "function checkPriceInETHToUSDC(address token) view returns (uint256 price, string priceStr)",
  // ENS resolution
  "function whatIsTheAddressOf(string calldata name) view returns (address owner, address receiver, bytes32 node)",
  "function whatIsTheNameOf(address user) view returns (string ensName)",
];

const ERC20_ABI = [
  "function transfer(address, uint256) returns (bool)",
  "function approve(address, uint256) returns (bool)",
  "event Transfer(address indexed from, address indexed to, uint256 value)",
];

// ZAMM AMM ABI for reading pool reserves
const ZAMM_AMM_ABI = [
  "function pools(uint256 poolId) view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast, uint256 price0CumulativeLast, uint256 price1CumulativeLast, uint256 kLast, uint256 supply)",
];

// Global state
let wallet = null;
let provider = null;
let zWalletContract = null;
let zQuoterContract = null;
let selectedGasSpeed = "normal";
let currentBalances = {};
let tokenPrices = {};
let ethPrice = 0;
let selectedToken = "ETH";
let savedWallets = [];
let customTokens = {};
let currentRpc =
  localStorage.getItem("rpc_endpoint") || "https://eth.llamarpc.com";
let autoRefreshInterval = null;
let txHistory = [];
let ensResolveTimeout = null;
let gasUpdateTimeout = null;
let gasPrices = {
  slow: null,
  normal: null,
  fast: null,
  custom: null,
};
let TOKENS = { ...DEFAULT_TOKENS };
// IOU state for signing
let pendingIouMessage = null;
let pendingIouAmount = null;

// Event listener management for cleanup
const eventListeners = new Map();
const abortControllers = new Map();
const activeTimeouts = new Set();
const activeIntervals = new Set();
const cleanupCallbacks = new Set();

// Cache configuration for balance data
const metadataCache = new Map(); // Cache for token metadata (name, symbol, decimals)
const METADATA_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours for metadata
const contractTypeCache = new Map(); // Cache for contract type checks (ERC721, ERC6909)
const CONTRACT_TYPE_CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 1 week for contract types

// Track all timers for cleanup
function setManagedTimeout(callback, delay) {
  const timeoutId = setTimeout(() => {
    activeTimeouts.delete(timeoutId);
    callback();
  }, delay);
  activeTimeouts.add(timeoutId);
  return timeoutId;
}

function clearManagedTimeout(timeoutId) {
  if (timeoutId && activeTimeouts.has(timeoutId)) {
    clearTimeout(timeoutId);
    activeTimeouts.delete(timeoutId);
  }
}

function setManagedInterval(callback, delay) {
  const intervalId = setInterval(callback, delay);
  activeIntervals.add(intervalId);
  return intervalId;
}

function clearManagedInterval(intervalId) {
  if (intervalId && activeIntervals.has(intervalId)) {
    clearInterval(intervalId);
    activeIntervals.delete(intervalId);
  }
}

// Register cleanup callbacks for components
function registerCleanup(callback) {
  cleanupCallbacks.add(callback);
  return () => cleanupCallbacks.delete(callback);
}


// Safe element selector with fallback
function safeGetElement(id, required = false) {
  const element = document.getElementById(id);
  if (!element && required) {
    throw new Error(`Required element not found: ${id}`);
  }
  return element;
}

// Safe query selector with fallback
function safeQuerySelector(selector, parent = document, required = false) {
  const element = parent.querySelector(selector);
  if (!element && required) {
    throw new Error(`Required element not found: ${selector}`);
  }
  return element;
}

// Safe array access with bounds checking
function safeArrayAccess(array, index, fallback = null) {
  if (!Array.isArray(array) || index < 0 || index >= array.length) {
    return fallback;
  }
  return array[index];
}

// Safe object property access with null checking
function safePropertyAccess(obj, path, fallback = null) {
  if (!obj) return fallback;
  
  const keys = path.split('.');
  let current = obj;
  
  for (const key of keys) {
    if (current == null || typeof current !== 'object') {
      return fallback;
    }
    current = current[key];
  }
  
  return current ?? fallback;
}

// Safe division with zero checking
function safeDivide(numerator, denominator, fallback = 0) {
  if (!denominator || denominator === 0 || !Number.isFinite(denominator)) {
    return fallback;
  }
  const result = numerator / denominator;
  return Number.isFinite(result) ? result : fallback;
}

// Create managed AbortController for fetch requests
function createManagedAbortController(key) {
  // Cancel any existing controller with the same key
  if (abortControllers.has(key)) {
    const existing = abortControllers.get(key);
    existing.abort();
  }
  
  const controller = new AbortController();
  abortControllers.set(key, controller);
  
  // Return controller and cleanup function
  return {
    controller,
    signal: controller.signal,
    cleanup: () => {
      abortControllers.delete(key);
    }
  };
}

// Removed getCachedOrFetch - using contract's efficient batching instead

function addManagedEventListener(element, event, handler, options = {}) {
  if (!element) return;
  
  const key = `${element.id || element.className}_${event}`;
  
  // Remove existing listener if present
  if (eventListeners.has(key)) {
    const { element: el, event: ev, handler: h } = eventListeners.get(key);
    el.removeEventListener(ev, h, options);
  }
  
  // Add new listener
  element.addEventListener(event, handler, options);
  eventListeners.set(key, { element, event, handler, options });
}

function cleanupEventListeners() {
  // Remove all managed event listeners - using for...of for better performance
  for (const { element, event, handler, options } of eventListeners.values()) {
    if (element && element.removeEventListener) {
      element.removeEventListener(event, handler, options);
    }
  }
  eventListeners.clear();
}

function cleanupTimers() {
  // Clear all managed timeouts - using for...of for better performance
  for (const timeoutId of activeTimeouts) {
    clearTimeout(timeoutId);
  }
  activeTimeouts.clear();
  
  // Clear all managed intervals - using for...of for better performance
  for (const intervalId of activeIntervals) {
    clearInterval(intervalId);
  }
  activeIntervals.clear();
  
  // Clear specific named timers
  if (ensResolveTimeout) {
    clearTimeout(ensResolveTimeout);
    ensResolveTimeout = null;
  }
  if (gasUpdateTimeout) {
    clearTimeout(gasUpdateTimeout);
    gasUpdateTimeout = null;
  }
  if (swapSimulationTimeout) {
    clearTimeout(swapSimulationTimeout);
    swapSimulationTimeout = null;
  }
  if (autoRefreshInterval) {
    clearInterval(autoRefreshInterval);
    autoRefreshInterval = null;
  }
}

function cleanupAbortControllers() {
  // Abort all pending requests
  abortControllers.forEach(controller => {
    try {
      controller.abort();
    } catch (e) {
      // Ignore errors from already aborted controllers
    }
  });
  abortControllers.clear();
}


function cleanupWalletState() {
  // Clear sensitive wallet data
  if (wallet) {
    wallet = null;
  }
  currentBalances = {};
  tokenPrices = {};
  txHistory = [];
  pendingIouMessage = null;
  pendingIouAmount = null;
}

/**
 * Master cleanup function - performs full resource cleanup
 * Used for major state changes but preserves wallet state
 */
function performFullCleanup() {
  // Run all cleanup callbacks
  cleanupCallbacks.forEach(callback => {
    try {
      callback();
    } catch (e) {
      // Cleanup error - handled silently
    }
  });
  
  cleanupEventListeners();
  cleanupTimers();
  cleanupAbortControllers();
  
  // Don't clean wallet state on normal cleanup
  // Only on explicit logout or page unload
}

/**
 * Cleanup for wallet switching - clears timers and requests
 * Preserves event listeners and cache for performance
 */
function cleanupForWalletSwitch() {
  cleanupTimers();
  cleanupAbortControllers();
  // Keep event listeners and cache
}

/**
 * Complete cleanup on page unload - clears everything
 * Including sensitive wallet data for security
 */
function cleanupOnUnload() {
  performFullCleanup();
  cleanupWalletState();
  cleanupCallbacks.clear();
}

const enc = new TextEncoder(),
  dec = new TextDecoder();
async function deriveKey(pass, salt, meta) {
  const kdf = (meta && meta.kdf) || "pbkdf2-sha256";
  if (kdf === "pbkdf2-sha256") {
    let iter = Number((meta && meta.iter) || 600000);
    if (!Number.isFinite(iter) || iter < 10000 || iter > 5000000) iter = 600000;
    iter = Math.min(Math.max(10_000, Math.floor(iter)), 5_000_000); // clamp
    const km = await crypto.subtle.importKey(
      "raw",
      enc.encode(pass),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
      km,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  throw new Error("Unsupported KDF: " + kdf);
}

const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) =>
  new Uint8Array(
    atob(s)
      .split("")
      .map((c) => c.charCodeAt(0))
  );

async function encryptPK(pkHex, pass, opts = {}) {
  const meta = { v: KEY_VERSION, ...DEFAULT_KDF, ...opts };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pass, salt, meta);
  const aad = meta.aad ? enc.encode(meta.aad) : undefined;
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      enc.encode(pkHex)
    )
  );
  return { ...meta, ct: b64(ct), iv: b64(iv), salt: b64(salt) };
}

async function decryptPK(payload, pass, aadExpected) {
  // Support backward compatibility with different iteration counts
  const possibleIterations = payload.iter ? [payload.iter] : [600000, 120000, 100000];
  
  let lastError;
  for (const iterations of possibleIterations) {
    const meta = {
      v: payload.v ?? 0,
      kdf: payload.kdf || "pbkdf2-sha256",
      iter: iterations,
      aad: payload.aad,
    };
    
    try {
      const key = await deriveKey(pass, unb64(payload.salt), meta);

      if (aadExpected && meta.aad && meta.aad !== aadExpected) {
        throw new Error("Keystore/address mismatch");
      }

      try {
        const aad = enc.encode(aadExpected || meta.aad || "");
        const pt = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: unb64(payload.iv), additionalData: aad },
          key,
          unb64(payload.ct)
        );
        return dec.decode(pt);
      } catch (e) {
        // Legacy fallback: only try if no AAD was used originally
        if (!meta.aad && aadExpected) {
          const pt = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: unb64(payload.iv) }, // no AAD
            key,
            unb64(payload.ct)
          );
          return dec.decode(pt);
        }
        throw e;
      }
    } catch (e) {
      lastError = e;
      // Try next iteration count
      continue;
    }
  }
  
  throw lastError || new Error("Decryption failed");
}

async function migrateKeystoreIfNeeded() {
  const list = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
  let changed = false;
  for (const w of list) {
    const c = w.crypto;
    // Old shape had no v/kdf/iter – wrap it with defaults without touching ct/iv/salt
    if (c && c.ct && !("v" in c)) {
      w.crypto = { v: KEY_VERSION, ...DEFAULT_KDF, ...c };
      changed = true;
    }
  }
  if (changed) localStorage.setItem(LS_WALLETS, JSON.stringify(list));
}

// Connection health monitoring
let connectionHealthInterval = null;
let connectionRetryCount = 0;
const MAX_CONNECTION_RETRIES = 3;

async function startConnectionHealthMonitor() {
  // Clear any existing interval
  if (connectionHealthInterval) {
    clearInterval(connectionHealthInterval);
  }
  
  // Check connection every 30 seconds
  connectionHealthInterval = setInterval(async () => {
    if (!provider) return;
    
    try {
      // Try to get block number with timeout
      const timeoutPromise = new Promise((_, reject) => 
        setManagedTimeout(() => reject(new Error('Health check timeout')), 5000)
      );
      await Promise.race([provider.getBlockNumber(), timeoutPromise]);
      
      // Connection is healthy, reset retry count
      if (connectionRetryCount > 0) {
        connectionRetryCount = 0;
        showToast("Connection restored", 2000);
      }
    } catch (error) {
      console.warn("Connection health check failed:", error.message);
      connectionRetryCount++;
      
      if (connectionRetryCount >= MAX_CONNECTION_RETRIES) {
        showToast("Connection lost. Attempting to reconnect...", 3000);
        
        // Stop the health monitor to prevent infinite loops
        clearInterval(connectionHealthInterval);
        connectionHealthInterval = null;
        connectionRetryCount = 0;
        
        // Try to reconnect
        try {
          await initProvider();
          
          // Restart health monitor only if reconnected successfully
          if (provider) {
            startConnectionHealthMonitor();
          }
        } catch (reconnectError) {
          console.error("Failed to reconnect:", reconnectError);
          showToast("Reconnection failed. Please refresh the page.", 5000);
        }
      }
    }
  }, 30000); // Check every 30 seconds
}

function stopConnectionHealthMonitor() {
  if (connectionHealthInterval) {
    clearInterval(connectionHealthInterval);
    connectionHealthInterval = null;
  }
}

// Initialize
async function init() {
  // Initialization started
  
  // Load saved network preference
  const savedNetwork = localStorage.getItem('network_mode');
  if (savedNetwork === 'BASE') {
    isBaseMode = true;
    currentNetwork = 'BASE';
    TOKENS = { ...DEFAULT_BASE_TOKENS };
  } else {
    isBaseMode = false;
    currentNetwork = 'MAINNET';
    TOKENS = { ...DEFAULT_MAINNET_TOKENS };
  }
  
  // Check if running as extension and handle CSP restrictions
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
    // Keep service worker alive
    setManagedInterval(() => {
      chrome.runtime.sendMessage({ action: 'keepAlive' }, () => {
        if (chrome.runtime.lastError) {
          // Service worker was inactive, will restart automatically
        }
      });
    }, 20000); // Every 20 seconds
  }
  
  // Register cleanup on page unload
  window.addEventListener('beforeunload', () => {
    stopConnectionHealthMonitor();
    cleanupOnUnload();
  });
  window.addEventListener('unload', () => {
    stopConnectionHealthMonitor();
    cleanupOnUnload();
  });
  
  // Also cleanup on visibility change (mobile browsers)
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      // Page is hidden, cleanup non-essential resources
      cleanupAbortControllers();
    }
  });
  
  loadTheme();
  
  // Initialize the base network toggle icon
  updateBaseNetworkToggleIcon();

  // Parallelize initialization tasks
  await Promise.all([
    migrateKeystoreIfNeeded(),
    initProvider(),
    loadCustomTokens()
  ]);
  
  // Start connection health monitor after successful provider init
  if (provider) {
    startConnectionHealthMonitor();
  }
  
  // These depend on provider being ready
  loadWallets();

  // --- auto-unlock last wallet (with password prompt) ---
  try {
    const last = localStorage.getItem(LS_LAST);
    // Check last wallet
    if (last) {
      const list = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
      const entry = list.find(
        (w) => w.address.toLowerCase() === last.toLowerCase()
      );
      // Wallet entry found
      if (entry) {
        const label =
          entry.label ||
          entry.address.slice(0, 6) + "..." + entry.address.slice(-4);
        try {
          // Show password prompt
          const pass = await securePasswordPrompt('Unlock Wallet', `Enter password to unlock ${label}:`, false, `wallet_${entry.address}`);
          const pk = await decryptPK(
              entry.crypto,
              pass,
              entry.address.toLowerCase()
            );

            // Rewrap legacy keystores that were saved without AAD
            if (!entry.crypto.aad) {
              try {
                const newPayload = await encryptPK(pk, pass, {
                  aad: entry.address.toLowerCase(),
                });
                entry.crypto = newPayload;
                const listNow = JSON.parse(
                  localStorage.getItem(LS_WALLETS) || "[]"
                ).map((w) =>
                  w.address.toLowerCase() === entry.address.toLowerCase()
                    ? entry
                    : w
                );
                localStorage.setItem(LS_WALLETS, JSON.stringify(listNow));
              } catch (e) {
                
              }
            }

            wallet = new ethers.Wallet(pk, provider);
            
            // Update selector to show current wallet
            const selector = document.getElementById("walletSelector");
            if (selector) {
              selector.value = entry.address;
            }
            
            await displayWallet();
            showToast("Wallet unlocked!");
          } catch (e) {
            // Failed to unlock - keep LS_LAST so user can try from selector
          }
      } else {
        // stale pointer, clean up
        localStorage.removeItem(LS_LAST);
      }
    }
  } catch (e) {
    
  }

  setupEventListeners();
  
  // Initialize display even without wallet
  updateBalanceDisplay();
  
  // Defer non-critical initialization to improve perceived performance
  setTimeout(() => {
    // Initialize keyboard shortcuts
    initKeyboardShortcuts();
    
    // Check if opened for dApp approval
    checkForDappRequest();
  }, 0);
}

// Keyboard Shortcuts Handler
function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Skip if user is typing in an input
    if (e.target.matches('input, textarea, select')) return;
    
    // Tab navigation with number keys
    if (e.key >= '1' && e.key <= '6' && !e.ctrlKey && !e.metaKey) {
      const tabIndex = parseInt(e.key) - 1;
      const tabs = document.querySelectorAll('.tab');
      if (tabs[tabIndex]) {
        tabs[tabIndex].click();
      }
    }
    
    // Ctrl/Cmd + shortcuts
    if (e.ctrlKey || e.metaKey) {
      switch(e.key) {
        case 's': // Send
          e.preventDefault();
          document.querySelector('.tab[data-tab="send"]')?.click();
          break;
        case 'w': // Swap
          e.preventDefault();
          document.querySelector('.tab[data-tab="swap"]')?.click();
          break;
        case 'b': // Bridge
          e.preventDefault();
          document.querySelector('.tab[data-tab="bridge"]')?.click();
          break;
        case 'r': // Refresh balances
          e.preventDefault();
          if (wallet) {
            fetchAllBalances();
            showToast('Refreshing balances...');
          }
          break;
        case 'c': // Copy address
          e.preventDefault();
          if (wallet?.address) {
            copyToClipboard(wallet.address, 'address');
          }
          break;
      }
    }
  });
  
  // Add tooltip hints for shortcuts
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach((tab, index) => {
    if (index < 6) {
      const text = tab.textContent;
      tab.title = `${text} (Press ${index + 1})`;
    }
  });
}

// Handle dApp requests when opened as popup
async function checkForDappRequest() {
  const params = new URLSearchParams(window.location.search);
  const requestId = params.get('request');
  const requestType = params.get('type');
  const origin = params.get('origin');
  
  if (!requestId || !requestType) return;
  
  // Show the dApp modal
  const modal = document.getElementById('dappApprovalModal');
  const originDiv = document.getElementById('dappOrigin');
  
  if (!modal || !originDiv) return;
  
  modal.classList.remove('hidden');
  // Safely set origin text to prevent XSS
  originDiv.textContent = '';
  const warningIcon = document.createTextNode('⚠️ Request from: ');
  const strongElem = document.createElement('strong');
  strongElem.textContent = decodeURIComponent(origin);
  originDiv.appendChild(warningIcon);
  originDiv.appendChild(strongElem);
  
  // Hide all request types first
  document.getElementById('connectionRequest')?.classList.add('hidden');
  document.getElementById('transactionRequest')?.classList.add('hidden');
  document.getElementById('signRequest')?.classList.add('hidden');
  
  // Get the request details from background script
  chrome.runtime.sendMessage({ 
    type: 'GET_REQUEST', 
    requestId: requestId 
  }, async (pendingRequest) => {
    if (!pendingRequest) {
      modal.classList.add('hidden');
      return;
    }
    
    switch (requestType) {
      case 'connect':
        handleConnectionRequest(requestId, pendingRequest);
        break;
      case 'transaction':
        await handleTransactionRequest(requestId, pendingRequest);
        break;
      case 'sign':
        handleSignRequest(requestId, pendingRequest);
        break;
    }
  });
}

function handleConnectionRequest(requestId, pendingRequest) {
  const connDiv = document.getElementById('connectionRequest');
  const accountDiv = document.getElementById('connectionAccount');
  const modalTitle = document.getElementById('dappModalTitle');
  
  if (!connDiv || !accountDiv || !modalTitle) return;
  
  modalTitle.textContent = 'Connect to DApp';
  connDiv.classList.remove('hidden');
  
  if (wallet) {
    accountDiv.textContent = wallet.address;
  } else {
    accountDiv.textContent = 'No wallet connected';
  }
  
  // Setup approve/reject handlers
  const approveBtn = document.getElementById('approveDapp');
  const rejectBtn = document.getElementById('rejectDapp');
  
  if (approveBtn) {
    approveBtn.onclick = async () => {
      if (!wallet) {
        showError('Please unlock your wallet first', 'Action');
        return;
      }
      
      // Store connected site
      chrome.storage.local.set({ 
        [`connected_${pendingRequest.origin}`]: true,
        'current_wallet': wallet.address 
      });
      
      // Send response
      chrome.runtime.sendMessage({
        type: 'USER_RESPONSE',
        requestId: requestId,
        response: { result: [wallet.address] }
      });
      
      window.close();
    };
  }
  
  if (rejectBtn) {
    rejectBtn.onclick = () => {
      chrome.runtime.sendMessage({
        type: 'USER_RESPONSE',
        requestId: requestId,
        response: { error: { code: 4001, message: 'User rejected connection' } }
      });
      
      window.close();
    };
  }
}

async function handleTransactionRequest(requestId, pendingRequest) {
  const txDiv = document.getElementById('transactionRequest');
  const modalTitle = document.getElementById('dappModalTitle');
  
  if (!txDiv || !modalTitle) return;
  
  modalTitle.textContent = 'Approve Transaction';
  txDiv.classList.remove('hidden');
  
  const txParams = pendingRequest.request.params[0];
  
  // Display transaction details
  document.getElementById('dappTxFrom').textContent = txParams.from || wallet?.address || '';
  document.getElementById('dappTxTo').textContent = txParams.to || '';
  document.getElementById('dappTxValue').textContent = txParams.value ? 
    `${ethers.formatEther(txParams.value)} ETH` : '0 ETH';
  document.getElementById('dappTxGas').textContent = txParams.gas || 'Auto';
  
  // Handle calldata
  const calldata = txParams.data || '0x';
  const calldataDisplay = document.getElementById('calldataDisplay');
  const swissKnifeLink = document.getElementById('swissKnifeLink');
  const toggleBtn = document.getElementById('toggleCalldata');
  const calldataSection = document.getElementById('calldataSection');
  
  if (calldataDisplay) {
    calldataDisplay.value = calldata;
  }
  
  // Setup Swiss Knife decoder link with correct format
  if (swissKnifeLink && calldata !== '0x' && calldata.length > 2) {
    // Use the correct decoder URL format
    const decoderUrl = `https://calldata.swiss-knife.xyz/decoder?calldata=${calldata}`;
    
    swissKnifeLink.href = decoderUrl;
    swissKnifeLink.target = '_blank';
    swissKnifeLink.style.display = 'inline-block';
    
    swissKnifeLink.onclick = (e) => {
      e.preventDefault();
      if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ action: 'open_external', url: decoderUrl });
      } else {
        window.open(decoderUrl, '_blank', 'noopener,noreferrer');
      }
    };
  } else if (swissKnifeLink) {
    swissKnifeLink.style.display = 'none';
  }
  
  if (toggleBtn && calldataSection) {
    toggleBtn.onclick = () => {
      const isHidden = calldataSection.classList.contains('hidden');
      calldataSection.classList.toggle('hidden');
      toggleBtn.textContent = isHidden ? 'Hide' : 'Show';
    };
  }
  
  // Setup approve/reject handlers
  const approveBtn = document.getElementById('approveDapp');
  const rejectBtn = document.getElementById('rejectDapp');
  
  if (approveBtn) {
    approveBtn.onclick = async () => {
      if (!wallet) {
        showError('Please unlock your wallet first', 'Action');
        return;
      }
      
      try {
        // Send the transaction
        const tx = await wallet.sendTransaction({
          to: txParams.to,
          value: txParams.value || 0,
          data: txParams.data || '0x',
          gasLimit: txParams.gas,
          maxFeePerGas: txParams.maxFeePerGas,
          maxPriorityFeePerGas: txParams.maxPriorityFeePerGas
        });
        
        // Send response with transaction hash
        chrome.runtime.sendMessage({
          type: 'USER_RESPONSE',
          requestId: requestId,
          response: { result: tx.hash }
        });
        
        showToast(`Transaction sent: ${tx.hash.slice(0, 10)}...`);
        window.close();
      } catch (err) {
        chrome.runtime.sendMessage({
          type: 'USER_RESPONSE',
          requestId: requestId,
          response: { error: { code: -32000, message: err.message } }
        });
        
        showError(err, 'Transaction');
      }
    };
  }
  
  if (rejectBtn) {
    rejectBtn.onclick = () => {
      chrome.runtime.sendMessage({
        type: 'USER_RESPONSE',
        requestId: requestId,
        response: { error: { code: 4001, message: 'User rejected transaction' } }
      });
      
      window.close();
    };
  }
}

function handleSignRequest(requestId, pendingRequest) {
  const signDiv = document.getElementById('signRequest');
  const modalTitle = document.getElementById('dappModalTitle');
  const messageDiv = document.getElementById('signMessage');
  
  if (!signDiv || !modalTitle || !messageDiv) return;
  
  modalTitle.textContent = 'Sign Message';
  signDiv.classList.remove('hidden');
  
  const message = pendingRequest.request.params[0];
  messageDiv.textContent = message;
  
  // Setup approve/reject handlers
  const approveBtn = document.getElementById('approveDapp');
  const rejectBtn = document.getElementById('rejectDapp');
  
  if (approveBtn) {
    approveBtn.onclick = async () => {
      if (!wallet) {
        showError('Please unlock your wallet first', 'Action');
        return;
      }
      
      try {
        const signature = await wallet.signMessage(message);
        
        chrome.runtime.sendMessage({
          type: 'USER_RESPONSE',
          requestId: requestId,
          response: { result: signature }
        });
        
        window.close();
      } catch (err) {
        chrome.runtime.sendMessage({
          type: 'USER_RESPONSE',
          requestId: requestId,
          response: { error: { code: -32000, message: err.message } }
        });
        
        showError(err, 'Signing');
      }
    };
  }
  
  if (rejectBtn) {
    rejectBtn.onclick = () => {
      chrome.runtime.sendMessage({
        type: 'USER_RESPONSE',
        requestId: requestId,
        response: { error: { code: 4001, message: 'User rejected signature' } }
      });
      
      window.close();
    };
  }
}

async function loadCustomTokens() {
  try {
    const stored = localStorage.getItem("custom_tokens");
    if (stored) {
      customTokens = JSON.parse(stored);
      // Create TOKENS in specific order: defaults first, then custom
      TOKENS = {};
      // Use network-specific defaults
      const currentDefaults = isBaseMode ? DEFAULT_BASE_TOKENS : DEFAULT_MAINNET_TOKENS;
      // Add default tokens in order
      for (const key of Object.keys(currentDefaults)) {
        TOKENS[key] = currentDefaults[key];
      }
      // Add custom tokens only on mainnet (Base only supports specific tokens)
      if (!isBaseMode) {
        for (const key of Object.keys(customTokens)) {
          if (!currentDefaults[key]) {
            TOKENS[key] = customTokens[key];
          }
        }
      }
    } else {
      TOKENS = {};
      const currentDefaults = isBaseMode ? DEFAULT_BASE_TOKENS : DEFAULT_MAINNET_TOKENS;
      for (const key of Object.keys(currentDefaults)) {
        TOKENS[key] = currentDefaults[key];
      }
    }
  } catch (err) {
    customTokens = {};
    TOKENS = {};
    const currentDefaults = isBaseMode ? DEFAULT_BASE_TOKENS : DEFAULT_MAINNET_TOKENS;
    for (const key of Object.keys(currentDefaults)) {
      TOKENS[key] = currentDefaults[key];
    }
  }
}

function saveCustomToken(token) {
  customTokens[token.symbol] = token;
  TOKENS[token.symbol] = token;
  localStorage.setItem("custom_tokens", JSON.stringify(customTokens));
}

function loadTheme() {
  const theme = localStorage.getItem("theme") || "light";
  document.documentElement.setAttribute("data-theme", theme);
}

function updateBaseNetworkToggleIcon() {
  const baseNetworkToggle = document.getElementById("baseNetworkToggle");
  if (!baseNetworkToggle) return;
  
  if (isBaseMode) {
    // When on Base, show Ethereum logo (to switch back to Ethereum)
    baseNetworkToggle.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
        <style type="text/css">
          .eth-st0{fill:#E3F2FD;}
          .eth-st1{fill:#80D8FF;}
          .eth-st2{fill:#1AD2A4;}
          .eth-st3{fill:#ECEFF1;}
          .eth-st4{fill:#55FB9B;}
          .eth-st5{fill:#BBDEFB;}
          .eth-st6{fill:#C1AEE1;}
          .eth-st7{fill:#FF5252;}
          .eth-st8{fill:#FF8A80;}
          .eth-st9{fill:#FFB74D;}
          .eth-st10{fill:#FFF176;}
          .eth-st11{fill:#FFFFFF;}
          .eth-st12{fill:#65C7EA;}
          .eth-st13{fill:#CFD8DC;}
          .eth-st14{fill:#37474F;}
          .eth-st15{fill:#78909C;}
          .eth-st16{fill:#42A5F5;}
          .eth-st17{fill:#455A64;}
        </style>
        <g>
          <polygon class="eth-st1" points="7.62,18.83 16.01,30.5 16.01,24.1"/>
          <polygon class="eth-st16" points="16.01,30.5 24.38,18.78 16.01,24.1"/>
          <polygon class="eth-st10" points="16.01,1.5 7.62,16.23 16.01,12.3"/>
          <polygon class="eth-st8" points="24.38,16.18 16.01,1.5 16.01,12.3"/>
          <polygon class="eth-st6" points="16.01,21.5 24.38,16.18 16.01,12.3"/>
          <polygon class="eth-st4" points="16.01,12.3 7.62,16.23 16.01,21.5"/>
        </g>
      </svg>
    `;
    baseNetworkToggle.classList.add('base-active');
    baseNetworkToggle.title = 'Switch to Ethereum';
  } else {
    // When on Ethereum, show Base logo (to switch to Base)
    baseNetworkToggle.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 111 111" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M54.921 110.034C85.359 110.034 110.034 85.402 110.034 55.017C110.034 24.632 85.359 0 54.921 0C26.322 0 2.816 21.822 0 50.003H72.272V59.993H0C2.816 88.174 26.322 110.034 54.921 110.034Z" fill="#0052FF"/>
      </svg>
    `;
    baseNetworkToggle.classList.remove('base-active');
    baseNetworkToggle.title = 'Switch to Base';
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme");
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
}

function loadRpcSettings() {
  const customRpc = localStorage.getItem("custom_rpc");

  document.querySelectorAll(".rpc-item").forEach((item) => {
    item.classList.remove("active");
    const itemRpc = item.dataset.rpc;

    if (itemRpc === "custom" && currentRpc === customRpc) {
      item.classList.add("active");
    } else if (itemRpc === currentRpc) {
      item.classList.add("active");
    }
  });

  if (customRpc) {
    document.getElementById("customRpcUrl").value = customRpc;
  }
}

async function initProvider() {
  try {
    // Add timeout for RPC connections
    const timeoutPromise = new Promise((_, reject) => 
      setManagedTimeout(() => reject(new Error('RPC timeout')), 5000)
    );
    
    // Use appropriate RPC based on network mode
    let rpcUrl = currentRpc;
    if (isBaseMode) {
      // Select Base RPC
      const baseRpc = localStorage.getItem('base_rpc') || NETWORKS.BASE.rpcUrls[0];
      rpcUrl = baseRpc;
    }
    
    // Use batch provider for better performance when available
    provider = new ethers.JsonRpcProvider(rpcUrl);
    
    // Test connection with block number
    await Promise.race([
      provider.getBlockNumber(),
      timeoutPromise
    ]);

    // Initialize contracts based on network
    if (!isBaseMode) {
      // Mainnet contracts
      zWalletContract = new ethers.Contract(
        ZWALLET_ADDRESS,
        ZWALLET_ABI,
        provider
      );
      
      // Initialize zQuoter contract once
      zQuoterContract = new ethers.Contract(
        ZQUOTER_ADDRESS,
        ZQUOTER_ABI,
        provider
      );
    } else {
      // Base network backend contract (same ABI as mainnet)
      zWalletContract = new ethers.Contract(
        BASE_ZWALLET_ADDRESS,
        ZWALLET_ABI,
        provider
      );
      zQuoterContract = null; // No zQuoter on Base
    }

    // Connected to RPC
    loadRpcSettings();
    showToast("Connected to network");
  } catch (err) {
    console.warn('Primary RPC failed:', err.message);
    
    // Enhanced fallback RPCs - prioritize most reliable ones
    const primaryRpcs = isBaseMode 
      ? [
          "https://mainnet.base.org",  // Most reliable for Base
          "https://base.llamarpc.com"   // Second most reliable
        ]
      : [
          "https://eth.llamarpc.com",   // Most reliable for Ethereum
          "https://ethereum.publicnode.com"
        ];
    
    const secondaryRpcs = isBaseMode
      ? [
          "https://base-mainnet.public.blastapi.io",
          "https://base.meowrpc.com",
          "https://base.blockpi.network/v1/rpc/public",
          "https://base-rpc.publicnode.com",
          "https://1rpc.io/base",
          "https://base.drpc.org"
        ]
      : [
          "https://eth-mainnet.public.blastapi.io",
          "https://rpc.ankr.com/eth",
          "https://eth.drpc.org",
          "https://ethereum-rpc.publicnode.com",
          "https://1rpc.io/eth",
          "https://eth-pokt.nodies.app",
          "https://ethereum.blockpi.network/v1/rpc/public",
          "https://rpc.payload.de",
          "https://eth.merkle.io",
          "https://rpc.flashbots.net/fast"
        ];
    
    // Try primary RPCs first, then shuffle secondary for load balancing
    const shuffledSecondary = [...secondaryRpcs].sort(() => Math.random() - 0.5);
    const fallbackRpcs = [...primaryRpcs, ...shuffledSecondary];
      
    let connectionAttempts = 0;
    let connectedRpc = null;
    
    for (const rpc of fallbackRpcs) {
      connectionAttempts++;
      try {
        provider = new ethers.JsonRpcProvider(rpc);
        
        // Test with timeout (3 seconds per RPC)
        const timeoutPromise = new Promise((_, reject) => 
          setManagedTimeout(() => reject(new Error('RPC timeout')), 3000)
        );
        
        await Promise.race([
          provider.getBlockNumber(),
          timeoutPromise
        ]);
        
        connectedRpc = rpc;
        console.log(`Connected to RPC: ${rpc} (attempt ${connectionAttempts}/${fallbackRpcs.length})`);
        
        if (!isBaseMode) {
          zWalletContract = new ethers.Contract(
            ZWALLET_ADDRESS,
            ZWALLET_ABI,
            provider
          );
          zQuoterContract = new ethers.Contract(
            ZQUOTER_ADDRESS,
            ZQUOTER_ABI,
            provider
          );
        } else {
          zWalletContract = new ethers.Contract(
            BASE_ZWALLET_ADDRESS,
            ZWALLET_ABI,
            provider
          );
          zQuoterContract = null;
        }
        
        currentRpc = connectedRpc;
        localStorage.setItem(isBaseMode ? "base_rpc" : "rpc_endpoint", connectedRpc);
        loadRpcSettings();
        
        // Show success message
        if (connectionAttempts > 1) {
          showToast(`Connected via backup RPC (${connectionAttempts}/${fallbackRpcs.length} tried)`, 2000);
        }
        break;
      } catch (e) {
        console.warn(`RPC ${rpc} failed:`, e.message);
        
        // Show progress to user (only for first few attempts to avoid spam)
        if (connectionAttempts <= 3 && connectionAttempts < fallbackRpcs.length) {
          showToast(`Trying backup RPC ${connectionAttempts + 1}/${Math.min(fallbackRpcs.length, 3)}...`, 1500);
        }
        continue;
      }
    }
    
    if (!provider) {
      showToast("All RPC connections failed. Please check your network.", 5000);
      console.error('Failed to connect to any RPC endpoint');
    }
  }
}

function loadWallets() {
  const v2 = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
  savedWallets = v2.map(({ address, label }) => ({ address, label }));
  updateWalletSelectorFrom(v2);
}

async function saveWallet(address, privateKey) {
  try {
    const pass = await securePasswordPrompt('Create Password', 'Create a strong password to encrypt your wallet:', true);
    if (!pass) return false;
    const payload = await encryptPK(privateKey, pass, {
      aad: address.toLowerCase(),
    });
    const entry = {
      address,
      label: address.slice(0, 6) + "..." + address.slice(-4),
      crypto: payload,
    };
    const stored = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
    if (!stored.find((w) => w.address === address)) {
      stored.push(entry);
      localStorage.setItem(LS_WALLETS, JSON.stringify(stored));
      localStorage.setItem(LS_LAST, address);
    }
    updateWalletSelectorFrom(stored);
    return true;
  } catch (error) {
    if (error.message && error.message.includes('cancelled')) {
      return false;
    }
    throw error;
  }
}

function deleteWallet(address) {
  const list = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]").filter(
    (w) => w.address.toLowerCase() !== address.toLowerCase()
  );
  localStorage.setItem(LS_WALLETS, JSON.stringify(list));
  updateWalletSelectorFrom(list);

  const last = localStorage.getItem(LS_LAST);
  if (last && last.toLowerCase() === address.toLowerCase()) {
    localStorage.removeItem(LS_LAST);
  }
  if (wallet && wallet.address.toLowerCase() === address.toLowerCase()) {
    // Clean up before removing wallet
    cleanupForWalletSwitch();
    wallet = null;
    document.getElementById("walletSection").classList.add("hidden");
    document.getElementById("balanceSection").classList.add("hidden");
  }
}

function updateWalletSelector() {
  const selector = document.getElementById("walletSelector");
  const selectorSection = document.getElementById("walletSelectorSection");

  selector.innerHTML = '<option value="">Select wallet...</option>';

  if (savedWallets.length > 0) {
    selectorSection.classList.remove("hidden");
    savedWallets.forEach((w) => {
      const option = document.createElement("option");
      option.value = w.address;
      option.textContent = w.label;
      if (wallet && wallet.address === w.address) {
        option.selected = true;
      }
      selector.appendChild(option);
    });
  } else {
    selectorSection.classList.add("hidden");
  }
}

function updateWalletSelectorFrom(list) {
  savedWallets = list.map(({ address, label }) => ({ address, label }));
  updateWalletSelector();
}

// Fetch ZAMM price from the AMM pool using constant product formula

/**
 * Get cached token metadata or fetch from zWallet contract
 * @param {string} tokenAddress - Token contract address
 * @returns {Promise<{name: string, symbol: string, decimals: number}>}
 */
async function getCachedMetadata(tokenAddress) {
  const cacheKey = `${currentNetwork}:${tokenAddress}`;
  const cached = metadataCache.get(cacheKey);
  
  // Return cached if valid
  if (cached && Date.now() - cached.timestamp < METADATA_CACHE_TTL) {
    return cached.data;
  }
  
  // Fetch from zWallet contract
  if (!zWalletContract) {
    return { name: '', symbol: '', decimals: 18 };
  }
  
  try {
    const [name, symbol, decimals] = await zWalletContract.getMetadata(tokenAddress);
    const metadata = { name, symbol, decimals: Number(decimals) };
    
    // Cache the result
    metadataCache.set(cacheKey, {
      data: metadata,
      timestamp: Date.now()
    });
    
    return metadata;
  } catch (err) {
    console.error('Failed to fetch metadata:', err);
    return { name: '', symbol: '', decimals: 18 };
  }
}

/**
 * Check if contract is ERC721 or ERC6909 using zWallet validation
 * @param {string} tokenAddress - Contract address to check
 * @returns {Promise<{isERC721: boolean, isERC6909: boolean}>}
 */
async function getCachedContractType(tokenAddress) {
  const cacheKey = `${currentNetwork}:${tokenAddress}`;
  const cached = contractTypeCache.get(cacheKey);
  
  // Return cached if valid
  if (cached && Date.now() - cached.timestamp < CONTRACT_TYPE_CACHE_TTL) {
    return cached.data;
  }
  
  if (!zWalletContract) {
    return { isERC721: false, isERC6909: false };
  }
  
  try {
    const [isERC721, isERC6909] = await Promise.all([
      zWalletContract.isERC721(tokenAddress),
      zWalletContract.isERC6909(tokenAddress)
    ]);
    
    const contractType = { isERC721, isERC6909 };
    
    // Cache the result
    contractTypeCache.set(cacheKey, {
      data: contractType,
      timestamp: Date.now()
    });
    
    return contractType;
  } catch (err) {
    console.error('Failed to check contract type:', err);
    return { isERC721: false, isERC6909: false };
  }
}

/**
 * Fetch individual token price using zWallet price functions with caching
 * Useful as fallback when batchView fails or for single token checks
 */
async function fetchTokenPrice(tokenAddress) {
  if (!zWalletContract) return { usd: 0, eth: 0 };
  
  try {
    // Get price in USDC terms
    const [priceInUSDC] = await zWalletContract.checkPrice(tokenAddress);
    
    // Get price in ETH terms for better accuracy
    const [priceInETH] = await zWalletContract.checkPriceInETH(tokenAddress);
    
    // Convert from raw values (assuming 18 decimals for price)
    const usdPrice = Number(priceInUSDC) / 1e18;
    const ethPrice = Number(priceInETH) / 1e18;
    
    return {
      usd: usdPrice,
      eth: ethPrice
    };
  } catch (err) {
    console.error('Failed to fetch token price:', err);
    return { usd: 0, eth: 0 };
  }
}

async function fetchZAMMPrice() {
  // Check cache first
  const now = Date.now();
  if (zammPriceCache.data && (now - zammPriceCache.timestamp < zammPriceCache.ttl)) {
    return zammPriceCache.data;
  }
  
  try {
    // Use ZAMM_0 for ZAMM token price checking
    const zammContract = new ethers.Contract(
      ZAMM_0_ADDRESS,
      ZAMM_AMM_ABI,
      provider
    );
    
    // Get pool reserves
    const poolData = await zammContract.pools(ZAMM_POOL_ID);
    const reserve0 = Number(poolData[0]); // ETH reserves
    const reserve1 = Number(poolData[1]); // ZAMM reserves
    
    if (reserve0 === 0 || reserve1 === 0) {
      // ZAMM pool has no liquidity
      const result = { eth: 0, usd: 0 };
      // Cache even empty results to avoid repeated calls
      zammPriceCache.data = result;
      zammPriceCache.timestamp = now;
      return result;
    }
    
    // Calculate price using constant product formula
    // Price of 1 ZAMM in ETH = reserve0 / reserve1
    const zammPriceInEth = safeDivide(reserve0, reserve1, 0);
    
    // Calculate USD price based on ETH price
    const zammPriceInUsd = zammPriceInEth * ethPrice;
    
    const result = {
      eth: zammPriceInEth,
      usd: zammPriceInUsd
    };
    
    // Update cache
    zammPriceCache.data = result;
    zammPriceCache.timestamp = now;
    
    return result;
  } catch (err) {
    
    // Return cached data if available, even if expired
    if (zammPriceCache.data) {
      return zammPriceCache.data;
    }
    return { eth: 0, usd: 0 };
  }
}

/**
 * Show loading skeleton for token grids
 */
function showTokenLoadingSkeleton() {
  const tokenGrid = document.getElementById("tokenGrid");
  const sendTokenGrid = document.getElementById("sendTokenGrid");
  
  if (tokenGrid) {
    tokenGrid.innerHTML = `
      <div class="skeleton skeleton-row"></div>
      <div class="skeleton skeleton-row"></div>
      <div class="skeleton skeleton-row"></div>
    `;
  }
  
  if (sendTokenGrid) {
    sendTokenGrid.innerHTML = `
      <div class="skeleton skeleton-row"></div>
      <div class="skeleton skeleton-row"></div>
      <div class="skeleton skeleton-row"></div>
    `;
  }
}

// Fetch all balances using zWallet contract's batchView
// Network switching functionality
async function toggleNetwork() {
  if (!wallet) {
    showToast("Please connect wallet first");
    return;
  }
  
  const baseNetworkToggle = document.getElementById("baseNetworkToggle");
  const networkIndicator = document.getElementById("networkIndicator");
  const etherscanLink = document.getElementById("etherscanLink");
  
  // Toggle network state
  isBaseMode = !isBaseMode;
  currentNetwork = isBaseMode ? 'BASE' : 'MAINNET';
  
  // Invalidate gas price cache on network switch
  gasPriceCache = { data: null, timestamp: 0, networkId: null };
  
  // Update tokens based on network
  if (isBaseMode) {
    TOKENS = { ...DEFAULT_BASE_TOKENS };
  } else {
    TOKENS = { ...DEFAULT_MAINNET_TOKENS };
  }
  
  // Save preference
  localStorage.setItem('network_mode', currentNetwork);
  
  // Update the header network button icon
  updateBaseNetworkToggleIcon();
  
  // Update UI
  if (isBaseMode) {
    // Switch to Base
    if (baseNetworkToggle) {
      baseNetworkToggle.classList.add('base-active');
      baseNetworkToggle.title = 'Switch to Ethereum';
    }
    networkIndicator.classList.add('active', 'base');
    networkIndicator.textContent = 'Base Network';
    
    // Update explorer link
    if (etherscanLink && wallet) {
      etherscanLink.href = `https://basescan.org/address/${wallet.address}`;
      etherscanLink.title = 'View on BaseScan';
    }
    
    // Hide swap and bridge tabs on Base
    document.querySelector('.tab[data-tab="swap"]').style.display = 'none';
    document.querySelector('.tab[data-tab="bridge"]').style.display = 'none';
    
    showToast('Switched to Base Network');
  } else {
    // Switch to Ethereum
    if (baseNetworkToggle) {
      baseNetworkToggle.classList.remove('base-active');
      baseNetworkToggle.title = 'Switch to Base';
    }
    networkIndicator.classList.remove('active', 'base');
    
    // Update explorer link
    if (etherscanLink && wallet) {
      etherscanLink.href = `https://etherscan.io/address/${wallet.address}`;
      etherscanLink.title = 'View on Etherscan';
    }
    
    // Show swap and bridge tabs on mainnet
    document.querySelector('.tab[data-tab="swap"]').style.display = '';
    document.querySelector('.tab[data-tab="bridge"]').style.display = '';
    
    showToast('Switched to Ethereum Mainnet');
  }
  
  // Reinitialize provider for new network
  await initProvider();
  
  // Reconnect wallet
  if (wallet && wallet.privateKey) {
    wallet = new ethers.Wallet(wallet.privateKey, provider);
  }
  
  // Refresh balances
  await fetchAllBalances();
  
  // Update gas prices
  updateGasPrices();
  
  // Update send tab if it's active
  const sendTab = document.getElementById('send-tab');
  if (sendTab && sendTab.classList.contains('active')) {
    updateSendTabForNetwork();
  }
}

// Update send tab based on network
function updateSendTabForNetwork() {
  const tokenSelector = document.getElementById('tokenSelector');
  const sendTitle = document.querySelector('#send-tab h2');
  
  if (isBaseMode) {
    // On Base, show all Base tokens
    if (tokenSelector) {
      tokenSelector.innerHTML = '';
      for (const symbol of Object.keys(DEFAULT_BASE_TOKENS)) {
        const option = document.createElement('option');
        option.value = symbol;
        option.textContent = symbol;
        tokenSelector.appendChild(option);
      }
      // Keep current selection if valid, otherwise default to ETH
      if (DEFAULT_BASE_TOKENS[selectedToken]) {
        tokenSelector.value = selectedToken;
      } else {
        tokenSelector.value = 'ETH';
        selectedToken = 'ETH';
      }
    }
    if (sendTitle) {
      sendTitle.textContent = 'Send on Base';
    }
  } else {
    // On mainnet, show all tokens
    if (tokenSelector) {
      updateTokenSelector();
    }
    if (sendTitle) {
      sendTitle.textContent = 'Send';
    }
  }
}

// Fetch all balances on Base network (uses backend contract)
async function fetchBaseETHBalance() {
  if (!wallet || !provider) return;
  
  try {
    // Show loading state
    showTokenLoadingSkeleton();
    
    // Since Base has the backend contract, we can use fetchAllBalances
    // which will use the zWalletContract's batchView
    await fetchAllBalances(true);
    
    // Hide add token button on Base
    const addTokenBtn = document.getElementById("addTokenBtn");
    if (addTokenBtn) {
      addTokenBtn.style.display = 'none';
    }
    
  } catch (err) {
    console.error("Error fetching Base balances:", err);
    showError("Failed to fetch balances");
  }
}

// Cache for balance data
let balanceCache = {
  data: null,
  timestamp: 0,
  ttl: 10000 // 10 seconds cache
};

// Cache for ZAMM price data
let zammPriceCache = {
  data: null,
  timestamp: 0,
  ttl: 10000 // 10 seconds - same as balance cache for consistency
};


let isFetchingBalances = false;

// Helper function to ensure balances are loaded before operations
async function ensureBalancesLoaded() {
  console.log("Ensuring balances loaded. Current state:", {
    hasBalances: !!currentBalances,
    balanceCount: currentBalances ? Object.keys(currentBalances).length : 0,
    ethBalance: currentBalances?.["ETH"]
  });
  
  if (!currentBalances || Object.keys(currentBalances).length === 0) {
    console.log("No balances found, fetching...");
    await fetchAllBalances();
    // Wait a bit for balances to propagate
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  
  // Double-check ETH balance is loaded for gas calculations
  if (!currentBalances["ETH"] || !currentBalances["ETH"].raw) {
    console.warn("ETH balance not loaded, force fetching...");
    await fetchAllBalances(true);
  }
  
  console.log("Balances after ensure:", {
    ethBalance: currentBalances?.["ETH"],
    totalTokens: currentBalances ? Object.keys(currentBalances).length : 0
  });
  
  return currentBalances;
}

async function fetchAllBalances(forceRefresh = false) {
  
  if (!wallet || !provider) {
    return;
  }
  
  // Base network now uses the backend contract for batch view
  if (!zWalletContract) {
    return;
  }
  
  // Prevent duplicate fetches
  if (isFetchingBalances && !forceRefresh) {
    // Wait for existing fetch to complete
    let attempts = 0;
    while (isFetchingBalances && attempts < 50) {
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    return;
  }
  
  // Use cache if valid and not forcing refresh
  const now = Date.now();
  if (!forceRefresh && balanceCache.data && (now - balanceCache.timestamp < balanceCache.ttl)) {
    currentBalances = balanceCache.data.balances;
    tokenPrices = balanceCache.data.prices || tokenPrices;
    updateBalanceDisplay();
    return;
  }
  
  isFetchingBalances = true;
  
  // Show loading state only if not cached and actually visible
  const tokenGrid = document.getElementById("tokenGrid");
  if (!balanceCache.data && tokenGrid && tokenGrid.offsetParent !== null) {
    showTokenLoadingSkeleton();
  }

  try {
    // Prepare token addresses and ids for batchView
    const tokenAddresses = [];
    const tokenIds = [];
    const tokenSymbols = [];

    for (const [symbol, token] of Object.entries(TOKENS)) {
      tokenAddresses.push(token.address || ethers.ZeroAddress);
      tokenIds.push(token.isERC6909 ? BigInt(token.id) : 0n);
      tokenSymbols.push(symbol);
    }

    
    // Call batchView to get all data in one call - this is the most efficient way
    // The zWallet contract returns all token balances, metadata, and prices in a single call
    const batchResult = await zWalletContract.batchView(
      wallet.address,
      tokenAddresses,
      tokenIds
    );
    
    
    const [
      ensName,
      , // tokensOut - unused
      , // idsOut - unused
      kinds,  // 0=ETH, 20=ERC20, 72=ERC721, 69=ERC6909
      rawBalances,
      , // balances - unused
      names,
      symbols,
      decimals,
      pricesETH,
      , // pricesETHStr - unused
      pricesUSDC,
      , // pricesUSDCStr - unused
    ] = batchResult;
    
    // Update ENS name if found
    if (ensName) {
      const ensNameEl = document.getElementById("ensName");
      if (ensNameEl) {
        ensNameEl.textContent = ensName;
      }
    }

    // Process the results
    currentBalances = {};
    tokenPrices = {};
    
    // Get ETH price from results
    const ethIndex = tokenSymbols.indexOf("ETH");
    if (ethIndex !== -1 && pricesUSDC[ethIndex]) {
      ethPrice = Number(pricesUSDC[ethIndex]) / 1e6;
    }

    // Start fetching ZAMM price in parallel (non-blocking) - only on mainnet
    let zammPricePromise = null;
    if (!isBaseMode && tokenSymbols.includes("ZAMM")) {
      zammPricePromise = fetchZAMMPrice().catch(() => {
        // ZAMM price fetch failed
        return { eth: 0, usd: 0 };
      });
    }

    for (let i = 0; i < tokenSymbols.length; i++) {
      const symbol = tokenSymbols[i];
      const token = TOKENS[symbol];
      
      if (!token) {
        continue;
      }

      // Update token type based on contract's detection
      const tokenKind = kinds ? Number(kinds[i]) : 0;
      if (tokenKind === 72) {
        token.isERC721 = true;
      } else if (tokenKind === 69) {
        token.isERC6909 = true;
      }

      // Store balance directly from contract
      const rawBal = rawBalances[i] || 0n;
      const dec = decimals ? (Number(decimals[i]) || 18) : 18;
      
      currentBalances[symbol] = {
        raw: rawBal,
        formatted: formatBalance(rawBal, dec),
      };

      // Use prices directly from contract - it already handles all special cases
      let priceInEth = pricesETH[i] ? Number(pricesETH[i]) / 1e18 : 0;
      let priceInUsd = pricesUSDC[i] ? Number(pricesUSDC[i]) / 1e6 : 0;

      tokenPrices[symbol] = {
        eth: priceInEth,
        usd: priceInUsd,
      };

      // Update token metadata from contract if needed
      if (!token.name || token.name === "") {
        token.name = names[i] || symbol;
        token.symbol = symbols[i] || symbol;
        token.decimals = dec;
      }
    }

    // Update ZAMM price after the loop if it was fetched
    if (zammPricePromise) {
      const zammPrice = await zammPricePromise;
      const zammSymbol = "ZAMM";
      if (tokenPrices[zammSymbol]) {
        tokenPrices[zammSymbol].eth = zammPrice.eth || tokenPrices[zammSymbol].eth;
        tokenPrices[zammSymbol].usd = zammPrice.usd || tokenPrices[zammSymbol].usd;
      }
    }

    // Cache the results
    balanceCache = {
      data: {
        balances: { ...currentBalances },
        prices: { ...tokenPrices }
      },
      timestamp: Date.now(),
      ttl: 10000
    };
    
    updateBalanceDisplay();
    isFetchingBalances = false;
  } catch (error) {
    
    // Fallback: try to at least get ETH balance using zWallet
    try {
      const [rawBalance] = await zWalletContract.getBalanceOf(
        wallet.address,
        ethers.ZeroAddress, // ETH uses zero address
        0 // id is 0 for ETH
      );
      const ethBalance = rawBalance;
      currentBalances = {
        ETH: {
          raw: ethBalance,
          formatted: ethers.formatEther(ethBalance)
        }
      };
      
      // Set default prices if not available
      if (!tokenPrices.ETH) {
        tokenPrices = {
          ETH: { eth: 1, usd: 3500 }
        };
      }
      
      // Initialize other tokens with zero balance
      for (const [symbol] of Object.entries(TOKENS)) {
        if (symbol !== 'ETH' && !currentBalances[symbol]) {
          currentBalances[symbol] = {
            raw: 0n,
            formatted: "0"
          };
          tokenPrices[symbol] = tokenPrices[symbol] || { eth: 0, usd: 0 };
        }
      }
      
      updateBalanceDisplay();
    } catch (fallbackError) {
      showError(error, 'Fetch Balances');
    } finally {
      isFetchingBalances = false;
    }
  } finally {
    isFetchingBalances = false;
  }
}

function updateBalanceDisplay() {
  const tokenGrid = document.getElementById("tokenGrid");
  const sendTokenGrid = document.getElementById("sendTokenGrid");
  if (!tokenGrid || !sendTokenGrid) {
    // Token grids not ready
    return;
  }
  
  // If no wallet is connected, show a message
  if (!wallet) {
    const noWalletMessage = `
      <div style="text-align: center; padding: 20px; color: var(--text-secondary);">
        <div style="font-size: 18px; margin-bottom: 10px;">No wallet connected</div>
        <div style="font-size: 14px;">Generate or import a wallet to send tokens</div>
      </div>
    `;
    if (tokenGrid) tokenGrid.innerHTML = noWalletMessage;
    if (sendTokenGrid) sendTokenGrid.innerHTML = noWalletMessage;
    return;
  }

  // Use DocumentFragment for batched DOM updates
  const walletFragment = document.createDocumentFragment();
  const sendFragment = document.createDocumentFragment();

  let totalValue = 0;
  let totalETH = 0;

  // Use Object.keys to maintain insertion order
  const tokenKeys = Object.keys(TOKENS);
  
  // Pre-calculate all values
  const tokenData = tokenKeys.map(symbol => {
    const token = TOKENS[symbol];
    const balance = currentBalances[symbol] || { formatted: "0" };
    const price = tokenPrices[symbol] || { eth: 0, usd: 0 };
    const value = parseFloat(balance.formatted) * price.usd;
    
    return { symbol, token, balance, price, value };
  });

  // Process all tokens
  for (const { symbol, token, balance, price, value } of tokenData) {
    totalValue += value;
    
    // Calculate ETH value
    if (symbol === "ETH") {
      totalETH += parseFloat(balance.formatted);
    } else {
      totalETH += parseFloat(balance.formatted) * price.eth;
    }

    // Create row for wallet tab
    const walletRow = document.createElement("div");
    walletRow.className = "token-row";
    walletRow.dataset.symbol = symbol;

    // Special display logic for ETH vs other tokens
    let priceDisplay1 = "";
    let priceDisplay2 = "";

    if (symbol === "ETH") {
      // For ETH: show USD price per ETH and total value
      if (price.usd > 0) {
        priceDisplay1 = formatCurrency(price.usd) + "/ETH";
        priceDisplay2 = formatCurrency(value);
      } else {
        priceDisplay1 = "Price unavailable";
        priceDisplay2 = "$0.00";
      }
    } else {
      // For other tokens: show ETH ratio and USD value
      priceDisplay1 = `${price.eth.toFixed(6)} ETH`;
      priceDisplay2 = formatCurrency(value);
    }

    // Use template literal once for efficiency
    walletRow.innerHTML = `
  <div class="token-left">
    <div class="token-icon">${TOKEN_LOGOS[symbol] || generateCoinSVG(symbol)}</div>
    <div class="token-details">
      <div class="token-symbol">${esc(symbol)}</div>
      <div class="token-name">${esc(token.name || symbol)}</div>
    </div>
  </div>
  <div class="token-right">
    <div class="token-balance">${Number(balance.formatted).toFixed(4)}</div>
    <div class="token-prices">
      <span class="eth-price">${esc(priceDisplay1)}</span>
      <span class="usd-price">${esc(priceDisplay2)}</span>
    </div>
  </div>`;

    walletFragment.appendChild(walletRow);

    // Create row for send tab
    const sendRow = walletRow.cloneNode(true);
    sendRow.dataset.tokenSymbol = symbol; // Store symbol for event delegation
    if (symbol === selectedToken) {
      sendRow.classList.add("selected");
    }
    sendFragment.appendChild(sendRow);
  }

  // Batch DOM updates efficiently
  requestAnimationFrame(() => {
    tokenGrid.replaceChildren(walletFragment);
    sendTokenGrid.replaceChildren(sendFragment);
    
    // Set up event delegation on sendTokenGrid if not already done
    if (!sendTokenGrid.hasAttribute('data-delegation-setup')) {
      sendTokenGrid.addEventListener('click', (e) => {
        const tokenRow = e.target.closest('.token-row');
        if (tokenRow && tokenRow.dataset.tokenSymbol) {
          selectToken(tokenRow.dataset.tokenSymbol);
        }
      });
      sendTokenGrid.setAttribute('data-delegation-setup', 'true');
    }
  });
  
  const portfolioTotal = document.getElementById("portfolioTotal");
  if (portfolioTotal) {
    portfolioTotal.innerHTML = `<div style="font-size: 20px; margin-bottom: 4px;">${formatCurrency(totalValue)}</div>
    <div style="font-size: 14px; color: var(--text-secondary);">${totalETH.toFixed(6)} ETH</div>`;
  }
  
  // Show/hide add token button based on network
  const addTokenBtn = document.getElementById("addTokenBtn");
  if (addTokenBtn) {
    addTokenBtn.style.display = isBaseMode ? 'none' : '';
  }
}

function selectToken(symbol) {
  selectedToken = symbol;
  // Optimize with for...of loop for better performance
  const rows = document.querySelectorAll("#sendTokenGrid .token-row");
  for (const row of rows) {
    row.classList.toggle("selected", row.dataset.symbol === symbol);
  }
  const label = document.getElementById("selectedTokenLabel");
  if (label) label.textContent = symbol;
  
  // Show/hide IOU mode for USDC
  const iouModeSection = document.getElementById("iouModeSection");
  const iouModeToggle = document.getElementById("iouModeToggle");
  if (symbol === "USDC") {
    iouModeSection?.classList.remove("hidden");
  } else {
    iouModeSection?.classList.add("hidden");
    // Reset IOU mode if switching away from USDC
    if (iouModeToggle && iouModeToggle.checked) {
      iouModeToggle.checked = false;
      // Trigger change event to reset UI
      iouModeToggle.dispatchEvent(new Event("change"));
    }
  }
  
  updateEstimatedTotal();
}

async function resolveENS(name) {
  // Support both .eth (ENS) and .base.eth (Base names)
  if (!zWalletContract) return null;
  
  // On Base, the backend contract checks Base names
  // On Mainnet, it checks ENS names
  // Both formats are supported: name.eth and name.base.eth
  if (!name.endsWith(".eth")) return null;

  try {
    const [owner, receiver] = await zWalletContract.whatIsTheAddressOf(name);
    // Return receiver if set, otherwise owner
    return receiver !== ethers.ZeroAddress ? receiver : owner !== ethers.ZeroAddress ? owner : null;
  } catch (err) {
    // Don't log error for Base names on Base network - it's expected
    if (!(isBaseMode && name.endsWith('.base.eth'))) {
      console.error('Name resolution failed:', err);
    }
    return null;
  }
}

async function updateGasPrices() {
  if (!provider) return;

  try {
    const feeData = await getCachedGasPrice();

    // Get current base fee and add buffer for next block
    let baseFee = feeData.maxFeePerGas;
    let priorityFee = feeData.maxPriorityFeePerGas;

    // Fallback to reasonable defaults if not available
    if (!baseFee || baseFee === 0n) {
      baseFee = ethers.parseUnits("20", "gwei"); // 20 gwei fallback
    }
    if (!priorityFee || priorityFee === 0n) {
      priorityFee = ethers.parseUnits("1.5", "gwei"); // 1.5 gwei fallback
    }

    // Optimized multipliers for better UX
    // Base network has lower fees, adjust accordingly
    const isBase = isBaseMode;
    
    gasPrices.slow = {
      maxFeePerGas: baseFee, // Use exact base fee for slow
      maxPriorityFeePerGas: isBase ? ethers.parseUnits("0.01", "gwei") : ethers.parseUnits("1", "gwei"),
    };

    gasPrices.normal = {
      maxFeePerGas: (baseFee * 105n) / 100n, // 5% buffer for normal
      maxPriorityFeePerGas: isBase ? ethers.parseUnits("0.05", "gwei") : priorityFee,
    };

    gasPrices.fast = {
      maxFeePerGas: (baseFee * 115n) / 100n, // 15% buffer for fast
      maxPriorityFeePerGas: isBase ? ethers.parseUnits("0.1", "gwei") : (priorityFee * 150n) / 100n,
    };

    // Cap maximum gas prices to prevent overpaying (different for Base)
    const maxGasPrice = isBase ? ethers.parseUnits("5", "gwei") : ethers.parseUnits("200", "gwei");
    const maxPriorityPrice = isBase ? ethers.parseUnits("0.5", "gwei") : ethers.parseUnits("10", "gwei");

    for (const speed of ["slow", "normal", "fast"]) {
      if (gasPrices[speed].maxFeePerGas > maxGasPrice) {
        gasPrices[speed].maxFeePerGas = maxGasPrice;
      }
      if (gasPrices[speed].maxPriorityFeePerGas > maxPriorityPrice) {
        gasPrices[speed].maxPriorityFeePerGas = maxPriorityPrice;
      }
    }

    // Update display with null checks
    const slowPriceEl = document.getElementById("slowPrice");
    const normalPriceEl = document.getElementById("normalPrice");
    const fastPriceEl = document.getElementById("fastPrice");
    
    if (slowPriceEl) {
      slowPriceEl.textContent = (Number(gasPrices.slow.maxFeePerGas) / 1e9).toFixed(1);
    }
    if (normalPriceEl) {
      normalPriceEl.textContent = (Number(gasPrices.normal.maxFeePerGas) / 1e9).toFixed(1);
    }
    if (fastPriceEl) {
      fastPriceEl.textContent = (Number(gasPrices.fast.maxFeePerGas) / 1e9).toFixed(1);
    }

    await updateEstimatedTotal();
  } catch (err) {
    

    // Fallback to safe defaults on error
    const fallbackGas = ethers.parseUnits("30", "gwei");
    const fallbackPriority = ethers.parseUnits("2", "gwei");

    gasPrices.slow = {
      maxFeePerGas: ethers.parseUnits("20", "gwei"),
      maxPriorityFeePerGas: ethers.parseUnits("1", "gwei"),
    };
    gasPrices.normal = {
      maxFeePerGas: fallbackGas,
      maxPriorityFeePerGas: fallbackPriority,
    };
    gasPrices.fast = {
      maxFeePerGas: ethers.parseUnits("50", "gwei"),
      maxPriorityFeePerGas: ethers.parseUnits("3", "gwei"),
    };
  }
}

async function updateEstimatedTotal() {
  const amount = document.getElementById("amount").value || "0";
  const estimatedTotalEl = document.getElementById("estimatedTotal");
  if (!estimatedTotalEl) return;
  
  if (!wallet || !provider) {
    estimatedTotalEl.textContent = "--";
    return;
  }

  try {
    const token = TOKENS[selectedToken];
    // More accurate gas limits based on actual usage
    const gasLimit =
      selectedToken === "ETH" ? 21000n : token?.isERC6909 ? 120000n : 65000n;

    const gasPrice = gasPrices[selectedGasSpeed]?.maxFeePerGas || 20000000000n;
    const gasCostEth = ethers.formatEther(gasLimit * gasPrice);
    const gasCostUsd = parseFloat(gasCostEth) * ethPrice;

    const tokenPrice = tokenPrices[selectedToken] || { eth: 0, usd: 0 };
    const amountUsd = parseFloat(amount) * tokenPrice.usd;

    estimatedTotalEl.textContent = `${amount} ${selectedToken} ($${amountUsd.toFixed(
      2
    )}) + Ξ${parseFloat(gasCostEth).toFixed(5)} gas ($${gasCostUsd.toFixed(
      2
    )})`;
  } catch (err) {
    
    estimatedTotalEl.textContent = amount + " " + selectedToken;
  }
}

async function calculateMaxAmount() {
  if (!wallet) return "0";

  const balance = currentBalances[selectedToken];
  if (!balance) return "0";

  if (selectedToken === "ETH") {
    const gasLimit = 21000n;
    const gasPrice = gasPrices[selectedGasSpeed]?.maxFeePerGas || 30000000000n;
    const gasCost = (gasLimit * gasPrice * 105n) / 100n; // 5% buffer for safety

    if (balance.raw > gasCost) {
      return ethers.formatEther(balance.raw - gasCost);
    }
    return "0";
  }

  return balance.formatted;
}

async function fetchTransactionHistoryExtended() {
  if (!wallet || !provider) return;

  const loadingMsg = document.getElementById("txLoadingMessage");
  const loadMoreBtn = document.getElementById("loadMoreTxBtn");

  if (!loadingMsg) {
    
    return;
  }

  loadingMsg.textContent = "Loading 24 hours of transactions...";
  loadingMsg.classList.remove("hidden");
  if (loadMoreBtn) loadMoreBtn.classList.add("hidden");
  txHistory = [];

  const uniqueTxs = new Set();

  try {
    const currentBlock = await provider.getBlockNumber();
    // ~7200 blocks in 24 hours (12 sec per block)
    // We'll fetch in chunks of 999 blocks
    const totalBlocks = 7200;
    const chunkSize = 999;
    const chunks = Math.ceil(totalBlocks / chunkSize);
    
    for (let i = 0; i < chunks; i++) {
      const toBlock = currentBlock - (i * chunkSize);
      const fromBlock = Math.max(0, toBlock - chunkSize + 1);
      
      loadingMsg.textContent = `Loading transactions... (${i + 1}/${chunks})`;
      
      const promises = [];
      
      // Fetch each token's transfers for this chunk
      for (const [symbol, token] of Object.entries(TOKENS)) {
        if (!token.address) continue;
        
        if (token.isERC6909 && token.id) {
          // Handle ERC6909 tokens - Transfer(address caller, address indexed sender, address indexed receiver, uint256 indexed id, uint256 amount)
          try {
            const tokenIdHex = ethers.toBeHex(token.id);
            promises.push(
            Promise.all([
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock,
                topics: [
                  ethers.id("Transfer(address,address,address,uint256,uint256)"),
                  ethers.zeroPadValue(wallet.address, 32), // sender (indexed)
                  null, // receiver can be anyone
                  ethers.zeroPadValue(tokenIdHex, 32), // id (indexed)
                ],
              }).catch(() => []),
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock,
                topics: [
                  ethers.id("Transfer(address,address,address,uint256,uint256)"),
                  null, // sender can be anyone
                  ethers.zeroPadValue(wallet.address, 32), // receiver (indexed)
                  ethers.zeroPadValue(tokenIdHex, 32), // id (indexed)
                ],
              }).catch(() => [])
            ]).then(([sentLogs, receivedLogs]) => {
              // Process ERC6909 sent transactions
              for (const log of sentLogs) {
                // Data contains: caller (address) and amount (uint256)
                const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                  ["address", "uint256"],
                  log.data
                );
                const txKey = `${log.transactionHash}-${log.logIndex}`;
                if (!uniqueTxs.has(txKey)) {
                  uniqueTxs.add(txKey);
                  txHistory.push({
                    type: "send",
                    token: symbol,
                    amount: ethers.formatUnits(decoded[1], token.decimals),
                    hash: log.transactionHash,
                    block: log.blockNumber,
                    to: "0x" + log.topics[2].slice(26), // receiver is topic[2]
                    logIndex: log.logIndex,
                  });
                }
              }
              // Process ERC6909 received transactions
              for (const log of receivedLogs) {
                // Data contains: caller (address) and amount (uint256)
                const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                  ["address", "uint256"],
                  log.data
                );
                const txKey = `${log.transactionHash}-${log.logIndex}`;
                if (!uniqueTxs.has(txKey)) {
                  uniqueTxs.add(txKey);
                  txHistory.push({
                    type: "receive",
                    token: symbol,
                    amount: ethers.formatUnits(decoded[1], token.decimals),
                    hash: log.transactionHash,
                    block: log.blockNumber,
                    from: "0x" + log.topics[1].slice(26), // sender is topic[1]
                    logIndex: log.logIndex,
                  });
                }
              }
            })
          );
          } catch (err) {
            console.error(`Failed to process ERC6909 token ${symbol} in extended history:`, err);
          }
        } else {
          // Standard ERC20
          promises.push(
            Promise.all([
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock,
                topics: [
                  ethers.id("Transfer(address,address,uint256)"),
                  ethers.zeroPadValue(wallet.address, 32),
                ],
              }).catch(() => []),
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock,
                topics: [
                  ethers.id("Transfer(address,address,uint256)"),
                  null,
                  ethers.zeroPadValue(wallet.address, 32),
                ],
              }).catch(() => [])
            ]).then(([sentLogs, receivedLogs]) => {
              for (const log of sentLogs) {
                const txKey = `${log.transactionHash}-${log.logIndex}`;
                if (!uniqueTxs.has(txKey)) {
                  uniqueTxs.add(txKey);
                  const amount = ethers.formatUnits(log.data, token.decimals);
                  txHistory.push({
                    type: "send",
                    token: symbol,
                    amount,
                    hash: log.transactionHash,
                    block: log.blockNumber,
                    to: "0x" + log.topics[2].slice(26),
                    logIndex: log.logIndex,
                  });
                }
              }
              for (const log of receivedLogs) {
                const txKey = `${log.transactionHash}-${log.logIndex}`;
                if (!uniqueTxs.has(txKey)) {
                  uniqueTxs.add(txKey);
                  const amount = ethers.formatUnits(log.data, token.decimals);
                  txHistory.push({
                    type: "receive",
                    token: symbol,
                    amount,
                    hash: log.transactionHash,
                    block: log.blockNumber,
                    from: "0x" + log.topics[1].slice(26),
                    logIndex: log.logIndex,
                  });
                }
              }
            })
          );
        }
      }
      
      await Promise.all(promises);
    }
    
    // Sort by block number and log index
    txHistory.sort((a, b) => {
      if (b.block !== a.block) return b.block - a.block;
      return (b.logIndex || 0) - (a.logIndex || 0);
    });

    displayTransactions();
  } catch (err) {
    
    if (loadingMsg) loadingMsg.textContent = "Error loading extended history";
    if (loadMoreBtn) loadMoreBtn.classList.remove("hidden");
  }
}

async function fetchTransactionHistory() {
  if (!wallet || !provider) {
    const loadingMsg = document.getElementById("txLoadingMessage");
    if (loadingMsg) {
      loadingMsg.textContent = "Please unlock wallet first";
    }
    return;
  }

  const txList = document.getElementById("txList");
  const loadingMsg = document.getElementById("txLoadingMessage");
  
  // Update loading message based on network
  const networkName = isBaseMode ? 'Base' : 'Ethereum';
  loadingMsg.textContent = `Loading recent ${networkName} transactions...`;
  txList.classList.add("hidden");
  txHistory = [];

  // Use a Set to track unique transactions
  const uniqueTxs = new Set();

  try {
    // Get block number for limiting search
    const currentBlock = await provider.getBlockNumber();
    // Use 999 blocks to stay under RPC limit of 1000
    // This is approximately 3.3 hours of Ethereum blocks (12 sec per block)
    const fromBlock = Math.max(0, currentBlock - 999);

    // Parallel fetch all logs
    const promises = [];
    
    // Fetch token transfers for each token in parallel
    for (const [symbol, token] of Object.entries(TOKENS)) {
      if (!token.address) continue; // Skip ETH

      // Handle ERC6909 tokens differently
      if (token.isERC6909 && token.id) {
        // ERC6909 uses Transfer event with 5 parameters: Transfer(address caller, address indexed sender, address indexed receiver, uint256 indexed id, uint256 amount)
        try {
          // Convert ID to hex format safely
          const tokenIdHex = ethers.toBeHex(token.id);
          
          promises.push(
            Promise.all([
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock: currentBlock,
                topics: [
                  ethers.id("Transfer(address,address,address,uint256,uint256)"),
                  ethers.zeroPadValue(wallet.address, 32), // sender (indexed)
                  null, // receiver can be anyone
                  ethers.zeroPadValue(tokenIdHex, 32), // id (indexed)
              ],
            }),
            provider.getLogs({
              address: token.address,
              fromBlock,
              toBlock: currentBlock,
              topics: [
                ethers.id("Transfer(address,address,address,uint256,uint256)"),
                null, // sender can be anyone
                ethers.zeroPadValue(wallet.address, 32), // receiver (indexed)
                ethers.zeroPadValue(tokenIdHex, 32), // id (indexed)
              ],
            })
          ]).then(([sentLogs, receivedLogs]) => {
            // Process ERC6909 sent
            for (const log of sentLogs) {
              // Data contains: caller (address) and amount (uint256)
              const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                ["address", "uint256"],
                log.data
              );
              const txKey = `${log.transactionHash}-${log.logIndex}`;
              if (!uniqueTxs.has(txKey)) {
                uniqueTxs.add(txKey);
                txHistory.push({
                  type: "send",
                  token: symbol,
                  amount: ethers.formatUnits(decoded[1], token.decimals),
                  hash: log.transactionHash,
                  block: log.blockNumber,
                  to: "0x" + log.topics[2].slice(26), // receiver is topic[2]
                  logIndex: log.logIndex,
                });
              }
            }
            // Process ERC6909 received
            for (const log of receivedLogs) {
              // Data contains: caller (address) and amount (uint256)
              const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                ["address", "uint256"],
                log.data
              );
              const txKey = `${log.transactionHash}-${log.logIndex}`;
              if (!uniqueTxs.has(txKey)) {
                uniqueTxs.add(txKey);
                txHistory.push({
                  type: "receive",
                  token: symbol,
                  amount: ethers.formatUnits(decoded[1], token.decimals),
                  hash: log.transactionHash,
                  block: log.blockNumber,
                  from: "0x" + log.topics[1].slice(26), // sender is topic[1]
                  logIndex: log.logIndex,
                });
              }
            }
          }).catch(() => {
            // Ignore errors for individual token fetches
          })
        );
        } catch (err) {
          // Skip failed token processing
        }
      } else {
        // Standard ERC20 transfers
        promises.push(
          Promise.all([
            provider.getLogs({
              address: token.address,
              fromBlock,
              toBlock: currentBlock,
              topics: [
                ethers.id("Transfer(address,address,uint256)"),
                ethers.zeroPadValue(wallet.address, 32),
              ],
            }),
            provider.getLogs({
              address: token.address,
              fromBlock,
              toBlock: currentBlock,
              topics: [
                ethers.id("Transfer(address,address,uint256)"),
                null,
                ethers.zeroPadValue(wallet.address, 32),
              ],
            })
          ]).then(([sentLogs, receivedLogs]) => {
            // Process sent
            for (const log of sentLogs) {
              const txKey = `${log.transactionHash}-${log.logIndex}`;
              if (!uniqueTxs.has(txKey)) {
                uniqueTxs.add(txKey);
                const amount = ethers.formatUnits(log.data, token.decimals);
                txHistory.push({
                  type: "send",
                  token: symbol,
                  amount,
                  hash: log.transactionHash,
                  block: log.blockNumber,
                  to: "0x" + log.topics[2].slice(26),
                  logIndex: log.logIndex,
                });
              }
            }
            // Process received
            for (const log of receivedLogs) {
              const txKey = `${log.transactionHash}-${log.logIndex}`;
              if (!uniqueTxs.has(txKey)) {
                uniqueTxs.add(txKey);
                const amount = ethers.formatUnits(log.data, token.decimals);
                txHistory.push({
                  type: "receive",
                  token: symbol,
                  amount,
                  hash: log.transactionHash,
                  block: log.blockNumber,
                  from: "0x" + log.topics[1].slice(26),
                  logIndex: log.logIndex,
                });
              }
            }
          }).catch(() => {
            // Ignore errors for individual token fetches
          })
        );
      }
    }

    // Wait for all fetches to complete
    await Promise.all(promises);

    // Sort by block number and log index
    txHistory.sort((a, b) => {
      if (b.block !== a.block) return b.block - a.block;
      return (b.logIndex || 0) - (a.logIndex || 0);
    });

    // Display transactions
    displayTransactions();
  } catch (err) {
    loadingMsg.textContent = err.message?.includes("limit") 
      ? "Too many transactions. Try 'Load Transactions' for recent only" 
      : "Error loading transactions. Check RPC connection.";
  }
}

function displayTransactions() {
  const txList = document.getElementById("txList");
  const loadingMsg = document.getElementById("txLoadingMessage");
  const loadMoreBtn = document.getElementById("loadMoreTxBtn");

  if (!txList || !loadingMsg) {
    
    return;
  }

  if (txHistory.length === 0) {
    loadingMsg.textContent = "No transactions found in the last 3 hours";
    txList.classList.add("hidden");
    if (loadMoreBtn) loadMoreBtn.classList.remove("hidden");
    return;
  }

  loadingMsg.classList.add("hidden");
  txList.classList.remove("hidden");
  if (loadMoreBtn) loadMoreBtn.classList.remove("hidden");
  txList.innerHTML = "";

  // Display max 100 most recent
  const displayTxs = txHistory.slice(0, 100);

  for (const tx of displayTxs) {
    const item = document.createElement("div");
    item.className = "tx-item";

    item.innerHTML = `
                    <span class="tx-type ${tx.type}">${tx.type}</span>
                    <div class="tx-details">
                        <a class="tx-hash" data-hash="${tx.hash}" href="#" title="View on Etherscan">${tx.hash.slice(0, 10)}... ↗</a>
                        <div style="font-size: 10px; color: var(--text-secondary);">
                            ${
                              tx.type === "send"
                                ? "To: " + tx.to?.slice(0, 8) + "..."
                                : "From: " + tx.from?.slice(0, 8) + "..."
                            }
                        </div>
                    </div>
                    <div class="tx-amount">
                        ${tx.type === "send" ? "-" : "+"}${parseFloat(
      tx.amount
    ).toFixed(4)} ${tx.token}
                    </div>
                `;

    // Add click handler to the hash link
    const hashLink = item.querySelector('.tx-hash');
    if (hashLink) {
      hashLink.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const hash = hashLink.dataset.hash;
        
        const explorerUrl = isBaseMode 
          ? `https://basescan.org/tx/${hash}`
          : `https://etherscan.io/tx/${hash}`;
        
        // Use Chrome API to open in new tab for extension compatibility
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({
            action: 'open_external',
            url: explorerUrl
          });
        } else {
          window.open(
            explorerUrl,
            "_blank",
            "noopener,noreferrer"
          );
        }
      });
    }

    txList.appendChild(item);
  }
}

function esc(s) {
  return String(s).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[c])
  );
}

window.addEventListener("beforeunload", () => {
  // Clean up all event listeners and timers
  stopConnectionHealthMonitor();
  cleanupEventListeners();
  wallet = null;
});
function lockWallet() {
  wallet = null;
  showToast("Locked");
}

// Helper function to open external URLs in Chrome extension
function openExternalUrl(url) {
  if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({ action: 'open_external', url: url });
  } else {
    window.open(url, '_blank', 'noopener,noreferrer');
  }
}

// Helper function to create clickable external links
function createExternalLink(url, text, style = '') {
  const link = document.createElement('a');
  link.href = url;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.textContent = text;
  if (style) {
    link.style.cssText = style;
  }
  
  // Add click handler for extension compatibility
  link.addEventListener('click', (e) => {
    e.preventDefault();
    openExternalUrl(url);
  });
  
  return link;
}

// Helper to attach click handlers to existing links
function attachLinkHandlers() {
  // Find all external links and attach handlers
  document.querySelectorAll('a[target="_blank"]').forEach(link => {
    if (!link.dataset.handlerAttached) {
      link.dataset.handlerAttached = 'true';
      link.addEventListener('click', (e) => {
        e.preventDefault();
        openExternalUrl(link.href);
      });
    }
  });
}

async function showEtherscanLink(txHash) {
  const status = document.getElementById("txStatus");
  
  // Create container for link
  const linksContainer = document.createElement("div");
  linksContainer.style.cssText = "margin-top: 8px; display: flex; gap: 12px; flex-wrap: wrap;";
  
  // Determine the correct block explorer based on network
  let explorerUrl;
  let explorerName;
  
  try {
    if (isBaseMode) {
      // Use Base explorer
      explorerUrl = `https://basescan.org/tx/${txHash}`;
      explorerName = "BaseScan";
    } else if (provider) {
      const network = await provider.getNetwork();
      const chainId = Number(network.chainId);
      
      switch(chainId) {
        case 8453:
          explorerUrl = `https://basescan.org/tx/${txHash}`;
          explorerName = "Basescan";
          break;
        case 1:
        default:
          explorerUrl = `https://etherscan.io/tx/${txHash}`;
          explorerName = "Etherscan";
          break;
      }
    } else {
      // Default to Etherscan if no provider
      explorerUrl = `https://etherscan.io/tx/${txHash}`;
      explorerName = "Etherscan";
    }
  } catch (err) {
    // Default to Etherscan on error
    explorerUrl = `https://etherscan.io/tx/${txHash}`;
    explorerName = "Etherscan";
  }
  
  // Create explorer link using helper
  const explorerLink = createExternalLink(
    explorerUrl,
    `${explorerName} →`,
    "color: var(--accent); text-decoration: underline; font-size: 12px;"
  );
  explorerLink.className = "explorer-link";
  
  linksContainer.appendChild(explorerLink);
  status.appendChild(linksContainer);
}

function showToast(message, duration = 3000, type = 'success') {
  const toast = document.getElementById("toast");
  if (!toast) return;
  
  toast.textContent = message;
  toast.classList.remove("error", "warning", "success");
  toast.classList.add("show", type);
  setManagedTimeout(() => toast.classList.remove("show"), duration);
}

// Function to show user-friendly error messages
function showError(error, context = '') {
  let message = '';
  let errorType = 'error';
  
  // Parse error message
  const errorStr = error?.message || error?.toString() || 'Unknown error';
  
  // Handle common blockchain errors with user-friendly messages
  if (errorStr.includes('user rejected') || errorStr.includes('User denied') || errorStr.includes('User rejected')) {
    message = 'Transaction cancelled';
    errorType = 'warning';
  } else if (errorStr.includes('insufficient funds') || errorStr.includes('insufficient balance')) {
    message = 'Insufficient balance for this transaction';
  } else if (errorStr.includes('nonce too low') || errorStr.includes('already known')) {
    message = 'Transaction already submitted. Please wait...';
    errorType = 'warning';
  } else if (errorStr.includes('replacement transaction') || errorStr.includes('was replaced')) {
    message = 'Transaction updated successfully';
    errorType = 'warning';
  } else if (errorStr.includes('gas required exceeds') || errorStr.includes('out of gas')) {
    message = 'Transaction requires more gas than available';
  } else if (errorStr.includes('execution reverted')) {
    message = 'Transaction would fail. Please check your input';
  } else if (errorStr.includes('network') || errorStr.includes('timeout')) {
    message = 'Network error. Please try again';
  } else if (errorStr.includes('Invalid RPC')) {
    message = 'Invalid RPC URL';
  } else if (errorStr.includes('Wrong password') || errorStr.includes('incorrect password')) {
    message = 'Incorrect password';
  } else if (errorStr.includes('Invalid private key')) {
    message = 'Invalid private key format';
  } else {
    // For other errors, try to extract a meaningful part
    if (context) {
      message = `${context} failed`;
    } else {
      // Clean up technical jargon
      message = errorStr
        .replace(/Error: /gi, '')
        .replace(/\(.*?\)/g, '')
        .replace(/\[.*?\]/g, '')
        .substring(0, 100);
    }
  }
  
  showToast(message, 3000, errorType);
}

// Show QR code modal
function showQRModal(address) {
  const modal = document.getElementById("qrModal");
  const qrImage = document.getElementById("qrCodeImage");
  const qrAddress = document.getElementById("qrAddress");
  
  if (!modal || !qrImage || !qrAddress) {
    console.error("QR modal elements not found");
    return;
  }
  
  // Generate QR code - use production-ready generator
  // Use plain address for maximum compatibility (MetaMask, Trust Wallet, etc)
  
  console.log("Generating QR for address:", address);
  
  let qrGenerated = false;
  
  if (window.generateQRCode) {
    try {
      // MetaMask Mobile expects JUST the plain address, no prefix
      // Ensure it's lowercase and starts with 0x
      let cleanAddress = address.toLowerCase();
      if (!cleanAddress.startsWith('0x')) {
        cleanAddress = '0x' + cleanAddress;
      }
      
      console.log("Using generateQRCode for:", cleanAddress);
      const qrDataUrl = window.generateQRCode(cleanAddress, 256);
      
      if (qrDataUrl) {
        qrImage.src = qrDataUrl;
        qrGenerated = true;
        console.log("QR code generated successfully");
      } else {
        console.error("generateQRCode returned null");
      }
    } catch (e) {
      console.error("QR generation error:", e);
    }
  } else {
    console.warn("window.generateQRCode not available");
  }
  
  // Fallback to visual-id if main QR generator failed
  if (!qrGenerated) {
    if (window.zWalletVisual && window.zWalletVisual.generateSimpleQR) {
      console.log("Using fallback generateSimpleQR");
      try {
        const qrDataUrl = window.zWalletVisual.generateSimpleQR(address, 256);
        if (qrDataUrl) {
          qrImage.src = qrDataUrl;
          qrGenerated = true;
          console.log("Fallback QR generated successfully");
        }
      } catch (e) {
        console.error("Fallback QR generation error:", e);
      }
    } else {
      console.error("No QR generation method available");
    }
  }
  
  if (!qrGenerated) {
    // Show error in the modal
    qrImage.style.display = 'none';
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = 'padding: 20px; text-align: center; color: var(--error);';
    errorDiv.textContent = 'QR code generation failed. Please copy the address manually.';
    qrImage.parentNode.insertBefore(errorDiv, qrImage);
  }
  
  // Display address
  qrAddress.textContent = address;
  
  // Show the modal
  modal.classList.remove('hidden');
  
  // Setup modal buttons
  const closeBtn = document.getElementById("qrModalClose");
  const downloadBtn = document.getElementById("downloadQR");
  const copyBtn = document.getElementById("copyQRAddress");
  
  if (closeBtn) {
    closeBtn.onclick = () => modal.classList.add("hidden");
  }
  
  if (downloadBtn) {
    downloadBtn.onclick = () => {
      const link = document.createElement("a");
      link.download = `zWallet-${address.slice(0, 8)}.png`;
      link.href = qrImage.src;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    };
  }
  
  if (copyBtn) {
    copyBtn.onclick = () => copyToClipboard(address, "address");
  }
  
  // Modal already shown above, no need to show again
  
  // Close on outside click
  modal.onclick = (e) => {
    if (e.target === modal) {
      modal.classList.add("hidden");
    }
  };
}

// Modal Management Helpers
function showModal(modalId, options = {}) {
  const modal = document.getElementById(modalId);
  if (!modal) return;
  
  // Remove hidden class with animation
  modal.classList.remove('hidden');
  
  // Add ESC key listener
  if (options.closeOnEsc !== false) {
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        hideModal(modalId);
        document.removeEventListener('keydown', escHandler);
      }
    };
    document.addEventListener('keydown', escHandler);
  }
  
  // Focus first input if available
  if (options.autoFocus !== false) {
    setTimeout(() => {
      const firstInput = modal.querySelector('input:not([type="hidden"]), textarea, select');
      if (firstInput) firstInput.focus();
    }, 100);
  }
}

function hideModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return;
  
  modal.classList.add('hidden');
}

// Button Loading State Helper
function setButtonLoading(buttonId, loading = true) {
  const button = document.getElementById(buttonId);
  if (!button) return;
  
  if (loading) {
    button.classList.add('loading');
    button.disabled = true;
    button.dataset.originalText = button.textContent;
  } else {
    button.classList.remove('loading');
    button.disabled = false;
    if (button.dataset.originalText) {
      button.textContent = button.dataset.originalText;
    }
  }
}

// Debounce and throttle helpers are already defined at the top of the file

async function copyToClipboard(text, type) {
  try {
    // Try modern Clipboard API first
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      showToast(type === "address" ? "Address copied!" : "Private key copied!");
    } else {
      // Fallback for non-secure contexts or older browsers
      // Create a temporary textarea element
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.left = "-999999px";
      textarea.style.top = "-999999px";
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      
      // Try to use the Selection API instead of execCommand
      try {
        const range = document.createRange();
        range.selectNodeContents(textarea);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        
        // Attempt to write to clipboard using the selected text
        const blob = new Blob([text], { type: 'text/plain' });
        const data = [new ClipboardItem({ 'text/plain': blob })];
        await navigator.clipboard.write(data);
        document.body.removeChild(textarea);
        showToast(type === "address" ? "Address copied!" : "Private key copied!");
      } catch (selectionErr) {
        // Last resort - deprecated but still works in some browsers
        document.body.removeChild(textarea);
        throw new Error("Copy not supported");
      }
    }
  } catch (err) {
    // Final fallback - show the text for manual copying
    showToast("Copy failed - please copy manually");
    
    // For private keys, we could show a modal with the text selected
    if (type === "privateKey") {
      // Create a modal to show the private key for manual copying
      const modal = document.createElement('div');
      modal.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: var(--bg-secondary);
        padding: 20px;
        border-radius: 8px;
        z-index: 10000;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      `;
      modal.innerHTML = `
        <p style="margin-bottom: 10px;">Copy your private key:</p>
        <input type="text" value="${escapeHtml(text)}" readonly style="width: 100%; padding: 8px;" />
        <button onclick="this.parentElement.remove()" style="margin-top: 10px; width: 100%;">Close</button>
      `;
      document.body.appendChild(modal);
      modal.querySelector('input').select();
    }
  }
}

async function exportEncryptedKey() {
  if (!wallet) return;

  try {
    const password = await securePasswordPrompt('Create Password', 'Create a strong password to encrypt your imported wallet:', true);
    if (!password) return;

    // Encrypt the private key
    const encrypted = await encryptPK(wallet.privateKey, password, {
      aad: wallet.address.toLowerCase()
    });

    const exportData = {
      version: 2,
      address: wallet.address,
      encrypted: encrypted,
      timestamp: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
      type: "application/json" 
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `zWallet-encrypted-${wallet.address.slice(2, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast("Encrypted key exported!");
  } catch (err) {
    
    showToast("Export failed");
  }
}

async function displayWallet() {
  document.getElementById("walletSection").classList.remove("hidden");
  document.getElementById("balanceSection").classList.remove("hidden");

  const address = wallet.address;
  document.getElementById("address").textContent =
    address.slice(0, 6) + "..." + address.slice(-4);
  document.getElementById("address").title = address;
  
  // Set explorer link based on network
  const etherscanLink = document.getElementById("etherscanLink");
  if (etherscanLink) {
    if (isBaseMode) {
      etherscanLink.href = `https://basescan.org/address/${address}`;
      etherscanLink.title = 'View on BaseScan';
    } else {
      etherscanLink.href = `https://etherscan.io/address/${address}`;
      etherscanLink.title = 'View on Etherscan';
    }
  }
  
  // Apply network UI state
  const networkIndicator = document.getElementById("networkIndicator");
  
  // Update the header network button icon
  updateBaseNetworkToggleIcon();
  
  if (isBaseMode) {
    // Apply Base UI
    if (networkIndicator) {
      networkIndicator.classList.add('active', 'base');
      networkIndicator.textContent = 'Base Network';
    }
    
    // Hide swap and bridge tabs on Base
    const swapTab = document.querySelector('.tab[data-tab="swap"]');
    const bridgeTab = document.querySelector('.tab[data-tab="bridge"]');
    if (swapTab) swapTab.style.display = 'none';
    if (bridgeTab) bridgeTab.style.display = 'none';
  } else {
    // Apply Mainnet UI
    if (networkIndicator) {
      networkIndicator.classList.remove('active', 'base');
    }
    
    // Show swap and bridge tabs on mainnet
    const swapTab = document.querySelector('.tab[data-tab="swap"]');
    const bridgeTab = document.querySelector('.tab[data-tab="bridge"]');
    if (swapTab) swapTab.style.display = '';
    if (bridgeTab) bridgeTab.style.display = '';
  }
  
  // Generate and display blockie avatar
  if (window.zWalletVisual && window.zWalletVisual.createBlockie) {
    const blockieAvatar = document.getElementById("blockieAvatar");
    if (blockieAvatar) {
      blockieAvatar.src = window.zWalletVisual.createBlockie(address, 128);
    }
  }
  
  // Setup QR button
  const qrBtn = document.getElementById("qrBtn");
  if (qrBtn) {
    qrBtn.onclick = () => showQRModal(address);
  }

  // Display EIP-7702 delegation status
  const delegationStatusEl = document.getElementById("delegationStatus");
  if (delegationStatusEl && (typeof window.EIP7702 !== 'undefined' || typeof EIP7702 !== 'undefined')) {
    try {
      const EIP7702Module = window.EIP7702 || EIP7702;
      const statusHTML = await EIP7702Module.getDelegationStatusHTML(address, provider);
      delegationStatusEl.innerHTML = statusHTML;
    } catch (err) {
      console.log("Could not check delegation status:", err);
      delegationStatusEl.innerHTML = '';
    }
  }

  // Private key display moved to Settings tab

  // ENS name is already fetched in batchView and displayed
  // No need for additional lookup here

  // Fetch balances only if we don't have cached data
  // This significantly speeds up wallet unlock
  const now = Date.now();
  const needsBalanceRefresh = !balanceCache.data || 
    (now - balanceCache.timestamp > balanceCache.ttl);
  
  // Fetch in parallel but only what's needed
  const fetchPromises = [];
  if (needsBalanceRefresh) {
    fetchPromises.push(fetchAllBalances());
  } else {
    // Use cached data immediately
    currentBalances = balanceCache.data.balances;
    tokenPrices = balanceCache.data.prices || tokenPrices;
    updateBalanceDisplay();
  }
  fetchPromises.push(updateGasPrices());
  
  if (fetchPromises.length > 0) {
    await Promise.all(fetchPromises);
  }

  if (document.getElementById("autoRefresh").checked) {
    clearManagedInterval(autoRefreshInterval);
    autoRefreshInterval = setManagedInterval(() => {
      fetchAllBalances(true); // Force refresh on auto-refresh
      updateGasPrices();
    }, 30000); // Increased to 30 seconds for better performance
  }
}

async function addCustomToken(tokenAddress, tokenId = null) {
  // Custom tokens only supported on mainnet
  if (isBaseMode) {
    showToast("Custom tokens not supported on Base network");
    return null;
  }
  
  if (!zWalletContract) return null;

  try {
    // Validate address
    if (!ethers.isAddress(tokenAddress)) {
      throw new Error("Invalid address");
    }

    // First check token type using cached contract type check
    const contractType = await getCachedContractType(tokenAddress);
    
    // Use batchView to get token kind and balance
    const [, , , kinds] = await zWalletContract.batchView(
      wallet.address,
      [tokenAddress],
      [tokenId ? BigInt(tokenId) : 0]
    );
    
    const tokenKind = kinds[0];
    
    // Get metadata using cached function
    let { name, symbol, decimals } = await getCachedMetadata(tokenAddress);
    
    // For ERC6909, metadata might not be available
    if ((tokenKind === 69 || tokenId || contractType.isERC6909) && !symbol) {
      name = name || '';
      symbol = symbol || '';
      decimals = decimals || 18;
    } else if (!symbol) {
      // For ERC20, metadata is required
      throw new Error("Could not fetch token metadata");
    }
    
    // For non-ERC6909, symbol is required
    if (!tokenId && tokenKind !== 69 && (!symbol || symbol === "")) {
      throw new Error("Could not fetch token metadata");
    }

    let token;

    if (tokenKind === 69 || tokenId) { // ERC6909
      if (!tokenId) {
        throw new Error("This is an ERC6909 contract - please provide a token ID");
      }
      
      // Create unique symbol for this ID
      const idSymbol = symbol ? `${symbol.toUpperCase()}_${tokenId}` : `ID_${tokenId}`;
      
      token = {
        address: tokenAddress,
        symbol: idSymbol,
        name: name ? `${name} ID ${tokenId}` : `Token ID ${tokenId}`,
        decimals: decimals || 18,
        isERC6909: true,
        id: tokenId,
      };
    } else if (tokenKind === 72) { // ERC721
      throw new Error("ERC721 (NFT) tokens are not supported in the wallet interface");
    } else { // ERC20
      token = {
        address: tokenAddress,
        symbol: symbol.toUpperCase(),
        name: name || symbol,
        decimals: decimals,
      };
    }

    // Check if already exists
    if (TOKENS[token.symbol]) {
      throw new Error("Token already exists");
    }
    
    // Try to fetch price for the new token
    if (!token.isERC6909) {
      const price = await fetchTokenPrice(tokenAddress);
      if (price.usd > 0) {
        // Store price in the token prices cache for immediate display
        tokenPrices[token.symbol] = price;
      }
    }

    return token;
  } catch (err) {
    throw err;
  }
}

/**
 * Simulates a transaction to check if it would succeed
 * @param {object} txParams - Transaction parameters
 * @returns {object} Simulation result with success status and gas estimate
 */
async function simulateTransaction(txParams) {
  try {
    // Validate required parameters
    if (!txParams.to && (!txParams.data || txParams.data === '0x')) {
      return {
        success: false,
        error: 'Invalid transaction: missing recipient',
        gasEstimate: BigInt(txParams.gasLimit || 300000)
      };
    }
    
    // First try eth_call for state-changing simulation (for better error messages)
    try {
      await provider.call({
        from: txParams.from || wallet.address,
        to: txParams.to,
        data: txParams.data || '0x',
        value: txParams.value || 0,
        gasLimit: txParams.gasLimit || 300000
      });
    } catch (callError) {
      // eth_call failed but we continue to gas estimation
      // Some calls fail in eth_call but work in actual transaction
      // We'll use the error info if gas estimation also fails
    }
    
    // Estimate gas for accurate costs
    const gasEstimate = await provider.estimateGas({
      from: txParams.from || wallet.address,
      to: txParams.to,
      data: txParams.data || '0x',
      value: txParams.value || 0
    });
    
    return {
      success: true,
      gasEstimate: gasEstimate,
      result: true
    };
  } catch (error) {
    // Gas estimation failed - transaction will likely fail
    let reason = 'Transaction would fail';
    
    if (error.message) {
      // Parse specific error types
      if (error.message.includes('insufficient funds for gas * price + value')) {
        reason = 'Insufficient ETH balance for transaction + gas';
      } else if (error.message.includes('insufficient funds')) {
        reason = 'Insufficient funds';
      } else if (error.message.includes('gas required exceeds allowance')) {
        reason = 'Gas limit too low';
      } else if (error.message.includes('nonce')) {
        reason = 'Nonce error - please try again';
      } else if (error.message.includes('replacement transaction underpriced')) {
        reason = 'Gas price too low for replacement';
      } else if (error.message.includes('execution reverted')) {
        // Try to extract revert reason
        const revertMatch = error.message.match(/reason="([^"]+)"/);
        if (revertMatch) {
          reason = revertMatch[1];
        } else if (error.message.includes('ERC20')) {
          reason = 'Token transfer would fail';
        } else {
          reason = 'Transaction would revert';
        }
      } else if (error.message.includes('invalid opcode')) {
        reason = 'Contract error: invalid operation';
      } else if (error.message.includes('out of gas')) {
        reason = 'Transaction would run out of gas';
      }
    }
    
    return {
      success: false,
      error: reason,
      gasEstimate: BigInt(txParams.gasLimit || 300000)
    };
  }
}

async function sendTransaction() {
  const toInput = sanitizeInput(document.getElementById("toAddress").value);
  const amountInput = sanitizeInput(document.getElementById("amount").value);
  const status = document.getElementById("txStatus");

  if (!toInput || !amountInput || !wallet) {
    status.innerHTML = '<div class="status error">Fill all fields</div>';
    return;
  }
  
  // Base network supports ETH and ERC20 tokens
  // No special restriction needed here since we now have the backend contract

  // Check transaction rate limiting
  const now = Date.now();
  if (now - lastTransactionTime < CONSTANTS.MIN_TX_INTERVAL) {
    status.innerHTML = '<div class="status error">Please wait before sending another transaction</div>';
    return;
  }

  // Check pending transaction limit
  if (pendingTransactionCount >= MAX_PENDING_TRANSACTIONS) {
    status.innerHTML = '<div class="status error">Too many pending transactions. Please wait.</div>';
    return;
  }

  // Ensure wallet is connected to provider
  if (!wallet.provider) {
    wallet = wallet.connect(provider);
  }

  // Validate recipient address
  let toAddress = toInput;
  let addressValidation;
  
  if (toInput.endsWith(".eth")) {
    // Validate ENS name first
    const ensValidation = InputValidator.validateENS(toInput);
    if (!ensValidation.valid) {
      status.innerHTML = `<div class="status error">${ensValidation.error}</div>`;
      return;
    }
    
    const nameType = toInput.endsWith('.base.eth') ? 'Base name' : 'ENS';
    status.innerHTML = `<div class="status">Resolving ${nameType}...</div>`;
    toAddress = await resolveENS(toInput);
    if (!toAddress) {
      status.innerHTML = `<div class="status error">${nameType} not found</div>`;
      return;
    }
    
    // Validate resolved address
    addressValidation = InputValidator.validateAddress(toAddress);
  } else {
    // Direct address validation
    addressValidation = InputValidator.validateAddress(toInput);
    if (addressValidation.valid) {
      toAddress = addressValidation.address; // Use checksummed address
    }
  }
  
  if (!addressValidation || !addressValidation.valid) {
    status.innerHTML = `<div class="status error">${addressValidation?.error || 'Invalid address'}</div>`;
    return;
  }
  
  // Validate amount
  const token = TOKENS[selectedToken];
  const balance = currentBalances[selectedToken];
  const amountValidation = InputValidator.validateAmount(
    amountInput,
    token?.decimals || 18,
    balance?.formatted
  );
  
  if (!amountValidation.valid) {
    status.innerHTML = `<div class="status error">${amountValidation.error}</div>`;
    return;
  }
  
  const amount = amountValidation.formatted;

  // Calculate values for confirmation
  const gasSettings = gasPrices[selectedGasSpeed] || gasPrices.normal;
  const ethPrice = tokenPrices.ETH?.usd || 0;
  // More accurate gas limits
  let gasLimit =
    selectedToken === "ETH" ? 21000n : token.isERC6909 ? 120000n : 65000n;
  const gasPrice = gasSettings.maxFeePerGas || 20000000000n;
  let gasCost = gasLimit * gasPrice;
  let gasCostEth = ethers.formatEther(gasCost);
  let gasCostUsd = parseFloat(gasCostEth) * ethPrice;

  const tokenPrice = tokenPrices[selectedToken] || { eth: 0, usd: 0 };
  let amountUsd = parseFloat(amount) * tokenPrice.usd;
  let totalUsd = amountUsd + gasCostUsd;

  // Balance already checked in validation above
  // Double-check ETH balance for gas
  if (!balance || parseFloat(balance.formatted) < parseFloat(amount)) {
    status.innerHTML = '<div class="status error">Insufficient balance</div>';
    return;
  }

  // Check ETH balance for gas (use cached balance)
  const ethBalanceObj = currentBalances["ETH"];
  let ethBalance;
  if (ethBalanceObj) {
    ethBalance = ethBalanceObj.raw;
  } else {
    // Use zWallet's unified balance function
    const [rawBalance] = await zWalletContract.getBalanceOf(
      wallet.address,
      ethers.ZeroAddress,
      0
    );
    ethBalance = rawBalance;
  }
  if (ethBalance < gasCost) {
    status.innerHTML =
      '<div class="status error">Insufficient ETH for gas</div>';
    return;
  }

  // Prepare transaction parameters for simulation
  status.innerHTML = '<div class="status">🔍 Simulating transaction...</div>';
  
  let txParams = {
    from: wallet.address,
    to: toAddress,
    gasLimit: gasLimit
  };

  // Build transaction based on token type
  if (selectedToken === "ETH") {
    txParams.value = ethers.parseEther(amount);
  } else if (token.isERC6909) {
    const amountWei = ethers.parseUnits(amount, token.decimals || 18);
    const transferData = await zWalletContract.getERC6909Transfer(
      toAddress,
      BigInt(token.id),
      amountWei
    );
    txParams.to = token.address;
    txParams.data = transferData;
  } else {
    const amountWei = ethers.parseUnits(amount, token.decimals || 18);
    const transferData = await zWalletContract.getERC20Transfer(
      toAddress,
      amountWei
    );
    txParams.to = token.address;
    txParams.data = transferData;
  }

  // Simulate the transaction
  const simulation = await simulateTransaction(txParams);
  
  if (!simulation.success) {
    status.innerHTML = `<div class="status error">Transaction would fail: ${simulation.error}</div>`;
    return;
  }

  // Update gas estimate if simulation provided better estimate
  if (simulation.gasEstimate) {
    const simulatedGasLimit = BigInt(simulation.gasEstimate.toString());
    // Add 20% buffer to gas estimate for safety
    const bufferedGasLimit = (simulatedGasLimit * 120n) / 100n;
    if (bufferedGasLimit > gasLimit) {
      // Update gas cost calculations with new estimate
      const newGasCost = bufferedGasLimit * gasPrice;
      
      // Check if user still has enough ETH for new gas estimate
      if (ethBalance < newGasCost) {
        const newGasCostEth = ethers.formatEther(newGasCost);
        status.innerHTML = `<div class="status error">Insufficient ETH for gas (need ${parseFloat(newGasCostEth).toFixed(5)} ETH)</div>`;
        return;
      }
      
      // Update gas variables for display
      gasLimit = bufferedGasLimit;
      gasCost = newGasCost;
      gasCostEth = ethers.formatEther(newGasCost);
      gasCostUsd = parseFloat(gasCostEth) * ethPrice;
      totalUsd = amountUsd + gasCostUsd;
    }
  }

  status.innerHTML = '<div class="status success">✅ Ready to send</div>';

  // Populate confirmation modal
  document.getElementById("confirmToken").textContent = selectedToken;
  document.getElementById(
    "confirmAmount"
  ).textContent = `${amount} ${selectedToken}`;
  document.getElementById("confirmTo").textContent = toInput.endsWith(".eth")
    ? `${toInput} (${toAddress.slice(0, 6)}...${toAddress.slice(-4)})`
    : `${toAddress.slice(0, 6)}...${toAddress.slice(-4)}`;
  document.getElementById(
    "confirmValueUSD"
  ).textContent = `$${amountUsd.toFixed(2)}`;
  document.getElementById("confirmGas").textContent = `Ξ${parseFloat(
    gasCostEth
  ).toFixed(5)} ($${gasCostUsd.toFixed(2)})`;
  document.getElementById("confirmTotal").textContent = `$${totalUsd.toFixed(
    2
  )}`;

  // Prepare transaction calldata using zWallet helpers
  let calldata = '0x';
  if (selectedToken === 'ETH') {
    // ETH transfers have no calldata
    calldata = '0x';
  } else {
    const token = TOKENS[selectedToken];
    const amountWei = ethers.parseUnits(amount.toString(), token.decimals);
    
    if (token.isERC6909) {
      // Use zWallet helper for ERC6909 transfer
      calldata = await zWalletContract.getERC6909Transfer(
        toAddress,
        BigInt(token.id),
        amountWei
      );
    } else {
      // Use zWallet helper for ERC20 transfer
      calldata = await zWalletContract.getERC20Transfer(
        toAddress,
        amountWei
      );
    }
  }

  // Setup calldata display
  const calldataDisplay = document.getElementById('sendCalldataDisplay');
  const swissKnifeLink = document.getElementById('sendSwissKnifeLink');
  const toggleBtn = document.getElementById('toggleSendCalldata');
  const calldataSection = document.getElementById('sendCalldataSection');
  
  if (calldataDisplay) {
    calldataDisplay.value = calldata;
  }
  
  // Setup Swiss Knife decoder link with correct format
  if (swissKnifeLink) {
    if (calldata !== '0x' && calldata.length > 2) {
      // Use the correct decoder URL format for all cases
      const simulationUrl = `https://calldata.swiss-knife.xyz/decoder?calldata=${calldata}`;
      
      // Set both href and onclick for maximum compatibility
      swissKnifeLink.href = simulationUrl;
      swissKnifeLink.target = '_blank';
      swissKnifeLink.style.display = 'inline-block';
      
      // Override click behavior for extension compatibility
      swissKnifeLink.onclick = (e) => {
        e.preventDefault();
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ action: 'open_external', url: simulationUrl });
        } else {
          window.open(simulationUrl, '_blank', 'noopener,noreferrer');
        }
      };
    } else {
      swissKnifeLink.style.display = 'none';
    }
  }
  
  if (toggleBtn && calldataSection) {
    // Reset state
    calldataSection.classList.add('hidden');
    toggleBtn.textContent = 'Show';
    
    // Add click handler (remove old one first to avoid duplicates)
    const newToggleBtn = toggleBtn.cloneNode(true);
    toggleBtn.parentNode.replaceChild(newToggleBtn, toggleBtn);
    
    newToggleBtn.onclick = () => {
      const isHidden = calldataSection.classList.contains('hidden');
      calldataSection.classList.toggle('hidden');
      newToggleBtn.textContent = isHidden ? 'Hide' : 'Show';
    };
  }

  // Show modal
  const modal = document.getElementById("txConfirmModal");
  modal.classList.remove("hidden");

  // Use the secure confirmation helper
  const confirmBtn = document.getElementById("confirmSend");
  const cancelBtn = document.getElementById("cancelSend");
  const closeBtn = document.getElementById("modalClose");
  
  const userConfirmed = await createSecureConfirmation(confirmBtn, cancelBtn, closeBtn);
  
  // Hide modal after decision
  modal.classList.add("hidden");

  if (!userConfirmed) {
    status.innerHTML = '<div class="status">Transaction cancelled</div>';
    return;
  }

  try {
    status.innerHTML = '<div class="status">Preparing transaction...</div>';
    document.getElementById("sendBtn").disabled = true;
    
    // Update rate limiting tracking
    lastTransactionTime = Date.now();
    pendingTransactionCount++;

    try {
      // Get the current nonce to prevent replay attacks
      const nonce = await wallet.getNonce();
    
    let tx;
    if (selectedToken === "ETH") {
      // Send ETH directly - estimate gas dynamically
      let gasLimit = 21000n;
      try {
        const estimated = await provider.estimateGas({
          from: wallet.address,
          to: toAddress,
          value: ethers.parseEther(amount)
        });
        if (estimated) {
          gasLimit = (estimated * 110n) / 100n; // 10% buffer
        }
      } catch (e) {
        // Use default gas limit if estimation fails
        console.warn('Gas estimation failed, using default:', e);
      }
      
      tx = await wallet.sendTransaction({
        to: toAddress,
        value: ethers.parseEther(amount),
        gasLimit: gasLimit,
        maxFeePerGas: gasSettings.maxFeePerGas,
        maxPriorityFeePerGas: gasSettings.maxPriorityFeePerGas,
        nonce: nonce,
      });
    } else if (token.isERC6909) {
      // For ERC6909 tokens
      const amountWei = ethers.parseUnits(amount, token.decimals || 18);

      // Get the transfer calldata from zWallet
      const transferData = await zWalletContract.getERC6909Transfer(
        toAddress,
        BigInt(token.id),
        amountWei
      );

      // Send to the TOKEN contract with the calldata
      let gasLimit = 120000n;
      try {
        const estimated = await provider.estimateGas({
          from: wallet.address,
          to: token.address,
          data: transferData
        });
        if (estimated) {
          gasLimit = (estimated * 115n) / 100n; // 15% buffer for ERC6909
        }
      } catch (e) {
        // Use default gas limit if estimation fails
        console.warn('Gas estimation failed for ERC6909, using default:', e);
      }
      
      tx = await wallet.sendTransaction({
        to: token.address,
        data: transferData,
        gasLimit: gasLimit,
        maxFeePerGas: gasSettings.maxFeePerGas,
        maxPriorityFeePerGas: gasSettings.maxPriorityFeePerGas,
        nonce: nonce,
      });
    } else {
      // For ERC20 tokens
      const amountWei = ethers.parseUnits(amount, token.decimals || 18);

      // Get the transfer calldata from zWallet
      const transferData = await zWalletContract.getERC20Transfer(
        toAddress,
        amountWei
      );

      // Send to the TOKEN contract with the calldata
      let gasLimit = 65000n;
      try {
        const estimated = await provider.estimateGas({
          from: wallet.address,
          to: token.address,
          data: transferData
        });
        if (estimated) {
          gasLimit = (estimated * 110n) / 100n; // 10% buffer for ERC20
        }
      } catch (e) {
        // Use default gas limit if estimation fails
        console.warn('Gas estimation failed for ERC20, using default:', e);
      }
      
      tx = await wallet.sendTransaction({
        to: token.address,
        data: transferData,
        gasLimit: gasLimit,
        maxFeePerGas: gasSettings.maxFeePerGas,
        maxPriorityFeePerGas: gasSettings.maxPriorityFeePerGas,
        nonce: nonce,
      });
    }

    status.innerHTML = `<div class="status">TX sent: ${tx.hash.slice(
      0,
      10
    )}...</div>`;
    showToast("Transaction sent! Waiting for confirmation...");

    const receipt = await tx.wait();
    
    // Decrement pending transaction count
    pendingTransactionCount = Math.max(0, pendingTransactionCount - 1);
    
    if (receipt.status === 1) {
      status.innerHTML = '<div class="status success">✓ Success!</div>';
      showEtherscanLink(tx.hash);
      
      // Only show transaction confirmed message for regular transfers
      // IOUSDC messages are handled in the createIOUSlip function
      showToast("Transaction confirmed!");
      
      await fetchAllBalances();
      document.getElementById("toAddress").value = "";
      document.getElementById("amount").value = "";
    } else {
      status.innerHTML = '<div class="status error">Transaction Failed</div>';
      showEtherscanLink(tx.hash);
    }
    } finally {
      // Always decrement pending transaction count
      pendingTransactionCount = Math.max(0, pendingTransactionCount - 1);
    }
  } catch (err) {
    // Log error securely without exposing sensitive info
    let errorMsg = "Transaction failed";

    if (err.message.includes("insufficient funds")) {
      errorMsg = "Insufficient funds for gas";
    } else if (err.message.includes("user rejected")) {
      errorMsg = "Transaction rejected";
    } else if (err.message.includes("nonce")) {
      errorMsg = "Nonce error - try again";
    } else if (err.code === "UNKNOWN_ERROR" || err.code === -32603) {
      errorMsg = "Network error - check balance and try again";
    }

    status.innerHTML = `<div class="status error">${errorMsg}</div>`;
  } finally {
    document.getElementById("sendBtn").disabled = false;
  }
}

// IOU Functions for USDC EIP-3009
async function createIOUSlip() {
  const toInput = sanitizeInput(document.getElementById("toAddress").value);
  const amountInput = sanitizeInput(document.getElementById("amount").value);
  const status = document.getElementById("txStatus");

  if (!toInput || !amountInput || !wallet) {
    status.innerHTML = '<div class="status error">Fill all fields</div>';
    return;
  }
  
  // Validate amount for USDC (6 decimals)
  const amountValidation = InputValidator.validateAmount(amountInput, 6);
  if (!amountValidation.valid) {
    status.innerHTML = `<div class="status error">${amountValidation.error}</div>`;
    return;
  }
  
  const amount = amountValidation.formatted;

  try {
    // Validate and resolve address
    let toAddress = toInput;
    let addressValidation;
    
    if (toInput.endsWith(".eth")) {
      // Validate ENS name
      const ensValidation = InputValidator.validateENS(toInput);
      if (!ensValidation.valid) {
        status.innerHTML = `<div class="status error">${ensValidation.error}</div>`;
        return;
      }
      
      const nameType = toInput.endsWith('.base.eth') ? 'Base name' : 'ENS';
      toAddress = await resolveENS(toInput);
      if (!toAddress) {
        status.innerHTML = `<div class="status error">${nameType} not found</div>`;
        return;
      }
      
      addressValidation = InputValidator.validateAddress(toAddress);
    } else {
      addressValidation = InputValidator.validateAddress(toInput);
      if (addressValidation.valid) {
        toAddress = addressValidation.address; // Use checksummed address
      }
    }
    
    if (!addressValidation || !addressValidation.valid) {
      status.innerHTML = `<div class="status error">${addressValidation?.error || 'Invalid address'}</div>`;
      return;
    }

    // Prepare IOU data
    const value = ethers.parseUnits(amount, 6); // USDC has 6 decimals
    const validAfter = 0; // Can be used immediately
    const validDays = 30; // Valid for 30 days by default
    const now = Math.floor(Date.now() / 1000);
    const validBefore = now + (validDays * 86400);
    const nonce = ethers.hexlify(ethers.randomBytes(32));

    // Update modal with preview
    document.getElementById("iouFrom").textContent = `${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}`;
    document.getElementById("iouTo").textContent = toInput.endsWith(".eth") 
      ? `${toInput} (${toAddress.slice(0, 6)}...${toAddress.slice(-4)})`
      : `${toAddress.slice(0, 6)}...${toAddress.slice(-4)}`;
    const networkLabel = isBaseMode ? ' (Base)' : ' (Ethereum)';
    document.getElementById("iouAmount").textContent = `${amount} USDC${networkLabel}`;
    document.getElementById("iouExpiry").textContent = new Date(validBefore * 1000).toLocaleString();

    // Prepare EIP-712 message
    const message = {
      from: wallet.address,
      to: toAddress,
      value: value.toString(),
      validAfter: String(validAfter),
      validBefore: String(validBefore),
      nonce: nonce
    };

    // Store message for signing
    pendingIouMessage = message;
    pendingIouAmount = amount;

    // Show preview in modal
    const iouData = {
      type: "transfer",
      from: wallet.address,
      to: toAddress,
      value: value.toString(),
      amount: amount,
      validAfter: validAfter,
      validBefore: validBefore,
      nonce: nonce,
      created: new Date().toISOString(),
      chainId: isBaseMode ? 8453 : 1,
      network: isBaseMode ? 'Base' : 'Ethereum'
    };

    document.getElementById("iouDataDisplay").value = JSON.stringify(iouData, null, 2);

    // Show modal
    document.getElementById("iouPreviewModal").classList.remove("hidden");

  } catch (err) {
    
    status.innerHTML = '<div class="status error">Failed to create IOU</div>';
  }
}

async function signAndDownloadIOU() {
  try {
    if (!pendingIouMessage || !wallet) {
      throw new Error("No IOU message to sign");
    }

    const status = document.getElementById("txStatus");
    status.innerHTML = '<div class="status">Signing IOU...</div>';

    // Sign EIP-712 message - use correct domain based on network
    const types = { TransferWithAuthorization: EIP3009_TYPES.TransferWithAuthorization };
    const domain = isBaseMode ? USDC_EIP712_DOMAIN_BASE : USDC_EIP712_DOMAIN_MAINNET;
    const signature = await wallet.signTypedData(domain, types, pendingIouMessage);
    
    // Extract v, r, s from signature - manual extraction for compatibility
    // ethers v6 splitSignature may not work the same as v5 that IOUSDC.html uses
    const sig = signature.startsWith('0x') ? signature.slice(2) : signature;
    if (sig.length !== 130) {
      throw new Error('Invalid signature length');
    }
    
    const r = '0x' + sig.slice(0, 64);  // First 32 bytes
    const s = '0x' + sig.slice(64, 128); // Next 32 bytes  
    let v = parseInt(sig.slice(128, 130), 16); // Last byte
    
    // Normalize v to 27/28 if it's 0/1
    if (v === 0 || v === 1) {
      v += 27;
    }

    // Create complete IOU slip
    const iouSlip = {
      type: "transfer",
      from: pendingIouMessage.from,
      to: pendingIouMessage.to,
      value: pendingIouMessage.value,
      validAfter: Number(pendingIouMessage.validAfter),
      validBefore: Number(pendingIouMessage.validBefore),
      nonce: pendingIouMessage.nonce,
      v: v,
      r: r,
      s: s,
      amount: pendingIouAmount,
      signature: signature,
      created: new Date().toISOString(),
      chainId: isBaseMode ? 8453 : 1,
      network: isBaseMode ? 'Base' : 'Ethereum'
    };

    // Download as JSON file
    const blob = new Blob([JSON.stringify(iouSlip, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const networkPrefix = isBaseMode ? 'base' : 'mainnet';
    a.download = `usdc-iou-${networkPrefix}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);

    // Update display
    document.getElementById("iouDataDisplay").value = JSON.stringify(iouSlip, null, 2);
    
    status.innerHTML = '';
    const successDiv = document.createElement('div');
    successDiv.className = 'status success';
    successDiv.textContent = 'IOU signed and downloaded!';
    status.appendChild(successDiv);
    
    const infoDiv = document.createElement('div');
    infoDiv.style.cssText = 'margin-top: 8px; font-size: 12px;';
    infoDiv.textContent = '📄 Recipient can redeem this IOU at ';
    
    const iouLink = createExternalLink(
      'https://iousdc.eth.limo/',
      'IOUSDC.eth',
      'color: var(--accent); text-decoration: underline;'
    );
    infoDiv.appendChild(iouLink);
    status.appendChild(infoDiv);
    showToast("IOU created! Recipient can check on IOUSDC.eth");

    // Clear form
    document.getElementById("toAddress").value = "";
    document.getElementById("amount").value = "";

    // Clean up
    pendingIouMessage = null;
    pendingIouAmount = null;

  } catch (err) {
    
    let errorMsg = "Failed to sign IOU";
    
    if (err.message.includes("user rejected") || err.message.includes("denied")) {
      errorMsg = "Signature rejected";
    }
    
    document.getElementById("txStatus").innerHTML = `<div class="status error">${errorMsg}</div>`;
  }
}

// Define handleTabClick outside setupEventListeners for proper scope
function handleTabClick(tab) {
  // Handle tab click
  
  // Remove active from all tabs and contents
  document.querySelectorAll(".tab").forEach((t) => {
    t.classList.remove("active");
  });
  document.querySelectorAll(".tab-content").forEach((c) => {
    c.classList.remove("active");
  });

  // Add active to clicked tab
  tab.classList.add("active");
  
  // Find and activate tab content
  const tabContentId = tab.dataset.tab + "-tab";
  const tabContent = document.getElementById(tabContentId);
  // Find tab content
  
  if (tabContent) {
    tabContent.classList.add("active");
    // Activate tab
    
    // Tab activated
  } else {
    // Tab content missing
  }
  
  // Load transactions when tab is opened
  if (tab.dataset.tab === "txs" && wallet && txHistory.length === 0) {
    fetchTransactionHistory();
  }
}

function setupEventListeners() {
  // Setup event listeners
  
  // Theme toggle
  const themeToggle = document.getElementById("themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", toggleTheme);
  } else {
    // Theme toggle not found
  }
  
  // Base network toggle in header
  const baseNetworkToggle = document.getElementById("baseNetworkToggle");
  if (baseNetworkToggle) {
    baseNetworkToggle.addEventListener("click", async () => {
      await toggleNetwork();
    });
  }

  // Tabs - simplified with just one event listener
  const allTabs = document.querySelectorAll(".tab");
  // Setup tabs
  
  allTabs.forEach((tab) => {
    // Configure tab
    
    // Use only addEventListener, not both onclick and addEventListener
    tab.addEventListener("click", async (e) => {
      // Tab selected
      e.preventDefault();
      e.stopPropagation();
      handleTabClick(tab);
      
      // Update 7702 status when switching to settings tab
      if (tab.dataset.tab === 'settings' && wallet) {
        await update7702Status();
      }
      
      // Ensure balances are loaded when switching to swap tab
      if (tab.dataset.tab === 'swap' && wallet) {
        // Always call updateSwapBalances - it will fetch if needed
        await updateSwapBalances();
      }
      
      // Ensure balances are loaded when switching to bridge tab
      if (tab.dataset.tab === 'bridge' && wallet) {
        // Always call updateBridgeBalance - it will fetch if needed
        await updateBridgeBalance();
      }
    });
  });

  // Transaction history button
  const loadTxBtn = document.getElementById("loadTxBtn");
  if (loadTxBtn) {
    loadTxBtn.addEventListener("click", () => {
      fetchTransactionHistory();
    });
  }

  // Load more transactions button  
  const loadMoreBtn = document.getElementById("loadMoreTxBtn");
  if (loadMoreBtn) {
    loadMoreBtn.addEventListener("click", async () => {
      try {
        await fetchTransactionHistoryExtended();
      } catch (err) {
        
        showToast("Failed to load transactions");
      }
    });
  }

  // Wallet management
  document
    .getElementById("walletSelector")
    .addEventListener("change", async (e) => {
      const addr = e.target.value;
      if (!addr) return;
      
      // Check if we're already unlocked with this wallet
      if (wallet && wallet.address.toLowerCase() === addr.toLowerCase()) {
        // Already using this wallet, no need to unlock again
        return;
      }
      
      // Clean up resources from previous wallet before switching
      cleanupForWalletSwitch();
      
      const list = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
      const entry = list.find((w) => w.address.toLowerCase() === addr.toLowerCase());
      
      if (!entry) {
        showError('Wallet not found');
        e.target.value = "";
        return;
      }
      
      // For multi-wallet, ask for password to unlock the specific wallet
      try {
        const pass = await securePasswordPrompt('Switch Wallet', `Enter password for ${addr.slice(0,6)}...${addr.slice(-4)}:`, false, `wallet_${addr}`);
        const pk = await decryptPK(
          entry.crypto,
          pass,
          entry.address.toLowerCase()
        );

        // Rewrap legacy keystores that were saved without AAD
        if (!entry.crypto.aad) {
          try {
            const newPayload = await encryptPK(pk, pass, {
              aad: entry.address.toLowerCase(),
            });
            entry.crypto = newPayload;
            const listNow = JSON.parse(
              localStorage.getItem(LS_WALLETS) || "[]"
            ).map((w) =>
              w.address.toLowerCase() === entry.address.toLowerCase()
                ? entry
                : w
            );
            localStorage.setItem(LS_WALLETS, JSON.stringify(listNow));
          } catch (e) {
            // Keystore rewrap failed - will use existing
          }
        }

        wallet = new ethers.Wallet(pk, provider);
        await displayWallet();

        localStorage.setItem(LS_LAST, addr);
        showToast("Switched to " + (entry.label || `${addr.slice(0,6)}...${addr.slice(-4)}`));
      } catch (err) {
        showError('Wrong password');
        // Reset selector to previous value if available
        if (wallet) {
          e.target.value = wallet.address;
        } else {
          e.target.value = "";
        }
      }
    });

  const deleteWalletBtn = document.getElementById("deleteWalletBtn");
  if (deleteWalletBtn) {
    deleteWalletBtn.addEventListener("click", async () => {
      const selector = document.getElementById("walletSelector");
      const address = selector.value;

      if (address && await securePasswordPrompt('Delete Wallet', 'Confirm wallet deletion:')) {
        deleteWallet(address);
        showToast("Wallet deleted");
      }
    });
  }

  const generateBtn = document.getElementById("generateBtn");
  if (generateBtn) {
    generateBtn.addEventListener("click", async () => {
      try {
        wallet = ethers.Wallet.createRandom().connect(provider);
        const saved = await saveWallet(wallet.address, wallet.privateKey);
        if (!saved) {
          // User cancelled password prompt
          wallet = null;
          return;
        }
        await displayWallet();
        showToast("Wallet generated!");
      } catch (err) {
        
        showError(err, 'Wallet generation');
      }
    });
  }

  const importBtn = document.getElementById("importBtn");
  if (importBtn) {
    importBtn.addEventListener("click", () => {
      document.getElementById("importSection").classList.toggle("hidden");
      document.getElementById("privateKeyInput").focus();
    });
  }

  document
    .getElementById("confirmImportBtn")
    .addEventListener("click", async () => {
      const keyInput = sanitizeInput(document.getElementById("privateKeyInput").value);
      if (!keyInput) {
        showToast("Please enter a private key", 3000, 'error');
        return;
      }

      try {
        // Validate private key using InputValidator
        const keyValidation = InputValidator.validatePrivateKey(keyInput);
        if (!keyValidation.valid) {
          showError(new Error(keyValidation.error), 'Private key import');
          return;
        }
        
        // Create wallet with validated key
        wallet = new ethers.Wallet(keyValidation.key, provider);
        
        // Double-check the wallet was created successfully
        if (!wallet.address) {
          throw new Error("Failed to create wallet");
        }
        
        // Check if this address already exists
        const existing = savedWallets.find(w => 
          w.address.toLowerCase() === wallet.address.toLowerCase()
        );
        if (existing) {
          showError(new Error("This wallet is already imported"), 'Private key import');
          return;
        }
        
        const saved = await saveWallet(wallet.address, wallet.privateKey);
        if (!saved) {
          // User cancelled password prompt - don't show error, just return
          return;
        }
        
        await displayWallet();
        
        // Clear sensitive data immediately
        document.getElementById("privateKeyInput").value = "";
        document.getElementById("importSection").classList.add("hidden");
        
        showToast("Wallet imported successfully!");
      } catch (err) {
        // Clear sensitive data on error too
        document.getElementById("privateKeyInput").value = "";
        showError(err, 'Private key import');
      }
    });

  const cancelImportBtn = document.getElementById("cancelImportBtn");
  if (cancelImportBtn) {
    cancelImportBtn.addEventListener("click", () => {
      document.getElementById("importSection").classList.add("hidden");
      document.getElementById("privateKeyInput").value = "";
    });
  }

  // Copy buttons
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!wallet) return;
      const type = btn.dataset.copy;
      if (type === "privateKey") {
        const confirmReveal = await securePasswordPrompt('Security Check', 'Enter password to reveal private key:');
        if (!confirmReveal) return;
      }
      await copyToClipboard(
        type === "address" ? wallet.address : wallet.privateKey,
        type
      );
    });
  });

  // Download key button removed - moved to Settings tab

  const refreshBtn = document.getElementById("refreshBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      try {
        await fetchAllBalances();
        showToast("Refreshed!");
      } catch (err) {
        
        showToast("Failed to refresh");
      }
    });
  }

  // Add token functionality
  const addTokenBtn = document.getElementById("addTokenBtn");
  if (addTokenBtn) {
    addTokenBtn.addEventListener("click", () => {
      document.getElementById("addTokenSection").classList.toggle("hidden");
      document.getElementById("newTokenAddress").focus();
    });
  }

  // Live detection of token type
  document.getElementById("newTokenAddress")?.addEventListener("input", async (e) => {
    const addressInput = sanitizeInput(e.target.value);
    const indicator = document.getElementById("tokenTypeIndicator");
    
    if (!addressInput) {
      indicator.classList.add("hidden");
      return;
    }
    
    // Validate address format
    const addressValidation = InputValidator.validateAddress(addressInput);
    if (!addressValidation.valid) {
      indicator.textContent = "✗ " + addressValidation.error;
      indicator.style.color = "var(--error)";
      indicator.classList.remove("hidden");
      return;
    }
    
    try {
      // Validate it's a contract
      const contractValidation = await InputValidator.validateTokenContract(
        addressValidation.address,
        provider
      );
      
      if (!contractValidation.valid) {
        indicator.textContent = "✗ " + contractValidation.error;
        indicator.style.color = "var(--error)";
        indicator.classList.remove("hidden");
        return;
      }
      
      // Check token type
      const isERC6909 = await zWalletContract.isERC6909(addressValidation.address);
      if (isERC6909) {
        indicator.textContent = "✓ ERC6909 detected - Token ID required";
        indicator.style.color = "var(--success)";
        document.getElementById("newTokenId").placeholder = "Token ID (required for ERC6909)";
      } else {
        indicator.textContent = "✓ ERC20 token detected";
        indicator.style.color = "var(--text-secondary)";
        document.getElementById("newTokenId").placeholder = "Token ID (for ERC6909, optional)";
      }
      indicator.classList.remove("hidden");
    } catch (err) {
      indicator.textContent = "✗ Failed to verify token contract";
      indicator.style.color = "var(--error)";
      indicator.classList.remove("hidden");
    }
  });

  document
    .getElementById("confirmAddToken")
    .addEventListener("click", async () => {
      const addressInput = sanitizeInput(document.getElementById("newTokenAddress").value);
      const tokenId = sanitizeInput(document.getElementById("newTokenId").value);
      const symbolOverride = sanitizeInput(document.getElementById("newTokenSymbol").value);

      if (!addressInput) {
        showToast("Please enter a token address", 3000, 'error');
        return;
      }
      
      // Validate address
      const addressValidation = InputValidator.validateAddress(addressInput);
      if (!addressValidation.valid) {
        showError(new Error(addressValidation.error), 'Token addition');
        return;
      }

      try {
        // Validate it's a contract
        const contractValidation = await InputValidator.validateTokenContract(
          addressValidation.address,
          provider
        );
        
        if (!contractValidation.valid) {
          showError(new Error(contractValidation.error), 'Token addition');
          return;
        }
        
        const token = await addCustomToken(addressValidation.address, tokenId);

        // Use override symbol if provided, or if default ID_ symbol was used
        if (symbolOverride || (token.isERC6909 && token.symbol.startsWith('ID_'))) {
          const baseSymbol = symbolOverride || 'TOKEN';
          // For ERC6909, append ID to symbol
          if (token.isERC6909) {
            token.symbol = `${baseSymbol.toUpperCase()}_${token.id}`;
            // Also update the name if it was a default
            if (token.name.startsWith('Token ID')) {
              token.name = `${baseSymbol} ID ${token.id}`;
            }
          } else {
            token.symbol = baseSymbol.toUpperCase();
          }
        }

        // Save the custom token
        saveCustomToken(token);

        // Hide the form
        document.getElementById("addTokenSection").classList.add("hidden");
        document.getElementById("newTokenAddress").value = "";
        document.getElementById("newTokenId").value = "";
        document.getElementById("newTokenSymbol").value = "";
        document.getElementById("tokenTypeIndicator").classList.add("hidden");

        // Invalidate cache and refresh balances to include new token
        balanceCache.data = null;
        balanceCache.timestamp = 0;
        await fetchAllBalances(true);
        
        // Refresh swap dropdowns to include new token
        if (typeof initializeTokenDropdowns === 'function') {
          await initializeTokenDropdowns();
        }
        
        showToast(`Added ${token.symbol}!`);
      } catch (err) {
        showError(err, 'Token addition');
      }
    });

  // Send functionality
  const maxBtn = document.getElementById("maxBtn");
  if (maxBtn) {
    maxBtn.addEventListener("click", async () => {
      try {
        const max = await calculateMaxAmount();
        document.getElementById("amount").value = parseFloat(max).toFixed(6);
        await updateEstimatedTotal();
      } catch (err) {
        
        showToast("Failed to calculate max");
      }
    });
  }

  // Debounced ENS resolution handler
  const handleAddressInput = debounce(async (value) => {
    const resolved = document.getElementById("resolvedAddress");
    if (!resolved) return;
    
    if (value.endsWith(".eth")) {
      resolved.textContent = "Resolving...";
      
      try {
        const address = await resolveENS(value);
        // Check if input hasn't changed
        if (document.getElementById("toAddress")?.value.trim() === value) {
          if (address) {
            resolved.textContent = `→ ${formatAddress(address)}`;
            resolved.style.color = "var(--success)";
          } else {
            resolved.textContent = "Not found";
            resolved.style.color = "var(--error)";
          }
        }
      } catch (err) {
        resolved.textContent = "Error resolving";
        resolved.style.color = "var(--error)";
      }
    } else {
      resolved.textContent = "";
    }
    
    updateEstimatedTotal();
  }, CONSTANTS.ENS_RESOLVE_DELAY);
  
  const toAddress = document.getElementById("toAddress");
  if (toAddress) {
    toAddress.addEventListener("input", (e) => {
      handleAddressInput(e.target.value.trim());
    });
  }

  // Debounced amount input handler
  const handleAmountInput = debounce(updateEstimatedTotal, 300);
  const amountInput = document.getElementById("amount");
  if (amountInput) {
    amountInput.addEventListener("input", handleAmountInput);
  }

  // Gas options
  document.querySelectorAll(".gas-option").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      document
        .querySelectorAll(".gas-option")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      selectedGasSpeed = btn.dataset.speed;

      const custom = document.getElementById("customGasSection");
      custom.classList.toggle("hidden", selectedGasSpeed !== "custom");

      updateEstimatedTotal();
    });
  });

  const customGasPrice = document.getElementById("customGasPrice");
  if (customGasPrice) {
    customGasPrice.addEventListener("input", async () => {
      if (selectedGasSpeed === "custom") {
        const max = document.getElementById("customGasPrice").value;
        const priority =
          document.getElementById("customPriorityFee").value || "1";

        if (max) {
          gasPrices.custom = {
            maxFeePerGas: ethers.parseUnits(max, "gwei"),
            maxPriorityFeePerGas: ethers.parseUnits(priority, "gwei"),
          };
          await updateEstimatedTotal();
        }
      }
    });
  }

  const sendBtn = document.getElementById("sendBtn");
  if (sendBtn) sendBtn.addEventListener("click", sendTransaction);
  
  // IOU Mode functionality
  document.getElementById("createIouBtn")?.addEventListener("click", createIOUSlip);
  
  document.getElementById("iouModeToggle")?.addEventListener("change", (e) => {
    const isIouMode = e.target.checked;
    const gasFeeSection = document.getElementById("gasFeeSection");
    const sendBtn = document.getElementById("sendBtn");
    const createIouBtn = document.getElementById("createIouBtn");
    const iouModeInfo = document.getElementById("iouModeInfo");
    
    if (isIouMode) {
      // Switch to IOU mode
      gasFeeSection.style.display = "none";
      sendBtn.classList.add("hidden");
      createIouBtn.classList.remove("hidden");
      iouModeInfo.style.display = "block";
      
      // Update gas display to show "Free!"
      const estimatedTotalEl = document.getElementById("estimatedTotal");
      if (estimatedTotalEl) {
        estimatedTotalEl.innerHTML = '<span style="color: var(--success);">🪽 Free! (Gasless)</span>';
      }
    } else {
      // Switch back to normal mode
      gasFeeSection.style.display = "block";
      sendBtn.classList.remove("hidden");
      createIouBtn.classList.add("hidden");
      iouModeInfo.style.display = "none";
      
      // Restore normal gas display
      updateEstimatedTotal();
    }
  });
  
  // IOU Modal event listeners
  document.getElementById("iouModalClose")?.addEventListener("click", () => {
    document.getElementById("iouPreviewModal").classList.add("hidden");
    // Clean up pending data
    pendingIouMessage = null;
    pendingIouAmount = null;
  });
  
  document.getElementById("confirmIouBtn")?.addEventListener("click", async () => {
    document.getElementById("iouPreviewModal").classList.add("hidden");
    await signAndDownloadIOU();
  });
  
  document.getElementById("cancelIouBtn")?.addEventListener("click", () => {
    document.getElementById("iouPreviewModal").classList.add("hidden");
    // Clean up pending data
    pendingIouMessage = null;
    pendingIouAmount = null;
  });
  
  document.getElementById("toggleIouData")?.addEventListener("click", (e) => {
    const section = document.getElementById("iouDataSection");
    if (section.classList.contains("hidden")) {
      section.classList.remove("hidden");
      e.target.textContent = "Hide";
    } else {
      section.classList.add("hidden");
      e.target.textContent = "Show";
    }
  });
  
  document.getElementById("copyIouData")?.addEventListener("click", async () => {
    const data = document.getElementById("iouDataDisplay").value;
    
    try {
      // Try modern Clipboard API first
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(data);
        showToast("IOU data copied! 📋");
      } else {
        // Fallback for non-secure contexts or older browsers
        const textarea = document.getElementById("iouDataDisplay");
        textarea.focus();
        textarea.select();
        
        // Create a temporary textarea for copying
        const tempTextarea = document.createElement("textarea");
        tempTextarea.value = data;
        tempTextarea.style.position = "fixed";
        tempTextarea.style.left = "-999999px";
        tempTextarea.style.top = "-999999px";
        document.body.appendChild(tempTextarea);
        tempTextarea.focus();
        tempTextarea.select();
        
        try {
          // Try using the Selection API instead of execCommand
          const range = document.createRange();
          range.selectNodeContents(tempTextarea);
          const selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
          
          // Try to write to clipboard using modern API
          const blob = new Blob([data], { type: 'text/plain' });
          const clipboardItem = new ClipboardItem({ 'text/plain': blob });
          await navigator.clipboard.write([clipboardItem]);
          showToast("IOU data copied! 📋");
        } catch (copyErr) {
          // If modern methods fail, show manual copy instruction
          showToast("Please copy manually (Ctrl+C / Cmd+C)", 3000, 'warning');
        } finally {
          document.body.removeChild(tempTextarea);
        }
      }
    } catch (err) {
      showToast("Please select and copy the IOU data manually");
    }
  });
  
  document.getElementById("downloadIou")?.addEventListener("click", () => {
    const data = document.getElementById("iouDataDisplay").value;
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const networkPrefix = isBaseMode ? 'base' : 'mainnet';
    a.download = `usdc-iou-${networkPrefix}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("IOU downloaded! 💾");
  });

  // Settings - Ethereum RPC
  document.querySelectorAll(".rpc-item:not(.base-rpc)").forEach((item) => {
    item.addEventListener("click", async () => {
      const rpc = item.dataset.rpc;

      if (rpc === "custom") {
        document.getElementById("customRpcSection").classList.toggle("hidden");
      } else {
        currentRpc = rpc;
        localStorage.setItem("rpc_endpoint", rpc);
        
        // Invalidate gas price cache on RPC switch
        gasPriceCache = { data: null, timestamp: 0, networkId: null };
        
        // Only reinit if on mainnet
        if (!isBaseMode) {
          await initProvider();

          if (wallet) {
            wallet = wallet.connect(provider);
            await fetchAllBalances();
          }
        }
      }
    });
  });
  
  // Settings - Base RPC
  document.querySelectorAll(".base-rpc").forEach((item) => {
    item.addEventListener("click", async () => {
      const baseRpc = item.dataset.baseRpc;
      
      if (baseRpc) {
        localStorage.setItem("base_rpc", baseRpc);
        
        // Invalidate gas price cache on RPC switch
        gasPriceCache = { data: null, timestamp: 0, networkId: null };
        
        // Only reinit if on Base
        if (isBaseMode) {
          await initProvider();

          if (wallet) {
            wallet = wallet.connect(provider);
            await fetchAllBalances();
          }
        }
        
        showToast("Base RPC updated");
      }
    });
  });

  document
    .getElementById("saveCustomRpc")
    .addEventListener("click", async () => {
      const urlInput = sanitizeInput(document.getElementById("customRpcUrl").value);
      
      if (!urlInput) {
        showToast("Please enter an RPC URL", 3000, 'error');
        return;
      }

      // Validate RPC URL
      const urlValidation = InputValidator.validateRPCUrl(urlInput);
      if (!urlValidation.valid) {
        showError(new Error(urlValidation.error), 'RPC configuration');
        return;
      }

      try {
        // Test the RPC connection
        const testProvider = new ethers.JsonRpcProvider(urlValidation.url);
        
        // Add timeout for connection test
        const timeoutPromise = new Promise((_, reject) => 
          setManagedTimeout(() => reject(new Error('RPC connection timeout')), 5000)
        );
        
        const blockNumber = await Promise.race([
          testProvider.getBlockNumber(),
          timeoutPromise
        ]);
        
        // Verify it's the correct network (mainnet)
        const network = await testProvider.getNetwork();
        if (network.chainId !== 1n) {
          throw new Error('RPC must be connected to Ethereum mainnet');
        }

        // Save and switch to the new RPC
        localStorage.setItem("custom_rpc", urlValidation.url);
        currentRpc = urlValidation.url;
        localStorage.setItem("rpc_endpoint", urlValidation.url);
        provider = testProvider;
        
        // Invalidate gas price cache on RPC switch
        gasPriceCache = { data: null, timestamp: 0, networkId: null };
        
        // Reinitialize contracts
        zWalletContract = new ethers.Contract(
          ZWALLET_ADDRESS,
          ZWALLET_ABI,
          provider
        );
        zQuoterContract = new ethers.Contract(
          ZQUOTER_ADDRESS,
          ZQUOTER_ABI,
          provider
        );

        if (wallet) {
          wallet = wallet.connect(provider);
          await fetchAllBalances();
        }

        showToast(`Connected to RPC (Block #${blockNumber})`);
        document.getElementById("customRpcSection").classList.add("hidden");
        loadRpcSettings();
      } catch (err) {
        if (err.message.includes('timeout')) {
          showError(new Error('RPC connection timed out'), 'RPC configuration');
        } else if (err.message.includes('mainnet')) {
          showError(err, 'RPC configuration');
        } else {
          showError(new Error('Failed to connect to RPC'), 'RPC configuration');
        }
      }
    });

  const autoRefreshToggle = document.getElementById("autoRefresh");
  if (autoRefreshToggle) {
    autoRefreshToggle.addEventListener("change", (e) => {
      if (e.target.checked) {
        if (wallet) {
          autoRefreshInterval = setManagedInterval(() => {
            fetchAllBalances(true); // Force refresh on auto-refresh
            updateGasPrices();
          }, 30000); // Increased to 30 seconds for better performance
        }
      } else {
        clearManagedInterval(autoRefreshInterval);
        autoRefreshInterval = null;
      }
      localStorage.setItem("auto_refresh", e.target.checked);
    });
  }

  // Default wallet toggle handler
  const defaultWalletToggle = document.getElementById("defaultWallet");
  const defaultWalletInfo = document.getElementById("defaultWalletInfo");
  
  if (defaultWalletToggle) {
    // Load saved setting
    chrome.storage.local.get(['zwalletDefault'], (result) => {
      if (result.zwalletDefault) {
        defaultWalletToggle.checked = true;
        defaultWalletInfo.classList.remove('hidden');
      }
    });
    
    defaultWalletToggle.addEventListener("change", (e) => {
      const isDefault = e.target.checked;
      
      // Save setting
      chrome.storage.local.set({ zwalletDefault: isDefault }, () => {
        
        
        // Show/hide info box
        if (isDefault) {
          defaultWalletInfo.classList.remove('hidden');
          showToast('⚡ Default wallet activated! Refresh dApp tabs.');
        } else {
          defaultWalletInfo.classList.add('hidden');
          showToast('Default wallet mode disabled');
        }
        
        // Notify all tabs about the setting change
        chrome.tabs.query({}, (tabs) => {
          tabs.forEach(tab => {
            chrome.tabs.sendMessage(tab.id, {
              type: 'SETTINGS_UPDATED',
              isDefault: isDefault
            }).catch(() => {
              // Ignore errors for tabs without content script
            });
          });
        });
      });
    });
  }

  // Private Key Management in Settings
  document.getElementById("revealKeyBtn")?.addEventListener("click", async () => {
    if (!wallet) {
      showError('Please unlock your wallet first', 'Export');
      return;
    }
    
    const confirmReveal = await securePasswordPrompt('Security Check', 'Enter password to reveal private key:');
    if (!confirmReveal) return;
    
    const keySection = document.getElementById("privateKeySection");
    const keyDisplay = document.getElementById("privateKeyDisplay");
    
    if (keySection && keyDisplay) {
      keyDisplay.textContent = wallet.privateKey;
      keySection.classList.remove("hidden");
      
      // Auto-hide after 60 seconds
      setTimeout(() => {
        keyDisplay.textContent = "••••••••••••••••••••••••••••••••";
        keySection.classList.add("hidden");
      }, 60000);
    }
  });
  
  document.getElementById("hideKeyBtn")?.addEventListener("click", () => {
    const keySection = document.getElementById("privateKeySection");
    const keyDisplay = document.getElementById("privateKeyDisplay");
    
    if (keySection && keyDisplay) {
      keyDisplay.textContent = "••••••••••••••••••••••••••••••••";
      keySection.classList.add("hidden");
    }
  });
  
  document.getElementById("exportKeyBtn")?.addEventListener("click", async () => {
    if (!wallet) {
      showError('Please unlock your wallet first', 'Export');
      return;
    }
    
    try {
      await exportEncryptedKey();
    } catch (err) {
      
      showError(err, 'Key export');
    }
  });

  const exportWalletsBtn = document.getElementById("exportWallets");
  if (exportWalletsBtn) {
    exportWalletsBtn.addEventListener("click", () => {
      try {
      const data = localStorage.getItem(LS_WALLETS) || "[]";
      const blob = new Blob([data], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `zWallet-backup-${new Date().toISOString().split('T')[0]}.encrypted.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast("Encrypted wallets exported!");
    } catch (err) {
      
      showToast("Export failed");
      }
    });
  }

  const clearDataBtn = document.getElementById("clearData");
  if (clearDataBtn) {
    clearDataBtn.addEventListener("click", () => {
    if (
      confirm(
        "Delete all data, wallets, and custom tokens? This cannot be undone!"
      )
    ) {
      localStorage.clear();
      location.reload();
      }
    });
  }

  // EIP-7702 Settings handlers - setup after DOM is ready
  function setupEIP7702Handlers() {
    const enable7702Btn = document.getElementById("enable7702Btn");
    const revoke7702Btn = document.getElementById("revoke7702Btn");
    
    if (enable7702Btn) {
      enable7702Btn.addEventListener("click", enable7702Delegation);
    }
    
    if (revoke7702Btn) {
      revoke7702Btn.addEventListener("click", revoke7702Delegation);
    }
  }
  
  // Call setup function immediately since popup.js loads at end of body
  setupEIP7702Handlers();

  // Load auto-refresh setting
  const autoRefresh = localStorage.getItem("auto_refresh") === "true";
  const autoRefreshCheckbox = document.getElementById("autoRefresh");
  if (autoRefreshCheckbox) autoRefreshCheckbox.checked = autoRefresh;
  
  // Setup swap event listeners
  setupSwapEventListeners();
}

// ============= SWAP FUNCTIONALITY =============
const ZROUTER_ADDRESS = "0x0000000000404FECAf36E6184245475eE1254835";
const ZROUTER_ABI = [
  // swapVZ for ERC6909 tokens (ZAMM and others)
  "function swapVZ(address to, bool exactOut, uint256 feeOrHook, address tokenIn, address tokenOut, uint256 idIn, uint256 idOut, uint256 swapAmount, uint256 amountLimit, uint256 deadline) payable returns (uint256 amountIn, uint256 amountOut)",
  "function swapV2(address to, bool exactOut, address tokenIn, address tokenOut, uint256 swapAmount, uint256 amountLimit, uint256 deadline) payable returns (uint256 amountIn, uint256 amountOut)"
];

// ZQUOTER_ABI already moved to top of file

// Note: Multicall3 is for batching view calls only, not state-changing transactions
// Each approval must be a separate transaction

// Helper to calculate pool ID for ERC6909 pairs
function calculatePoolId(id0, id1, token0, token1, swapFee) {
  // Pool key is keccak256(id0, id1, token0, token1, swapFee)
  const abiCoder = new ethers.AbiCoder();
  const encoded = abiCoder.encode(
    ["uint256", "uint256", "address", "address", "uint256"],
    [id0, id1, token0, token1, swapFee]
  );
  return ethers.keccak256(encoded);
}

// Calculate swap output for ERC6909 tokens using constant product formula
async function calculateERC6909SwapOutput(tokenIn, tokenOut, amountIn) {
  try {
    const fromToken = TOKENS[tokenIn];
    const toToken = TOKENS[tokenOut];
    
    // Check if this is an ERC6909 swap
    if (!fromToken?.isERC6909 && !toToken?.isERC6909) {
      return null; // Not an ERC6909 swap
    }
    
    // ERC6909 tokens can only swap with ETH (ETH is always token0 with id0)
    // This includes custom ERC6909 tokens added by users
    const isETHIn = tokenIn === "ETH";
    const isETHOut = tokenOut === "ETH";
    
    if (!isETHIn && !isETHOut) {
      return null; // Not an ETH pair - ERC6909 requires ETH on one side
    }
    
    // Determine which ZAMM contract to use
    // ZAMM_0_ADDRESS: Original contract for ZAMM token specifically
    // ZAMM_1_ADDRESS: New contract for all other ERC6909 tokens (including custom ones)
    const isZAMM = (fromToken?.id === ZAMM_ID) || (toToken?.id === ZAMM_ID);
    const zammAddress = isZAMM ? ZAMM_0_ADDRESS : ZAMM_1_ADDRESS;
    
    // Create contract instance
    const zammContract = new ethers.Contract(
      zammAddress,
      ZAMM_AMM_ABI,
      provider
    );
    
    // Calculate pool ID - for ERC6909, we need the actual contract address
    const token0 = isETHIn ? ethers.ZeroAddress : fromToken.address;
    const token1 = isETHOut ? ethers.ZeroAddress : toToken.address;
    const id0 = isETHIn ? 0n : BigInt(fromToken.id || 0);
    const id1 = isETHOut ? 0n : BigInt(toToken.id || 0);
    
    // Sort tokens for pool key - addresses are compared as hex strings
    const shouldSort = token0.toLowerCase() < token1.toLowerCase();
    const sortedToken0 = shouldSort ? token0 : token1;
    const sortedToken1 = shouldSort ? token1 : token0;
    const sortedId0 = shouldSort ? id0 : id1;
    const sortedId1 = shouldSort ? id1 : id0;
    
    // Determine swap direction (zeroForOne means swapping sorted token0 for sorted token1)
    // IMPORTANT: ETH (ZeroAddress) is ALWAYS token0 when paired with any ERC6909 token
    // because 0x0000... sorts before any other address
    // So for ETH/ZAMM pairs:
    // - sortedToken0 is always ETH (0x0000...)
    // - sortedToken1 is always ZAMM
    let zeroForOne;
    if (isETHIn) {
      // Swapping ETH (token0) for ZAMM (token1) -> zeroForOne = true
      zeroForOne = true;
    } else {
      // Swapping ZAMM (token1) for ETH (token0) -> zeroForOne = false
      zeroForOne = false;
    }
    
    // Default swap fee is 100 bps (1%)
    const swapFee = 100;
    
    // Calculate pool ID
    const poolId = calculatePoolId(sortedId0, sortedId1, sortedToken0, sortedToken1, swapFee);
    
    // Get pool reserves
    const poolData = await zammContract.pools(poolId);
    const reserve0 = BigInt(poolData[0]);
    const reserve1 = BigInt(poolData[1]);
    
    if (reserve0 === 0n || reserve1 === 0n) {
      
      return null;
    }
    
    // Calculate output using constant product formula with fee
    // zeroForOne means we're swapping sorted token0 for sorted token1
    const reserveIn = zeroForOne ? reserve0 : reserve1;
    const reserveOut = zeroForOne ? reserve1 : reserve0;
    
    const amountInBigInt = BigInt(amountIn);
    const amountInWithFee = amountInBigInt * BigInt(10000 - swapFee);
    const numerator = amountInWithFee * reserveOut;
    const denominator = (reserveIn * 10000n) + amountInWithFee;
    const amountOut = numerator / denominator;
    
    return {
      amountOut,
      poolId,
      zammAddress,
      swapFee,
      reserve0,
      reserve1,
      zeroForOne
    };
  } catch (err) {
    
    return null;
  }
}

// Swap state persistence functions
function saveSwapState() {
  const swapState = {
    fromToken: swapFromToken,
    toToken: swapToToken,
    slippage: swapSlippage,
    mode: swapMode,
    fromAmount: document.getElementById('swapFromAmount')?.value || '',
    toAmount: document.getElementById('swapToAmount')?.value || '',
    timestamp: Date.now()
  };
  localStorage.setItem('swap_state', JSON.stringify(swapState));
}



function restoreSwapState() {
  try {
    const saved = localStorage.getItem('swap_state');
    if (!saved) return false;
    
    const state = JSON.parse(saved);
    // Only restore if less than 24 hours old
    if (Date.now() - state.timestamp > 24 * 60 * 60 * 1000) {
      localStorage.removeItem('swap_state');
      return false;
    }
    
    // Validate tokens still exist
    if (TOKENS[state.fromToken] && TOKENS[state.toToken]) {
      swapFromToken = state.fromToken;
      swapToToken = state.toToken;
      swapSlippage = state.slippage || 0.5;
      swapMode = state.mode || "exactIn";
      
      // Restore input values after DOM is ready
      setTimeout(() => {
        const fromAmountInput = document.getElementById('swapFromAmount');
        const toAmountInput = document.getElementById('swapToAmount');
        if (fromAmountInput && state.fromAmount) {
          fromAmountInput.value = state.fromAmount;
        }
        if (toAmountInput && state.toAmount) {
          toAmountInput.value = state.toAmount;
        }
        updateSwapTokenDisplay('from');
        updateSwapTokenDisplay('to');
        updateSwapBalances();
      }, 100);
      
      return true;
    }
  } catch (err) {
    console.error('Failed to restore swap state:', err);
  }
  return false;
}

// Swap state - initialize with saved values or defaults
let swapFromToken = "ETH";
let swapToToken = "USDC";
let swapSlippage = 0.5; // 0.5% default
let swapMode = "exactIn"; // exactIn or exactOut
let bestSwapRoute = null;
let tokenSelectorTarget = null; // 'from' or 'to'
let swapSimulationTimeout = null; // Debounce timer
let isSimulating = false; // Prevent concurrent simulations

// Try to restore saved state
restoreSwapState();

// AMM sources enum from zQuoter contract
const AMM_SOURCES = {
  0: "UNI_V2",
  1: "SUSHI",
  2: "ZAMM",
  3: "UNI_V3",
  4: "UNI_V4"
};

// Standard Uniswap V3 fee tiers
const V3_FEE_TIERS = [500, 3000, 10000]; // 0.05%, 0.3%, 1%

// Uniswap V4 tick spacings
const V4_TICK_SPACINGS = {
  500: 10,    // 0.05% fee
  3000: 60,   // 0.3% fee
  10000: 200  // 1% fee
};

async function setupSwapEventListeners() {
  
  // Function to initialize token dropdowns with logos
  async function initializeTokenDropdowns() {
    // Ensure balances are loaded before initializing dropdowns
    if (wallet && (!currentBalances || Object.keys(currentBalances).length === 0)) {
      await fetchAllBalances();
    }
    
    // Get all available tokens including custom ones
    const swapTokens = Object.keys(TOKENS);
    
    // Populate from dropdown
    const fromDropdown = document.getElementById('swapFromDropdown');
    if (fromDropdown) {
      // Filter out the currently selected 'to' token
      const fromTokens = swapTokens.filter(symbol => symbol !== swapToToken);
      
      fromDropdown.innerHTML = fromTokens.map(symbol => {
        const token = TOKENS[symbol];
        const logo = TOKEN_LOGOS[symbol] || generateCoinSVG(symbol);
        const balance = currentBalances[symbol];
        const balanceDisplay = balance ? Number(balance.formatted).toFixed(4) : '0.0000';
        return `
          <div class="token-option" data-token="${symbol}" style="display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; cursor: pointer; transition: background 0.2s;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <div class="token-option-icon" style="width: 24px; height: 24px;">${logo}</div>
              <span class="token-option-symbol" style="font-weight: 500;">${symbol}</span>
              ${token.isERC6909 ? '<span style="font-size: 10px; color: var(--text-secondary);">(ERC6909)</span>' : ''}
            </div>
            <span style="font-size: 12px; color: var(--text-secondary);">${balanceDisplay}</span>
          </div>
        `;
      }).join('');
      
      // Add click handlers
      fromDropdown.querySelectorAll('.token-option').forEach(option => {
        option.addEventListener('click', async (e) => {
          e.stopPropagation();
          swapFromToken = option.dataset.token;
          updateSwapTokenDisplay('from');
          updateSwapBalances();
          fromDropdown.classList.add('hidden');
          saveSwapState();
          
          // Re-initialize to dropdown based on new from token
          await initializeTokenDropdowns();
          
          // Check if current to token is still valid
          const fromToken = TOKENS[swapFromToken];
          const toToken = TOKENS[swapToToken];
          
          if (fromToken?.isERC6909 && swapToToken !== 'ETH') {
            // Force to ETH if from is ERC6909
            swapToToken = 'ETH';
            updateSwapTokenDisplay('to');
          } else if (toToken?.isERC6909 && swapFromToken !== 'ETH') {
            // If to is ERC6909 but from is not ETH, switch to ETH
            swapToToken = 'ETH';
            updateSwapTokenDisplay('to');
          }
          
          if (document.getElementById("swapFromAmount").value) {
            simulateSwap();
          }
        });
      });
    }
    
    // Populate to dropdown - dynamically filter based on from token
    const toDropdown = document.getElementById('swapToDropdown');
    if (toDropdown) {
      // If from token is ERC6909, only show ETH
      // If from token is ETH, show all tokens
      // If from token is ERC20, show ETH and other ERC20s (not ERC6909)
      let toTokens;
      const fromToken = TOKENS[swapFromToken];
      
      if (fromToken?.isERC6909) {
        // ERC6909 can only swap with ETH
        toTokens = ['ETH'];
      } else if (swapFromToken === 'ETH') {
        // ETH can swap with anything except itself
        toTokens = swapTokens.filter(symbol => symbol !== 'ETH');
      } else {
        // ERC20 can swap with ETH and other ERC20s, but not ERC6909 or itself
        toTokens = swapTokens.filter(symbol => !TOKENS[symbol].isERC6909 && symbol !== swapFromToken);
      }
      
      toDropdown.innerHTML = toTokens.map(symbol => {
        const token = TOKENS[symbol];
        const logo = TOKEN_LOGOS[symbol] || generateCoinSVG(symbol);
        const balance = currentBalances[symbol];
        const balanceDisplay = balance ? Number(balance.formatted).toFixed(4) : '0.0000';
        return `
          <div class="token-option" data-token="${symbol}" style="display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; cursor: pointer; transition: background 0.2s;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <div class="token-option-icon" style="width: 24px; height: 24px;">${logo}</div>
              <span class="token-option-symbol" style="font-weight: 500;">${symbol}</span>
              ${token.isERC6909 ? '<span style="font-size: 10px; color: var(--text-secondary);">(ERC6909)</span>' : ''}
            </div>
            <span style="font-size: 12px; color: var(--text-secondary);">${balanceDisplay}</span>
          </div>
        `;
      }).join('');
      
      // Add click handlers
      toDropdown.querySelectorAll('.token-option').forEach(option => {
        option.addEventListener('click', (e) => {
          e.stopPropagation();
          swapToToken = option.dataset.token;
          updateSwapTokenDisplay('to');
          updateSwapBalances();
          toDropdown.classList.add('hidden');
          saveSwapState();
          if (document.getElementById("swapFromAmount").value) {
            simulateSwap();
          }
        });
      });
    }
  }
  
  // Initialize token displays and dropdowns
  updateSwapTokenDisplay('from');
  updateSwapTokenDisplay('to');
  await initializeTokenDropdowns();
  
  // Setup token selector clicks
  document.getElementById('swapFromTokenSelector')?.addEventListener('click', (e) => {
    e.stopPropagation();
    const dropdown = document.getElementById('swapFromDropdown');
    const otherDropdown = document.getElementById('swapToDropdown');
    
    if (dropdown) {
      dropdown.classList.toggle('hidden');
      otherDropdown?.classList.add('hidden');
    }
  });
  
  document.getElementById('swapToTokenSelector')?.addEventListener('click', (e) => {
    e.stopPropagation();
    const dropdown = document.getElementById('swapToDropdown');
    const otherDropdown = document.getElementById('swapFromDropdown');
    
    if (dropdown) {
      dropdown.classList.toggle('hidden');
      otherDropdown?.classList.add('hidden');
    }
  });
  
  // Hide dropdowns when clicking elsewhere
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.token-selector') && !e.target.closest('.token-dropdown')) {
      document.getElementById('swapFromDropdown')?.classList.add('hidden');
      document.getElementById('swapToDropdown')?.classList.add('hidden');
    }
  });
  
  // Swap direction button
  document.getElementById("swapDirectionBtn")?.addEventListener("click", async () => {
    // Check if swap is valid before allowing
    const fromToken = TOKENS[swapFromToken];
    const toToken = TOKENS[swapToToken];
    
    // Don't allow swapping if it would create an invalid pair
    if (fromToken?.isERC6909 && toToken?.isERC6909) {
      showToast("Cannot swap between two ERC6909 tokens");
      return;
    }
    
    // Swap tokens
    const temp = swapFromToken;
    swapFromToken = swapToToken;
    swapToToken = temp;
    
    // Swap amounts
    const fromAmount = document.getElementById("swapFromAmount").value;
    const toAmount = document.getElementById("swapToAmount").value;
    document.getElementById("swapFromAmount").value = toAmount;
    document.getElementById("swapToAmount").value = fromAmount;
    
    // Update displays
    updateSwapTokenDisplay('from');
    updateSwapTokenDisplay('to');
    updateSwapBalances();
    
    // Re-initialize dropdowns with new restrictions
    await initializeTokenDropdowns();
    
    // Save the new state
    saveSwapState();
    
    if (fromAmount || toAmount) {
      simulateSwap();
    }
  });
  
  // Amount inputs with smart detection and debouncing
  // Debounced swap simulation handler
  const debouncedSimulateSwap = debounce(() => {
    simulateSwap();
  }, CONSTANTS.SWAP_SIMULATION_DELAY);
  
  // Optimized swap from amount handler
  const handleSwapFromInput = (e) => {
    swapMode = "exactIn";
    
    // Store current cursor position
    const cursorPos = e.target.selectionStart;
    const originalValue = e.target.value;
    
    // Sanitize input - only allow numbers and decimal point
    let value = originalValue.replace(/[^0-9.]/g, '');
    
    // Ensure only one decimal point
    const parts = value.split('.');
    if (parts.length > 2) {
      value = parts[0] + '.' + parts.slice(1).join('');
    }
    
    // Only update if value actually changed
    if (value !== originalValue) {
      e.target.value = value;
      // Restore cursor position adjusted for removed characters
      const diff = originalValue.length - value.length;
      const newPos = Math.max(0, cursorPos - diff);
      e.target.setSelectionRange(newPos, newPos);
    }
    
    // Validate against balance
    const inputAmount = parseFloat(e.target.value);
    if (inputAmount && inputAmount > 0) {
      const token = TOKENS[swapFromToken];
      const balanceObj = currentBalances[swapFromToken === "ETH" ? "ETH" : swapFromToken];
      const maxBalance = parseFloat(balanceObj?.formatted || "0");
      
      if (swapFromToken === "ETH") {
        // For ETH, check against actual balance minus gas buffer
        const balanceETH = maxBalance;
        let gasBuffer;
        if (balanceETH < 0.01) {
          gasBuffer = 0.003;
        } else if (balanceETH < 0.05) {
          gasBuffer = 0.005;
        } else {
          gasBuffer = 0.01;
        }
        const effectiveBalance = Math.max(0, maxBalance - gasBuffer);
        
        if (inputAmount > effectiveBalance && effectiveBalance > 0) {
          // Don't automatically change the value, just show a warning
          showToast(`Warning: Max available is ${effectiveBalance.toFixed(6)} ETH (${gasBuffer} ETH gas reserved)`);
        }
      } else {
        // For tokens, check against token balance
        if (inputAmount > maxBalance && maxBalance > 0) {
          const decimals = token?.decimals || 18;
          const precision = decimals <= 6 ? 6 : (decimals <= 8 ? 8 : 6);
          // Don't automatically change the value, just show a warning
          showToast(`Warning: Max available is ${maxBalance.toFixed(precision)} ${swapFromToken}`);
        }
      }
    }
    
    // Update USD display immediately
    updateSwapUSDValues();
    
    if (e.target.value) {
      debouncedSimulateSwap();
      saveSwapState(); // Save state on input change
    } else {
      clearSwapQuote();
      saveSwapState(); // Save even when clearing
    }
  };
  
  document.getElementById("swapFromAmount")?.addEventListener("input", handleSwapFromInput);
  
  // Optimized swap to amount handler
  const handleSwapToInput = (e) => {
    swapMode = "exactOut";
    
    // Store current cursor position
    const cursorPos = e.target.selectionStart;
    const originalValue = e.target.value;
    
    // Sanitize input - only allow numbers and decimal point
    let value = originalValue.replace(/[^0-9.]/g, '');
    
    // Ensure only one decimal point
    const parts = value.split('.');
    if (parts.length > 2) {
      value = parts[0] + '.' + parts.slice(1).join('');
    }
    
    // Only update if value actually changed
    if (value !== originalValue) {
      e.target.value = value;
      // Restore cursor position adjusted for removed characters
      const diff = originalValue.length - value.length;
      const newPos = Math.max(0, cursorPos - diff);
      e.target.setSelectionRange(newPos, newPos);
    }
    
    // Update USD display immediately
    updateSwapUSDValues();
    
    if (e.target.value) {
      debouncedSimulateSwap();
      saveSwapState(); // Save state on input change
    } else {
      clearSwapQuote();
      saveSwapState(); // Save even when clearing
    }
  };
  
  document.getElementById("swapToAmount")?.addEventListener("input", handleSwapToInput);
  
  // Max button
  document.getElementById("swapMaxBtn")?.addEventListener("click", async () => {
    if (!wallet || !provider) {
      showToast("Connect wallet first");
      return;
    }
    
    // Ensure balances are loaded
    if (!currentBalances || Object.keys(currentBalances).length === 0) {
      showToast("Loading balances...");
      await fetchAllBalances();
    }
    
    try {
      let maxAmount;
      const token = TOKENS[swapFromToken];
      
      if (!token || swapFromToken === "ETH") {
        // For ETH, we need to account for gas fees more accurately
        const balanceObj = currentBalances["ETH"];
        if (!balanceObj || !balanceObj.formatted) {
          showToast("No ETH balance");
          document.getElementById("swapFromAmount").value = "";
          return;
        }
        
        const balanceETH = parseFloat(balanceObj.formatted.toString());
        
        // Get current gas price to calculate buffer more accurately
        let gasBuffer;
        try {
          const feeData = await getCachedGasPrice();
          const gasPrice = feeData.maxFeePerGas || feeData.gasPrice || ethers.parseUnits("30", "gwei");
          
          // Estimate gas for a swap transaction (typically 150k-250k gas)
          const estimatedGasLimit = 250000n; // Conservative estimate
          const estimatedGasCost = gasPrice * estimatedGasLimit;
          const estimatedGasETH = parseFloat(ethers.formatEther(estimatedGasCost));
          
          // Add 20% buffer to gas estimate for safety
          gasBuffer = estimatedGasETH * 1.2;
          
          // Apply minimum gas buffers based on balance
          if (balanceETH < 0.01) {
            // For very small balances, use at least the estimated gas cost
            gasBuffer = Math.max(gasBuffer, estimatedGasETH);
          } else if (balanceETH < 0.05) {
            // For small balances, ensure at least 0.002 ETH buffer
            gasBuffer = Math.max(gasBuffer, 0.002);
          } else if (balanceETH < 0.1) {
            // For medium balances, ensure at least 0.003 ETH buffer
            gasBuffer = Math.max(gasBuffer, 0.003);
          } else {
            // For larger balances, ensure at least 0.005 ETH buffer
            gasBuffer = Math.max(gasBuffer, 0.005);
          }
          
          
        } catch (err) {
          
          // Fallback to conservative buffer if gas estimation fails
          if (balanceETH < 0.01) {
            gasBuffer = 0.002;
          } else if (balanceETH < 0.05) {
            gasBuffer = 0.003;
          } else if (balanceETH < 0.1) {
            gasBuffer = 0.005;
          } else {
            gasBuffer = 0.01;
          }
        }
        
        // Calculate max amount after gas buffer
        maxAmount = Math.max(0, balanceETH - gasBuffer);
        
        // Round down to 6 decimal places to avoid precision issues
        maxAmount = Math.floor(maxAmount * 1000000) / 1000000;
        
        // If the result is too small, set to 0
        if (maxAmount < 0.0001) {
          maxAmount = 0;
          const needed = gasBuffer.toFixed(4);
          showToast(`Need ~${needed} ETH for gas`);
        }
      } else {
        // For tokens, use the formatted balance from currentBalances
        const balanceObj = currentBalances[swapFromToken];
        if (!balanceObj || !balanceObj.formatted) {
          showToast(`No ${swapFromToken} balance`);
          document.getElementById("swapFromAmount").value = "";
          return;
        }
        
        maxAmount = parseFloat(balanceObj.formatted);
        
        // Round down to avoid precision issues
        const decimals = token?.decimals || 18;
        if (decimals <= 6) {
          maxAmount = Math.floor(maxAmount * 1000000) / 1000000;
        } else if (decimals <= 8) {
          maxAmount = Math.floor(maxAmount * 100000000) / 100000000;
        } else {
          maxAmount = Math.floor(maxAmount * 1000000) / 1000000;
        }
        
        // Also check if user has ETH for gas
        const ethBalance = currentBalances["ETH"];
        if (!ethBalance || parseFloat(ethBalance.formatted) < 0.001) {
          showToast("Warning: Low ETH for gas");
        }
      }
      
      // Set the value in the input field
      if (maxAmount > 0) {
        const displayDecimals = swapFromToken === "ETH" ? 6 : 
                               (token?.decimals === 6 ? 6 : 
                                token?.decimals === 8 ? 8 : 6);
        document.getElementById("swapFromAmount").value = maxAmount.toFixed(displayDecimals);
        
        // Update USD display
        updateSwapUSDValues();
        
        // Trigger simulation
        swapMode = "exactIn";
        
        // Small delay to ensure UI updates
        setTimeout(() => {
          simulateSwap();
        }, 100);
      } else {
        document.getElementById("swapFromAmount").value = "0";
        updateSwapUSDValues();
      }
    } catch (err) {
      
      showToast("Failed to calculate max");
    }
  });
  
  // Slippage options
  document.querySelectorAll(".slippage-option").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      document.querySelectorAll(".slippage-option").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      
      const slippage = btn.dataset.slippage;
      if (slippage === "custom") {
        document.getElementById("customSlippageSection")?.classList.remove("hidden");
        // Focus on custom input
        document.getElementById("customSlippage")?.focus();
      } else {
        document.getElementById("customSlippageSection")?.classList.add("hidden");
        swapSlippage = parseFloat(slippage);
        saveSwapState(); // Save slippage preference
        
        // Re-simulate if amounts are present
        if (document.getElementById("swapFromAmount").value || document.getElementById("swapToAmount").value) {
          simulateSwap();
        }
      }
    });
  });
  
  // Custom slippage input
  document.getElementById("customSlippage")?.addEventListener("input", (e) => {
    const value = parseFloat(e.target.value);
    if (!isNaN(value) && value >= 0 && value <= 50) {
      swapSlippage = value;
      saveSwapState(); // Save custom slippage
      if (document.getElementById("swapFromAmount").value || document.getElementById("swapToAmount").value) {
        simulateSwap();
      }
    }
  });
  
  // Swap button
  document.getElementById("swapBtn")?.addEventListener("click", executeSwap);
  
  // Swap confirmation modal
  document.getElementById("swapModalClose")?.addEventListener("click", () => {
    document.getElementById("swapConfirmModal")?.classList.add("hidden");
  });
  
  document.getElementById("cancelSwapBtn")?.addEventListener("click", () => {
    document.getElementById("swapConfirmModal")?.classList.add("hidden");
  });
  
  // Initialize token dropdowns and display
  await initializeTokenDropdowns();
  updateSwapTokenDisplay();
  updateSwapBalances();
  
  // Bridge Tab Event Listeners
  setupBridgeEventListeners();
}

// Update swap token display
function updateSwapTokenDisplay(which = 'both') {
  if (which === 'from' || which === 'both') {
    const fromIcon = document.getElementById("swapFromTokenIcon");
    const fromDisplay = document.getElementById("swapFromTokenDisplay");
    if (fromIcon) fromIcon.innerHTML = TOKEN_LOGOS[swapFromToken] || generateCoinSVG(swapFromToken);
    if (fromDisplay) fromDisplay.textContent = swapFromToken;
  }
  
  if (which === 'to' || which === 'both') {
    const toIcon = document.getElementById("swapToTokenIcon");
    const toDisplay = document.getElementById("swapToTokenDisplay");
    if (toIcon) toIcon.innerHTML = TOKEN_LOGOS[swapToToken] || generateCoinSVG(swapToToken);
    if (toDisplay) toDisplay.textContent = swapToToken;
  }
}

async function updateSwapBalances() {
  // Always ensure balances are properly loaded using the same logic as Send tab
  if (!wallet || !provider) {
    const fromBalance = document.getElementById("swapFromBalance");
    const toBalance = document.getElementById("swapToBalance");
    if (fromBalance) fromBalance.textContent = "0.000000";
    if (toBalance) toBalance.textContent = "0.000000";
    return;
  }
  
  // Force fetch if no balances or missing critical tokens
  if (!currentBalances || Object.keys(currentBalances).length === 0 || 
      !currentBalances["ETH"] || 
      (swapFromToken !== "ETH" && !currentBalances[swapFromToken]) ||
      (swapToToken !== "ETH" && !currentBalances[swapToToken])) {
    console.log("Swap tab: Fetching balances because missing tokens", { swapFromToken, swapToToken });
    await fetchAllBalances(true); // Force refresh
    // Wait a bit for balances to propagate
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  
  const fromBalance = document.getElementById("swapFromBalance");
  const toBalance = document.getElementById("swapToBalance");
  
  if (fromBalance) {
    const balanceObj = currentBalances[swapFromToken];
    if (balanceObj && balanceObj.formatted !== undefined) {
      const numBalance = parseFloat(balanceObj.formatted) || 0;
      fromBalance.textContent = numBalance === 0 ? "0.000000" : Math.min(numBalance, 1e10).toFixed(6);
    } else {
      fromBalance.textContent = "0.000000";
    }
  }
  
  if (toBalance) {
    const balanceObj = currentBalances[swapToToken];
    if (balanceObj && balanceObj.formatted !== undefined) {
      const numBalance = parseFloat(balanceObj.formatted) || 0;
      toBalance.textContent = numBalance === 0 ? "0.000000" : Math.min(numBalance, 1e10).toFixed(6);
    } else {
      toBalance.textContent = "0.000000";
    }
  }
  
  // Check approval status for non-ETH tokens
  if (swapFromToken !== "ETH" && zWalletContract && wallet) {
    const token = TOKENS[swapFromToken];
    if (token && token.address) {
      try {
        const approvalNeeded = token.isERC6909 
          ? await zWalletContract.checkERC6909RouterIsOperator(wallet.address, token.address)
          : await zWalletContract.checkERC20RouterApproval(wallet.address, token.address, ethers.MaxUint256, true);
        
        // Add visual indicator if approval is needed
        const indicator = document.getElementById("swapFromApprovalIndicator");
        if (indicator) {
          indicator.style.display = (approvalNeeded && approvalNeeded !== "0x") ? "inline" : "none";
          indicator.title = "Approval required for first swap";
        }
      } catch (err) {
        
      }
    }
  }
}

function clearSwapQuote() {
  document.getElementById("swapRoute").textContent = "--";
  document.getElementById("swapMinimum").textContent = "--";
  document.getElementById("swapGasFee").textContent = "--";
  document.getElementById("swapBtn").textContent = "Enter Amount to Swap";
  document.getElementById("swapBtn").disabled = true;
  bestSwapRoute = null;
}

// Helper to update USD values
function updateSwapUSDValues() {
  const fromAmount = document.getElementById("swapFromAmount").value;
  const toAmount = document.getElementById("swapToAmount").value;
  
  const fromUSD = document.getElementById("swapFromUSD");
  const toUSD = document.getElementById("swapToUSD");
  
  if (fromUSD && fromAmount) {
    const price = tokenPrices[swapFromToken]?.usd || 0;
    const usdValue = parseFloat(fromAmount) * price;
    fromUSD.textContent = `$${usdValue.toFixed(2)}`;
  } else if (fromUSD) {
    fromUSD.textContent = "$0.00";
  }
  
  if (toUSD && toAmount) {
    const price = tokenPrices[swapToToken]?.usd || 0;
    const usdValue = parseFloat(toAmount) * price;
    toUSD.textContent = `$${usdValue.toFixed(2)}`;
  } else if (toUSD) {
    toUSD.textContent = "$0.00";
  }
}

async function simulateSwap() {
  if (!wallet || !provider) {
    showToast("Please connect wallet first");
    return;
  }
  
  // Ensure balances are loaded
  await ensureBalancesLoaded();
  
  // Prevent concurrent simulations
  if (isSimulating) {
    
    return;
  }
  
  isSimulating = true;
  
  try {
    const fromToken = TOKENS[swapFromToken];
    const toToken = TOKENS[swapToToken];
    
    // Get amount based on swap mode
    let amountIn, amountOut;
    if (swapMode === "exactIn") {
      amountIn = document.getElementById("swapFromAmount").value;
      if (!amountIn || parseFloat(amountIn) <= 0) {
        clearSwapQuote();
        return;
      }
    } else {
      // exactOut mode - not yet fully implemented
      amountOut = document.getElementById("swapToAmount").value;
      if (!amountOut || parseFloat(amountOut) <= 0) {
        clearSwapQuote();
        return;
      }
      // For now, we'll still use exactIn logic
      // TODO: Implement exactOut quotes
      showToast("Exact output mode coming soon");
      return;
    }
    
    // Update UI to show loading
    document.getElementById("swapRoute").textContent = "Finding best route...";
    document.getElementById("swapBtn").textContent = "Getting quote...";
    document.getElementById("swapBtn").disabled = true;
    
    // Prepare token addresses (use 0x0 for ETH)
    const tokenInAddress = swapFromToken === "ETH" ? ethers.ZeroAddress : fromToken.address;
    const tokenOutAddress = swapToToken === "ETH" ? ethers.ZeroAddress : toToken.address;
    
    // Convert amount to wei with validation
    const maxDecimals = fromToken?.decimals || 18;
    const parsedAmount = parseFloat(amountIn);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      clearSwapQuote();
      return;
    }
    const truncated = parsedAmount.toFixed(maxDecimals);
    const swapAmount = ethers.parseUnits(truncated, maxDecimals);
    
    // Check if this is a CULT swap (only ETH pairs allowed)
    const isCultSwap = swapFromToken === "CULT" || swapToToken === "CULT";
    if (isCultSwap) {
      // CULT only trades with ETH
      if (swapFromToken !== "ETH" && swapToToken !== "ETH") {
        document.getElementById("swapRoute").textContent = "CULT only trades with ETH";
        document.getElementById("swapBtn").textContent = "Invalid pair";
        document.getElementById("swapBtn").disabled = true;
        clearSwapQuote();
        return;
      }
      
      // Calculate CULT swap output using actual pool reserves from ZAMM_1
      // CULT uses the special feeOrHook value to identify its pool
      const cultFee = 40; // 0.4% in basis points
      
      // Use ZAMM_1 contract for CULT pools
      const zammContract = new ethers.Contract(
        ZAMM_1_ADDRESS,
        ZAMM_AMM_ABI,
        provider
      );
      
      // Build pool key for CULT - ETH is always token0 (sorts first)
      // CULT trades against ETH, so we need to determine which is which
      const isETHIn = swapFromToken === "ETH";
      // Pool key components not needed with hardcoded pool ID
      // const token0 = ethers.ZeroAddress; // ETH is always token0
      // const token1 = TOKENS["CULT"].address; // CULT address is fixed
      // const id0 = 0n; // ETH has id 0
      // const id1 = 0n; // CULT has id 0 (not ERC6909)
      
      // Hardcoded CULT pool ID for now
      const poolId = BigInt("96057217671165627097175198549959274650003499289597433381056646234071826883364");
      
      // Get the actual pool reserves
      let reserve0, reserve1;
      try {
        const poolInfo = await zammContract.pools(poolId);
        reserve0 = poolInfo.reserve0;
        reserve1 = poolInfo.reserve1;
        
        if (!reserve0 || !reserve1 || reserve0 === 0n || reserve1 === 0n) {
          // Pool doesn't exist or has no liquidity
          document.getElementById("swapRoute").textContent = "CULT Pool (No liquidity)";
          document.getElementById("swapBtn").textContent = "No liquidity";
          document.getElementById("swapBtn").disabled = true;
          clearSwapQuote();
          return;
        }
      } catch (err) {
        // Error fetching pool, fallback to simple calculation
        const feeAmount = swapAmount * BigInt(cultFee) / 10000n;
        const outputAmount = swapAmount - feeAmount;
        const outputFormatted = ethers.formatUnits(outputAmount, toToken?.decimals || 18);
        
        // Only update the output field if we're in exactIn mode
        if (swapMode === "exactIn") {
          document.getElementById("swapToAmount").value = parseFloat(outputFormatted).toFixed(6);
        }
        document.getElementById("swapRoute").textContent = "CULT Pool (0.4% fee)";
        document.getElementById("swapBtn").textContent = "Swap";
        document.getElementById("swapBtn").disabled = false;
        
        bestSwapRoute = {
          isERC6909: true,
          tokenIn: swapFromToken === "ETH" ? ethers.ZeroAddress : fromToken.address,
          tokenOut: swapToToken === "ETH" ? ethers.ZeroAddress : toToken.address,
          idIn: 0,
          idOut: 0,
          amountIn: swapAmount,
          amountOut: outputAmount,
          slippage: swapSlippage,
          sourceName: "CULT Pool",
          swapFee: cultFee,
          isCult: true,
          poolId: poolId
        };
        
        updateSwapUSDValues();
        return;
      }
      
      // Calculate swap output using constant product formula (x * y = k)
      // Determine which reserve corresponds to input/output
      const zeroForOne = isETHIn; // Swapping token0 (ETH) for token1 (CULT)
      
      const reserveIn = zeroForOne ? reserve0 : reserve1;
      const reserveOut = zeroForOne ? reserve1 : reserve0;
      
      // Apply fee to input amount (0.4% fee = 40 basis points)
      // AMM takes fee from input, so actual amount used for swap is input * (1 - fee)
      const amountInAfterFee = swapAmount * (10000n - BigInt(cultFee)) / 10000n;
      
      // Calculate output using constant product formula
      // outputAmount = (reserveOut * amountInAfterFee) / (reserveIn + amountInAfterFee)
      const numerator = reserveOut * amountInAfterFee;
      const denominator = reserveIn + amountInAfterFee;
      const outputAmount = numerator / denominator;
      
      const outputFormatted = ethers.formatUnits(outputAmount, toToken?.decimals || 18);
      
      // Update UI with CULT quote
      // Only update the output field if we're in exactIn mode
      if (swapMode === "exactIn") {
        document.getElementById("swapToAmount").value = parseFloat(outputFormatted).toFixed(6);
      }
      document.getElementById("swapRoute").textContent = `CULT Pool (0.4% fee)`;
      document.getElementById("swapBtn").textContent = "Swap";
      document.getElementById("swapBtn").disabled = false;
      
      // Display pool reserves for transparency
      const ethReserve = zeroForOne ? reserve0 : reserve1;
      const cultReserve = zeroForOne ? reserve1 : reserve0;
      
      // Calculate price impact
      const priceImpact = (swapAmount * 10000n / reserveIn) / 100n;
      const priceImpactPercent = Number(priceImpact) / 100;
      
      // Update route text with more info if significant price impact
      if (priceImpactPercent > 1) {
        document.getElementById("swapRoute").textContent = `CULT Pool (0.4% fee, ${priceImpactPercent.toFixed(2)}% impact)`;
      }
      
      // Store the route for execution - mark as ERC6909 to use swapVZ
      bestSwapRoute = {
        isERC6909: true, // Use swapVZ path
        tokenIn: swapFromToken === "ETH" ? ethers.ZeroAddress : fromToken.address,
        tokenOut: swapToToken === "ETH" ? ethers.ZeroAddress : toToken.address,
        idIn: 0,
        idOut: 0,
        amountIn: swapAmount,
        amountOut: outputAmount,
        slippage: swapSlippage,
        sourceName: "CULT Pool",
        swapFee: cultFee,
        isCult: true, // Special flag for CULT
        poolId: poolId,
        zeroForOne: zeroForOne,
        reserves: {
          eth: ethReserve,
          cult: cultReserve
        }
      };
      
      updateSwapUSDValues();
      return;
    }
    
    // Check if this is an ERC6909 swap
    const erc6909Result = await calculateERC6909SwapOutput(swapFromToken, swapToToken, swapAmount);
    
    if (erc6909Result) {
      // This is an ERC6909 swap, use the calculated output
      const outputAmount = erc6909Result.amountOut;
      const outputFormatted = ethers.formatUnits(outputAmount, toToken?.decimals || 18);
      
      // Update UI with ERC6909 quote
      // Only update the output field if we're in exactIn mode
      if (swapMode === "exactIn") {
        document.getElementById("swapToAmount").value = parseFloat(outputFormatted).toFixed(6);
      }
      document.getElementById("swapRoute").textContent = `ZAMM AMM (${erc6909Result.swapFee / 100}% fee)`;
      document.getElementById("swapBtn").textContent = "Swap";
      document.getElementById("swapBtn").disabled = false;
      
      // Store the route for execution
      bestSwapRoute = {
        isERC6909: true,
        tokenIn: tokenInAddress,
        tokenOut: tokenOutAddress,
        idIn: fromToken?.id || 0,
        idOut: toToken?.id || 0,
        amountIn: swapAmount,
        amountOut: outputAmount,
        slippage: swapSlippage,
        sourceName: "ZAMM AMM",
        poolId: erc6909Result.poolId,
        zammAddress: erc6909Result.zammAddress,
        swapFee: erc6909Result.swapFee,
        zeroForOne: erc6909Result.zeroForOne
      };
      
      updateSwapUSDValues();
      return;
    }
    
    // Not an ERC6909 swap, use zQuoter for regular tokens
    if (!zQuoterContract) {
      
      return;
    }
    
    let quotesResult, bestQuote;
    try {
      // Get quotes from zQuoter (exactOut = false for exactIn mode)
      quotesResult = await zQuoterContract.getQuotes(
        false, // exactOut = false (we're doing exactIn)
        tokenInAddress,
        tokenOutAddress,
        swapAmount
      );
      
      bestQuote = quotesResult.best;
    } catch (quoterError) {
      
      // If quoter fails, show a more specific error
      document.getElementById("swapRoute").textContent = "Quoter unavailable";
      document.getElementById("swapBtn").textContent = "Network error";
      document.getElementById("swapBtn").disabled = true;
      return;
    }
    
    // Check if we got a valid quote
    if (!bestQuote || bestQuote.amountOut === 0n) {
      document.getElementById("swapRoute").textContent = "No route found";
      document.getElementById("swapBtn").textContent = "No liquidity";
      document.getElementById("swapBtn").disabled = true;
      if (swapMode === "exactIn") {
        document.getElementById("swapToAmount").value = "";
      }
      updateSwapUSDValues();
      return;
    }
    
    // Format the output amount
    const outputAmount = ethers.formatUnits(bestQuote.amountOut, toToken?.decimals || 18);
    
    // Only update the output field if we're in exactIn mode
    if (swapMode === "exactIn") {
      document.getElementById("swapToAmount").value = parseFloat(outputAmount).toFixed(6);
    }
    
    // Update USD values
    updateSwapUSDValues();
    
    // Determine the source name
    const sourceNames = ["Uniswap V2", "Sushiswap", "zAMM", "Uniswap V3", "Uniswap V4"];
    const sourceName = sourceNames[bestQuote.source] || `AMM ${bestQuote.source}`;
    // Add fee information to the source name
    const feeValue = bestQuote.feeBps / 100;
    // Format fee: remove trailing zeros but keep at least 1 decimal place for whole numbers
    let feePercent = feeValue.toFixed(2);
    if (feePercent.endsWith('0') && !feePercent.endsWith('.0')) {
      feePercent = feePercent.slice(0, -1);
    }
    const sourceWithFee = `${sourceName} (${feePercent}% fee)`;
    
    
    // Calculate minimum received with slippage
    const slippage = swapSlippage;
    const minOutput = parseFloat(outputAmount) * (1 - slippage / 100);
    
    // Estimate gas fee
    const gasPrice = await getCachedGasPrice();
    const gasLimit = 150000n; // Realistic gas for swap
    const gasFee = gasPrice.gasPrice * gasLimit;
    const gasFeeETH = ethers.formatEther(gasFee);
    const gasFeeUSD = parseFloat(gasFeeETH) * (tokenPrices["ETH"]?.usd || 0);
    
    // Update UI with quote details
    document.getElementById("swapRoute").textContent = sourceWithFee;
    document.getElementById("swapMinimum").textContent = `${minOutput.toFixed(6)} ${swapToToken}`;
    document.getElementById("swapGasFee").textContent = `$${gasFeeUSD.toFixed(2)}`;
    
    // Store the best quote for execution
    bestSwapRoute = {
      quote: bestQuote,
      tokenIn: tokenInAddress,
      tokenOut: tokenOutAddress,
      amountIn: swapAmount,
      amountOut: bestQuote.amountOut,
      sourceName: sourceWithFee,
      slippage
    };
    
    // Enable swap button
    document.getElementById("swapBtn").textContent = "Swap";
    document.getElementById("swapBtn").disabled = false;
    
  } catch (err) {
    
    document.getElementById("swapRoute").textContent = "Error";
    document.getElementById("swapBtn").textContent = "Try again";
    document.getElementById("swapBtn").disabled = false;
  } finally {
    isSimulating = false;
  }
}

async function executeSwap() {
  if (!wallet) {
    showToast("Please connect wallet first");
    return;
  }
  
  // Check transaction rate limiting for swaps
  const now = Date.now();
  if (now - lastTransactionTime < CONSTANTS.MIN_TX_INTERVAL) {
    showToast("Please wait before executing another transaction");
    return;
  }
  
  // Check pending transaction limit
  if (pendingTransactionCount >= MAX_PENDING_TRANSACTIONS) {
    showToast("Too many pending transactions. Please wait.");
    return;
  }
  
  if (!bestSwapRoute) {
    showToast("Please enter amount to get quote first");
    return;
  }
  
  // Ensure balances are loaded
  await ensureBalancesLoaded();
  
  // Special handling for CULT token - must use ETH pair
  const isCultSwap = swapFromToken === "CULT" || swapToToken === "CULT";
  if (isCultSwap && swapFromToken !== "ETH" && swapToToken !== "ETH") {
    showToast("CULT can only be swapped with ETH");
    return;
  }
  
  // Check sufficient balance
  const fromBalance = currentBalances[swapFromToken];
  if (!fromBalance || (!fromBalance.formatted && fromBalance.formatted !== 0)) {
    showToast(`No ${swapFromToken} balance available`);
    return;
  }
  
  try {
    const decimals = TOKENS[swapFromToken]?.decimals || 18;
    // Use raw balance if available for more accurate comparison
    let balanceWei;
    if (fromBalance.raw !== undefined && fromBalance.raw !== null) {
      balanceWei = BigInt(fromBalance.raw);
      console.log(`Using raw balance for ${swapFromToken}:`, balanceWei.toString());
    } else {
      // Fallback to formatted balance
      const formattedStr = fromBalance.formatted.toString();
      balanceWei = ethers.parseUnits(formattedStr, decimals);
      console.log(`Using formatted balance for ${swapFromToken}:`, formattedStr, "=>", balanceWei.toString());
    }
    
    const amountInBigInt = BigInt(bestSwapRoute.amountIn);
    console.log("Swap validation:", {
      token: swapFromToken,
      balance: balanceWei.toString(),
      needed: amountInBigInt.toString(),
      sufficient: balanceWei >= amountInBigInt
    });
    
    if (balanceWei < amountInBigInt) {
      const needed = ethers.formatUnits(amountInBigInt, decimals);
      const available = ethers.formatUnits(balanceWei, decimals);
      showToast(`Insufficient ${swapFromToken}: need ${parseFloat(needed).toFixed(6)}, have ${parseFloat(available).toFixed(6)}`);
      return;
    }
  } catch (err) {
    console.error("Balance validation error:", err, {
      token: swapFromToken,
      balance: fromBalance,
      route: bestSwapRoute
    });
    showToast("Error validating balance");
    return;
  }
  
  try {
    // Check if we should use EIP-7702 batching
    const needsApproval = swapFromToken !== "ETH";
    const shouldBatch = needsApproval && typeof EIP7702 !== 'undefined' && await EIP7702.shouldUseBatching(
      wallet.address,
      provider,
      needsApproval
    );
    
    // If using 7702 batching, execute batched swap
    if (shouldBatch) {
      await executeBatchedSwap();
      return;
    }
    
    // Regular flow: Check if approval is needed for non-ETH tokens
    if (swapFromToken !== "ETH") {
      const fromToken = TOKENS[swapFromToken];
      const approved = await checkAndRequestApproval(fromToken, bestSwapRoute.amountIn);
      if (!approved) return;
    }
    
    let callData, msgValue;
    const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour deadline
    
    // Check if this is a CULT swap (treat like ERC6909)
    const isCultSwap = swapFromToken === "CULT" || swapToToken === "CULT";
    
    if (bestSwapRoute.isERC6909 || isCultSwap) {
      // Handle ERC6909 and CULT swaps using swapVZ
      const fromToken = TOKENS[swapFromToken];
      const toToken = TOKENS[swapToToken];
      
      // For ZAMM, use max deadline to use the old ZAMM_0 contract
      const vzDeadline = fromToken?.id === ZAMM_ID || toToken?.id === ZAMM_ID 
        ? ethers.MaxUint256 
        : deadline;
      
      // Calculate minimum output with slippage
      const minOutput = bestSwapRoute.amountOut * BigInt(Math.floor((100 - swapSlippage) * 100)) / 10000n;
      
      // Create zRouter contract instance
      const zRouter = new ethers.Contract(ZROUTER_ADDRESS, ZROUTER_ABI, wallet);
      
      // Build swapVZ calldata - need actual token addresses
      const tokenInAddr = swapFromToken === "ETH" ? ethers.ZeroAddress : fromToken.address;
      const tokenOutAddr = swapToToken === "ETH" ? ethers.ZeroAddress : toToken.address;
      
      // For CULT, use special feeOrHook value and 0 for ids; for ERC6909 use normal ids
      const cultFeeOrHook = BigInt("57896044618658097711785492504343953926636021160616296542400437774503196477768");
      let idIn, idOut, feeOrHook;
      if (isCultSwap) {
        // CULT uses special feeOrHook value (0.4% fee) and 0 for ids
        idIn = 0n;
        idOut = 0n;
        feeOrHook = cultFeeOrHook;
      } else {
        // ERC6909 tokens use their ids and swapFee
        idIn = swapFromToken === "ETH" ? 0n : BigInt(fromToken.id || 0);
        idOut = swapToToken === "ETH" ? 0n : BigInt(toToken.id || 0);
        feeOrHook = bestSwapRoute.swapFee || 100n; // Default 100 bps = 1%
      }
      
      const swapVZCall = zRouter.interface.encodeFunctionData("swapVZ", [
        wallet.address, // to
        false, // exactOut = false
        feeOrHook, // feeOrHook (special value for CULT, fee for others)
        tokenInAddr, // tokenIn
        tokenOutAddr, // tokenOut
        idIn, // idIn
        idOut, // idOut
        bestSwapRoute.amountIn, // swapAmount
        minOutput, // amountLimit
        vzDeadline // deadline
      ]);
      
      callData = swapVZCall;
      msgValue = swapFromToken === "ETH" ? bestSwapRoute.amountIn : 0n;
      
    } else {
      // Use zQuoter for regular token swaps
      if (!zQuoterContract) {
        throw new Error("zQuoter contract not initialized");
      }
      
      const slippageBps = Math.floor(bestSwapRoute.slippage * 100); // Convert % to basis points
      
      let swapData;
      try {
        swapData = await zQuoterContract.buildBestSwap(
          wallet.address,
          false, // exactOut = false
          bestSwapRoute.tokenIn,
          bestSwapRoute.tokenOut,
          bestSwapRoute.amountIn,
          slippageBps,
          deadline
        );
      } catch (err) {
        
        showToast("Failed to prepare swap");
        return;
      }
      
      // Extract the calldata and value
      callData = swapData.callData;
      msgValue = swapData.msgValue;
    }
    
    // Simulate the swap transaction before showing confirmation
    const statusEl = document.getElementById("swapStatus");
    statusEl.innerHTML = '<div class="status">🔍 Simulating swap...</div>';
    
    const swapSimulation = await simulateTransaction({
      from: wallet.address,
      to: ZROUTER_ADDRESS, // Always use zRouter for swaps
      data: callData,
      value: msgValue,
      gasLimit: 300000
    });
    
    if (!swapSimulation.success) {
      statusEl.innerHTML = `<div class="status error">Swap would fail: ${swapSimulation.error}</div>`;
      return;
    }
    
    statusEl.innerHTML = '<div class="status success">✅ Ready to swap</div>';
    
    // Show confirmation modal
    const modal = document.getElementById("swapConfirmModal");
    const fromToken = TOKENS[swapFromToken];
    const toToken = TOKENS[swapToToken];
    
    // Populate confirmation details
    const inputFormatted = ethers.formatUnits(bestSwapRoute.amountIn, fromToken?.decimals || 18);
    const outputFormatted = ethers.formatUnits(bestSwapRoute.amountOut, toToken?.decimals || 18);
    
    document.getElementById("confirmSwapFrom").textContent = `${parseFloat(inputFormatted).toFixed(6)} ${swapFromToken}`;
    document.getElementById("confirmSwapTo").textContent = `${parseFloat(outputFormatted).toFixed(6)} ${swapToToken}`;
    document.getElementById("confirmSwapRoute").textContent = bestSwapRoute.sourceName || "Best Route";
    document.getElementById("confirmSwapSlippage").textContent = `${swapSlippage}%`;
    
    // Use the already calculated minOutput
    const minOutputBigInt = bestSwapRoute.amountOut * BigInt(Math.floor((100 - swapSlippage) * 100)) / 10000n;
    const minFormatted = ethers.formatUnits(minOutputBigInt, toToken?.decimals || 18);
    document.getElementById("confirmSwapMinimum").textContent = `${parseFloat(minFormatted).toFixed(6)} ${swapToToken}`;
    
    const gasPrice = (await getCachedGasPrice()).maxFeePerGas || ethers.parseUnits("30", "gwei");
    const gasLimit = 150000n; // Realistic estimate
    const gasCost = gasLimit * gasPrice;
    const gasCostEth = ethers.formatEther(gasCost);
    document.getElementById("confirmSwapGas").textContent = `${parseFloat(gasCostEth).toFixed(5)} ETH`;
    
    const totalCostEth = swapFromToken === "ETH" 
      ? parseFloat(inputFormatted) + parseFloat(gasCostEth)
      : parseFloat(gasCostEth);
    document.getElementById("confirmSwapTotal").textContent = `${totalCostEth.toFixed(6)} ETH`;
    
    // Setup calldata display
    const calldataDisplay = document.getElementById("swapCalldataDisplay");
    if (calldataDisplay) calldataDisplay.value = callData || '';
    
    // Setup Swiss Knife decoder link with correct format
    const swissKnifeLink = document.getElementById("swapSwissKnifeLink");
    if (swissKnifeLink) {
      if (callData && callData !== '0x' && callData.length > 2) {
        // Use the correct decoder URL format
        const simulationUrl = `https://calldata.swiss-knife.xyz/decoder?calldata=${callData}`;
        
        // Set both href and onclick for maximum compatibility
        swissKnifeLink.href = simulationUrl;
        swissKnifeLink.target = '_blank';
        swissKnifeLink.style.display = 'inline-block';
        
        // Override click behavior for extension compatibility
        swissKnifeLink.onclick = (e) => {
          e.preventDefault();
          if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({ action: 'open_external', url: simulationUrl });
          } else {
            window.open(simulationUrl, '_blank', 'noopener,noreferrer');
          }
        };
      } else {
        swissKnifeLink.style.display = 'none';
      }
    }
    
    const toggleBtn = document.getElementById("toggleSwapCalldata");
    const calldataSection = document.getElementById("swapCalldataSection");
    
    // Auto-show calldata section if there's a simulation link
    if (calldataSection && callData && callData !== '0x' && callData.length > 2) {
      calldataSection.classList.remove("hidden");
      if (toggleBtn) toggleBtn.textContent = "Hide";
    }
    
    if (toggleBtn) {
      toggleBtn.onclick = () => {
        if (calldataSection.classList.contains("hidden")) {
          calldataSection.classList.remove("hidden");
          toggleBtn.textContent = "Hide";
        } else {
          calldataSection.classList.add("hidden");
          toggleBtn.textContent = "Show";
        }
      };
    }
    
    modal.classList.remove("hidden");
    
    // Use the secure confirmation helper
    const confirmBtn = document.getElementById("confirmSwapBtn");
    const cancelBtn = document.getElementById("cancelSwapBtn");
    
    const userConfirmed = await createSecureConfirmation(confirmBtn, cancelBtn, null);
    
    // Hide modal after decision
    modal.classList.add("hidden");
    
    if (!userConfirmed) {
      statusEl.innerHTML = '<div class="status">Swap cancelled</div>';
      return;
    }
    
    // Update rate limiting tracking
    lastTransactionTime = Date.now();
    pendingTransactionCount++;
    
    try {
      // Execute the swap
      document.getElementById("swapStatus").innerHTML = '<div style="color: var(--warning)">Sending transaction...</div>';
      
      // Get current nonce for replay protection
      const nonce = await wallet.getNonce();
      
      const tx = await wallet.sendTransaction({
      to: ZROUTER_ADDRESS,
      data: callData,
      value: msgValue,
      nonce: nonce
    });
    
    document.getElementById("swapStatus").innerHTML = `<div style="color: var(--info)">Transaction sent: ${tx.hash.slice(0, 10)}...</div>`;
    
    // Wait for confirmation
    const receipt = await tx.wait();
    
    // Decrement pending transaction count
    pendingTransactionCount = Math.max(0, pendingTransactionCount - 1);
    
    if (receipt.status === 1) {
      // Show success message with appropriate explorer link
      const explorerUrl = isBaseMode 
        ? `https://basescan.org/tx/${tx.hash}`
        : `https://etherscan.io/tx/${tx.hash}`;
      const explorerName = isBaseMode ? "Basescan" : "Etherscan";
      
      const swapStatus = document.getElementById("swapStatus");
      swapStatus.innerHTML = '';
      const successDiv = document.createElement('div');
      successDiv.style.cssText = "color: var(--success); font-weight: bold; margin-bottom: 8px;";
      successDiv.textContent = "✓ Swap successful!";
      swapStatus.appendChild(successDiv);
      
      const link = createExternalLink(
        explorerUrl,
        `View on ${explorerName} →`,
        "color: var(--accent); text-decoration: underline; font-size: 12px;"
      );
      swapStatus.appendChild(link);
      
      showToast("Swap successful!");
      
      // Clear inputs and refresh balances
      document.getElementById("swapFromAmount").value = "";
      document.getElementById("swapToAmount").value = "";
      clearSwapQuote();
      await fetchAllBalances();
    } else {
      throw new Error("Transaction failed");
    }
    } finally {
      // Always decrement pending transaction count
      pendingTransactionCount = Math.max(0, pendingTransactionCount - 1);
    }
    
  } catch (err) {
    
    // Parse common error messages for better UX
    let errorMessage = err.message || "Unknown error";
    if (errorMessage.includes("insufficient funds")) {
      errorMessage = "Insufficient balance for gas fees";
    } else if (errorMessage.includes("slippage")) {
      errorMessage = "Price changed too much - try increasing slippage";
    } else if (errorMessage.includes("user rejected") || errorMessage.includes("denied")) {
      errorMessage = "Transaction cancelled";
    }
    
    document.getElementById("swapStatus").innerHTML = `<div style="color: var(--error)">✗ ${errorMessage}</div>`;
    showToast(`Swap failed: ${errorMessage}`);
  }
}

// Execute batched swap using EIP-7702 delegation
async function executeBatchedSwap() {
  try {
    const fromToken = TOKENS[swapFromToken];
    const statusEl = document.getElementById("swapStatus");
    
    // Show batching indicator with clear UX
    statusEl.innerHTML = '<div class="status">🚀 Preparing optimized transaction...<span class="batch-indicator">⚡ 7702</span></div>';
    
    // First check if delegation is active
    const delegation = await EIP7702.checkDelegation(wallet.address, provider);
    if (!delegation.isOurExecutor) {
      statusEl.innerHTML = `
        <div class="status info">
          <div style="margin-bottom: 8px;">🔗 First-time setup required</div>
          <div style="font-size: 11px; opacity: 0.9;">We'll enable batching to save you gas on future swaps.</div>
        </div>
      `;
      await new Promise(resolve => setTimeout(resolve, 2000)); // Give user time to read
    }
    
    // Get approval data
    const approvalPayload = fromToken.isERC6909
      ? await zWalletContract.checkERC6909RouterIsOperator(wallet.address, fromToken.address)
      : await zWalletContract.checkERC20RouterApproval(wallet.address, fromToken.address, bestSwapRoute.amountIn, true);
    
    if (!approvalPayload || approvalPayload === "0x") {
      // Already approved, no need for batching - execute swap directly
      showToast("Already approved, executing regular swap");
      statusEl.innerHTML = '<div class="status">Already approved, executing swap...</div>';
      
      // Get swap calldata and execute directly
      const deadline = Math.floor(Date.now() / 1000) + 3600;
      let swapCallData, msgValue;
      
      // Build swap calldata based on route type
      if (bestSwapRoute.isERC6909 || swapFromToken === "CULT" || swapToToken === "CULT") {
        const toToken = TOKENS[swapToToken];
        swapCallData = await zWalletContract.swapVZ.populateTransaction(
          fromToken.address,
          fromToken.isNative ? ethers.ZeroAddress : fromToken.address,
          toToken.isNative ? ethers.ZeroAddress : toToken.address,
          bestSwapRoute.amountIn,
          bestSwapRoute.amountOut,
          wallet.address,
          deadline
        ).then(tx => tx.data);
        msgValue = swapFromToken === "ETH" ? bestSwapRoute.amountIn : 0n;
      } else if (swapFromToken === "ETH") {
        swapCallData = await zWalletContract.swapExactETHForTokens.populateTransaction(
          bestSwapRoute.amountOut,
          [WETH_ADDRESS[chainId], TOKENS[swapToToken].address],
          wallet.address,
          deadline
        ).then(tx => tx.data);
        msgValue = bestSwapRoute.amountIn;
      } else if (swapToToken === "ETH") {
        swapCallData = await zWalletContract.swapExactTokensForETH.populateTransaction(
          bestSwapRoute.amountIn,
          bestSwapRoute.amountOut,
          [fromToken.address, WETH_ADDRESS[chainId]],
          wallet.address,
          deadline
        ).then(tx => tx.data);
        msgValue = 0n;
      } else {
        const toToken = TOKENS[swapToToken];
        swapCallData = await zWalletContract.swapExactTokensForTokens.populateTransaction(
          bestSwapRoute.amountIn,
          bestSwapRoute.amountOut,
          [fromToken.address, toToken.address],
          wallet.address,
          deadline
        ).then(tx => tx.data);
        msgValue = 0n;
      }
      
      try {
        const swapTx = await wallet.sendTransaction({
          to: ZROUTER_ADDRESS,
          data: swapCallData,
          value: msgValue,
          ...gasPrices.normal
        });
        
        statusEl.innerHTML = `<div style="color: var(--info)">Swap tx sent: ${swapTx.hash.slice(0, 10)}...</div>`;
        const receipt = await swapTx.wait();
        
        if (receipt.status === 1) {
          statusEl.innerHTML = '<div style="color: var(--success)">✓ Swap successful!</div>';
          showToast("Swap successful!");
          await fetchAllBalances();
        }
      } catch (err) {
        statusEl.innerHTML = `<div style="color: var(--error)">✗ Swap failed: ${err.message}</div>`;
        showToast(`Swap failed: ${err.message}`);
      }
      return;
    }
    
    // Get swap calldata
    let swapCallData, msgValue;
    const deadline = Math.floor(Date.now() / 1000) + 3600;
    
    // Check if this is a CULT swap (treat like ERC6909)
    const isCultSwap = swapFromToken === "CULT" || swapToToken === "CULT";
    
    if (bestSwapRoute.isERC6909 || isCultSwap) {
      // Handle ERC6909 and CULT swaps using swapVZ
      const toToken = TOKENS[swapToToken];
      
      // For ZAMM, use max deadline to use the old ZAMM_0 contract
      const vzDeadline = fromToken?.id === ZAMM_ID || toToken?.id === ZAMM_ID 
        ? ethers.MaxUint256 
        : deadline;
      
      // Calculate minimum output with slippage
      const minOutput = bestSwapRoute.amountOut * BigInt(Math.floor((100 - swapSlippage) * 100)) / 10000n;
      
      // Create zRouter contract instance
      const zRouter = new ethers.Contract(ZROUTER_ADDRESS, ZROUTER_ABI, wallet);
      
      // Build swapVZ calldata - need actual token addresses
      const tokenInAddr = swapFromToken === "ETH" ? ethers.ZeroAddress : fromToken.address;
      const tokenOutAddr = swapToToken === "ETH" ? ethers.ZeroAddress : toToken.address;
      
      // For CULT, use special feeOrHook value and 0 for ids; for ERC6909 use normal ids
      const cultFeeOrHook = BigInt("57896044618658097711785492504343953926636021160616296542400437774503196477768");
      let idIn, idOut, feeOrHook;
      if (isCultSwap) {
        // CULT uses special feeOrHook value (0.4% fee) and 0 for ids
        idIn = 0n;
        idOut = 0n;
        feeOrHook = cultFeeOrHook;
      } else {
        // ERC6909 tokens use their ids and swapFee
        idIn = swapFromToken === "ETH" ? 0n : BigInt(fromToken.id || 0);
        idOut = swapToToken === "ETH" ? 0n : BigInt(toToken.id || 0);
        feeOrHook = bestSwapRoute.swapFee || 100n; // Default 100 bps = 1%
      }
      
      swapCallData = zRouter.interface.encodeFunctionData("swapVZ", [
        wallet.address, // to
        false, // exactOut = false
        feeOrHook, // feeOrHook (special value for CULT, fee for others)
        tokenInAddr, // tokenIn
        tokenOutAddr, // tokenOut
        idIn, // idIn
        idOut, // idOut
        bestSwapRoute.amountIn, // swapAmount
        minOutput, // amountLimit
        vzDeadline // deadline
      ]);
      
      msgValue = swapFromToken === "ETH" ? bestSwapRoute.amountIn : 0n;
    } else {
      // Use zQuoter for regular token swaps
      if (!zQuoterContract) {
        throw new Error("zQuoter contract not initialized");
      }
      
      const slippageBps = Math.floor(bestSwapRoute.slippage * 100); // Convert % to basis points
      
      let swapData;
      try {
        swapData = await zQuoterContract.buildBestSwap(
          wallet.address,
          false, // exactOut = false
          bestSwapRoute.tokenIn,
          bestSwapRoute.tokenOut,
          bestSwapRoute.amountIn,
          slippageBps,
          deadline
        );
      } catch (err) {
        
        showToast("Failed to prepare swap");
        return;
      }
      
      // Extract the calldata and value
      swapCallData = swapData.callData;
      msgValue = swapData.msgValue;
    }
    
    // Show simulation status if already delegated
    if (delegation.isOurExecutor) {
      statusEl.innerHTML = `
        <div class="status">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="spinner" style="display: inline-block; width: 12px; height: 12px; border: 2px solid var(--dim); border-top-color: var(--accent); border-radius: 50%; animation: spin 1s linear infinite;"></span>
            <span>Simulating optimized transaction...</span>
            <span class="batch-indicator">⚡ 7702</span>
          </div>
        </div>
        <style>
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
        </style>
      `;
    }
    
    // Create batched transaction (includes simulation)
    let batchedTx;
    try {
      batchedTx = await EIP7702.createBatchedSwapTx({
        signer: wallet,
        tokenAddress: fromToken.address,
        spenderAddress: ZROUTER_ADDRESS,
        approveAmount: bestSwapRoute.amountIn,
        approveData: approvalPayload,
        swapData: swapCallData,
        swapTarget: ZROUTER_ADDRESS,
        swapValue: msgValue.toString(),
        gasSettings: gasPrices.normal || {
          maxFeePerGas: ethers.parseUnits("30", "gwei"),
          maxPriorityFeePerGas: ethers.parseUnits("2", "gwei")
        },
        simulate: true // Enable simulation
      });
      
      // If we get here, simulation passed (or delegation wasn't set yet)
      if (delegation.isOurExecutor) {
        statusEl.innerHTML = '<div class="status success">✓ Simulation successful<span class="batch-indicator">⚡ 7702 Batch</span></div>';
      }
    } catch (simError) {
      // Simulation failed - show error and abort
      statusEl.innerHTML = `<div class="status error">Simulation failed: ${simError.message}</div>`;
      showToast(`Transaction would fail: ${simError.message}`);
      return;
    }
    
    // Show confirmation modal with batch indicator
    const modal = document.getElementById("swapConfirmModal");
    const fromFormatted = ethers.formatUnits(bestSwapRoute.amountIn, fromToken?.decimals || 18);
    const toToken = TOKENS[swapToToken];
    const toFormatted = ethers.formatUnits(bestSwapRoute.amountOut, toToken?.decimals || 18);
    
    // Populate confirmation details
    document.getElementById("confirmSwapFrom").textContent = `${parseFloat(fromFormatted).toFixed(6)} ${swapFromToken}`;
    document.getElementById("confirmSwapTo").textContent = `${parseFloat(toFormatted).toFixed(6)} ${swapToToken}`;
    document.getElementById("confirmSwapRoute").textContent = bestSwapRoute.sourceName || "Best Route";
    document.getElementById("confirmSwapSlippage").textContent = `${swapSlippage}%`;
    
    const minOutputBigInt = bestSwapRoute.amountOut * BigInt(Math.floor((100 - swapSlippage) * 100)) / 10000n;
    const minFormatted = ethers.formatUnits(minOutputBigInt, toToken?.decimals || 18);
    document.getElementById("confirmSwapMinimum").textContent = `${parseFloat(minFormatted).toFixed(6)} ${swapToToken}`;
    
    const gasPrice = (await getCachedGasPrice()).maxFeePerGas || ethers.parseUnits("30", "gwei");
    const gasLimit = 200000n; // Higher for batched tx
    const regularGasLimit = 300000n; // Approve + swap separately
    const gasCost = gasLimit * gasPrice;
    const regularGasCost = regularGasLimit * gasPrice;
    const gasSaved = regularGasCost - gasCost;
    const gasCostEth = ethers.formatEther(gasCost);
    const gasSavedEth = ethers.formatEther(gasSaved);
    
    // Show gas savings
    document.getElementById("confirmSwapGas").innerHTML = `
      <span>${parseFloat(gasCostEth).toFixed(5)} ETH</span>
      <span style="color: var(--success); font-size: 10px; margin-left: 8px;">
        💰 Save ~${parseFloat(gasSavedEth).toFixed(5)} ETH vs 2 txs
      </span>
    `;
    
    const totalCostEth = swapFromToken === "ETH" 
      ? parseFloat(fromFormatted) + parseFloat(gasCostEth)
      : parseFloat(gasCostEth);
    document.getElementById("confirmSwapTotal").textContent = `${totalCostEth.toFixed(6)} ETH`;
    
    // Add batch indicator to the modal
    const modalTitle = modal.querySelector("h3");
    if (modalTitle && !modalTitle.innerHTML.includes("Batched")) {
      modalTitle.innerHTML = 'Confirm Swap <span class="batch-indicator">⚡ 7702</span>';
    }
    
    // Setup calldata display for batched transaction
    const calldataDisplay = document.getElementById("swapCalldataDisplay");
    if (calldataDisplay) {
      // For batched transactions, show the data field from the transaction
      calldataDisplay.value = batchedTx.data || '0x';
    }
    
    // Setup Swiss Knife decoder link for batched transaction
    const swissKnifeLink = document.getElementById("swapSwissKnifeLink");
    if (swissKnifeLink && batchedTx.data && batchedTx.data !== '0x' && batchedTx.data.length > 2) {
      const simulationUrl = `https://calldata.swiss-knife.xyz/decoder?calldata=${batchedTx.data}`;
      
      swissKnifeLink.href = simulationUrl;
      swissKnifeLink.target = '_blank';
      swissKnifeLink.style.display = 'inline-block';
      
      swissKnifeLink.onclick = (e) => {
        e.preventDefault();
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ action: 'open_external', url: simulationUrl });
        } else {
          window.open(simulationUrl, '_blank', 'noopener,noreferrer');
        }
      };
    } else if (swissKnifeLink) {
      swissKnifeLink.style.display = 'none';
    }
    
    // Auto-show calldata section for batched transactions
    const calldataSection = document.getElementById("swapCalldataSection");
    const toggleBtn = document.getElementById("toggleSwapCalldata");
    if (calldataSection && batchedTx.data && batchedTx.data !== '0x') {
      calldataSection.classList.remove("hidden");
      if (toggleBtn) toggleBtn.textContent = "Hide";
    }
    
    modal.classList.remove("hidden");
    
    // Wait for user confirmation
    const confirmBtn = document.getElementById("confirmSwapBtn");
    const cancelBtn = document.getElementById("cancelSwapBtn");
    
    const userConfirmed = await new Promise((resolve) => {
      const handleConfirm = () => {
        confirmBtn.removeEventListener("click", handleConfirm);
        cancelBtn.removeEventListener("click", handleCancel);
        resolve(true);
      };
      const handleCancel = () => {
        confirmBtn.removeEventListener("click", handleConfirm);
        cancelBtn.removeEventListener("click", handleCancel);
        resolve(false);
      };
      confirmBtn.addEventListener("click", handleConfirm);
      cancelBtn.addEventListener("click", handleCancel);
    });
    
    modal.classList.add("hidden");
    
    if (!userConfirmed) {
      statusEl.innerHTML = '<div class="status">Swap cancelled</div>';
      return;
    }
    
    // Send batched transaction
    statusEl.innerHTML = '<div style="color: var(--warning)">Sending batched transaction...</div>';
    
    // If already delegated, it's a regular tx. Otherwise, it's type-4
    const tx = batchedTx.type === 4 
      ? await EIP7702.sendType4Transaction(wallet, batchedTx)
      : await wallet.sendTransaction(batchedTx);
    
    statusEl.innerHTML = `<div style="color: var(--info)">Batched tx sent: ${tx.hash.slice(0, 10)}...</div>`;
    
    const receipt = await tx.wait();
    
    if (receipt.status === 1) {
      const explorerUrl = isBaseMode 
        ? `https://basescan.org/tx/${tx.hash}`
        : `https://etherscan.io/tx/${tx.hash}`;
      
      statusEl.innerHTML = '';
      const successDiv = document.createElement('div');
      successDiv.style.cssText = "color: var(--success); font-weight: bold; margin-bottom: 8px;";
      successDiv.innerHTML = '✓ Batched swap successful! <span class="batch-indicator">⚡ 7702</span>';
      statusEl.appendChild(successDiv);
      
      const link = createExternalLink(
        explorerUrl,
        `View on ${isBaseMode ? "Basescan" : "Etherscan"} →`,
        "color: var(--accent); text-decoration: underline; font-size: 12px;"
      );
      statusEl.appendChild(link);
      
      showToast("Batched swap successful!");
      
      // Clear inputs and refresh
      document.getElementById("swapFromAmount").value = "";
      document.getElementById("swapToAmount").value = "";
      clearSwapQuote();
      await fetchAllBalances();
    } else {
      throw new Error("Transaction failed");
    }
    
  } catch (err) {
    console.error("Batched swap error:", err);
    document.getElementById("swapStatus").innerHTML = `<div style="color: var(--error)">✗ Batched swap failed: ${err.message}</div>`;
    showToast(`Batched swap failed: ${err.message}`);
  }
}

async function checkAndRequestApproval(token, amount) {
  if (!token || !token.address || !zWalletContract) return true;
  
  try {
    // Get approval payload from contract - it handles both ERC20 and ERC6909
    const approvalPayload = token.isERC6909
      ? await zWalletContract.checkERC6909RouterIsOperator(wallet.address, token.address)
      : await zWalletContract.checkERC20RouterApproval(wallet.address, token.address, amount, true);
    
    // If no payload or empty, already approved
    if (!approvalPayload || approvalPayload === "0x") {
      return true;
    }
    
    // Show approval modal with calldata
    const approvalConfirmed = await showApprovalModal(token, token.isERC6909, approvalPayload);
    if (!approvalConfirmed) return false;
    
    // Update status
    const statusEl = document.getElementById("swapStatus");
    if (statusEl) {
      statusEl.innerHTML = `<div class="status">Approving ${token.symbol}...</div>`;
    }
    
    // Execute approval with proper gas estimation and settings
    let gasLimit = token.isERC6909 ? 80000n : 60000n; // Default limits for approvals
    const estimated = await estimateGasWithCache({
      from: wallet.address,
      to: token.address,
      data: approvalPayload
    });
    if (estimated) {
      gasLimit = (estimated * 110n) / 100n; // 10% buffer
    }
    
    // Use current gas prices
    const gasSettings = gasPrices.normal || {
      maxFeePerGas: ethers.parseUnits("30", "gwei"),
      maxPriorityFeePerGas: ethers.parseUnits("2", "gwei")
    };
    
    const approveTx = await wallet.sendTransaction({
      to: token.address,
      data: approvalPayload,
      gasLimit: gasLimit,
      ...gasSettings
    });
    
    const explorerUrl = isBaseMode 
      ? `https://basescan.org/tx/${approveTx.hash}`
      : `https://etherscan.io/tx/${approveTx.hash}`;
    
    if (statusEl) {
      statusEl.innerHTML = '';
      const waitingDiv = document.createElement('div');
      waitingDiv.className = 'status';
      waitingDiv.textContent = 'Waiting for approval... ';
      
      const viewLink = createExternalLink(
        explorerUrl,
        'View →',
        'color: var(--accent);'
      );
      waitingDiv.appendChild(viewLink);
      statusEl.appendChild(waitingDiv);
    }
    
    const receipt = await approveTx.wait();
    
    if (receipt.status === 1) {
      showToast(`${token.symbol} approved!`);
      if (statusEl) {
        statusEl.innerHTML = '';
        const successDiv = document.createElement('div');
        successDiv.className = 'status success';
        successDiv.textContent = `✓ ${token.symbol} approved! `;
        
        const viewLink = createExternalLink(
          explorerUrl,
          'View →',
          'color: var(--accent);'
        );
        successDiv.appendChild(viewLink);
        statusEl.appendChild(successDiv);
      }
    }
    return true;
    
  } catch (err) {
    const statusEl = document.getElementById("swapStatus");
    if (statusEl) {
      statusEl.innerHTML = '<div class="status error">Approval failed</div>';
    }
    return false;
  }
}

// Approval checking is now consolidated in checkAndRequestApproval function

async function showApprovalModal(token, isERC6909, calldata) {
  return new Promise((resolve) => {
    // Create a simple approval modal
    const modalHtml = `
      <div id="approvalModal" class="modal">
        <div class="modal-content">
          <div class="modal-header">
            <h3>Approval Required</h3>
            <button class="modal-close" id="approvalModalClose">×</button>
          </div>
          <div class="modal-body">
            <div class="warning" style="margin-bottom: 16px;">
              ⚠️ First-time swap requires approval
            </div>
            <div class="confirm-row">
              <span class="confirm-label">Token:</span>
              <span class="confirm-value">${token.symbol}</span>
            </div>
            <div class="confirm-row">
              <span class="confirm-label">Contract:</span>
              <span class="confirm-value mono" style="font-size: 10px;">${token.address.slice(0, 6)}...${token.address.slice(-4)}</span>
            </div>
            <div class="confirm-row">
              <span class="confirm-label">Approval Type:</span>
              <span class="confirm-value">${isERC6909 ? 'ERC6909 Operator' : 'ERC20 Allowance'}</span>
            </div>
            <div class="confirm-row">
              <span class="confirm-label">Spender:</span>
              <span class="confirm-value mono" style="font-size: 10px;">zRouter: ${ZROUTER_ADDRESS.slice(0, 6)}...${ZROUTER_ADDRESS.slice(-4)}</span>
            </div>
            <div style="margin-top: 12px; padding: 12px; background: var(--info-bg); border: 1px solid var(--border); font-size: 11px;">
              ${isERC6909 
                ? 'This will grant zRouter permission to transfer your ERC6909 tokens (like ZAMM) for swapping.'
                : 'This will grant zRouter permission to spend your tokens for swapping. This is a one-time approval.'}
            </div>
            <!-- Calldata Preview -->
            <div style="margin-top: 16px;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <label style="font-weight: bold; font-size: 12px;">Transaction Data</label>
                <button id="toggleApprovalCalldata" style="padding: 4px 8px; font-size: 11px; background: var(--bg); border: 1px solid var(--border); cursor: pointer;">Show</button>
              </div>
              <div id="approvalCalldataSection" style="display: none; margin-top: 8px;">
                <textarea id="approvalCalldataDisplay" readonly style="width: 100%; height: 80px; font-family: 'Courier New', monospace; font-size: 10px; resize: none; padding: 8px; border: 1px solid var(--border); background: var(--input-bg); color: var(--fg);">${calldata || ''}</textarea>
                <a id="approvalSwissKnifeLink" href="#" style="display: inline-block; margin-top: 8px; font-size: 11px; color: var(--accent); text-decoration: underline;">
                  Decode with Swiss Knife →
                </a>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button id="confirmApproval" class="btn-confirm">Approve</button>
            <button id="cancelApproval" class="btn-cancel">Cancel</button>
          </div>
        </div>
      </div>
    `;
    
    // Add modal to page
    const modalDiv = document.createElement('div');
    modalDiv.innerHTML = modalHtml;
    document.body.appendChild(modalDiv);
    
    // Add toggle handler for calldata
    const toggleBtn = document.getElementById('toggleApprovalCalldata');
    const calldataSection = document.getElementById('approvalCalldataSection');
    if (toggleBtn && calldataSection) {
      toggleBtn.addEventListener('click', () => {
        const isHidden = calldataSection.style.display === 'none';
        calldataSection.style.display = isHidden ? 'block' : 'none';
        toggleBtn.textContent = isHidden ? 'Hide' : 'Show';
      });
    }
    
    // Setup Swiss Knife decoder link with correct format (same as swap)
    const swissKnifeLink = document.getElementById('approvalSwissKnifeLink');
    if (swissKnifeLink && calldata && calldata !== '0x' && calldata.length > 2) {
      const decoderUrl = `https://calldata.swiss-knife.xyz/decoder?calldata=${calldata}`;
      
      swissKnifeLink.href = decoderUrl;
      swissKnifeLink.target = '_blank';
      
      // Override click behavior for extension compatibility
      swissKnifeLink.onclick = (e) => {
        e.preventDefault();
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ action: 'open_external', url: decoderUrl });
        } else {
          window.open(decoderUrl, '_blank', 'noopener,noreferrer');
        }
      };
    } else if (swissKnifeLink) {
      swissKnifeLink.style.display = 'none';
    }
    
    const confirmBtn = document.getElementById('confirmApproval');
    const cancelBtn = document.getElementById('cancelApproval');
    const closeBtn = document.getElementById('approvalModalClose');
    
    const cleanup = () => {
      document.body.removeChild(modalDiv);
      resolve(false);
    };
    
    const handleConfirm = () => {
      document.body.removeChild(modalDiv);
      resolve(true);
    };
    
    confirmBtn.addEventListener('click', handleConfirm);
    cancelBtn.addEventListener('click', cleanup);
    closeBtn.addEventListener('click', cleanup);
  });
}

// Mobile optimizations
function initMobileOptimizations() {
  // Detect if mobile - exclude desktop with touch screens
  const isMobileDevice = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
  const isSmallScreen = window.innerWidth <= 768;
  const isMobile = isMobileDevice || (isSmallScreen && 'ontouchstart' in window);
  
  if (isMobile && !window.matchMedia('(pointer: fine)').matches) {
    // Prevent pull-to-refresh on mobile
    let startY = 0;
    document.addEventListener('touchstart', (e) => {
      startY = e.touches[0].pageY;
    }, { passive: true });
    
    document.addEventListener('touchmove', (e) => {
      const y = e.touches[0].pageY;
      const scrollTop = document.documentElement.scrollTop || document.body.scrollTop;
      
      // Prevent overscroll at top (but allow in scrollable elements)
      if (scrollTop === 0 && y > startY && !e.target.closest('.modal-content, .token-dropdown')) {
        e.preventDefault();
      }
    }, { passive: false });
    
    // Better touch feedback
    document.addEventListener('touchstart', (e) => {
      const target = e.target.closest('button, .tab, .token-row, .token-option');
      if (target) {
        target.style.transform = 'scale(0.98)';
        target.style.opacity = '0.9';
      }
    }, { passive: true });
    
    document.addEventListener('touchend', (e) => {
      const target = e.target.closest('button, .tab, .token-row, .token-option');
      if (target) {
        target.style.transform = '';
        target.style.opacity = '';
      }
    }, { passive: true });
    
    // Fix iOS keyboard issues
    let scrollPosition = 0;
    const inputs = document.querySelectorAll('input:not([readonly]), textarea');
    inputs.forEach(input => {
      input.addEventListener('focus', () => {
        scrollPosition = window.pageYOffset;
        // Delay to let keyboard open
        setTimeout(() => {
          input.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 300);
      });
      
      input.addEventListener('blur', () => {
        // Restore scroll position after keyboard closes
        window.scrollTo(0, scrollPosition);
      });
    });
  }
}

// Initialize app with proper error handling
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initPasswordModal();
    initMobileOptimizations();
    
    // Attach click handlers to the main etherscan link
    const etherscanLink = document.getElementById('etherscanLink');
    if (etherscanLink) {
      etherscanLink.addEventListener('click', (e) => {
        e.preventDefault();
        openExternalUrl(etherscanLink.href);
      });
    }
    
    // Attach handlers to any existing external links
    attachLinkHandlers();
    
    init().catch(() => {
      // Show user-friendly error
      const errorDiv = document.createElement('div');
      errorDiv.className = 'status error';
      errorDiv.textContent = 'Failed to initialize wallet. Please reload.';
      document.body.appendChild(errorDiv);
    });
  });
} else {
  initPasswordModal();
  initMobileOptimizations();
  
  // Attach click handlers to the main etherscan link
  const etherscanLink = document.getElementById('etherscanLink');
  if (etherscanLink) {
    etherscanLink.addEventListener('click', (e) => {
      e.preventDefault();
      openExternalUrl(etherscanLink.href);
    });
  }
  
  // Attach handlers to any existing external links
  attachLinkHandlers();
  
  init().catch(() => {
    // Error already handled in init function
  });
}

// Bridge Tab Functions
const BASE_BRIDGE_CONTRACT = "0x49048044D57e1C92A77f79988d21Fa8fAF74E97e";
let pendingBridgeTx = null;

function setupBridgeEventListeners() {
  // Bridge amount input
  const bridgeAmountInput = document.getElementById("bridgeAmount");
  if (bridgeAmountInput) {
    bridgeAmountInput.addEventListener("input", debounce(() => {
      updateBridgeEstimates();
    }, 300));
  }
  
  // Bridge Max button
  const bridgeMaxBtn = document.getElementById("bridgeMaxBtn");
  if (bridgeMaxBtn) {
    bridgeMaxBtn.addEventListener("click", async () => {
      if (!wallet || !provider) {
        showToast("Please connect wallet first");
        return;
      }
      
      try {
        // Ensure balances are loaded first
        if (!currentBalances || !currentBalances["ETH"] || Object.keys(currentBalances).length === 0) {
          showToast("Loading balances...");
          await fetchAllBalances();
        }
        
        // Use the cached balance instead of making another call
        const balanceObj = currentBalances["ETH"];
        if (!balanceObj || !balanceObj.raw) {
          showToast("No ETH balance available");
          return;
        }
        
        const balance = balanceObj.raw;
        
        // Estimate gas for bridge transaction
        const gasPrice = await getCachedGasPrice();
        const gasLimit = 130000n; // Actual bridge gas usage
        const gasCost = gasLimit * gasPrice.maxFeePerGas;
        
        // Calculate max amount (balance - gas)
        const maxAmount = balance - gasCost;
        
        if (maxAmount > 0n) {
          const formattedAmount = ethers.formatEther(maxAmount);
          bridgeAmountInput.value = formattedAmount;
          updateBridgeEstimates();
        } else {
          showToast("Insufficient balance for gas");
        }
      } catch (err) {
        console.error("Error calculating max bridge amount:", err);
        showToast("Error calculating max amount");
      }
    });
  }
  
  // Bridge button
  const bridgeBtn = document.getElementById("bridgeBtn");
  if (bridgeBtn) {
    bridgeBtn.addEventListener("click", prepareBridge);
  }
  
  // Bridge confirmation modal
  document.getElementById("bridgeModalClose")?.addEventListener("click", () => {
    document.getElementById("bridgeConfirmModal")?.classList.add("hidden");
  });
  
  document.getElementById("cancelBridgeBtn")?.addEventListener("click", () => {
    document.getElementById("bridgeConfirmModal")?.classList.add("hidden");
    pendingBridgeTx = null;
  });
  
  document.getElementById("confirmBridgeBtn")?.addEventListener("click", executeBridge);
  
  // Update balance when switching to bridge tab
  document.querySelector('.tab[data-tab="bridge"]')?.addEventListener("click", () => {
    updateBridgeBalance();
  });
}

async function updateBridgeBalance() {
  const balanceEl = document.getElementById("bridgeBalance");
  
  if (!wallet || !provider) {
    if (balanceEl) balanceEl.textContent = "0.0000";
    return;
  }
  
  try {
    // Force fetch if no balances or missing ETH balance (same logic as Send tab)
    if (!currentBalances || Object.keys(currentBalances).length === 0 || !currentBalances["ETH"]) {
      console.log("Bridge tab: Fetching balances because ETH balance missing");
      await fetchAllBalances(true); // Force refresh
      // Wait a bit for balances to propagate
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    const balanceObj = currentBalances["ETH"];
    if (balanceObj && balanceObj.formatted !== undefined) {
      const formatted = parseFloat(balanceObj.formatted).toFixed(4);
      if (balanceEl) {
        balanceEl.textContent = formatted;
      }
    } else {
      // Fallback to direct fetch if still no balance
      console.log("Bridge tab: Fallback to direct ETH balance fetch");
      const balance = await provider.getBalance(wallet.address);
      const formatted = parseFloat(ethers.formatEther(balance)).toFixed(4);
      if (balanceEl) {
        balanceEl.textContent = formatted;
      }
      // Update cache with fetched balance
      if (!currentBalances) currentBalances = {};
      currentBalances["ETH"] = {
        formatted: ethers.formatEther(balance),
        raw: balance.toString(),
        symbol: "ETH",
        decimals: 18
      };
    }
  } catch (err) {
    console.error("Error updating bridge balance:", err);
    if (balanceEl) balanceEl.textContent = "0.0000";
  }
}

async function updateBridgeEstimates() {
  const amountInput = document.getElementById("bridgeAmount");
  const amount = amountInput?.value;
  
  if (!amount || parseFloat(amount) <= 0) {
    document.getElementById("bridgeUSD").textContent = "$0.00";
    document.getElementById("bridgeGasFee").textContent = "--";
    document.getElementById("bridgeBtn").textContent = "Bridge ETH to Base";
    document.getElementById("bridgeBtn").disabled = true;
    return;
  }
  
  try {
    // Update USD value
    const ethPrice = tokenPrices.ETH?.usd || 0;
    const usdValue = parseFloat(amount) * ethPrice;
    document.getElementById("bridgeUSD").textContent = formatCurrency(usdValue);
    
    // Estimate gas
    if (provider) {
      const feeData = await getCachedGasPrice();
      const gasLimit = 130000n; // Bridge transactions typically use ~130k
      const gasCost = gasLimit * feeData.maxFeePerGas;
      const gasCostEth = parseFloat(ethers.formatEther(gasCost));
      const gasCostUsd = gasCostEth * ethPrice;
      
      document.getElementById("bridgeGasFee").textContent = 
        `${gasCostEth.toFixed(6)} ETH ($${gasCostUsd.toFixed(2)})`;
    }
    
    // Enable button
    document.getElementById("bridgeBtn").textContent = "Bridge ETH to Base";
    document.getElementById("bridgeBtn").disabled = false;
    
  } catch (err) {
    console.error("Error updating bridge estimates:", err);
  }
}

async function prepareBridge() {
  const amountInput = document.getElementById("bridgeAmount");
  const amount = amountInput?.value;
  
  if (!wallet || !provider) {
    showToast("Please connect wallet first", "error");
    return;
  }
  
  if (!amount || parseFloat(amount) <= 0) {
    showToast("Please enter a valid amount", "error");
    return;
  }
  
  // Ensure balances are loaded
  await ensureBalancesLoaded();
  
  try {
    // Check balance - prefer cached balance first
    let balance;
    if (currentBalances && currentBalances["ETH"] && currentBalances["ETH"].raw) {
      balance = BigInt(currentBalances["ETH"].raw);
    } else {
      // Fallback to direct query
      console.warn("ETH balance not cached, fetching directly...");
      balance = await provider.getBalance(wallet.address);
    }
    
    // Validate balance is valid
    if (!balance && balance !== 0n) {
      showToast("Unable to retrieve ETH balance", "error");
      return;
    }
    
    const amountWei = ethers.parseEther(amount);
    
    // Estimate gas - Bridge requires more gas than simple transfer
    const feeData = await getCachedGasPrice();
    if (!feeData || !feeData.maxFeePerGas) {
      showToast("Unable to estimate gas price", "error");
      return;
    }
    
    // Bridge transactions typically use ~130k gas
    const gasLimit = 135000n; // Small buffer for safety
    const gasCost = gasLimit * feeData.maxFeePerGas;
    
    const totalCost = amountWei + gasCost;
    
    if (totalCost > balance) {
      const balanceEth = ethers.formatEther(balance);
      const totalEth = ethers.formatEther(totalCost);
      const gasEth = ethers.formatEther(gasCost);
      showToast(`Insufficient balance: need ${parseFloat(totalEth).toFixed(6)} ETH (${amount} + ${parseFloat(gasEth).toFixed(6)} gas), have ${parseFloat(balanceEth).toFixed(6)} ETH`, "error");
      return;
    }
    
    // Simulate the bridge transaction first
    showToast("Simulating bridge transaction...");
    
    try {
      const simulation = await simulateTransaction({
        from: wallet.address,
        to: BASE_BRIDGE_CONTRACT,
        value: amountWei.toString(),
        gasLimit: gasLimit
      });
      
      if (!simulation.success) {
        showToast(`Bridge would fail: ${simulation.error}`, "error");
        return;
      }
    } catch (simError) {
      console.error("Bridge simulation error:", simError);
      // Continue anyway if simulation fails
    }
    
    // Prepare transaction
    pendingBridgeTx = {
      to: BASE_BRIDGE_CONTRACT,
      value: amountWei,
      gasLimit: gasLimit,
      maxFeePerGas: feeData.maxFeePerGas,
      maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
      type: 2 // EIP-1559
    };
    
    // Update confirmation modal
    const ethPrice = tokenPrices.ETH?.usd || 0;
    const usdValue = parseFloat(amount) * ethPrice;
    const gasCostEth = parseFloat(ethers.formatEther(gasCost));
    const gasCostUsd = gasCostEth * ethPrice;
    const totalEth = parseFloat(amount) + gasCostEth;
    const totalUsd = totalEth * ethPrice;
    
    document.getElementById("confirmBridgeAmount").textContent = `${amount} ETH`;
    document.getElementById("confirmBridgeUSD").textContent = formatCurrency(usdValue);
    document.getElementById("confirmBridgeGas").textContent = 
      `${gasCostEth.toFixed(6)} ETH ($${gasCostUsd.toFixed(2)})`;
    document.getElementById("confirmBridgeTotal").textContent = 
      `${totalEth.toFixed(6)} ETH ($${totalUsd.toFixed(2)})`;
    
    // Show modal
    document.getElementById("bridgeConfirmModal").classList.remove("hidden");
    
  } catch (err) {
    console.error("Error preparing bridge:", err);
    showToast("Error preparing bridge transaction", "error");
  }
}

async function executeBridge() {
  if (!wallet || !provider || !pendingBridgeTx) {
    showToast("Invalid bridge state", "error");
    return;
  }
  
  const statusEl = document.getElementById("bridgeStatus");
  const btnEl = document.getElementById("confirmBridgeBtn");
  
  try {
    // Update UI
    btnEl.disabled = true;
    btnEl.textContent = "Bridging...";
    
    // Close modal
    document.getElementById("bridgeConfirmModal").classList.add("hidden");
    
    // Update status
    if (statusEl) {
      statusEl.innerHTML = `
        <div class="status" style="background: var(--info-bg); padding: 12px; border: 1px solid var(--border); border-radius: 8px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <div class="loading-spinner"></div>
            <span>Sending transaction to Base bridge...</span>
          </div>
        </div>
      `;
    }
    
    // Send transaction
    const tx = await wallet.sendTransaction(pendingBridgeTx);
    
    // Update status with tx hash
    if (statusEl) {
      statusEl.innerHTML = `
        <div class="status" style="background: var(--info-bg); padding: 12px; border: 1px solid var(--border); border-radius: 8px;">
          <div style="font-weight: bold; margin-bottom: 8px;">🔄 Bridge Transaction Sent</div>
          <div style="font-size: 11px; margin-bottom: 8px;">
            Tx: ${tx.hash.slice(0, 10)}...${tx.hash.slice(-8)}
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <div class="loading-spinner"></div>
            <span>Waiting for confirmation...</span>
          </div>
        </div>
      `;
    }
    
    // Wait for confirmation
    const receipt = await tx.wait();
    
    // Success
    if (statusEl && receipt.status === 1) {
      statusEl.innerHTML = '';
      const successContainer = document.createElement('div');
      successContainer.className = 'status success';
      successContainer.style.cssText = 'padding: 12px; border-radius: 8px;';
      
      const titleDiv = document.createElement('div');
      titleDiv.style.cssText = 'font-weight: bold; margin-bottom: 8px;';
      titleDiv.textContent = '✅ Bridge Successful!';
      successContainer.appendChild(titleDiv);
      
      const infoDiv = document.createElement('div');
      infoDiv.style.cssText = 'font-size: 12px; margin-bottom: 8px;';
      infoDiv.textContent = 'Your ETH has been sent to the Base bridge contract.';
      successContainer.appendChild(infoDiv);
      
      const checkDiv = document.createElement('div');
      checkDiv.style.cssText = 'font-size: 11px; margin-bottom: 8px;';
      checkDiv.textContent = 'Your ETH will appear on Base in 1-2 minutes. Check your balance on: ';
      
      const baseLink = createExternalLink(
        `https://basescan.org/address/${wallet.address}`,
        'Base Explorer →',
        'color: var(--accent); text-decoration: underline;'
      );
      checkDiv.appendChild(baseLink);
      successContainer.appendChild(checkDiv);
      
      // Add Etherscan link for the mainnet transaction
      const etherscanDiv = document.createElement('div');
      etherscanDiv.style.cssText = 'font-size: 11px; display: flex; align-items: center; gap: 8px;';
      
      const etherscanText = document.createElement('span');
      etherscanText.textContent = 'Mainnet transaction: ';
      etherscanDiv.appendChild(etherscanText);
      
      const etherscanLink = createExternalLink(
        `https://etherscan.io/tx/${tx.hash}`,
        'View on Etherscan →',
        'color: var(--accent); text-decoration: underline;'
      );
      etherscanDiv.appendChild(etherscanLink);
      successContainer.appendChild(etherscanDiv);
      
      statusEl.appendChild(successContainer);
      
      // Show proper Etherscan link using our helper function
      await showEtherscanLink(tx.hash);
    } else if (statusEl) {
      statusEl.innerHTML = `
        <div class="status error" style="padding: 12px; border-radius: 8px;">
          <div style="font-weight: bold; margin-bottom: 8px;">❌ Bridge Failed</div>
          <div style="font-size: 12px;">Transaction was not successful. Please try again.</div>
        </div>
      `;
      
      // Still show transaction link for debugging
      await showEtherscanLink(tx.hash);
    }
    
    showToast("Bridge successful! ETH will appear on Base soon", "success");
    
    // Clear input and refresh balance
    document.getElementById("bridgeAmount").value = "";
    updateBridgeEstimates();
    updateBridgeBalance();
    fetchAllBalances();
    
  } catch (err) {
    console.error("Bridge error:", err);
    
    if (statusEl) {
      statusEl.innerHTML = `
        <div class="status error" style="padding: 12px; border-radius: 8px;">
          <div style="font-weight: bold; margin-bottom: 4px;">❌ Bridge Failed</div>
          <div style="font-size: 12px;">${err.message || "Transaction failed"}</div>
        </div>
      `;
    }
    
    showToast("Bridge failed: " + (err.message || "Unknown error"), "error");
    
  } finally {
    // Reset button
    btnEl.disabled = false;
    btnEl.textContent = "Confirm Bridge";
    pendingBridgeTx = null;
  }
}

// EIP-7702 Settings handlers
async function update7702Status() {
  if (!wallet || !provider) return;
  
  const statusEl = document.getElementById("eip7702Status");
  const enableBtn = document.getElementById("enable7702Btn");
  const revokeBtn = document.getElementById("revoke7702Btn");
  const infoEl = document.getElementById("eip7702Info");
  const delegatedAddressEl = document.getElementById("delegatedToAddress");
  
  if (!statusEl || !enableBtn || !revokeBtn) return;
  
  try {
    const delegation = await EIP7702.checkDelegation(wallet.address, provider);
    
    if (delegation.isDelegated) {
      // Show current delegation status
      if (delegation.isOurExecutor) {
        statusEl.innerHTML = '<div class="delegation-status active"><span class="status-icon">🔗</span><span>7702 Batching Active</span></div>';
        enableBtn.classList.add("hidden");
        revokeBtn.classList.remove("hidden");
        infoEl.classList.remove("hidden");
        if (delegatedAddressEl) {
          delegatedAddressEl.textContent = delegation.delegatedTo;
        }
      } else {
        statusEl.innerHTML = `
          <div class="delegation-status other">
            <span class="status-icon">⚠️</span>
            <span>Delegated to other contract</span>
          </div>
          <div style="margin-top: 8px; padding: 8px; background: rgba(255, 165, 0, 0.1); border: 1px solid rgba(255, 165, 0, 0.3); font-size: 11px; color: orange;">
            <strong>Warning:</strong> Your account is currently delegated to a different contract (${delegation.delegatedTo.slice(0, 10)}...). 
            Updating will replace this delegation. Multiple delegations can cause unexpected behavior.
          </div>
        `;
        enableBtn.textContent = "Update Delegation";
        enableBtn.classList.remove("hidden");
        revokeBtn.classList.remove("hidden");
        infoEl.classList.add("hidden");
      }
    } else {
      statusEl.innerHTML = '<div class="delegation-status inactive"><span class="status-icon">⭕</span><span>Standard EOA Mode</span></div>';
      enableBtn.textContent = "Enable 7702 Batching";
      enableBtn.classList.remove("hidden");
      revokeBtn.classList.add("hidden");
      infoEl.classList.add("hidden");
    }
    
    // Check if network supports 7702
    const isSupported = await EIP7702.isSupported(provider);
    if (!isSupported) {
      const networkName = isBaseMode ? "this network" : "this network";
      statusEl.innerHTML += `<div style="margin-top: 8px; color: var(--warning); font-size: 11px;">⚠️ EIP-7702 not supported on ${networkName}</div>`;
      enableBtn.disabled = true;
      revokeBtn.disabled = true;
    } else {
      // Show network support confirmation
      const networkName = isBaseMode ? "Base" : "Ethereum";
      if (statusEl.innerHTML.indexOf("not supported") === -1) {
        statusEl.innerHTML += `<div style="margin-top: 4px; color: var(--dim); font-size: 10px;">✓ 7702 supported on ${networkName}</div>`;
      }
    }
  } catch (err) {
    console.error("Error checking 7702 status:", err);
    statusEl.innerHTML = '<div style="color: var(--error); font-size: 11px;">Could not check delegation status</div>';
  }
}

// Enable 7702 delegation - just like any other function in this file
async function enable7702Delegation() {
  if (!wallet) {
    showToast("Please connect your wallet first");
    return;
  }
  
  if (!provider) {
    showToast("Provider not initialized. Please refresh the page.");
    return;
  }
  
  const enableBtn = document.getElementById("enable7702Btn");
  const statusEl = document.getElementById("eip7702Status");
  
  try {
    enableBtn.disabled = true;
    enableBtn.textContent = "Enabling...";
    
    // Check if already delegated
    const currentDelegation = await EIP7702.checkDelegation(wallet.address, provider);
    if (currentDelegation.isOurExecutor) {
      showToast("Already delegated to the batch executor");
      await update7702Status();
      return;
    }
    
    // Warn user about the implications
    if (!confirm("⚠️ IMPORTANT: You are about to delegate your EOA to a smart contract.\n\nThis delegation:\n• Allows batched transactions (approve + swap in one tx)\n• Is tied to your current nonce for security\n• Can be revoked at any time\n\nOnly proceed if you trust the batch executor contract.\n\nContinue?")) {
      return;
    }
    
    // Send delegation transaction
    statusEl.innerHTML = '<div style="color: var(--warning)">Sending delegation transaction...</div>';
    
    const receipt = await EIP7702.sendDelegation(wallet);
    
    if (receipt.status === 1) {
      showToast("7702 delegation enabled successfully!");
      statusEl.innerHTML = '<div style="color: var(--success)">✓ Delegation successful!</div>';
      
      // Update UI
      await update7702Status();
      
      // Also update main wallet display
      await displayWallet();
    } else {
      throw new Error("Delegation transaction failed");
    }
    
  } catch (err) {
    console.error("Failed to enable 7702:", err);
    let errorMsg = err.message || "Unknown error";
    let userFriendlyMsg = errorMsg;
    
    // Handle common errors with user-friendly messages
    if (errorMsg.includes("user rejected") || errorMsg.includes("denied")) {
      userFriendlyMsg = "You cancelled the transaction";
    } else if (errorMsg.includes("insufficient funds")) {
      userFriendlyMsg = "Not enough ETH for gas fees. Please add funds to your wallet.";
    } else if (errorMsg.includes("Executor contract not deployed")) {
      userFriendlyMsg = "The batch executor is not available on this network yet.";
    } else if (errorMsg.includes("nonce")) {
      userFriendlyMsg = "Transaction nonce issue. Please try again.";
    } else if (errorMsg.includes("gas")) {
      userFriendlyMsg = "Gas estimation failed. The network may be congested.";
    }
    
    showToast(userFriendlyMsg);
    statusEl.innerHTML = `<div style="color: var(--error)">❌ ${userFriendlyMsg}</div>`;
  } finally {
    enableBtn.disabled = false;
    enableBtn.textContent = "Enable 7702 Batching";
  }
}

// Revoke 7702 delegation
async function revoke7702Delegation() {
  if (!wallet || !provider || (typeof window.EIP7702 === 'undefined' && typeof EIP7702 === 'undefined')) return;
  
  const EIP7702Module = window.EIP7702 || EIP7702;
  
  const revokeBtn = document.getElementById("revoke7702Btn");
  const statusEl = document.getElementById("eip7702Status");
  
  try {
    revokeBtn.disabled = true;
    revokeBtn.textContent = "Revoking...";
    
    // Confirm revocation
    if (!confirm("Are you sure you want to revoke 7702 delegation? You will lose batching capabilities.")) {
      return;
    }
    
    statusEl.innerHTML = '<div style="color: var(--warning)">Revoking delegation...</div>';
    
    const receipt = await EIP7702Module.revokeDelegation(wallet);
    
    if (receipt.status === 1) {
      showToast("7702 delegation revoked successfully");
      statusEl.innerHTML = '<div style="color: var(--success)">✓ Delegation revoked</div>';
      
      // Update UI
      await update7702Status();
      
      // Also update main wallet display
      await displayWallet();
    } else {
      throw new Error("Revocation transaction failed");
    }
    
  } catch (err) {
    console.error("Failed to revoke 7702:", err);
    let errorMsg = err.message || "Unknown error";
    
    if (errorMsg.includes("user rejected") || errorMsg.includes("denied")) {
      errorMsg = "Transaction cancelled";
    }
    
    showToast(`Failed to revoke 7702: ${errorMsg}`);
    statusEl.innerHTML = `<div style="color: var(--error)">Failed: ${errorMsg}</div>`;
  } finally {
    revokeBtn.disabled = false;
    revokeBtn.textContent = "Revoke 7702 Delegation";
  }
}