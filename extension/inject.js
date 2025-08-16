// Injected script that provides window.ethereum to dApps
(function() {
  let requestId = 0;
  const pendingRequests = new Map();
  let isDefaultWallet = false;
  
  // Check if we should be the default wallet
  window.addEventListener('message', (event) => {
    if (event.data.type === 'ZWALLET_SETTINGS') {
      isDefaultWallet = event.data.isDefault;
      if (isDefaultWallet) {
        injectAsDefault();
      }
    }
  });
  
  // Request current settings
  window.postMessage({ type: 'ZWALLET_GET_SETTINGS' }, '*');

  // Listen for responses from content script
  window.addEventListener('message', (event) => {
    if (event.data.type === 'ZWALLET_PROVIDER_RESPONSE') {
      const callback = pendingRequests.get(event.data.id);
      if (callback) {
        callback(event.data.data);
        pendingRequests.delete(event.data.id);
      }
    } else if (event.data.type === 'ZWALLET_PROVIDER_EVENT') {
      // Handle events like accountsChanged, chainChanged
      if (window.ethereum && event.data.data.event) {
        window.ethereum.emit(event.data.data.event, event.data.data.params);
      }
    }
  });

  // Store original providers if they exist
  const originalProviders = {
    ethereum: window.ethereum,
    web3: window.web3
  };
  
  // Create the provider object with full EIP-1193 compatibility
  const provider = {
    // Identity flags for maximum compatibility
    isZWallet: true,
    isMetaMask: true, // Many dApps check for this
    _metamask: {
      isUnlocked: () => Promise.resolve(true),
      requestBatch: (requests) => Promise.all(requests.map(r => provider.request(r))),
      version: '10.35.2' // Mimic MetaMask version for compatibility
    },
    
    // Additional provider identifiers for broader compatibility
    _state: {
      isConnected: true,
      isUnlocked: true,
      initialized: true,
      isPermanentlyDisconnected: false
    },
    
    // Connection state
    isConnected: () => true,
    chainId: '0x1', // Default to mainnet
    networkVersion: '1',
    selectedAddress: null,
    
    // Event emitter functionality (EIP-1193 compliant)
    _events: {},
    on: function(event, callback) {
      if (!this._events[event]) this._events[event] = [];
      this._events[event].push(callback);
      return this; // Chainable
    },
    once: function(event, callback) {
      const wrapped = (...args) => {
        this.removeListener(event, wrapped);
        callback(...args);
      };
      return this.on(event, wrapped);
    },
    off: function(event, callback) {
      return this.removeListener(event, callback);
    },
    removeListener: function(event, callback) {
      if (!this._events[event]) return this;
      this._events[event] = this._events[event].filter(cb => cb !== callback);
      return this; // Chainable
    },
    removeAllListeners: function(event) {
      if (event) {
        delete this._events[event];
      } else {
        this._events = {};
      }
      return this;
    },
    emit: function(event, ...args) {
      if (!this._events[event]) return false;
      this._events[event].forEach(callback => {
        try {
          callback(...args);
        } catch (err) {
          console.error('Provider event error:', err);
        }
      });
      return true;
    },
    
    // Alias for EventEmitter compatibility
    addListener: function(event, callback) {
      return this.on(event, callback);
    },

    // Main request method with error handling
    request: function(args) {
      return new Promise((resolve, reject) => {
        // Validate args
        if (!args || typeof args.method !== 'string') {
          reject({
            code: -32602,
            message: 'Invalid request parameters'
          });
          return;
        }
        
        const id = ++requestId;
        pendingRequests.set(id, (response) => {
          if (response.error) {
            // Format error properly
            const error = typeof response.error === 'object' ? 
              response.error : 
              { code: -32603, message: String(response.error) };
            reject(error);
          } else {
            resolve(response.result);
          }
        });

        try {
          window.postMessage({
            type: 'ZWALLET_PROVIDER_REQUEST',
            id: id,
            data: args
          }, '*');
        } catch (err) {
          pendingRequests.delete(id);
          reject({
            code: -32603,
            message: 'Failed to send request: ' + err.message
          });
          return;
        }

        // Timeout after 30 seconds
        setTimeout(() => {
          if (pendingRequests.has(id)) {
            pendingRequests.delete(id);
            reject({
              code: -32603,
              message: 'Request timeout after 30 seconds'
            });
          }
        }, 30000);
      });
    },

    // Legacy methods for maximum compatibility
    enable: function() {
      return this.request({ method: 'eth_requestAccounts' });
    },
    
    // Support both old and new send signatures
    send: function(methodOrPayload, params) {
      if (typeof methodOrPayload === 'string') {
        // Old signature: send(method, params)
        return this.request({ method: methodOrPayload, params });
      } else if (methodOrPayload.jsonrpc) {
        // Sync send for specific methods (some dApps expect this)
        const syncMethods = ['eth_accounts', 'eth_chainId', 'net_version'];
        if (syncMethods.includes(methodOrPayload.method)) {
          // Return cached values synchronously for these methods
          switch(methodOrPayload.method) {
            case 'eth_chainId':
              return { id: methodOrPayload.id, jsonrpc: '2.0', result: this.chainId };
            case 'net_version':
              return { id: methodOrPayload.id, jsonrpc: '2.0', result: this.networkVersion };
            case 'eth_accounts':
              return { id: methodOrPayload.id, jsonrpc: '2.0', result: this.selectedAddress ? [this.selectedAddress] : [] };
          }
        }
        // Async send
        return this.request(methodOrPayload);
      } else {
        // New signature: send(args)
        return this.request(methodOrPayload);
      }
    },
    
    sendAsync: function(payload, callback) {
      // Handle batch requests
      if (Array.isArray(payload)) {
        Promise.all(payload.map(p => this.request(p)))
          .then(results => callback(null, results.map((result, i) => ({
            id: payload[i].id,
            jsonrpc: '2.0',
            result
          }))))
          .catch(error => callback(error));
      } else {
        this.request(payload)
          .then(result => callback(null, { 
            id: payload.id,
            jsonrpc: '2.0',
            result 
          }))
          .catch(error => callback(error));
      }
    },
    
    // Additional compatibility methods
    autoRefreshOnNetworkChange: false,
    
    // WalletConnect and other protocols compatibility
    isWalletConnect: false,
    isCoinbaseWallet: false,
    isBraveWallet: false,
    
    // Request accounts helper
    eth_requestAccounts: function() {
      return this.request({ method: 'eth_requestAccounts' });
    }
  };

  // Function to inject as default wallet
  function injectAsDefault() {
    // Store existing providers
    if (window.ethereum && !window.ethereum.isZWallet) {
      window.ethereum._originalProvider = window.ethereum;
    }
    
    // Inject our provider
    window.ethereum = provider;
    
    // Also set web3 for older dApps
    if (typeof window.Web3 !== 'undefined') {
      window.web3 = new window.Web3(provider);
    }
    
    // Proxy provider list to ensure we're first
    if (window.ethereum.providers) {
      const providers = [...window.ethereum.providers];
      const ourIndex = providers.findIndex(p => p.isZWallet);
      if (ourIndex > 0) {
        providers.splice(ourIndex, 1);
        providers.unshift(provider);
        window.ethereum.providers = providers;
      }
    }
  }
  
  // Function to intercept wallet connections
  function interceptWalletConnections() {
    // Override window.open to catch wallet connection popups
    const originalOpen = window.open;
    window.open = function(...args) {
      const url = args[0];
      if (url && typeof url === 'string') {
        // Check if it's a MetaMask or other wallet connection
        if (url.includes('metamask.io') || 
            url.includes('connect.metamask.io') ||
            url.includes('wallet.coinbase.com') ||
            url.includes('walletconnect.org')) {
          
          // If we're set as default, intercept and use our wallet
          if (isDefaultWallet) {
            console.log('[zWallet] Intercepting wallet connection');
            // Trigger our connection flow instead
            provider.request({ method: 'eth_requestAccounts' })
              .then(accounts => {
                // Emit connected event
                provider.emit('connect', { chainId: provider.chainId });
                provider.emit('accountsChanged', accounts);
              })
              .catch(err => {
                console.error('[zWallet] Connection failed:', err);
              });
            return null; // Don't open the original popup
          }
        }
      }
      return originalOpen.apply(window, args);
    };
  }
  
  // Initial injection
  if (!window.ethereum || !window.ethereum.isZWallet) {
    window.ethereum = provider;
    
    // Dispatch events to notify dApps
    window.dispatchEvent(new Event('ethereum#initialized'));
    
    // For EIP-6963 provider discovery
    window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
      detail: {
        info: {
          uuid: '350670db-19fa-4704-a166-e52e178b59d4',
          name: 'zWallet',
          icon: 'data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMTAwIDEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cG9seWdvbiBwb2ludHM9IjUwLDIwIDMwLDYwIDUwLDQ1IiBmaWxsPSIjRkY2QjlEIiAvPjxwb2x5Z29uIHBvaW50cz0iNTAsMjAgNTAsNDUgNzAsNjAiIGZpbGw9IiMwMEQ0RkYiIC8+PHBvbHlnb24gcG9pbnRzPSIzMCw2MCA1MCw0NSA1MCw2MCIgZmlsbD0iI0ZGRTA2NiIgLz48cG9seWdvbiBwb2ludHM9IjUwLDQ1IDcwLDYwIDUwLDYwIiBmaWxsPSIjNjZEOUE2IiAvPjxwb2x5Z29uIHBvaW50cz0iMzAsNjAgNTAsNjAgNTAsODAiIGZpbGw9IiNGRjlGNDAiIC8+PHBvbHlnb24gcG9pbnRzPSI1MCw2MCA3MCw2MCA1MCw4MCIgZmlsbD0iI0I5NjdEQiIgLz48L3N2Zz4=',
          rdns: 'com.zwallet'
        },
        provider: provider
      }
    }));
  }
  
  // Set up interception
  interceptWalletConnections();
})();