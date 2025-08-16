// Injected script that provides window.ethereum to dApps
(function() {
  let requestId = 0;
  const pendingRequests = new Map();

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

  // Create the provider object with full EIP-1193 compatibility
  const provider = {
    // Identity flags for maximum compatibility
    isZWallet: true,
    isMetaMask: true, // Many dApps check for this
    _metamask: {
      isUnlocked: () => Promise.resolve(true),
      requestBatch: (requests) => Promise.all(requests.map(r => provider.request(r)))
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

    // Main request method
    request: function(args) {
      return new Promise((resolve, reject) => {
        const id = ++requestId;
        pendingRequests.set(id, (response) => {
          if (response.error) {
            reject(response.error);
          } else {
            resolve(response.result);
          }
        });

        window.postMessage({
          type: 'ZWALLET_PROVIDER_REQUEST',
          id: id,
          data: args
        }, '*');

        // Timeout after 30 seconds
        setTimeout(() => {
          if (pendingRequests.has(id)) {
            pendingRequests.delete(id);
            reject(new Error('Request timeout'));
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

  // Inject as window.ethereum
  window.ethereum = provider;
  
  // Dispatch event to notify dApps
  window.dispatchEvent(new Event('ethereum#initialized'));
})();