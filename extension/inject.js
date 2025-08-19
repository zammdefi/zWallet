// Injected script that provides window.ethereum to dApps
(function() {
  'use strict';
  
  // Don't inject if already present
  if (window.ethereum && window.ethereum.isZWallet) {
    return;
  }
  
  let requestId = 0;
  const pendingRequests = new Map();
  
  // Listen for responses from content script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    
    if (event.data && event.data.type === 'ZWALLET_PROVIDER_RESPONSE') {
      const callback = pendingRequests.get(event.data.id);
      if (callback) {
        pendingRequests.delete(event.data.id);
        callback(event.data.response);
      }
    }
    
    if (event.data && event.data.type === 'ZWALLET_PROVIDER_EVENT') {
      if (event.data.event === 'ACCOUNT_CHANGED') {
        provider.selectedAddress = event.data.data.account;
        provider.emit('accountsChanged', event.data.data.account ? [event.data.data.account] : []);
      }
      if (event.data.event === 'CHAIN_CHANGED') {
        provider.chainId = event.data.data.chainId;
        provider.networkVersion = parseInt(event.data.data.chainId, 16).toString();
        provider.emit('chainChanged', event.data.data.chainId);
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
      return this;
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
      return this;
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
          console.error('Event handler error:', err);
        }
      });
      return true;
    },
    addListener: function(event, callback) {
      return this.on(event, callback);
    },

    // Main request method with error handling
    request: function(args) {
      return new Promise((resolve, reject) => {
        if (!args || typeof args.method !== 'string') {
          reject({
            code: -32602,
            message: 'Invalid request parameters'
          });
          return;
        }
        
        const id = ++requestId;
        pendingRequests.set(id, (response) => {
          if (response && response.error) {
            const error = typeof response.error === 'object' ? 
              response.error : 
              { code: -32603, message: String(response.error) };
            reject(error);
          } else {
            resolve(response && response.result);
          }
        });

        window.postMessage({
          type: 'ZWALLET_PROVIDER_REQUEST',
          id: id,
          payload: args
        }, '*');

        // Timeout after 30 seconds
        setTimeout(() => {
          if (pendingRequests.has(id)) {
            pendingRequests.delete(id);
            reject({
              code: -32603,
              message: 'Request timeout'
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
      } else if (methodOrPayload && methodOrPayload.method) {
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
    eth_requestAccounts: function() {
      return this.request({ method: 'eth_requestAccounts' });
    }
  };

  // Expose to window
  window.ethereum = provider;
  
  // Also expose as web3.currentProvider for legacy dApps
  if (!window.web3) {
    window.web3 = {
      currentProvider: provider
    };
  }
  
  // Announce provider
  window.dispatchEvent(new Event('ethereum#initialized'));
  
  // For EIP-6963 provider discovery
  window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
    detail: {
      info: {
        uuid: '350670db-19fa-4704-a166-e52e178b59d4',
        name: 'zWallet',
        icon: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHZpZXdCb3g9IjAgMCA2NCA2NCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIGZpbGw9IiM2NjdlZWEiLz48dGV4dCB4PSIzMiIgeT0iMzgiIGZvbnQtZmFtaWx5PSJtb25vc3BhY2UiIGZvbnQtc2l6ZT0iMjQiIGZpbGw9IndoaXRlIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj56VzwvdGV4dD48L3N2Zz4=',
        rdns: 'com.zwallet'
      },
      provider: provider
    }
  }));
})();