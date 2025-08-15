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

  // Create the provider object
  const provider = {
    isZWallet: true,
    isMetaMask: true, // Many dApps check for this
    isConnected: () => true,
    
    // Event emitter functionality
    _events: {},
    on: function(event, callback) {
      if (!this._events[event]) this._events[event] = [];
      this._events[event].push(callback);
    },
    removeListener: function(event, callback) {
      if (!this._events[event]) return;
      this._events[event] = this._events[event].filter(cb => cb !== callback);
    },
    emit: function(event, ...args) {
      if (!this._events[event]) return;
      this._events[event].forEach(callback => callback(...args));
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

    // Legacy methods for compatibility
    enable: function() {
      return this.request({ method: 'eth_requestAccounts' });
    },
    
    send: function(method, params) {
      return this.request({ method, params });
    },
    
    sendAsync: function(payload, callback) {
      this.request(payload)
        .then(result => callback(null, { result }))
        .catch(error => callback(error));
    }
  };

  // Inject as window.ethereum
  window.ethereum = provider;
  
  // Dispatch event to notify dApps
  window.dispatchEvent(new Event('ethereum#initialized'));
})();