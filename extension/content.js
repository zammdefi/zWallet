// Content script to inject Web3 provider into dApps
(function() {
  // Get wallet settings first
  chrome.storage.local.get(['zwalletDefault', 'current_wallet'], (result) => {
    const isDefault = result.zwalletDefault || false;
    const hasWallet = !!result.current_wallet;
    
    // Inject the provider script into the page
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('inject.js');
    script.onload = function() {
      this.remove();
      
      // Send settings to injected script
      if (hasWallet) {
        window.postMessage({
          type: 'ZWALLET_SETTINGS',
          isDefault: isDefault
        }, window.location.origin);
      }
    };
    (document.head || document.documentElement).appendChild(script);
  });

  // Allowed message types for strict validation
  const ALLOWED_MESSAGE_TYPES = [
    'ZWALLET_GET_SETTINGS',
    'ZWALLET_PROVIDER_REQUEST'
  ];
  
  // Set up message relay between page and extension with strict origin checking
  window.addEventListener('message', async (event) => {
    // Only accept messages from the same window and origin
    if (event.source !== window) return;
    if (event.origin !== window.location.origin) return;
    
    // Validate message structure
    if (!event.data || typeof event.data !== 'object' || !event.data.type) {
      return;
    }
    
    // Only process known message types
    if (!ALLOWED_MESSAGE_TYPES.includes(event.data.type)) {
      return;
    }
    
    // Handle settings request
    if (event.data.type === 'ZWALLET_GET_SETTINGS') {
      chrome.storage.local.get(['zwalletDefault', 'current_wallet'], (result) => {
        window.postMessage({
          type: 'ZWALLET_SETTINGS',
          isDefault: result.zwalletDefault || false
        }, window.location.origin);
      });
      return;
    }
    
    if (event.data.type === 'ZWALLET_PROVIDER_REQUEST') {
      // Validate request structure before forwarding
      if (!event.data.data || typeof event.data.id !== 'number') {
        return;
      }
      
      // Forward to background script
      chrome.runtime.sendMessage({
        type: 'PROVIDER_REQUEST',
        data: event.data.data
      }, (response) => {
        // Send response back to page with specific origin
        window.postMessage({
          type: 'ZWALLET_PROVIDER_RESPONSE',
          id: event.data.id,
          data: response
        }, window.location.origin);
      });
    }
  });

  // Listen for responses from background
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'PROVIDER_EVENT') {
      // Forward events to the page
      window.postMessage({
        type: 'ZWALLET_PROVIDER_EVENT',
        data: request.data
      }, window.location.origin);
    } else if (request.type === 'SETTINGS_UPDATED') {
      // Forward settings updates to the page
      window.postMessage({
        type: 'ZWALLET_SETTINGS',
        isDefault: request.isDefault
      }, window.location.origin);
    }
  });
  
  // Listen for storage changes to update settings in real-time
  chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.zwalletDefault) {
      window.postMessage({
        type: 'ZWALLET_SETTINGS',
        isDefault: changes.zwalletDefault.newValue || false
      }, window.location.origin);
    }
  });
})();