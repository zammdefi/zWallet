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
        }, '*');
      }
    };
    (document.head || document.documentElement).appendChild(script);
  });

  // Set up message relay between page and extension
  window.addEventListener('message', async (event) => {
    // Only accept messages from the same window
    if (event.source !== window) return;
    
    // Handle settings request
    if (event.data.type === 'ZWALLET_GET_SETTINGS') {
      chrome.storage.local.get(['zwalletDefault', 'current_wallet'], (result) => {
        window.postMessage({
          type: 'ZWALLET_SETTINGS',
          isDefault: result.zwalletDefault || false
        }, '*');
      });
      return;
    }
    
    if (event.data.type && event.data.type === 'ZWALLET_PROVIDER_REQUEST') {
      // Forward to background script
      chrome.runtime.sendMessage({
        type: 'PROVIDER_REQUEST',
        data: event.data.data
      }, (response) => {
        // Send response back to page
        window.postMessage({
          type: 'ZWALLET_PROVIDER_RESPONSE',
          id: event.data.id,
          data: response
        }, '*');
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
      }, '*');
    } else if (request.type === 'SETTINGS_UPDATED') {
      // Forward settings updates to the page
      window.postMessage({
        type: 'ZWALLET_SETTINGS',
        isDefault: request.isDefault
      }, '*');
    }
  });
  
  // Listen for storage changes to update settings in real-time
  chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.zwalletDefault) {
      window.postMessage({
        type: 'ZWALLET_SETTINGS',
        isDefault: changes.zwalletDefault.newValue || false
      }, '*');
    }
  });
})();