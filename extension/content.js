// Content script to inject Web3 provider into dApps
(function() {
  // Inject the provider script into the page
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('inject.js');
  script.onload = function() {
    this.remove();
  };
  (document.head || document.documentElement).appendChild(script);

  // Set up message relay between page and extension
  window.addEventListener('message', async (event) => {
    // Only accept messages from the same window
    if (event.source !== window) return;
    
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
    }
  });
})();