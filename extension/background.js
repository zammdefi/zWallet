// Background service worker for zWallet Chrome Extension
// Minimal background script for handling external links and extension events

// Listen for extension installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('zWallet extension installed');
});

// Handle opening external links (like Etherscan)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'open_external') {
    chrome.tabs.create({ 
      url: request.url,
      active: false 
    });
    sendResponse({ success: true });
    return true;
  }
  
  // Keep service worker alive
  if (request.action === 'keepAlive') {
    sendResponse({ status: 'alive' });
    return true;
  }
});