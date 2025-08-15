// Background service worker for zWallet Chrome Extension
// Handles dApp connections and transaction approvals

// Store connected sites and pending requests
let connectedSites = {};
let pendingRequests = {};

// Listen for extension installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('zWallet extension installed');
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'open_external') {
    chrome.tabs.create({ 
      url: request.url,
      active: false 
    });
    sendResponse({ success: true });
    return true;
  }
  
  // Handle provider requests from dApps
  if (request.type === 'PROVIDER_REQUEST') {
    handleProviderRequest(request.data, sender, sendResponse);
    return true; // Will respond asynchronously
  }
  
  // Handle approval/rejection from popup
  if (request.type === 'USER_RESPONSE') {
    const pending = pendingRequests[request.requestId];
    if (pending) {
      pending.sendResponse(request.response);
      delete pendingRequests[request.requestId];
    }
    return true;
  }
  
  // Get request details for popup
  if (request.type === 'GET_REQUEST') {
    const pending = pendingRequests[request.requestId];
    sendResponse(pending || null);
    return true;
  }
  
  // Keep service worker alive
  if (request.action === 'keepAlive') {
    sendResponse({ status: 'alive' });
    return true;
  }
});

async function handleProviderRequest(request, sender, sendResponse) {
  const origin = new URL(sender.tab.url).origin;
  
  switch (request.method) {
    case 'eth_requestAccounts':
    case 'eth_accounts':
      // Check if already connected
      if (connectedSites[origin]) {
        const accounts = await getAccounts();
        sendResponse({ result: accounts });
      } else {
        // Show connection popup
        const requestId = Date.now().toString();
        pendingRequests[requestId] = { sendResponse, request, origin };
        
        chrome.windows.create({
          url: chrome.runtime.getURL(`popup.html?request=${requestId}&type=connect&origin=${encodeURIComponent(origin)}`),
          type: 'popup',
          width: 450,
          height: 650
        });
      }
      break;
      
    case 'eth_sendTransaction':
      // Show transaction approval popup
      const requestId = Date.now().toString();
      pendingRequests[requestId] = { sendResponse, request, origin };
      
      chrome.windows.create({
        url: chrome.runtime.getURL(`popup.html?request=${requestId}&type=transaction&origin=${encodeURIComponent(origin)}`),
        type: 'popup',
        width: 450,
        height: 700
      });
      break;
      
    case 'eth_chainId':
      sendResponse({ result: '0x1' }); // Mainnet
      break;
      
    case 'eth_blockNumber':
      // Forward to popup's provider
      chrome.runtime.sendMessage({ 
        type: 'PROVIDER_METHOD',
        method: 'eth_blockNumber'
      }, sendResponse);
      break;
      
    case 'personal_sign':
    case 'eth_sign':
    case 'eth_signTypedData':
    case 'eth_signTypedData_v4':
      // Show signing popup
      const signRequestId = Date.now().toString();
      pendingRequests[signRequestId] = { sendResponse, request, origin };
      
      chrome.windows.create({
        url: chrome.runtime.getURL(`popup.html?request=${signRequestId}&type=sign&origin=${encodeURIComponent(origin)}`),
        type: 'popup',
        width: 450,
        height: 650
      });
      break;
      
    default:
      // Forward other methods to the provider
      chrome.runtime.sendMessage({ 
        type: 'PROVIDER_METHOD',
        method: request.method,
        params: request.params
      }, sendResponse);
  }
}

async function getAccounts() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['current_wallet'], (result) => {
      if (result.current_wallet) {
        resolve([result.current_wallet]);
      } else {
        resolve([]);
      }
    });
  });
}