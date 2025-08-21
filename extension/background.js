// Background service worker for zWallet Chrome Extension
// Handles dApp connections and transaction approvals

// Store connected sites and pending requests
let connectedSites = {};
let pendingRequests = {};
let accountCache = null;
let chainId = '0x1'; // Default to mainnet


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
  
  // Validate origin format
  if (!origin || origin === 'null') {
    sendResponse({ error: { code: -32602, message: 'Invalid origin' } });
    return;
  }
  
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
        
        const popupUrl = new URL(chrome.runtime.getURL('popup.html'));
        popupUrl.searchParams.set('request', requestId);
        popupUrl.searchParams.set('type', 'connect');
        popupUrl.searchParams.set('origin', origin);
        
        chrome.windows.create({
          url: popupUrl.toString(),
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
      
      const txPopupUrl = new URL(chrome.runtime.getURL('popup.html'));
      txPopupUrl.searchParams.set('request', requestId);
      txPopupUrl.searchParams.set('type', 'transaction');
      txPopupUrl.searchParams.set('origin', origin);
      
      chrome.windows.create({
        url: txPopupUrl.toString(),
        type: 'popup',
        width: 450,
        height: 700
      });
      break;
      
    case 'eth_chainId':
      sendResponse({ result: chainId });
      break;
      
    case 'net_version':
      sendResponse({ result: parseInt(chainId, 16).toString() });
      break;
      
    case 'web3_clientVersion':
      sendResponse({ result: 'zWallet/0.0.7' });
      break;
      
    case 'eth_syncing':
      sendResponse({ result: false });
      break;
      
    case 'eth_coinbase':
      // Return the first account as coinbase
      getAccounts().then(accounts => {
        sendResponse({ result: accounts[0] || null });
      });
      break;
      
    case 'eth_blockNumber':
    case 'eth_gasPrice':
    case 'eth_getBalance':
    case 'eth_getCode':
    case 'eth_getTransactionCount':
    case 'eth_estimateGas':
    case 'eth_call':
    case 'eth_getTransactionReceipt':
    case 'eth_getTransactionByHash':
    case 'eth_getBlockByNumber':
    case 'eth_getBlockByHash':
    case 'eth_getLogs':
      // Forward RPC methods to provider
      forwardToProvider(request, sendResponse);
      break;
      
    case 'personal_sign':
    case 'eth_sign':
    case 'eth_signTypedData':
    case 'eth_signTypedData_v4':
      // Show signing popup
      const signRequestId = Date.now().toString();
      pendingRequests[signRequestId] = { sendResponse, request, origin };
      
      const signPopupUrl = new URL(chrome.runtime.getURL('popup.html'));
      signPopupUrl.searchParams.set('request', signRequestId);
      signPopupUrl.searchParams.set('type', 'sign');
      signPopupUrl.searchParams.set('origin', origin);
      
      chrome.windows.create({
        url: signPopupUrl.toString(),
        type: 'popup',
        width: 450,
        height: 650
      });
      break;
      
    case 'wallet_switchEthereumChain':
    case 'wallet_addEthereumChain':
      // Handle chain switching
      handleChainSwitch(request, sendResponse);
      break;
      
    case 'wallet_watchAsset':
      // Handle token addition requests
      handleWatchAsset(request, origin, sendResponse);
      break;
      
    case 'wallet_requestPermissions':
    case 'wallet_getPermissions':
      // Handle permissions
      handlePermissions(request, origin, sendResponse);
      break;
      
    default:
      // Check if it's a signing method that needs approval
      if (request.method.startsWith('eth_sign') || 
          request.method.startsWith('personal_') ||
          request.method === 'eth_sendRawTransaction') {
        // These need user approval
        const signRequestId = Date.now().toString();
        pendingRequests[signRequestId] = { sendResponse, request, origin };
        
        const fallbackPopupUrl = new URL(chrome.runtime.getURL('popup.html'));
        fallbackPopupUrl.searchParams.set('request', signRequestId);
        fallbackPopupUrl.searchParams.set('type', 'sign');
        fallbackPopupUrl.searchParams.set('origin', origin);
        
        chrome.windows.create({
          url: fallbackPopupUrl.toString(),
          type: 'popup',
          width: 450,
          height: 650
        });
      } else {
        // Unknown method
        sendResponse({ 
          error: {
            code: -32601,
            message: `Method ${request.method} not supported`
          }
        });
      }
  }
}

// Forward requests to Ethereum provider
async function forwardToProvider(request, sendResponse) {
  try {
    const response = await fetch('https://eth.llamarpc.com', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: request.method,
        params: request.params || []
      })
    });
    
    const data = await response.json();
    if (data.error) {
      sendResponse({ error: data.error });
    } else {
      sendResponse({ result: data.result });
    }
  } catch (error) {
    sendResponse({ 
      error: {
        code: -32603,
        message: 'Internal error: ' + error.message
      }
    });
  }
}

// Handle chain switching
function handleChainSwitch(request, sendResponse) {
  // For now, we only support mainnet
  if (request.params[0].chainId === '0x1') {
    chainId = '0x1';
    sendResponse({ result: null });
  } else {
    sendResponse({ 
      error: {
        code: 4902,
        message: 'Unrecognized chain ID'
      }
    });
  }
}

// Handle watch asset requests
function handleWatchAsset(request, origin, sendResponse) {
  const params = request.params;
  if (params.type === 'ERC20') {
    // Show approval popup for adding token
    const requestId = Date.now().toString();
    pendingRequests[requestId] = { sendResponse, request, origin };
    
    const assetPopupUrl = new URL(chrome.runtime.getURL('popup.html'));
    assetPopupUrl.searchParams.set('request', requestId);
    assetPopupUrl.searchParams.set('type', 'watchAsset');
    assetPopupUrl.searchParams.set('origin', origin);
    
    chrome.windows.create({
      url: assetPopupUrl.toString(),
      type: 'popup',
      width: 450,
      height: 500
    });
  } else {
    sendResponse({ 
      error: {
        code: -32602,
        message: 'Invalid parameters'
      }
    });
  }
}

// Handle permissions
function handlePermissions(request, origin, sendResponse) {
  if (request.method === 'wallet_getPermissions') {
    // Return current permissions for this origin
    const permissions = connectedSites[origin] ? 
      [{ parentCapability: 'eth_accounts' }] : [];
    sendResponse({ result: permissions });
  } else {
    // Request new permissions (similar to eth_requestAccounts)
    handleProviderRequest(
      { method: 'eth_requestAccounts', params: [] },
      { tab: { url: origin } },
      (response) => {
        if (response.result) {
          sendResponse({ 
            result: [{ parentCapability: 'eth_accounts' }]
          });
        } else {
          sendResponse(response);
        }
      }
    );
  }
}

async function getAccounts() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['current_wallet'], (result) => {
      if (result.current_wallet) {
        accountCache = result.current_wallet;
        resolve([result.current_wallet]);
      } else {
        resolve([]);
      }
    });
  });
}

// Listen for account changes
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && changes.current_wallet) {
    const newAccount = changes.current_wallet.newValue;
    accountCache = newAccount;
    
    // Notify all connected sites of account change
    Object.keys(connectedSites).forEach(origin => {
      // Send accountsChanged event to all tabs from this origin
      chrome.tabs.query({ url: origin + '/*' }, (tabs) => {
        tabs.forEach(tab => {
          chrome.tabs.sendMessage(tab.id, {
            type: 'PROVIDER_EVENT',
            data: {
              event: 'accountsChanged',
              params: newAccount ? [newAccount] : []
            }
          }).catch(() => {});
        });
      });
    });
  }
});

// Keep service worker alive
setInterval(() => {
  chrome.storage.local.get(null, () => {});
}, 20000);