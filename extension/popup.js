if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id) {
  document.documentElement.classList.add("is-extension");
}

// Generate dynamic coin SVG
function generateCoinSVG(id) {
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  const textColor = isDark ? "#ffffff" : "#000000";
  const goldColor = isDark ? "#FFD700" : "#DAA520";
  const shadowColor = isDark ? "#B8860B" : "#996515";

  return `<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="coinGrad${id}" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:${goldColor};stop-opacity:1" />
              <stop offset="50%" style="stop-color:#FFA500;stop-opacity:1" />
              <stop offset="100%" style="stop-color:${shadowColor};stop-opacity:1" />
            </linearGradient>
          </defs>
          <circle cx="16" cy="16" r="14" fill="url(#coinGrad${id})" stroke="${shadowColor}" stroke-width="1"/>
          <circle cx="16" cy="16" r="11" fill="none" stroke="${shadowColor}" stroke-width="0.5" opacity="0.5"/>
          <text x="16" y="20" font-family="monospace" font-size="8" font-weight="bold" text-anchor="middle" fill="${textColor}">${id}</text>
        </svg>`;
}

// Token configuration with logos
const TOKEN_LOGOS = {
  ETH: '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><g fill="none" fill-rule="evenodd"><circle cx="16" cy="16" r="16" fill="#627EEA"/><g fill="#FFF" fill-rule="nonzero"><path fill-opacity=".602" d="M16.498 4v8.87l7.497 3.35z"/><path d="M16.498 4L9 16.22l7.498-3.35z"/><path fill-opacity=".602" d="M16.498 21.968v6.027L24 17.616z"/><path d="M16.498 27.995v-6.028L9 17.616z"/><path fill-opacity=".2" d="M16.498 20.573l7.497-4.353-7.497-3.348z"/><path fill-opacity=".602" d="M9 16.22l7.498 4.353v-7.701z"/></g></g></svg>',
  USDC: '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><g fill="none"><circle fill="#3E73C4" cx="16" cy="16" r="16"/><g fill="#FFF"><path d="M20.022 18.124c0-2.124-1.28-2.852-3.84-3.156-1.828-.243-2.193-.728-2.193-1.578 0-.85.61-1.396 1.828-1.396 1.097 0 1.707.364 2.011 1.275a.458.458 0 00.427.303h.975a.416.416 0 00.427-.425v-.06a3.04 3.04 0 00-2.743-2.489V9.142c0-.243-.183-.425-.487-.486h-.915c-.243 0-.426.182-.487.486v1.396c-1.829.242-2.986 1.456-2.986 2.974 0 2.002 1.218 2.791 3.778 3.095 1.707.303 2.255.668 2.255 1.639 0 .97-.853 1.638-2.011 1.638-1.585 0-2.133-.667-2.316-1.578-.06-.242-.244-.364-.427-.364h-1.036a.416.416 0 00-.426.425v.06c.243 1.518 1.219 2.61 3.23 2.914v1.457c0 .242.183.425.487.485h.915c.243 0 .426-.182.487-.485V21.34c1.829-.303 3.047-1.578 3.047-3.217z"/><path d="M12.892 24.497c-4.754-1.7-7.192-6.98-5.424-11.653.914-2.55 2.925-4.491 5.424-5.402.244-.121.365-.303.365-.607v-.85c0-.242-.121-.424-.365-.485-.061 0-.183 0-.244.06a10.895 10.895 0 00-7.13 13.717c1.096 3.4 3.717 6.01 7.13 7.102.244.121.488 0 .548-.243.061-.06.061-.122.061-.243v-.85c0-.182-.182-.424-.365-.546zm6.46-18.936c-.244-.122-.488 0-.548.242-.061.061-.061.122-.061.243v.85c0 .243.182.485.365.607 4.754 1.7 7.192 6.98 5.424 11.653-.914 2.55-2.925 4.491-5.424 5.402-.244.121-.365.303-.365.607v.85c0 .242.121.424.365.485.061 0 .183 0 .244-.06a10.895 10.895 0 007.13-13.717c-1.096-3.46-3.778-6.07-7.13-7.162z"/></g></g></svg>',
  DAI: '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><g fill="none" fill-rule="evenodd"><circle fill="#F4B731" fill-rule="nonzero" cx="16" cy="16" r="16"/><path d="M9.277 8h6.552c3.985 0 7.006 2.116 8.13 5.194H26v1.861h-1.611c.031.294.047.594.047.898v.046c0 .342-.02.68-.06 1.01H26v1.86h-2.08C22.767 21.905 19.77 24 15.83 24H9.277v-5.131H7v-1.86h2.277v-1.954H7v-1.86h2.277V8zm1.831 10.869v3.462h4.72c2.914 0 5.078-1.387 6.085-3.462H11.108zm11.366-1.86H11.108v-1.954h11.37c.041.307.063.622.063.944v.045c0 .329-.023.65-.067.964zM15.83 9.665c2.926 0 5.097 1.424 6.098 3.528h-10.82V9.666h4.72z" fill="#FFF"/></g></svg>',
  USDT: '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><g fill="none"><circle fill="#26A17B" cx="16" cy="16" r="16"/><path fill="#FFF" d="M17.922 17.383v-.002c-.11.008-.677.042-1.942.042-1.01 0-1.721-.03-1.971-.042v.003c-3.888-.171-6.79-.848-6.79-1.658 0-.809 2.902-1.486 6.79-1.66v2.644c.254.018.982.061 1.988.061 1.207 0 1.812-.05 1.925-.06v-2.643c3.88.173 6.775.85 6.775 1.658 0 .81-2.895 1.485-6.775 1.657m0-3.59v-2.366h5.414V7.819H8.595v3.608h5.414v2.365c-4.4.202-7.709 1.074-7.709 2.118 0 1.044 3.309 1.915 7.709 2.118v7.582h3.913v-7.584c4.393-.202 7.694-1.073 7.694-2.116 0-1.043-3.301-1.914-7.694-2.117"/></g></svg>',
  ENS: '<svg viewBox="0 0 202 231" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M98.3592 2.80337L34.8353 107.327C34.3371 108.147 33.1797 108.238 32.5617 107.505C26.9693 100.864 6.13478 72.615 31.9154 46.8673C55.4403 23.3726 85.4045 6.62129 96.5096 0.831705C97.7695 0.174847 99.0966 1.59007 98.3592 2.80337Z" fill="#0080BC"/><path d="M94.8459 230.385C96.1137 231.273 97.6758 229.759 96.8261 228.467C82.6374 206.886 35.4713 135.081 28.9559 124.302C22.5295 113.67 9.88976 96.001 8.83534 80.8842C8.7301 79.3751 6.64332 79.0687 6.11838 80.4879C5.27178 82.7767 4.37045 85.5085 3.53042 88.6292C-7.07427 128.023 8.32698 169.826 41.7753 193.238L94.8459 230.386V230.385Z" fill="#0080BC"/><path d="M103.571 228.526L167.095 124.003C167.593 123.183 168.751 123.092 169.369 123.825C174.961 130.465 195.796 158.715 170.015 184.463C146.49 207.957 116.526 224.709 105.421 230.498C104.161 231.155 102.834 229.74 103.571 228.526Z" fill="#0080BC"/><path d="M107.154 0.930762C105.886 0.0433954 104.324 1.5567 105.174 2.84902C119.363 24.4301 166.529 96.2354 173.044 107.014C179.471 117.646 192.11 135.315 193.165 150.432C193.27 151.941 195.357 152.247 195.882 150.828C196.728 148.539 197.63 145.808 198.47 142.687C209.074 103.293 193.673 61.4905 160.225 38.078L107.154 0.930762Z" fill="#0080BC"/></svg>',
  CULT: '<img src="https://assets.coingecko.com/coins/images/52583/standard/cult.jpg?1733712273" style="width: 100%; height: 100%; object-fit: contain;" />',
  ZAMM: '<img src="https://raw.githubusercontent.com/NaniDAO/coinchan/main/public/zammzamm.gif" style="width: 100%; height: 100%; object-fit: contain;" />',
};

// WETH address for ETH price
const WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

// zQuoter contract for finding best swap routes
const ZQUOTER_ADDRESS = "0xC802D186BdFC8F53F35dF9B424CAf13f5AC5aec7";

// ERC6909 addresses
const COINS_CONTRACT = "0x0000000000009710cd229bf635c4500029651ee8";
const ZAMM_ID = "1334160193485309697971829933264346612480800613613";

// CTC contract for price checking
const CTC_ADDRESS = "0x0000000000cDC1F8d393415455E382c30FBc0a84";
const CTC_ABI = [
  "function checkPrice(address token) view returns (uint256 price, string priceStr)",
];

const LS_WALLETS = "eth_wallets_v2";
const LS_LAST = "last_wallet_addr";

const KEY_VERSION = 1;
const DEFAULT_KDF = { kdf: "pbkdf2-sha256", iter: 210000 }; // bump iter later if you want

// Default tokens configuration
const DEFAULT_TOKENS = {
  ETH: { address: null, symbol: "ETH", name: "Ethereum", decimals: 18 },
  ZAMM: {
    address: COINS_CONTRACT,
    symbol: "ZAMM",
    name: "ZAMM",
    decimals: 18,
    isERC6909: true,
    id: ZAMM_ID,
  },
  USDT: {
    address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    symbol: "USDT",
    name: "Tether",
    decimals: 6,
  },
  DAI: {
    address: "0x6B175474E89094C44Da98b954EedeAC495271d0F",
    symbol: "DAI",
    name: "Dai",
    decimals: 18,
  },
  USDC: {
    address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    symbol: "USDC",
    name: "USD Coin",
    decimals: 6,
  },
  ENS: {
    address: "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72",
    symbol: "ENS",
    name: "ENS",
    decimals: 18,
  },
  CULT: {
    address: "0x0000000000c5dc95539589fbD24BE07c6C14eCa4",
    symbol: "CULT",
    name: "Milady Cult Coin",
    decimals: 18,
  },
};

// zWallet contract address and ABI
const ZWALLET_ADDRESS = "0xF0cf3dD4A74dA18012Ec3FF83E9794440E80d095";
const ZWALLET_ABI = [
  "function batchView(address user, address[] calldata tokens, uint256[] calldata ids) view returns (uint256[] rawBalances, uint256[] balances, string[] names, string[] symbols, uint8[] decimals, uint256[] pricesETH, uint256[] pricesUSDC, string[] pricesETHStr, string[] pricesUSDCStr)",
  "function getBalanceOf(address user, address token, uint256 id) view returns (uint256 raw, uint256 bal)",
  "function getMetadata(address token) view returns (string name, string symbol, uint8 decimals)",
  "function getERC20Transfer(address to, uint256 amount) pure returns (bytes)",
  "function getERC6909Transfer(address to, uint256 id, uint256 amount) pure returns (bytes)",
  "function checkPriceInETH(address token) view returns (uint256 price, string priceStr)",
  "function checkPriceInETHToUSDC(address token) view returns (uint256 price, string priceStr)",
];

const ERC20_ABI = [
  "function transfer(address, uint256) returns (bool)",
  "function approve(address, uint256) returns (bool)",
  "event Transfer(address indexed from, address indexed to, uint256 value)",
];

// Global state
let wallet = null;
let provider = null;
let zWalletContract = null;
let selectedGasSpeed = "normal";
let currentBalances = {};
let tokenPrices = {};
let ethPrice = 0;
let selectedToken = "ETH";
let savedWallets = [];
let customTokens = {};
let currentRpc =
  localStorage.getItem("rpc_endpoint") || "https://eth.llamarpc.com";
let autoRefreshInterval = null;
let txHistory = [];
let ensResolveTimeout = null;
let gasUpdateTimeout = null;
let gasPrices = {
  slow: null,
  normal: null,
  fast: null,
  custom: null,
};
let TOKENS = { ...DEFAULT_TOKENS };

// Event listener management for cleanup
const eventListeners = new Map();
const abortControllers = new Map();

function addManagedEventListener(element, event, handler, options = {}) {
  if (!element) return;
  
  const key = `${element.id || element.className}_${event}`;
  
  // Remove existing listener if present
  if (eventListeners.has(key)) {
    const oldHandler = eventListeners.get(key);
    element.removeEventListener(event, oldHandler);
  }
  
  // Add new listener
  element.addEventListener(event, handler, options);
  eventListeners.set(key, handler);
}

function cleanupEventListeners() {
  // Remove all managed event listeners
  eventListeners.forEach((handler, key) => {
    const [elementId, event] = key.split('_');
    const element = document.getElementById(elementId) || document.querySelector(`.${elementId}`);
    if (element) {
      element.removeEventListener(event, handler);
    }
  });
  eventListeners.clear();
  
  // Abort all pending requests
  abortControllers.forEach(controller => controller.abort());
  abortControllers.clear();
  
  // Clear timeouts
  if (ensResolveTimeout) clearTimeout(ensResolveTimeout);
  if (gasUpdateTimeout) clearTimeout(gasUpdateTimeout);
  if (swapSimulationTimeout) clearTimeout(swapSimulationTimeout);
  if (autoRefreshInterval) clearInterval(autoRefreshInterval);
}

const enc = new TextEncoder(),
  dec = new TextDecoder();
async function deriveKey(pass, salt, meta) {
  const kdf = (meta && meta.kdf) || "pbkdf2-sha256";
  if (kdf === "pbkdf2-sha256") {
    let iter = Number((meta && meta.iter) || 210000);
    if (!Number.isFinite(iter)) iter = 210000;
    iter = Math.min(Math.max(10_000, Math.floor(iter)), 5_000_000); // clamp
    const km = await crypto.subtle.importKey(
      "raw",
      enc.encode(pass),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
      km,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  throw new Error("Unsupported KDF: " + kdf);
}

const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) =>
  new Uint8Array(
    atob(s)
      .split("")
      .map((c) => c.charCodeAt(0))
  );

async function encryptPK(pkHex, pass, opts = {}) {
  const meta = { v: KEY_VERSION, ...DEFAULT_KDF, ...opts };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pass, salt, meta);
  const aad = meta.aad ? enc.encode(meta.aad) : undefined;
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      enc.encode(pkHex)
    )
  );
  return { ...meta, ct: b64(ct), iv: b64(iv), salt: b64(salt) };
}

async function decryptPK(payload, pass, aadExpected) {
  const meta = {
    v: payload.v ?? 0,
    kdf: payload.kdf || "pbkdf2-sha256",
    iter: payload.iter || 210000,
    aad: payload.aad,
  };
  const key = await deriveKey(pass, unb64(payload.salt), meta);

  if (aadExpected && meta.aad && meta.aad !== aadExpected) {
    throw new Error("Keystore/address mismatch");
  }

  try {
    const aad = enc.encode(aadExpected || meta.aad || "");
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(payload.iv), additionalData: aad },
      key,
      unb64(payload.ct)
    );
    return dec.decode(pt);
  } catch (e) {
    // Legacy fallback: only try if no AAD was used originally
    if (!meta.aad && aadExpected) {
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: unb64(payload.iv) }, // no AAD
        key,
        unb64(payload.ct)
      );
      return dec.decode(pt);
    }
    throw e;
  }
}

async function migrateKeystoreIfNeeded() {
  const list = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
  let changed = false;
  for (const w of list) {
    const c = w.crypto;
    // Old shape had no v/kdf/iter – wrap it with defaults without touching ct/iv/salt
    if (c && c.ct && !("v" in c)) {
      w.crypto = { v: KEY_VERSION, ...DEFAULT_KDF, ...c };
      changed = true;
    }
  }
  if (changed) localStorage.setItem(LS_WALLETS, JSON.stringify(list));
}

// Initialize
async function init() {
  // Check if running as extension and handle CSP restrictions
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
    // Keep service worker alive
    setInterval(() => {
      chrome.runtime.sendMessage({ action: 'keepAlive' }, () => {
        if (chrome.runtime.lastError) {
          // Service worker was inactive, will restart automatically
        }
      });
    }, 20000); // Every 20 seconds
  }
  
  loadTheme();

  await migrateKeystoreIfNeeded();

  loadWallets();
  await initProvider();
  await loadCustomTokens();

  // --- auto-unlock last wallet (with password prompt) ---
  try {
    const last = localStorage.getItem(LS_LAST);
    if (last) {
      const list = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
      const entry = list.find(
        (w) => w.address.toLowerCase() === last.toLowerCase()
      );
      if (entry) {
        const label =
          entry.label ||
          entry.address.slice(0, 6) + "..." + entry.address.slice(-4);
        const pass = prompt(`Unlock ${label}: enter your wallet password`);
        if (pass) {
          try {
            const pk = await decryptPK(
              entry.crypto,
              pass,
              entry.address.toLowerCase()
            );

            // Rewrap legacy keystores that were saved without AAD
            if (!entry.crypto.aad) {
              try {
                const newPayload = await encryptPK(pk, pass, {
                  aad: entry.address.toLowerCase(),
                });
                entry.crypto = newPayload;
                const listNow = JSON.parse(
                  localStorage.getItem(LS_WALLETS) || "[]"
                ).map((w) =>
                  w.address.toLowerCase() === entry.address.toLowerCase()
                    ? entry
                    : w
                );
                localStorage.setItem(LS_WALLETS, JSON.stringify(listNow));
              } catch (e) {
                console.warn("Keystore rewrap failed:", e);
              }
            }

            wallet = new ethers.Wallet(pk, provider);
            await displayWallet();

            showToast("Wallet unlocked!");
          } catch (e) {
            console.warn("Auto-unlock failed (bad password)");
            // keep LS_LAST so user can try from selector
          }
        }
      } else {
        // stale pointer, clean up
        localStorage.removeItem(LS_LAST);
      }
    }
  } catch (e) {
    console.warn("Auto-unlock skipped:", e);
  }

  setupEventListeners();
  
  // Check if opened for dApp approval
  checkForDappRequest();
}

// Handle dApp requests when opened as popup
async function checkForDappRequest() {
  const params = new URLSearchParams(window.location.search);
  const requestId = params.get('request');
  const requestType = params.get('type');
  const origin = params.get('origin');
  
  if (!requestId || !requestType) return;
  
  // Show the dApp modal
  const modal = document.getElementById('dappApprovalModal');
  const originDiv = document.getElementById('dappOrigin');
  
  if (!modal || !originDiv) return;
  
  modal.classList.remove('hidden');
  // Safely set origin text to prevent XSS
  originDiv.textContent = '';
  const warningIcon = document.createTextNode('⚠️ Request from: ');
  const strongElem = document.createElement('strong');
  strongElem.textContent = decodeURIComponent(origin);
  originDiv.appendChild(warningIcon);
  originDiv.appendChild(strongElem);
  
  // Hide all request types first
  document.getElementById('connectionRequest')?.classList.add('hidden');
  document.getElementById('transactionRequest')?.classList.add('hidden');
  document.getElementById('signRequest')?.classList.add('hidden');
  
  // Get the request details from background script
  chrome.runtime.sendMessage({ 
    type: 'GET_REQUEST', 
    requestId: requestId 
  }, async (pendingRequest) => {
    if (!pendingRequest) {
      modal.classList.add('hidden');
      return;
    }
    
    switch (requestType) {
      case 'connect':
        handleConnectionRequest(requestId, pendingRequest);
        break;
      case 'transaction':
        await handleTransactionRequest(requestId, pendingRequest);
        break;
      case 'sign':
        handleSignRequest(requestId, pendingRequest);
        break;
    }
  });
}

function handleConnectionRequest(requestId, pendingRequest) {
  const connDiv = document.getElementById('connectionRequest');
  const accountDiv = document.getElementById('connectionAccount');
  const modalTitle = document.getElementById('dappModalTitle');
  
  if (!connDiv || !accountDiv || !modalTitle) return;
  
  modalTitle.textContent = 'Connect to DApp';
  connDiv.classList.remove('hidden');
  
  if (wallet) {
    accountDiv.textContent = wallet.address;
  } else {
    accountDiv.textContent = 'No wallet connected';
  }
  
  // Setup approve/reject handlers
  const approveBtn = document.getElementById('approveDapp');
  const rejectBtn = document.getElementById('rejectDapp');
  
  if (approveBtn) {
    approveBtn.onclick = async () => {
      if (!wallet) {
        alert('Please unlock your wallet first');
        return;
      }
      
      // Store connected site
      chrome.storage.local.set({ 
        [`connected_${pendingRequest.origin}`]: true,
        'current_wallet': wallet.address 
      });
      
      // Send response
      chrome.runtime.sendMessage({
        type: 'USER_RESPONSE',
        requestId: requestId,
        response: { result: [wallet.address] }
      });
      
      window.close();
    };
  }
  
  if (rejectBtn) {
    rejectBtn.onclick = () => {
      chrome.runtime.sendMessage({
        type: 'USER_RESPONSE',
        requestId: requestId,
        response: { error: { code: 4001, message: 'User rejected connection' } }
      });
      
      window.close();
    };
  }
}

async function handleTransactionRequest(requestId, pendingRequest) {
  const txDiv = document.getElementById('transactionRequest');
  const modalTitle = document.getElementById('dappModalTitle');
  
  if (!txDiv || !modalTitle) return;
  
  modalTitle.textContent = 'Approve Transaction';
  txDiv.classList.remove('hidden');
  
  const txParams = pendingRequest.request.params[0];
  
  // Display transaction details
  document.getElementById('dappTxFrom').textContent = txParams.from || wallet?.address || '';
  document.getElementById('dappTxTo').textContent = txParams.to || '';
  document.getElementById('dappTxValue').textContent = txParams.value ? 
    `${ethers.formatEther(txParams.value)} ETH` : '0 ETH';
  document.getElementById('dappTxGas').textContent = txParams.gas || 'Auto';
  
  // Handle calldata
  const calldata = txParams.data || '0x';
  const calldataDisplay = document.getElementById('calldataDisplay');
  const swissKnifeLink = document.getElementById('swissKnifeLink');
  const toggleBtn = document.getElementById('toggleCalldata');
  const calldataSection = document.getElementById('calldataSection');
  
  if (calldataDisplay) {
    calldataDisplay.value = calldata;
  }
  
  if (swissKnifeLink && calldata !== '0x') {
    swissKnifeLink.href = `https://calldata.swiss-knife.xyz/decoder?calldata=${calldata}`;
  }
  
  if (toggleBtn && calldataSection) {
    toggleBtn.onclick = () => {
      const isHidden = calldataSection.classList.contains('hidden');
      calldataSection.classList.toggle('hidden');
      toggleBtn.textContent = isHidden ? 'Hide' : 'Show';
    };
  }
  
  // Setup approve/reject handlers
  const approveBtn = document.getElementById('approveDapp');
  const rejectBtn = document.getElementById('rejectDapp');
  
  if (approveBtn) {
    approveBtn.onclick = async () => {
      if (!wallet) {
        alert('Please unlock your wallet first');
        return;
      }
      
      try {
        // Send the transaction
        const tx = await wallet.sendTransaction({
          to: txParams.to,
          value: txParams.value || 0,
          data: txParams.data || '0x',
          gasLimit: txParams.gas,
          maxFeePerGas: txParams.maxFeePerGas,
          maxPriorityFeePerGas: txParams.maxPriorityFeePerGas
        });
        
        // Send response with transaction hash
        chrome.runtime.sendMessage({
          type: 'USER_RESPONSE',
          requestId: requestId,
          response: { result: tx.hash }
        });
        
        showToast(`Transaction sent: ${tx.hash.slice(0, 10)}...`);
        window.close();
      } catch (err) {
        chrome.runtime.sendMessage({
          type: 'USER_RESPONSE',
          requestId: requestId,
          response: { error: { code: -32000, message: err.message } }
        });
        
        alert('Transaction failed: ' + err.message);
      }
    };
  }
  
  if (rejectBtn) {
    rejectBtn.onclick = () => {
      chrome.runtime.sendMessage({
        type: 'USER_RESPONSE',
        requestId: requestId,
        response: { error: { code: 4001, message: 'User rejected transaction' } }
      });
      
      window.close();
    };
  }
}

function handleSignRequest(requestId, pendingRequest) {
  const signDiv = document.getElementById('signRequest');
  const modalTitle = document.getElementById('dappModalTitle');
  const messageDiv = document.getElementById('signMessage');
  
  if (!signDiv || !modalTitle || !messageDiv) return;
  
  modalTitle.textContent = 'Sign Message';
  signDiv.classList.remove('hidden');
  
  const message = pendingRequest.request.params[0];
  messageDiv.textContent = message;
  
  // Setup approve/reject handlers
  const approveBtn = document.getElementById('approveDapp');
  const rejectBtn = document.getElementById('rejectDapp');
  
  if (approveBtn) {
    approveBtn.onclick = async () => {
      if (!wallet) {
        alert('Please unlock your wallet first');
        return;
      }
      
      try {
        const signature = await wallet.signMessage(message);
        
        chrome.runtime.sendMessage({
          type: 'USER_RESPONSE',
          requestId: requestId,
          response: { result: signature }
        });
        
        window.close();
      } catch (err) {
        chrome.runtime.sendMessage({
          type: 'USER_RESPONSE',
          requestId: requestId,
          response: { error: { code: -32000, message: err.message } }
        });
        
        alert('Signing failed: ' + err.message);
      }
    };
  }
  
  if (rejectBtn) {
    rejectBtn.onclick = () => {
      chrome.runtime.sendMessage({
        type: 'USER_RESPONSE',
        requestId: requestId,
        response: { error: { code: 4001, message: 'User rejected signature' } }
      });
      
      window.close();
    };
  }
}

async function loadCustomTokens() {
  try {
    const stored = localStorage.getItem("custom_tokens");
    if (stored) {
      customTokens = JSON.parse(stored);
      // Create TOKENS in specific order: defaults first, then custom
      TOKENS = {};
      // Add default tokens in order
      for (const key of Object.keys(DEFAULT_TOKENS)) {
        TOKENS[key] = DEFAULT_TOKENS[key];
      }
      // Add custom tokens
      for (const key of Object.keys(customTokens)) {
        if (!DEFAULT_TOKENS[key]) {
          TOKENS[key] = customTokens[key];
        }
      }
    } else {
      TOKENS = {};
      for (const key of Object.keys(DEFAULT_TOKENS)) {
        TOKENS[key] = DEFAULT_TOKENS[key];
      }
    }
  } catch (err) {
    customTokens = {};
    TOKENS = {};
    for (const key of Object.keys(DEFAULT_TOKENS)) {
      TOKENS[key] = DEFAULT_TOKENS[key];
    }
  }
}

function saveCustomToken(address, token) {
  customTokens[token.symbol] = token;
  TOKENS[token.symbol] = token;
  localStorage.setItem("custom_tokens", JSON.stringify(customTokens));
}

function loadTheme() {
  const theme = localStorage.getItem("theme") || "light";
  document.documentElement.setAttribute("data-theme", theme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme");
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
}

function loadRpcSettings() {
  const customRpc = localStorage.getItem("custom_rpc");

  document.querySelectorAll(".rpc-item").forEach((item) => {
    item.classList.remove("active");
    const itemRpc = item.dataset.rpc;

    if (itemRpc === "custom" && currentRpc === customRpc) {
      item.classList.add("active");
    } else if (itemRpc === currentRpc) {
      item.classList.add("active");
    }
  });

  if (customRpc) {
    document.getElementById("customRpcUrl").value = customRpc;
  }
}

async function initProvider() {
  try {
    // Add timeout for RPC connections
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    provider = new ethers.JsonRpcProvider(currentRpc);
    await provider.getBlockNumber();
    clearTimeout(timeoutId);

    // Initialize zWallet contract
    zWalletContract = new ethers.Contract(
      ZWALLET_ADDRESS,
      ZWALLET_ABI,
      provider
    );

    console.log("Connected to:", currentRpc);
    loadRpcSettings();
    showToast("Connected to network");
  } catch (err) {
    console.error("RPC connection failed:", err);
    if (typeof timeoutId !== 'undefined') clearTimeout(timeoutId);
    // Try fallback
    for (const rpc of [
      "https://eth.llamarpc.com",
      "https://ethereum.publicnode.com",
    ]) {
      try {
        provider = new ethers.JsonRpcProvider(rpc);
        await provider.getBlockNumber();
        zWalletContract = new ethers.Contract(
          ZWALLET_ADDRESS,
          ZWALLET_ABI,
          provider
        );
        currentRpc = rpc;
        localStorage.setItem("rpc_endpoint", rpc);
        loadRpcSettings();
        break;
      } catch (e) {
        continue;
      }
    }
    if (!provider) {
      showToast("Network connection failed");
    }
  }
}

function loadWallets() {
  const v2 = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
  savedWallets = v2.map(({ address, label }) => ({ address, label }));
  updateWalletSelectorFrom(v2);
}

async function saveWallet(address, privateKey) {
  const pass = prompt("Create a password to encrypt this wallet:");
  if (!pass) return;
  const payload = await encryptPK(privateKey, pass, {
    aad: address.toLowerCase(),
  });
  const entry = {
    address,
    label: address.slice(0, 6) + "..." + address.slice(-4),
    crypto: payload,
  };
  const stored = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
  if (!stored.find((w) => w.address === address)) {
    stored.push(entry);
    localStorage.setItem(LS_WALLETS, JSON.stringify(stored));
    localStorage.setItem(LS_LAST, address);
  }
  updateWalletSelectorFrom(stored);
}

function deleteWallet(address) {
  const list = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]").filter(
    (w) => w.address.toLowerCase() !== address.toLowerCase()
  );
  localStorage.setItem(LS_WALLETS, JSON.stringify(list));
  updateWalletSelectorFrom(list);

  const last = localStorage.getItem(LS_LAST);
  if (last && last.toLowerCase() === address.toLowerCase()) {
    localStorage.removeItem(LS_LAST);
  }
  if (wallet && wallet.address.toLowerCase() === address.toLowerCase()) {
    wallet = null;
    document.getElementById("walletSection").classList.add("hidden");
    document.getElementById("balanceSection").classList.add("hidden");
  }
}

function updateWalletSelector() {
  const selector = document.getElementById("walletSelector");
  const selectorSection = document.getElementById("walletSelectorSection");

  selector.innerHTML = '<option value="">Select wallet...</option>';

  if (savedWallets.length > 0) {
    selectorSection.classList.remove("hidden");
    savedWallets.forEach((w) => {
      const option = document.createElement("option");
      option.value = w.address;
      option.textContent = w.label;
      if (wallet && wallet.address === w.address) {
        option.selected = true;
      }
      selector.appendChild(option);
    });
  } else {
    selectorSection.classList.add("hidden");
  }
}

function updateWalletSelectorFrom(list) {
  savedWallets = list.map(({ address, label }) => ({ address, label }));
  updateWalletSelector();
}

// Fetch all balances using zWallet contract's batchView
async function fetchAllBalances() {
  if (!wallet || !provider || !zWalletContract) return;

  try {
    // Get WETH price from CTC contract directly
    let wethPrice = 0;
    try {
      const ctcContract = new ethers.Contract(CTC_ADDRESS, CTC_ABI, provider);
      const [priceUSDC, priceStr] = await ctcContract.checkPrice(WETH_ADDRESS);
      wethPrice = Number(priceUSDC) / 1e6; // USDC has 6 decimals
      ethPrice = wethPrice;
      console.log("WETH/ETH price fetched:", wethPrice, "USDC per ETH");
    } catch (err) {
      console.error("Error fetching WETH price:", err);
      ethPrice = 3500; // Fallback
      wethPrice = ethPrice;
    }

    // Prepare token addresses and ids for batchView
    const tokenAddresses = [];
    const tokenIds = [];
    const tokenSymbols = [];

    for (const [symbol, token] of Object.entries(TOKENS)) {
      if (token.isERC6909) {
        tokenAddresses.push(token.address);
        tokenIds.push(BigInt(token.id));
      } else {
        tokenAddresses.push(token.address || ethers.ZeroAddress);
        tokenIds.push(0);
      }
      tokenSymbols.push(symbol);
    }

    // Call batchView to get all data in one call
    const [
      rawBalances,
      balances,
      names,
      symbols,
      decimals,
      pricesETH,
      pricesUSDC,
      pricesETHStr,
      pricesUSDCStr,
    ] = await zWalletContract.batchView(
      wallet.address,
      tokenAddresses,
      tokenIds
    );

    // Process the results
    currentBalances = {};
    tokenPrices = {};

    for (let i = 0; i < tokenSymbols.length; i++) {
      const symbol = tokenSymbols[i];
      const token = TOKENS[symbol];

      // Store balance
      currentBalances[symbol] = {
        raw: rawBalances[i],
        formatted: ethers.formatUnits(rawBalances[i], decimals[i]),
      };

      // Store prices
      let priceInEth = Number(pricesETH[i]) / 1e18;
      let priceInUsd = Number(pricesUSDC[i]) / 1e6;

      // Override stablecoin prices to exactly $1.00
      if (symbol === "USDC" || symbol === "USDT" || symbol === "DAI") {
        priceInUsd = 1.0; // Stablecoins are always $1
        // Calculate ETH price based on current ETH/USD rate
        if (wethPrice > 0) {
          priceInEth = 1.0 / wethPrice; // 1 USD worth of ETH
        }
      }
      // Override ETH price with WETH price we fetched
      else if (symbol === "ETH") {
        priceInUsd = wethPrice; // Use the WETH price in USDC
        priceInEth = 1; // 1 ETH = 1 ETH always
      }

      tokenPrices[symbol] = {
        eth: priceInEth,
        usd: priceInUsd,
      };

      // Update token metadata if needed
      if (!token.isCoin && (token.name === undefined || token.name === "")) {
        token.name = names[i] || symbol;
        token.symbol = symbols[i] || symbol;
        token.decimals = decimals[i];
      }
    }

    updateBalanceDisplay();
  } catch (err) {
    console.error("Error fetching balances with batchView:", err);
    await fetchBalancesFallback();
  }
}

async function fetchBalancesFallback() {
  if (!wallet || !provider || !zWalletContract) return;

  // Get WETH price from CTC contract directly
  try {
    const ctcContract = new ethers.Contract(CTC_ADDRESS, CTC_ABI, provider);
    const [priceUSDC, priceStr] = await ctcContract.checkPrice(WETH_ADDRESS);
    ethPrice = Number(priceUSDC) / 1e6; // USDC has 6 decimals
    console.log("WETH/ETH price (fallback):", ethPrice, "USDC per ETH");
  } catch (err) {
    console.error("Error fetching WETH price:", err);
    ethPrice = 3500; // Fallback
  }

  for (const [symbol, token] of Object.entries(TOKENS)) {
    try {
      const tokenAddress = token.address || ethers.ZeroAddress;
      const tokenId = token.isERC6909 ? BigInt(token.id) : 0;

      // Get balance
      const [raw, bal] = await zWalletContract.getBalanceOf(
        wallet.address,
        tokenAddress,
        tokenId
      );

      currentBalances[symbol] = {
        raw: raw,
        formatted: ethers.formatUnits(raw, token.decimals || 18),
      };

      // Get prices
      if (symbol === "ETH") {
        // For ETH, use the WETH price we already fetched
        tokenPrices[symbol] = {
          eth: 1, // 1 ETH = 1 ETH
          usd: ethPrice, // Use WETH price in USDC
        };
      } else if (symbol === "USDC" || symbol === "USDT" || symbol === "DAI") {
        // Override stablecoin prices to exactly $1.00
        tokenPrices[symbol] = {
          eth: ethPrice > 0 ? 1.0 / ethPrice : 0,
          usd: 1.0,
        };
      } else {
        try {
          const [priceETH] = await zWalletContract.checkPriceInETH(
            tokenAddress
          );
          const [priceUSDC] = await zWalletContract.checkPriceInETHToUSDC(
            tokenAddress
          );

          tokenPrices[symbol] = {
            eth: Number(priceETH) / 1e18,
            usd: Number(priceUSDC) / 1e6,
          };
        } catch {
          tokenPrices[symbol] = { eth: 0, usd: 0 };
        }
      }
    } catch (err) {
      console.error(`Failed to fetch ${symbol} data:`, err);
      currentBalances[symbol] = { raw: 0n, formatted: "0" };
      tokenPrices[symbol] = { eth: 0, usd: 0 };
    }
  }

  updateBalanceDisplay();
}

function updateBalanceDisplay() {
  const tokenGrid = document.getElementById("tokenGrid");
  const sendTokenGrid = document.getElementById("sendTokenGrid");
  tokenGrid.innerHTML = "";
  sendTokenGrid.innerHTML = "";

  let totalValue = 0;

  // Use Object.keys to maintain insertion order
  const tokenKeys = Object.keys(TOKENS);
  for (const symbol of tokenKeys) {
    const token = TOKENS[symbol];
    const balance = currentBalances[symbol] || { formatted: "0" };
    const price = tokenPrices[symbol] || { eth: 0, usd: 0 };
    const value = parseFloat(balance.formatted) * price.usd;
    totalValue += value;

    // Create row for wallet tab
    const walletRow = document.createElement("div");
    walletRow.className = "token-row";
    walletRow.dataset.symbol = symbol;

    // Special display logic for ETH vs other tokens
    let priceDisplay1 = "";
    let priceDisplay2 = "";

    if (symbol === "ETH") {
      // For ETH: show USD price per ETH and total value
      if (price.usd > 0) {
        priceDisplay1 = `$${price.usd.toFixed(2)}/ETH`;
        priceDisplay2 = `$${value.toFixed(2)}`;
      } else {
        priceDisplay1 = "Price unavailable";
        priceDisplay2 = "$0.00";
      }
    } else {
      // For other tokens: show ETH ratio and USD value
      priceDisplay1 = `${price.eth.toFixed(6)} ETH`;
      priceDisplay2 = `$${value.toFixed(2)}`;
    }

    walletRow.innerHTML = `
  <div class="token-left">
    <div class="token-icon">${TOKEN_LOGOS[symbol] || "💰"}</div>
    <div class="token-details">
      <div class="token-symbol">${esc(symbol)}</div>
      <div class="token-name">${esc(token.name || symbol)}</div>
    </div>
  </div>
  <div class="token-right">
    <div class="token-balance">${Number(balance.formatted).toFixed(4)}</div>
    <div class="token-prices">
      <span class="eth-price">${esc(priceDisplay1)}</span>
      <span class="usd-price">${esc(priceDisplay2)}</span>
    </div>
  </div>`;

    tokenGrid.appendChild(walletRow);

    // Create row for send tab
    const sendRow = walletRow.cloneNode(true);
    if (symbol === selectedToken) {
      sendRow.classList.add("selected");
    }
    sendRow.addEventListener("click", () => selectToken(symbol));
    sendTokenGrid.appendChild(sendRow);
  }

  document.getElementById(
    "portfolioTotal"
  ).textContent = `Total: $${totalValue.toFixed(2)}`;
}

function selectToken(symbol) {
  selectedToken = symbol;
  document.querySelectorAll("#sendTokenGrid .token-row").forEach((row) => {
    row.classList.toggle("selected", row.dataset.symbol === symbol);
  });
  document.getElementById("selectedTokenLabel").textContent = symbol;
  updateEstimatedTotal();
}

async function resolveENS(name) {
  if (!name.endsWith(".eth")) return null;

  try {
    return await provider.resolveName(name);
  } catch {
    return null;
  }
}

async function updateGasPrices() {
  if (!provider) return;

  try {
    const feeData = await provider.getFeeData();

    // Get current base fee and add buffer for next block
    let baseFee = feeData.maxFeePerGas;
    let priorityFee = feeData.maxPriorityFeePerGas;

    // Fallback to reasonable defaults if not available
    if (!baseFee || baseFee === 0n) {
      baseFee = ethers.parseUnits("20", "gwei"); // 20 gwei fallback
    }
    if (!priorityFee || priorityFee === 0n) {
      priorityFee = ethers.parseUnits("1.5", "gwei"); // 1.5 gwei fallback
    }

    // More conservative multipliers
    gasPrices.slow = {
      maxFeePerGas: (baseFee * 95n) / 100n, // 95% of base (was 90%)
      maxPriorityFeePerGas: ethers.parseUnits("1", "gwei"), // Fixed 1 gwei for slow
    };

    gasPrices.normal = {
      maxFeePerGas: (baseFee * 110n) / 100n, // 110% buffer (was 100%)
      maxPriorityFeePerGas: priorityFee, // Keep suggested priority
    };

    gasPrices.fast = {
      maxFeePerGas: (baseFee * 125n) / 100n, // 125% buffer (was 120%)
      maxPriorityFeePerGas: (priorityFee * 120n) / 100n, // 120% priority (was 150%)
    };

    // Cap maximum gas prices to prevent overpaying
    const maxGasPrice = ethers.parseUnits("200", "gwei");
    const maxPriorityPrice = ethers.parseUnits("10", "gwei");

    for (const speed of ["slow", "normal", "fast"]) {
      if (gasPrices[speed].maxFeePerGas > maxGasPrice) {
        gasPrices[speed].maxFeePerGas = maxGasPrice;
      }
      if (gasPrices[speed].maxPriorityFeePerGas > maxPriorityPrice) {
        gasPrices[speed].maxPriorityFeePerGas = maxPriorityPrice;
      }
    }

    // Update display
    document.getElementById("slowPrice").textContent = (
      Number(gasPrices.slow.maxFeePerGas) / 1e9
    ).toFixed(1);
    document.getElementById("normalPrice").textContent = (
      Number(gasPrices.normal.maxFeePerGas) / 1e9
    ).toFixed(1);
    document.getElementById("fastPrice").textContent = (
      Number(gasPrices.fast.maxFeePerGas) / 1e9
    ).toFixed(1);

    await updateEstimatedTotal();
  } catch (err) {
    console.error("Gas price error:", err);

    // Fallback to safe defaults on error
    const fallbackGas = ethers.parseUnits("30", "gwei");
    const fallbackPriority = ethers.parseUnits("2", "gwei");

    gasPrices.slow = {
      maxFeePerGas: ethers.parseUnits("20", "gwei"),
      maxPriorityFeePerGas: ethers.parseUnits("1", "gwei"),
    };
    gasPrices.normal = {
      maxFeePerGas: fallbackGas,
      maxPriorityFeePerGas: fallbackPriority,
    };
    gasPrices.fast = {
      maxFeePerGas: ethers.parseUnits("50", "gwei"),
      maxPriorityFeePerGas: ethers.parseUnits("3", "gwei"),
    };
  }
}

async function updateEstimatedTotal() {
  const amount = document.getElementById("amount").value || "0";
  if (!wallet || !provider) {
    document.getElementById("estimatedTotal").textContent = "--";
    return;
  }

  try {
    const token = TOKENS[selectedToken];
    const gasLimit =
      selectedToken === "ETH" ? 21000n : token?.isERC6909 ? 150000n : 100000n;

    const gasPrice = gasPrices[selectedGasSpeed]?.maxFeePerGas || 20000000000n;
    const gasCostEth = ethers.formatEther(gasLimit * gasPrice);
    const gasCostUsd = parseFloat(gasCostEth) * ethPrice;

    const tokenPrice = tokenPrices[selectedToken] || { eth: 0, usd: 0 };
    const amountUsd = parseFloat(amount) * tokenPrice.usd;

    document.getElementById(
      "estimatedTotal"
    ).textContent = `${amount} ${selectedToken} ($${amountUsd.toFixed(
      2
    )}) + Ξ${parseFloat(gasCostEth).toFixed(5)} gas ($${gasCostUsd.toFixed(
      2
    )})`;
  } catch {
    document.getElementById("estimatedTotal").textContent =
      amount + " " + selectedToken;
  }
}

async function calculateMaxAmount() {
  if (!wallet) return "0";

  const balance = currentBalances[selectedToken];
  if (!balance) return "0";

  if (selectedToken === "ETH") {
    const gasLimit = 21000n;
    const gasPrice = gasPrices[selectedGasSpeed]?.maxFeePerGas || 30000000000n;
    const gasCost = (gasLimit * gasPrice * 110n) / 100n; // 110% buffer (was 120%)

    if (balance.raw > gasCost) {
      return ethers.formatEther(balance.raw - gasCost);
    }
    return "0";
  }

  return balance.formatted;
}

async function fetchTransactionHistoryExtended() {
  if (!wallet || !provider) return;

  const txList = document.getElementById("txList");
  const loadingMsg = document.getElementById("txLoadingMessage");
  const loadMoreBtn = document.getElementById("loadMoreTxBtn");

  if (!loadingMsg) {
    console.error("Loading message element not found");
    return;
  }

  loadingMsg.textContent = "Loading 24 hours of transactions...";
  loadingMsg.classList.remove("hidden");
  if (loadMoreBtn) loadMoreBtn.classList.add("hidden");
  txHistory = [];

  const uniqueTxs = new Set();

  try {
    const currentBlock = await provider.getBlockNumber();
    // ~7200 blocks in 24 hours (12 sec per block)
    // We'll fetch in chunks of 999 blocks
    const totalBlocks = 7200;
    const chunkSize = 999;
    const chunks = Math.ceil(totalBlocks / chunkSize);
    
    for (let i = 0; i < chunks; i++) {
      const toBlock = currentBlock - (i * chunkSize);
      const fromBlock = Math.max(0, toBlock - chunkSize + 1);
      
      loadingMsg.textContent = `Loading transactions... (${i + 1}/${chunks})`;
      
      const promises = [];
      
      // Fetch each token's transfers for this chunk
      for (const [symbol, token] of Object.entries(TOKENS)) {
        if (!token.address) continue;
        
        if (token.isERC6909) {
          // Handle ERC6909 tokens
          promises.push(
            Promise.all([
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock,
                topics: [
                  ethers.id("TransferSingle(address,address,address,uint256,uint256)"),
                  null,
                  ethers.zeroPadValue(wallet.address, 32),
                ],
              }).catch(() => []),
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock,
                topics: [
                  ethers.id("TransferSingle(address,address,address,uint256,uint256)"),
                  null,
                  null,
                  ethers.zeroPadValue(wallet.address, 32),
                ],
              }).catch(() => [])
            ]).then(([sentLogs, receivedLogs]) => {
              // Process logs same as before
              for (const log of sentLogs) {
                const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                  ["uint256", "uint256"],
                  log.data
                );
                if (decoded[0].toString() === token.id) {
                  const txKey = `${log.transactionHash}-${log.logIndex}`;
                  if (!uniqueTxs.has(txKey)) {
                    uniqueTxs.add(txKey);
                    txHistory.push({
                      type: "send",
                      token: symbol,
                      amount: ethers.formatUnits(decoded[1], token.decimals),
                      hash: log.transactionHash,
                      block: log.blockNumber,
                      to: "0x" + log.topics[3].slice(26),
                      logIndex: log.logIndex,
                    });
                  }
                }
              }
              for (const log of receivedLogs) {
                const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                  ["uint256", "uint256"],
                  log.data
                );
                if (decoded[0].toString() === token.id) {
                  const txKey = `${log.transactionHash}-${log.logIndex}`;
                  if (!uniqueTxs.has(txKey)) {
                    uniqueTxs.add(txKey);
                    txHistory.push({
                      type: "receive",
                      token: symbol,
                      amount: ethers.formatUnits(decoded[1], token.decimals),
                      hash: log.transactionHash,
                      block: log.blockNumber,
                      from: "0x" + log.topics[2].slice(26),
                      logIndex: log.logIndex,
                    });
                  }
                }
              }
            })
          );
        } else {
          // Standard ERC20
          promises.push(
            Promise.all([
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock,
                topics: [
                  ethers.id("Transfer(address,address,uint256)"),
                  ethers.zeroPadValue(wallet.address, 32),
                ],
              }).catch(() => []),
              provider.getLogs({
                address: token.address,
                fromBlock,
                toBlock,
                topics: [
                  ethers.id("Transfer(address,address,uint256)"),
                  null,
                  ethers.zeroPadValue(wallet.address, 32),
                ],
              }).catch(() => [])
            ]).then(([sentLogs, receivedLogs]) => {
              for (const log of sentLogs) {
                const txKey = `${log.transactionHash}-${log.logIndex}`;
                if (!uniqueTxs.has(txKey)) {
                  uniqueTxs.add(txKey);
                  const amount = ethers.formatUnits(log.data, token.decimals);
                  txHistory.push({
                    type: "send",
                    token: symbol,
                    amount,
                    hash: log.transactionHash,
                    block: log.blockNumber,
                    to: "0x" + log.topics[2].slice(26),
                    logIndex: log.logIndex,
                  });
                }
              }
              for (const log of receivedLogs) {
                const txKey = `${log.transactionHash}-${log.logIndex}`;
                if (!uniqueTxs.has(txKey)) {
                  uniqueTxs.add(txKey);
                  const amount = ethers.formatUnits(log.data, token.decimals);
                  txHistory.push({
                    type: "receive",
                    token: symbol,
                    amount,
                    hash: log.transactionHash,
                    block: log.blockNumber,
                    from: "0x" + log.topics[1].slice(26),
                    logIndex: log.logIndex,
                  });
                }
              }
            })
          );
        }
      }
      
      await Promise.all(promises);
    }
    
    // Sort by block number and log index
    txHistory.sort((a, b) => {
      if (b.block !== a.block) return b.block - a.block;
      return (b.logIndex || 0) - (a.logIndex || 0);
    });

    displayTransactions();
  } catch (err) {
    console.error("Error fetching extended history:", err);
    if (loadingMsg) loadingMsg.textContent = "Error loading extended history";
    if (loadMoreBtn) loadMoreBtn.classList.remove("hidden");
  }
}

async function fetchTransactionHistory() {
  if (!wallet || !provider) return;

  const txList = document.getElementById("txList");
  const loadingMsg = document.getElementById("txLoadingMessage");

  loadingMsg.textContent = "Loading recent transactions (last ~3 hours)...";
  txList.classList.add("hidden");
  txHistory = [];

  // Use a Set to track unique transactions
  const uniqueTxs = new Set();

  try {
    // Get block number for limiting search
    const currentBlock = await provider.getBlockNumber();
    // Use 999 blocks to stay under RPC limit of 1000
    // This is approximately 3.3 hours of Ethereum blocks (12 sec per block)
    const fromBlock = Math.max(0, currentBlock - 999);

    // Parallel fetch all logs
    const promises = [];
    
    // Fetch token transfers for each token in parallel
    for (const [symbol, token] of Object.entries(TOKENS)) {
      if (!token.address) continue; // Skip ETH

      // Handle ERC6909 tokens differently
      if (token.isERC6909) {
        // ERC6909 uses TransferSingle event
        promises.push(
          Promise.all([
            provider.getLogs({
              address: token.address,
              fromBlock,
              toBlock: currentBlock,
              topics: [
                ethers.id("TransferSingle(address,address,address,uint256,uint256)"),
                null,
                ethers.zeroPadValue(wallet.address, 32),
              ],
            }),
            provider.getLogs({
              address: token.address,
              fromBlock,
              toBlock: currentBlock,
              topics: [
                ethers.id("TransferSingle(address,address,address,uint256,uint256)"),
                null,
                null,
                ethers.zeroPadValue(wallet.address, 32),
              ],
            })
          ]).then(([sentLogs, receivedLogs]) => {
            // Process ERC6909 sent
            for (const log of sentLogs) {
              const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                ["uint256", "uint256"],
                log.data
              );
              if (decoded[0].toString() === token.id) {
                const txKey = `${log.transactionHash}-${log.logIndex}`;
                if (!uniqueTxs.has(txKey)) {
                  uniqueTxs.add(txKey);
                  txHistory.push({
                    type: "send",
                    token: symbol,
                    amount: ethers.formatUnits(decoded[1], token.decimals),
                    hash: log.transactionHash,
                    block: log.blockNumber,
                    to: "0x" + log.topics[3].slice(26),
                    logIndex: log.logIndex,
                  });
                }
              }
            }
            // Process ERC6909 received
            for (const log of receivedLogs) {
              const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                ["uint256", "uint256"],
                log.data
              );
              if (decoded[0].toString() === token.id) {
                const txKey = `${log.transactionHash}-${log.logIndex}`;
                if (!uniqueTxs.has(txKey)) {
                  uniqueTxs.add(txKey);
                  txHistory.push({
                    type: "receive",
                    token: symbol,
                    amount: ethers.formatUnits(decoded[1], token.decimals),
                    hash: log.transactionHash,
                    block: log.blockNumber,
                    from: "0x" + log.topics[2].slice(26),
                    logIndex: log.logIndex,
                  });
                }
              }
            }
          }).catch(err => {
            console.error(`Error fetching ${symbol} history:`, err);
          })
        );
      } else {
        // Standard ERC20 transfers
        promises.push(
          Promise.all([
            provider.getLogs({
              address: token.address,
              fromBlock,
              toBlock: currentBlock,
              topics: [
                ethers.id("Transfer(address,address,uint256)"),
                ethers.zeroPadValue(wallet.address, 32),
              ],
            }),
            provider.getLogs({
              address: token.address,
              fromBlock,
              toBlock: currentBlock,
              topics: [
                ethers.id("Transfer(address,address,uint256)"),
                null,
                ethers.zeroPadValue(wallet.address, 32),
              ],
            })
          ]).then(([sentLogs, receivedLogs]) => {
            // Process sent
            for (const log of sentLogs) {
              const txKey = `${log.transactionHash}-${log.logIndex}`;
              if (!uniqueTxs.has(txKey)) {
                uniqueTxs.add(txKey);
                const amount = ethers.formatUnits(log.data, token.decimals);
                txHistory.push({
                  type: "send",
                  token: symbol,
                  amount,
                  hash: log.transactionHash,
                  block: log.blockNumber,
                  to: "0x" + log.topics[2].slice(26),
                  logIndex: log.logIndex,
                });
              }
            }
            // Process received
            for (const log of receivedLogs) {
              const txKey = `${log.transactionHash}-${log.logIndex}`;
              if (!uniqueTxs.has(txKey)) {
                uniqueTxs.add(txKey);
                const amount = ethers.formatUnits(log.data, token.decimals);
                txHistory.push({
                  type: "receive",
                  token: symbol,
                  amount,
                  hash: log.transactionHash,
                  block: log.blockNumber,
                  from: "0x" + log.topics[1].slice(26),
                  logIndex: log.logIndex,
                });
              }
            }
          }).catch(err => {
            console.error(`Error fetching ${symbol} history:`, err);
          })
        );
      }
    }

    // Wait for all fetches to complete
    await Promise.all(promises);

    // Sort by block number and log index
    txHistory.sort((a, b) => {
      if (b.block !== a.block) return b.block - a.block;
      return (b.logIndex || 0) - (a.logIndex || 0);
    });

    // Display transactions
    displayTransactions();
  } catch (err) {
    console.error("Error fetching history:", err);
    loadingMsg.textContent = "Error loading transactions";
  }
}

function displayTransactions() {
  const txList = document.getElementById("txList");
  const loadingMsg = document.getElementById("txLoadingMessage");
  const loadMoreBtn = document.getElementById("loadMoreTxBtn");

  if (!txList || !loadingMsg) {
    console.error("Transaction display elements not found");
    return;
  }

  if (txHistory.length === 0) {
    loadingMsg.textContent = "No transactions found in the last 3 hours";
    txList.classList.add("hidden");
    if (loadMoreBtn) loadMoreBtn.classList.remove("hidden");
    return;
  }

  loadingMsg.classList.add("hidden");
  txList.classList.remove("hidden");
  if (loadMoreBtn) loadMoreBtn.classList.remove("hidden");
  txList.innerHTML = "";

  // Display max 100 most recent
  const displayTxs = txHistory.slice(0, 100);

  for (const tx of displayTxs) {
    const item = document.createElement("div");
    item.className = "tx-item";

    const icon = TOKEN_LOGOS[tx.token]
      ? `<div style="width: 20px; height: 20px;">${TOKEN_LOGOS[tx.token]}</div>`
      : tx.token;

    item.innerHTML = `
                    <span class="tx-type ${tx.type}">${tx.type}</span>
                    <div class="tx-details">
                        <a class="tx-hash" data-hash="${tx.hash}" href="#" title="View on Etherscan">${tx.hash.slice(0, 10)}... ↗</a>
                        <div style="font-size: 10px; color: var(--text-secondary);">
                            ${
                              tx.type === "send"
                                ? "To: " + tx.to?.slice(0, 8) + "..."
                                : "From: " + tx.from?.slice(0, 8) + "..."
                            }
                        </div>
                    </div>
                    <div class="tx-amount">
                        ${tx.type === "send" ? "-" : "+"}${parseFloat(
      tx.amount
    ).toFixed(4)} ${tx.token}
                    </div>
                `;

    // Add click handler to the hash link
    const hashLink = item.querySelector('.tx-hash');
    if (hashLink) {
      hashLink.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const hash = hashLink.dataset.hash;
        
        // Use Chrome API to open in new tab for extension compatibility
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({
            action: 'open_external',
            url: `https://etherscan.io/tx/${hash}`
          });
        } else {
          window.open(
            `https://etherscan.io/tx/${hash}`,
            "_blank",
            "noopener,noreferrer"
          );
        }
      });
    }

    txList.appendChild(item);
  }
}

function esc(s) {
  return String(s).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[c])
  );
}

window.addEventListener("beforeunload", () => {
  // Clean up all event listeners and timers
  cleanupEventListeners();
  wallet = null;
});
function lockWallet() {
  wallet = null;
  showToast("Locked");
}

function showEtherscanLink(txHash) {
  const status = document.getElementById("txStatus");
  const link = document.createElement("a");
  link.href = `#`;
  link.className = "etherscan-link";
  link.textContent = "View on Etherscan →";
  link.addEventListener('click', (e) => {
    e.preventDefault();
    if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        action: 'open_external',
        url: `https://etherscan.io/tx/${txHash}`
      });
    } else {
      window.open(`https://etherscan.io/tx/${txHash}`, '_blank', 'noopener,noreferrer');
    }
  });
  status.appendChild(link);
}

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2000);
}

async function copyToClipboard(text, type) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(type === "address" ? "Address copied!" : "Private key copied!");
  } catch (err) {
    // Fallback for older browsers or permission issues
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    textarea.style.pointerEvents = "none";
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand("copy");
      showToast(type === "address" ? "Address copied!" : "Private key copied!");
    } catch (copyErr) {
      console.error("Copy failed:", copyErr);
      showToast("Copy failed - please copy manually");
    } finally {
      document.body.removeChild(textarea);
    }
  }
}

async function exportEncryptedKey() {
  if (!wallet) return;

  try {
    const password = prompt("Enter a password to encrypt your private key:");
    if (!password) return;
    
    const confirmPassword = prompt("Confirm password:");
    if (password !== confirmPassword) {
      alert("Passwords don't match!");
      return;
    }

    // Encrypt the private key
    const encrypted = await encryptPK(wallet.privateKey, password, {
      aad: wallet.address.toLowerCase()
    });

    const exportData = {
      version: 2,
      address: wallet.address,
      encrypted: encrypted,
      timestamp: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
      type: "application/json" 
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `zWallet-encrypted-${wallet.address.slice(2, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast("Encrypted key exported!");
  } catch (err) {
    console.error("Export failed:", err);
    showToast("Export failed");
  }
}

async function displayWallet() {
  document.getElementById("walletSection").classList.remove("hidden");
  document.getElementById("balanceSection").classList.remove("hidden");

  const address = wallet.address;
  document.getElementById("address").textContent =
    address.slice(0, 6) + "..." + address.slice(-4);
  document.getElementById("address").title = address;
  
  // Set Etherscan link
  const etherscanLink = document.getElementById("etherscanLink");
  if (etherscanLink) {
    etherscanLink.href = `https://etherscan.io/address/${address}`;
  }

  // Private key display moved to Settings tab

  try {
    const ensName = await provider.lookupAddress(address);
    document.getElementById("ensName").textContent = ensName || "";
  } catch {
    document.getElementById("ensName").textContent = "";
  }

  // Immediately fetch balances and prices
  await fetchAllBalances();
  await updateGasPrices();

  if (document.getElementById("autoRefresh").checked) {
    clearInterval(autoRefreshInterval);
    autoRefreshInterval = setInterval(() => {
      fetchAllBalances();
      updateGasPrices();
    }, 15000);
  }
}

async function addCustomToken(tokenAddress) {
  if (!zWalletContract) return null;

  try {
    // Validate address
    if (!ethers.isAddress(tokenAddress)) {
      throw new Error("Invalid address");
    }

    // Get metadata from zWallet contract
    const [name, symbol, decimals] = await zWalletContract.getMetadata(
      tokenAddress
    );

    if (!symbol || symbol === "") {
      throw new Error("Could not fetch token metadata");
    }

    const token = {
      address: tokenAddress,
      symbol: symbol.toUpperCase(),
      name: name || symbol,
      decimals: decimals,
    };

    // Check if already exists
    if (TOKENS[token.symbol]) {
      throw new Error("Token already exists");
    }

    return token;
  } catch (err) {
    console.error("Error adding token:", err);
    throw err;
  }
}

async function sendTransaction() {
  const toInput = document.getElementById("toAddress").value.trim();
  const amount = document.getElementById("amount").value;
  const status = document.getElementById("txStatus");

  if (!toInput || !amount || !wallet) {
    status.innerHTML = '<div class="status error">Fill all fields</div>';
    return;
  }

  // Ensure wallet is connected to provider
  if (!wallet.provider) {
    wallet = wallet.connect(provider);
  }

  let toAddress = toInput;
  if (toInput.endsWith(".eth")) {
    status.innerHTML = '<div class="status">Resolving ENS...</div>';
    toAddress = await resolveENS(toInput);
    if (!toAddress) {
      status.innerHTML = '<div class="status error">ENS not found</div>';
      return;
    }
  }

  if (!ethers.isAddress(toAddress)) {
    status.innerHTML = '<div class="status error">Invalid address</div>';
    return;
  }

  // Calculate values for confirmation
  const token = TOKENS[selectedToken];
  const gasSettings = gasPrices[selectedGasSpeed] || gasPrices.normal;
  const gasLimit =
    selectedToken === "ETH" ? 21000n : token.isERC6909 ? 150000n : 100000n;
  const gasPrice = gasSettings.maxFeePerGas || 20000000000n;
  const gasCost = gasLimit * gasPrice;
  const gasCostEth = ethers.formatEther(gasCost);
  const gasCostUsd = parseFloat(gasCostEth) * ethPrice;

  const tokenPrice = tokenPrices[selectedToken] || { eth: 0, usd: 0 };
  const amountUsd = parseFloat(amount) * tokenPrice.usd;
  const totalUsd = amountUsd + gasCostUsd;

  // Check balances before showing confirmation
  const balance = currentBalances[selectedToken];
  if (!balance || parseFloat(balance.formatted) < parseFloat(amount)) {
    status.innerHTML = '<div class="status error">Insufficient balance</div>';
    return;
  }

  // Check ETH balance for gas
  const ethBalance = await provider.getBalance(wallet.address);
  if (ethBalance < gasCost) {
    status.innerHTML =
      '<div class="status error">Insufficient ETH for gas</div>';
    return;
  }

  // Populate confirmation modal
  document.getElementById("confirmToken").textContent = selectedToken;
  document.getElementById(
    "confirmAmount"
  ).textContent = `${amount} ${selectedToken}`;
  document.getElementById("confirmTo").textContent = toInput.endsWith(".eth")
    ? `${toInput} (${toAddress.slice(0, 6)}...${toAddress.slice(-4)})`
    : `${toAddress.slice(0, 6)}...${toAddress.slice(-4)}`;
  document.getElementById(
    "confirmValueUSD"
  ).textContent = `$${amountUsd.toFixed(2)}`;
  document.getElementById("confirmGas").textContent = `Ξ${parseFloat(
    gasCostEth
  ).toFixed(5)} ($${gasCostUsd.toFixed(2)})`;
  document.getElementById("confirmTotal").textContent = `$${totalUsd.toFixed(
    2
  )}`;

  // Prepare transaction calldata
  let calldata = '0x';
  if (selectedToken === 'ETH') {
    // ETH transfers have no calldata
    calldata = '0x';
  } else {
    // ERC20 transfer calldata
    const token = TOKENS[selectedToken];
    if (token.isERC6909) {
      // ERC6909 transferFrom calldata
      const iface = new ethers.Interface([
        "function transferFrom(address from, address to, uint256 id, uint256 amount)"
      ]);
      calldata = iface.encodeFunctionData("transferFrom", [
        wallet.address,
        toAddress,
        token.id,
        ethers.parseUnits(amount.toString(), token.decimals)
      ]);
    } else {
      // Standard ERC20 transfer calldata
      const iface = new ethers.Interface([
        "function transfer(address to, uint256 amount)"
      ]);
      calldata = iface.encodeFunctionData("transfer", [
        toAddress,
        ethers.parseUnits(amount.toString(), token.decimals)
      ]);
    }
  }

  // Setup calldata display
  const calldataDisplay = document.getElementById('sendCalldataDisplay');
  const swissKnifeLink = document.getElementById('sendSwissKnifeLink');
  const toggleBtn = document.getElementById('toggleSendCalldata');
  const calldataSection = document.getElementById('sendCalldataSection');
  
  if (calldataDisplay) {
    calldataDisplay.value = calldata;
  }
  
  if (swissKnifeLink) {
    if (calldata !== '0x' && calldata.length > 2) {
      swissKnifeLink.href = `https://calldata.swiss-knife.xyz/decoder?calldata=${calldata}`;
      swissKnifeLink.style.display = 'inline-block';
    } else {
      swissKnifeLink.style.display = 'none';
    }
  }
  
  if (toggleBtn && calldataSection) {
    // Reset state
    calldataSection.classList.add('hidden');
    toggleBtn.textContent = 'Show';
    
    // Add click handler (remove old one first to avoid duplicates)
    const newToggleBtn = toggleBtn.cloneNode(true);
    toggleBtn.parentNode.replaceChild(newToggleBtn, toggleBtn);
    
    newToggleBtn.onclick = () => {
      const isHidden = calldataSection.classList.contains('hidden');
      calldataSection.classList.toggle('hidden');
      newToggleBtn.textContent = isHidden ? 'Hide' : 'Show';
    };
  }

  // Show modal
  const modal = document.getElementById("txConfirmModal");
  modal.classList.remove("hidden");

  // Create promise for user confirmation
  const userConfirmed = await new Promise((resolve) => {
    const confirmBtn = document.getElementById("confirmSend");
    const cancelBtn = document.getElementById("cancelSend");
    const closeBtn = document.getElementById("modalClose");

    const cleanup = () => {
      confirmBtn.removeEventListener("click", handleConfirm);
      cancelBtn.removeEventListener("click", handleCancel);
      closeBtn.removeEventListener("click", handleCancel);
      modal.classList.add("hidden");
    };

    const handleConfirm = () => {
      cleanup();
      resolve(true);
    };

    const handleCancel = () => {
      cleanup();
      resolve(false);
    };

    confirmBtn.addEventListener("click", handleConfirm);
    cancelBtn.addEventListener("click", handleCancel);
    closeBtn.addEventListener("click", handleCancel);
  });

  if (!userConfirmed) {
    status.innerHTML = '<div class="status">Transaction cancelled</div>';
    return;
  }

  try {
    status.innerHTML = '<div class="status">Preparing transaction...</div>';
    document.getElementById("sendBtn").disabled = true;

    let tx;
    if (selectedToken === "ETH") {
      // Send ETH directly - no calldata needed
      tx = await wallet.sendTransaction({
        to: toAddress,
        value: ethers.parseEther(amount),
        gasLimit: 21000,
        maxFeePerGas: gasSettings.maxFeePerGas,
        maxPriorityFeePerGas: gasSettings.maxPriorityFeePerGas,
      });
    } else if (token.isERC6909) {
      // For ERC6909 tokens
      const amountWei = ethers.parseUnits(amount, token.decimals || 18);

      // Get the transfer calldata from zWallet
      const transferData = await zWalletContract.getERC6909Transfer(
        toAddress,
        BigInt(token.id),
        amountWei
      );

      // Send to the TOKEN contract with the calldata
      tx = await wallet.sendTransaction({
        to: token.address,
        data: transferData,
        gasLimit: 150000,
        maxFeePerGas: gasSettings.maxFeePerGas,
        maxPriorityFeePerGas: gasSettings.maxPriorityFeePerGas,
      });
    } else {
      // For ERC20 tokens
      const amountWei = ethers.parseUnits(amount, token.decimals || 18);

      // Get the transfer calldata from zWallet
      const transferData = await zWalletContract.getERC20Transfer(
        toAddress,
        amountWei
      );

      // Send to the TOKEN contract with the calldata
      tx = await wallet.sendTransaction({
        to: token.address,
        data: transferData,
        gasLimit: 100000,
        maxFeePerGas: gasSettings.maxFeePerGas,
        maxPriorityFeePerGas: gasSettings.maxPriorityFeePerGas,
      });
    }

    status.innerHTML = `<div class="status">TX sent: ${tx.hash.slice(
      0,
      10
    )}...</div>`;
    showToast("Transaction sent! Waiting for confirmation...");

    const receipt = await tx.wait();
    if (receipt.status === 1) {
      status.innerHTML = '<div class="status success">✓ Success!</div>';
      showEtherscanLink(tx.hash);
      showToast("Transaction confirmed!");
      await fetchAllBalances();
      document.getElementById("toAddress").value = "";
      document.getElementById("amount").value = "";
    } else {
      status.innerHTML = '<div class="status error">Transaction Failed</div>';
      showEtherscanLink(tx.hash);
    }
  } catch (err) {
    console.error("Transaction error:", err);
    let errorMsg = "Transaction failed";

    if (err.message.includes("insufficient funds")) {
      errorMsg = "Insufficient funds for gas";
    } else if (err.message.includes("user rejected")) {
      errorMsg = "Transaction rejected";
    } else if (err.message.includes("nonce")) {
      errorMsg = "Nonce error - try again";
    } else if (err.code === "UNKNOWN_ERROR" || err.code === -32603) {
      errorMsg = "Network error - check balance and try again";
    }

    status.innerHTML = `<div class="status error">${errorMsg}</div>`;
  } finally {
    document.getElementById("sendBtn").disabled = false;
  }
}

function setupEventListeners() {
  // Theme toggle
  document.getElementById("themeToggle").addEventListener("click", toggleTheme);

  // Tabs
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document
        .querySelectorAll(".tab")
        .forEach((t) => t.classList.remove("active"));
      document
        .querySelectorAll(".tab-content")
        .forEach((c) => c.classList.remove("active"));

      tab.classList.add("active");
      const tabContent = document.getElementById(tab.dataset.tab + "-tab");
      tabContent.classList.add("active");

      // Load transactions when tab is opened
      if (tab.dataset.tab === "txs" && wallet && txHistory.length === 0) {
        fetchTransactionHistory();
      }
    });
  });

  // Transaction history button
  document.getElementById("loadTxBtn").addEventListener("click", () => {
    fetchTransactionHistory();
  });

  // Load more transactions button  
  const loadMoreBtn = document.getElementById("loadMoreTxBtn");
  if (loadMoreBtn) {
    loadMoreBtn.addEventListener("click", async () => {
      try {
        await fetchTransactionHistoryExtended();
      } catch (err) {
        console.error("Error loading extended history:", err);
        showToast("Failed to load transactions");
      }
    });
  }

  // Wallet management
  document
    .getElementById("walletSelector")
    .addEventListener("change", async (e) => {
      const addr = e.target.value;
      if (!addr) return;
      const list = JSON.parse(localStorage.getItem(LS_WALLETS) || "[]");
      const entry = list.find((w) => w.address === addr);
      const pass = prompt("Enter your wallet password:");
      try {
        const pk = await decryptPK(
          entry.crypto,
          pass,
          entry.address.toLowerCase()
        );

        // Rewrap legacy keystores that were saved without AAD
        if (!entry.crypto.aad) {
          try {
            const newPayload = await encryptPK(pk, pass, {
              aad: entry.address.toLowerCase(),
            });
            entry.crypto = newPayload;
            const listNow = JSON.parse(
              localStorage.getItem(LS_WALLETS) || "[]"
            ).map((w) =>
              w.address.toLowerCase() === entry.address.toLowerCase()
                ? entry
                : w
            );
            localStorage.setItem(LS_WALLETS, JSON.stringify(listNow));
          } catch (e) {
            console.warn("Keystore rewrap failed:", e);
          }
        }

        wallet = new ethers.Wallet(pk, provider);
        await displayWallet();

        localStorage.setItem(LS_LAST, addr);
        showToast("Wallet unlocked!");
      } catch {
        alert("Wrong password");
        e.target.value = "";
      }
    });

  document.getElementById("deleteWalletBtn").addEventListener("click", () => {
    const selector = document.getElementById("walletSelector");
    const address = selector.value;

    if (address && confirm("Delete wallet?")) {
      deleteWallet(address);
      showToast("Wallet deleted");
    }
  });

  document.getElementById("generateBtn").addEventListener("click", async () => {
    try {
      wallet = ethers.Wallet.createRandom().connect(provider);
      saveWallet(wallet.address, wallet.privateKey);
      await displayWallet();
      showToast("Wallet generated!");
    } catch (err) {
      console.error("Error generating wallet:", err);
      alert("Failed to generate wallet: " + err.message);
    }
  });

  document.getElementById("importBtn").addEventListener("click", () => {
    document.getElementById("importSection").classList.toggle("hidden");
    document.getElementById("privateKeyInput").focus();
  });

  document
    .getElementById("confirmImportBtn")
    .addEventListener("click", async () => {
      const key = document.getElementById("privateKeyInput").value.trim();
      if (!key) return;

      try {
        // Validate private key format and length
        const cleanKey = key.replace(/^0x/i, '');
        if (!/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
          throw new Error("Invalid private key format");
        }
        
        const formattedKey = "0x" + cleanKey;
        wallet = new ethers.Wallet(formattedKey, provider);
        
        // Verify the wallet was created successfully
        if (!wallet.address) {
          throw new Error("Failed to create wallet");
        }
        
        saveWallet(wallet.address, wallet.privateKey);
        await displayWallet();
        document.getElementById("importSection").classList.add("hidden");
        document.getElementById("privateKeyInput").value = "";
        showToast("Wallet imported!");
      } catch (err) {
        console.error("Import error:", err);
        alert("Invalid private key: " + (err.message || "Unknown error"));
      }
    });

  document.getElementById("cancelImportBtn").addEventListener("click", () => {
    document.getElementById("importSection").classList.add("hidden");
    document.getElementById("privateKeyInput").value = "";
  });

  // Copy buttons
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!wallet) return;
      const type = btn.dataset.copy;
      if (type === "privateKey") {
        if (!confirm("Reveal and copy private key?")) return;
      }
      await copyToClipboard(
        type === "address" ? wallet.address : wallet.privateKey,
        type
      );
    });
  });

  // Download key button removed - moved to Settings tab

  document.getElementById("refreshBtn").addEventListener("click", async () => {
    try {
      await fetchAllBalances();
      showToast("Refreshed!");
    } catch (err) {
      console.error("Error refreshing balances:", err);
      showToast("Failed to refresh");
    }
  });

  // Add token functionality
  document.getElementById("addTokenBtn").addEventListener("click", () => {
    document.getElementById("addTokenSection").classList.toggle("hidden");
    document.getElementById("newTokenAddress").focus();
  });

  document
    .getElementById("confirmAddToken")
    .addEventListener("click", async () => {
      const address = document.getElementById("newTokenAddress").value.trim();
      const symbolOverride = document
        .getElementById("newTokenSymbol")
        .value.trim();

      if (!address) return;

      try {
        const token = await addCustomToken(address);

        // Use override symbol if provided
        if (symbolOverride) {
          token.symbol = symbolOverride.toUpperCase();
        }

        saveCustomToken(address, token);

        // Hide the form
        document.getElementById("addTokenSection").classList.add("hidden");
        document.getElementById("newTokenAddress").value = "";
        document.getElementById("newTokenSymbol").value = "";

        // Refresh balances to include new token
        await fetchAllBalances();
        showToast(`Added ${token.symbol}!`);
      } catch (err) {
        alert("Error adding token: " + err.message);
      }
    });

  // Send functionality
  document.getElementById("maxBtn").addEventListener("click", async () => {
    try {
      const max = await calculateMaxAmount();
      document.getElementById("amount").value = parseFloat(max).toFixed(6);
      await updateEstimatedTotal();
    } catch (err) {
      console.error("Error calculating max amount:", err);
      showToast("Failed to calculate max");
    }
  });

  document.getElementById("toAddress").addEventListener("input", async (e) => {
    const value = e.target.value.trim();
    const resolved = document.getElementById("resolvedAddress");

    // Clear previous timeout to prevent race conditions
    if (ensResolveTimeout) {
      clearTimeout(ensResolveTimeout);
      ensResolveTimeout = null;
    }

    if (value.endsWith(".eth")) {
      resolved.textContent = "Resolving...";
      
      // Debounce ENS resolution by 500ms
      ensResolveTimeout = setTimeout(async () => {
        try {
          const address = await resolveENS(value);
          // Check if input hasn't changed
          if (document.getElementById("toAddress").value.trim() === value) {
            if (address) {
              resolved.textContent = `→ ${address.slice(0, 6)}...${address.slice(-4)}`;
              resolved.style.color = "var(--success)";
            } else {
              resolved.textContent = "Not found";
              resolved.style.color = "var(--error)";
            }
          }
        } catch (err) {
          console.error("ENS resolution error:", err);
          resolved.textContent = "Error resolving";
          resolved.style.color = "var(--error)";
        }
      }, 500);
    } else {
      resolved.textContent = "";
    }

    // Debounce gas update
    if (gasUpdateTimeout) {
      clearTimeout(gasUpdateTimeout);
    }
    gasUpdateTimeout = setTimeout(() => {
      updateEstimatedTotal();
    }, 300);
  });

  document
    .getElementById("amount")
    .addEventListener("input", updateEstimatedTotal);

  // Gas options
  document.querySelectorAll(".gas-option").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      document
        .querySelectorAll(".gas-option")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      selectedGasSpeed = btn.dataset.speed;

      const custom = document.getElementById("customGasSection");
      custom.classList.toggle("hidden", selectedGasSpeed !== "custom");

      updateEstimatedTotal();
    });
  });

  document
    .getElementById("customGasPrice")
    .addEventListener("input", async () => {
      if (selectedGasSpeed === "custom") {
        const max = document.getElementById("customGasPrice").value;
        const priority =
          document.getElementById("customPriorityFee").value || "1";

        if (max) {
          gasPrices.custom = {
            maxFeePerGas: ethers.parseUnits(max, "gwei"),
            maxPriorityFeePerGas: ethers.parseUnits(priority, "gwei"),
          };
          await updateEstimatedTotal();
        }
      }
    });

  document.getElementById("sendBtn").addEventListener("click", sendTransaction);

  // Settings
  document.querySelectorAll(".rpc-item").forEach((item) => {
    item.addEventListener("click", async () => {
      const rpc = item.dataset.rpc;

      if (rpc === "custom") {
        document.getElementById("customRpcSection").classList.toggle("hidden");
      } else {
        currentRpc = rpc;
        localStorage.setItem("rpc_endpoint", rpc);
        await initProvider();

        if (wallet) {
          wallet = wallet.connect(provider);
          await fetchAllBalances();
        }
      }
    });
  });

  document
    .getElementById("saveCustomRpc")
    .addEventListener("click", async () => {
      const url = document.getElementById("customRpcUrl").value.trim();
      if (!url) return;

      try {
        const testProvider = new ethers.JsonRpcProvider(url);
        await testProvider.getBlockNumber();

        localStorage.setItem("custom_rpc", url);
        currentRpc = url;
        localStorage.setItem("rpc_endpoint", url);
        provider = testProvider;
        zWalletContract = new ethers.Contract(
          ZWALLET_ADDRESS,
          ZWALLET_ABI,
          provider
        );

        if (wallet) {
          wallet = wallet.connect(provider);
          await fetchAllBalances();
        }

        showToast("Custom RPC saved!");
        document.getElementById("customRpcSection").classList.add("hidden");
        loadRpcSettings();
      } catch {
        alert("Invalid RPC URL");
      }
    });

  document.getElementById("autoRefresh").addEventListener("change", (e) => {
    if (e.target.checked) {
      if (wallet) {
        autoRefreshInterval = setInterval(() => {
          fetchAllBalances();
          updateGasPrices();
        }, 15000);
      }
    } else {
      clearInterval(autoRefreshInterval);
    }
    localStorage.setItem("auto_refresh", e.target.checked);
  });

  // Private Key Management in Settings
  document.getElementById("revealKeyBtn")?.addEventListener("click", () => {
    if (!wallet) {
      alert("Please unlock your wallet first");
      return;
    }
    
    if (!confirm("Are you sure you want to reveal your private key?")) return;
    
    const keySection = document.getElementById("privateKeySection");
    const keyDisplay = document.getElementById("privateKeyDisplay");
    
    if (keySection && keyDisplay) {
      keyDisplay.textContent = wallet.privateKey;
      keySection.classList.remove("hidden");
      
      // Auto-hide after 60 seconds
      setTimeout(() => {
        keyDisplay.textContent = "••••••••••••••••••••••••••••••••";
        keySection.classList.add("hidden");
      }, 60000);
    }
  });
  
  document.getElementById("hideKeyBtn")?.addEventListener("click", () => {
    const keySection = document.getElementById("privateKeySection");
    const keyDisplay = document.getElementById("privateKeyDisplay");
    
    if (keySection && keyDisplay) {
      keyDisplay.textContent = "••••••••••••••••••••••••••••••••";
      keySection.classList.add("hidden");
    }
  });
  
  document.getElementById("exportKeyBtn")?.addEventListener("click", async () => {
    if (!wallet) {
      alert("Please unlock your wallet first");
      return;
    }
    
    try {
      await exportEncryptedKey();
    } catch (err) {
      console.error("Export error:", err);
      alert("Failed to export key: " + err.message);
    }
  });

  document.getElementById("exportWallets").addEventListener("click", () => {
    try {
      const data = localStorage.getItem(LS_WALLETS) || "[]";
      const blob = new Blob([data], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `zWallet-backup-${new Date().toISOString().split('T')[0]}.encrypted.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast("Encrypted wallets exported!");
    } catch (err) {
      console.error("Export failed:", err);
      showToast("Export failed");
    }
  });

  document.getElementById("clearData").addEventListener("click", () => {
    if (
      confirm(
        "Delete all data, wallets, and custom tokens? This cannot be undone!"
      )
    ) {
      localStorage.clear();
      location.reload();
    }
  });

  // Load auto-refresh setting
  const autoRefresh = localStorage.getItem("auto_refresh") === "true";
  document.getElementById("autoRefresh").checked = autoRefresh;
  
  // Setup swap event listeners
  setupSwapEventListeners();
}

// ============= SWAP FUNCTIONALITY =============
const ZROUTER_ADDRESS = "0x0000000000404FECAf36E6184245475eE1254835";
const ZROUTER_ABI = [
  "function swapV2(address to, bool exactOut, address tokenIn, address tokenOut, uint256 swapAmount, uint256 amountLimit, uint256 deadline) payable returns (uint256 amountIn, uint256 amountOut)",
  "function swapVZ(address to, bool exactOut, uint256 feeOrHook, address tokenIn, address tokenOut, uint256 idIn, uint256 idOut, uint256 swapAmount, uint256 amountLimit, uint256 deadline) payable returns (uint256 amountIn, uint256 amountOut)"
];

// zQuoter ABI for getting best quotes
const ZQUOTER_ABI = [
  "function getQuotes(bool exactOut, address tokenIn, address tokenOut, uint256 swapAmount) view returns ((uint8 source, uint256 feeBps, uint256 amountIn, uint256 amountOut) best, (uint8 source, uint256 feeBps, uint256 amountIn, uint256 amountOut)[] quotes)",
  "function buildBestSwap(address to, bool exactOut, address tokenIn, address tokenOut, uint256 swapAmount, uint256 slippageBps, uint256 deadline) view returns ((uint8 source, uint256 feeBps, uint256 amountIn, uint256 amountOut) best, bytes callData, uint256 amountLimit, uint256 msgValue)"
];

// Multicall3 contract (deployed on Ethereum mainnet)
const MULTICALL3_ADDRESS = "0xcA11bde05977b3631167028862bE2a173976CA11";
const MULTICALL3_ABI = [
  "function tryAggregate(bool requireSuccess, (address target, bytes callData)[] calls) returns ((bool success, bytes returnData)[] returnData)"
];

// Swap state
let swapFromToken = "ETH";
let swapToToken = "USDC";
let swapSlippage = 0.5; // 0.5% default
let swapMode = "exactIn"; // exactIn or exactOut
let bestSwapRoute = null;
let tokenSelectorTarget = null; // 'from' or 'to'
let swapSimulationTimeout = null; // Debounce timer
let isSimulating = false; // Prevent concurrent simulations

// AMM sources enum from zQuoter contract
const AMM_SOURCES = {
  0: "UNI_V2",
  1: "SUSHI",
  2: "ZAMM"
};

// Standard Uniswap V3 fee tiers
const V3_FEE_TIERS = [500, 3000, 10000]; // 0.05%, 0.3%, 1%

// Uniswap V4 tick spacings
const V4_TICK_SPACINGS = {
  500: 10,    // 0.05% fee
  3000: 60,   // 0.3% fee
  10000: 200  // 1% fee
};

async function setupSwapEventListeners() {
  // Token selector dropdowns
  // Initialize swap token displays
  function updateSwapTokenDisplay(which) {
    const token = which === 'from' ? swapFromToken : swapToToken;
    const iconEl = document.getElementById(which === 'from' ? 'swapFromTokenIcon' : 'swapToTokenIcon');
    const displayEl = document.getElementById(which === 'from' ? 'swapFromTokenDisplay' : 'swapToTokenDisplay');
    
    if (iconEl && displayEl) {
      iconEl.innerHTML = TOKEN_LOGOS[token] || '💰';
      displayEl.textContent = token;
    }
  }
  
  // Function to initialize token dropdowns with logos
  function initializeTokenDropdowns() {
    const swapTokens = ['ETH', 'USDC', 'USDT', 'DAI', 'ENS'];
    
    // Populate from dropdown
    const fromDropdown = document.getElementById('swapFromDropdown');
    if (fromDropdown) {
      fromDropdown.innerHTML = swapTokens.map(token => `
        <div class="token-option" data-token="${token}">
          <div class="token-option-icon">${TOKEN_LOGOS[token] || '<div style="width: 100%; height: 100%; background: var(--border); border-radius: 50%;"></div>'}</div>
          <span class="token-option-symbol">${token}</span>
        </div>
      `).join('');
      
      // Add click handlers
      fromDropdown.querySelectorAll('.token-option').forEach(option => {
        option.addEventListener('click', (e) => {
          e.stopPropagation();
          swapFromToken = option.dataset.token;
          updateSwapTokenDisplay('from');
          updateSwapBalances();
          fromDropdown.classList.add('hidden');
          if (document.getElementById("swapFromAmount").value) {
            simulateSwap();
          }
        });
      });
    }
    
    // Populate to dropdown
    const toDropdown = document.getElementById('swapToDropdown');
    if (toDropdown) {
      toDropdown.innerHTML = swapTokens.map(token => `
        <div class="token-option" data-token="${token}">
          <div class="token-option-icon">${TOKEN_LOGOS[token] || '<div style="width: 100%; height: 100%; background: var(--border); border-radius: 50%;"></div>'}</div>
          <span class="token-option-symbol">${token}</span>
        </div>
      `).join('');
      
      // Add click handlers
      toDropdown.querySelectorAll('.token-option').forEach(option => {
        option.addEventListener('click', (e) => {
          e.stopPropagation();
          swapToToken = option.dataset.token;
          updateSwapTokenDisplay('to');
          updateSwapBalances();
          toDropdown.classList.add('hidden');
          if (document.getElementById("swapFromAmount").value) {
            simulateSwap();
          }
        });
      });
    }
  }
  
  // Initialize token displays and dropdowns
  updateSwapTokenDisplay('from');
  updateSwapTokenDisplay('to');
  initializeTokenDropdowns();
  
  // Setup token selector clicks
  document.getElementById('swapFromTokenSelector')?.addEventListener('click', (e) => {
    e.stopPropagation();
    const dropdown = document.getElementById('swapFromDropdown');
    const otherDropdown = document.getElementById('swapToDropdown');
    
    if (dropdown) {
      dropdown.classList.toggle('hidden');
      otherDropdown?.classList.add('hidden');
    }
  });
  
  document.getElementById('swapToTokenSelector')?.addEventListener('click', (e) => {
    e.stopPropagation();
    const dropdown = document.getElementById('swapToDropdown');
    const otherDropdown = document.getElementById('swapFromDropdown');
    
    if (dropdown) {
      dropdown.classList.toggle('hidden');
      otherDropdown?.classList.add('hidden');
    }
  });
  
  // Hide dropdowns when clicking elsewhere
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.token-selector') && !e.target.closest('.token-dropdown')) {
      document.getElementById('swapFromDropdown')?.classList.add('hidden');
      document.getElementById('swapToDropdown')?.classList.add('hidden');
    }
  });
  
  // Swap direction button
  document.getElementById("swapDirectionBtn")?.addEventListener("click", () => {
    // Swap tokens
    const temp = swapFromToken;
    swapFromToken = swapToToken;
    swapToToken = temp;
    
    // Swap amounts
    const fromAmount = document.getElementById("swapFromAmount").value;
    const toAmount = document.getElementById("swapToAmount").value;
    document.getElementById("swapFromAmount").value = toAmount;
    document.getElementById("swapToAmount").value = fromAmount;
    
    // Update displays
    updateSwapTokenDisplay('from');
    updateSwapTokenDisplay('to');
    updateSwapBalances();
    
    if (fromAmount || toAmount) {
      simulateSwap();
    }
  });
  
  // Amount inputs with smart detection and debouncing
  document.getElementById("swapFromAmount")?.addEventListener("input", (e) => {
    swapMode = "exactIn";
    
    // Sanitize input - only allow numbers and decimal point
    let value = e.target.value.replace(/[^0-9.]/g, '');
    
    // Ensure only one decimal point
    const parts = value.split('.');
    if (parts.length > 2) {
      value = parts[0] + '.' + parts.slice(1).join('');
    }
    
    e.target.value = value;
    
    // Validate against balance
    const inputAmount = parseFloat(e.target.value);
    if (inputAmount && inputAmount > 0) {
      const token = TOKENS[swapFromToken];
      let maxBalance;
      
      if (swapFromToken === "ETH") {
        // For ETH, check against actual balance minus gas buffer
        maxBalance = parseFloat(currentBalances["ETH"] || "0");
        // Smart gas buffer based on balance
        const balanceETH = maxBalance;
        let gasBuffer;
        if (balanceETH < 0.01) {
          gasBuffer = 0.003; // ~$12 for low balance users
        } else if (balanceETH < 0.05) {
          gasBuffer = 0.005; // ~$20 for medium balance
        } else {
          gasBuffer = 0.01; // ~$40 for higher balance
        }
        const effectiveBalance = Math.max(0, maxBalance - gasBuffer);
        
        if (inputAmount > effectiveBalance) {
          e.target.value = effectiveBalance > 0 ? effectiveBalance.toFixed(6) : "0";
          showToast(`Max available: ${effectiveBalance.toFixed(6)} ETH (${gasBuffer} ETH gas reserved)`);
        }
      } else {
        // For tokens, check against token balance
        maxBalance = parseFloat(currentBalances[swapFromToken] || "0");
        
        if (inputAmount > maxBalance) {
          const decimals = token?.decimals || 18;
          const precision = decimals <= 6 ? 6 : (decimals <= 8 ? 8 : 6);
          e.target.value = maxBalance > 0 ? maxBalance.toFixed(precision) : "0";
          showToast(`Max available: ${maxBalance.toFixed(precision)} ${swapFromToken}`);
        }
      }
    }
    
    // Clear existing timeout
    if (swapSimulationTimeout) {
      clearTimeout(swapSimulationTimeout);
    }
    
    if (e.target.value) {
      // Debounce simulation by 500ms
      swapSimulationTimeout = setTimeout(() => {
        simulateSwap();
      }, 500);
    } else {
      clearSwapQuote();
    }
  });
  
  document.getElementById("swapToAmount")?.addEventListener("input", (e) => {
    swapMode = "exactOut";
    
    // Sanitize input - only allow numbers and decimal point
    let value = e.target.value.replace(/[^0-9.]/g, '');
    
    // Ensure only one decimal point
    const parts = value.split('.');
    if (parts.length > 2) {
      value = parts[0] + '.' + parts.slice(1).join('');
    }
    
    e.target.value = value;
    
    // Clear existing timeout
    if (swapSimulationTimeout) {
      clearTimeout(swapSimulationTimeout);
    }
    
    if (e.target.value) {
      // Debounce simulation by 500ms
      swapSimulationTimeout = setTimeout(() => {
        simulateSwap();
      }, 500);
    } else {
      clearSwapQuote();
    }
  });
  
  // Max button
  document.getElementById("swapMaxBtn")?.addEventListener("click", async () => {
    if (!wallet || !provider) {
      showToast("Connect wallet first");
      return;
    }
    
    try {
      let maxAmount;
      const token = TOKENS[swapFromToken];
      
      if (!token || swapFromToken === "ETH") {
        // For ETH, we need to account for gas fees more accurately
        const balanceObj = currentBalances["ETH"];
        if (!balanceObj || !balanceObj.formatted) {
          console.log("No ETH balance found");
          showToast("No ETH balance");
          return;
        }
        
        const balanceETH = parseFloat(balanceObj.formatted);
        
        // Get current gas price to calculate buffer more accurately
        let gasBuffer;
        try {
          const feeData = await provider.getFeeData();
          const gasPrice = feeData.maxFeePerGas || feeData.gasPrice || ethers.parseUnits("30", "gwei");
          
          // Estimate gas for a swap transaction (typically 150k-250k gas)
          const estimatedGasLimit = 250000n; // Conservative estimate
          const estimatedGasCost = gasPrice * estimatedGasLimit;
          const estimatedGasETH = parseFloat(ethers.formatEther(estimatedGasCost));
          
          // Add 20% buffer to gas estimate for safety
          gasBuffer = estimatedGasETH * 1.2;
          
          // Apply minimum gas buffers based on balance
          if (balanceETH < 0.01) {
            // For very small balances, use at least the estimated gas cost
            gasBuffer = Math.max(gasBuffer, estimatedGasETH);
          } else if (balanceETH < 0.05) {
            // For small balances, ensure at least 0.002 ETH buffer
            gasBuffer = Math.max(gasBuffer, 0.002);
          } else if (balanceETH < 0.1) {
            // For medium balances, ensure at least 0.003 ETH buffer
            gasBuffer = Math.max(gasBuffer, 0.003);
          } else {
            // For larger balances, ensure at least 0.005 ETH buffer
            gasBuffer = Math.max(gasBuffer, 0.005);
          }
          
          console.log(`ETH Balance: ${balanceETH}, Gas Buffer: ${gasBuffer.toFixed(6)}`);
        } catch (err) {
          console.error("Error estimating gas:", err);
          // Fallback to conservative buffer if gas estimation fails
          if (balanceETH < 0.01) {
            gasBuffer = 0.002;
          } else if (balanceETH < 0.05) {
            gasBuffer = 0.003;
          } else if (balanceETH < 0.1) {
            gasBuffer = 0.005;
          } else {
            gasBuffer = 0.01;
          }
        }
        
        // Calculate max amount after gas buffer
        maxAmount = Math.max(0, balanceETH - gasBuffer);
        
        // Round down to 6 decimal places to avoid precision issues
        maxAmount = Math.floor(maxAmount * 1000000) / 1000000;
        
        // If the result is too small, set to 0
        if (maxAmount < 0.0001) {
          maxAmount = 0;
          const needed = gasBuffer.toFixed(4);
          showToast(`Need ~${needed} ETH for gas`);
        }
      } else {
        // For tokens, use the formatted balance from currentBalances
        const balanceObj = currentBalances[swapFromToken];
        if (!balanceObj || !balanceObj.formatted) {
          console.log(`No balance found for ${swapFromToken}`);
          showToast(`No ${swapFromToken} balance`);
          return;
        }
        
        maxAmount = parseFloat(balanceObj.formatted);
        
        // Round down to avoid precision issues
        const decimals = token?.decimals || 18;
        if (decimals <= 6) {
          maxAmount = Math.floor(maxAmount * 1000000) / 1000000;
        } else if (decimals <= 8) {
          maxAmount = Math.floor(maxAmount * 100000000) / 100000000;
        } else {
          maxAmount = Math.floor(maxAmount * 1000000) / 1000000;
        }
        
        // Also check if user has ETH for gas
        const ethBalance = currentBalances["ETH"];
        if (!ethBalance || parseFloat(ethBalance.formatted) < 0.001) {
          showToast("Warning: Low ETH for gas");
        }
      }
      
      // Set the value in the input field
      if (maxAmount > 0) {
        const displayDecimals = swapFromToken === "ETH" ? 6 : 
                               (token?.decimals === 6 ? 6 : 
                                token?.decimals === 8 ? 8 : 6);
        document.getElementById("swapFromAmount").value = maxAmount.toFixed(displayDecimals);
        
        // Update USD display
        updateSwapUSDValues();
        
        // Trigger simulation
        swapMode = "exactIn";
        
        // Small delay to ensure UI updates
        setTimeout(() => {
          simulateSwap();
        }, 100);
      } else {
        document.getElementById("swapFromAmount").value = "0";
        updateSwapUSDValues();
      }
    } catch (err) {
      console.error("Error getting max amount:", err);
      showToast("Failed to calculate max");
    }
  });
  
  // Slippage options
  document.querySelectorAll(".slippage-option").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      document.querySelectorAll(".slippage-option").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      
      const slippage = btn.dataset.slippage;
      if (slippage === "custom") {
        document.getElementById("customSlippageSection")?.classList.remove("hidden");
        // Focus on custom input
        document.getElementById("customSlippage")?.focus();
      } else {
        document.getElementById("customSlippageSection")?.classList.add("hidden");
        swapSlippage = parseFloat(slippage);
        
        // Re-simulate if amounts are present
        if (document.getElementById("swapFromAmount").value || document.getElementById("swapToAmount").value) {
          simulateSwap();
        }
      }
    });
  });
  
  // Custom slippage input
  document.getElementById("customSlippage")?.addEventListener("input", (e) => {
    const value = parseFloat(e.target.value);
    if (!isNaN(value) && value >= 0 && value <= 50) {
      swapSlippage = value;
      if (document.getElementById("swapFromAmount").value || document.getElementById("swapToAmount").value) {
        simulateSwap();
      }
    }
  });
  
  // Swap button
  document.getElementById("swapBtn")?.addEventListener("click", executeSwap);
  
  // Swap confirmation modal
  document.getElementById("swapModalClose")?.addEventListener("click", () => {
    document.getElementById("swapConfirmModal")?.classList.add("hidden");
  });
  
  document.getElementById("cancelSwapBtn")?.addEventListener("click", () => {
    document.getElementById("swapConfirmModal")?.classList.add("hidden");
  });
  
  // Initialize swap display
  updateSwapTokenDisplay();
  updateSwapBalances();
}

// Update swap token display
function updateSwapTokenDisplay() {
  // Update From token
  const fromIcon = document.getElementById("swapFromIcon");
  const fromSymbol = document.getElementById("swapFromSymbol");
  if (fromIcon) fromIcon.innerHTML = TOKEN_LOGOS[swapFromToken] || generateCoinSVG(swapFromToken);
  if (fromSymbol) fromSymbol.textContent = swapFromToken;
  
  // Update To token
  const toIcon = document.getElementById("swapToIcon");
  const toSymbol = document.getElementById("swapToSymbol");
  if (toIcon) toIcon.innerHTML = TOKEN_LOGOS[swapToToken] || generateCoinSVG(swapToToken);
  if (toSymbol) toSymbol.textContent = swapToToken;
}

function updateSwapBalances() {
  const fromBalance = document.getElementById("swapFromBalance");
  const toBalance = document.getElementById("swapToBalance");
  
  if (fromBalance) {
    const balanceObj = currentBalances[swapFromToken];
    const balance = balanceObj ? balanceObj.formatted : "0";
    const numBalance = parseFloat(balance);
    fromBalance.textContent = isNaN(numBalance) || numBalance === 0 ? "0.000000" : numBalance.toFixed(6);
  }
  
  if (toBalance) {
    const balanceObj = currentBalances[swapToToken];
    const balance = balanceObj ? balanceObj.formatted : "0";
    const numBalance = parseFloat(balance);
    toBalance.textContent = isNaN(numBalance) || numBalance === 0 ? "0.000000" : numBalance.toFixed(6);
  }
}

function clearSwapQuote() {
  document.getElementById("swapRoute").textContent = "--";
  document.getElementById("swapMinimum").textContent = "--";
  document.getElementById("swapGasFee").textContent = "--";
  document.getElementById("swapBtn").textContent = "Enter Amount to Swap";
  document.getElementById("swapBtn").disabled = true;
  bestSwapRoute = null;
}

// Helper to update USD values
function updateSwapUSDValues() {
  const fromAmount = document.getElementById("swapFromAmount").value;
  const toAmount = document.getElementById("swapToAmount").value;
  
  const fromUSD = document.getElementById("swapFromUSD");
  const toUSD = document.getElementById("swapToUSD");
  
  if (fromUSD && fromAmount) {
    const price = tokenPrices[swapFromToken]?.usd || 0;
    const usdValue = parseFloat(fromAmount) * price;
    fromUSD.textContent = `$${usdValue.toFixed(2)}`;
  } else if (fromUSD) {
    fromUSD.textContent = "$0.00";
  }
  
  if (toUSD && toAmount) {
    const price = tokenPrices[swapToToken]?.usd || 0;
    const usdValue = parseFloat(toAmount) * price;
    toUSD.textContent = `$${usdValue.toFixed(2)}`;
  } else if (toUSD) {
    toUSD.textContent = "$0.00";
  }
}

async function simulateSwap() {
  if (!wallet || !provider) {
    showToast("Please connect wallet first");
    return;
  }
  
  // Prevent concurrent simulations
  if (isSimulating) {
    console.log("Simulation already in progress, skipping...");
    return;
  }
  
  isSimulating = true;
  
  try {
    const fromToken = TOKENS[swapFromToken];
    const toToken = TOKENS[swapToToken];
    
    // Get amount  
    const amountIn = document.getElementById("swapFromAmount").value;
    if (!amountIn || parseFloat(amountIn) <= 0) {
      clearSwapQuote();
      return;
    }
    
    // Update UI to show loading
    document.getElementById("swapRoute").textContent = "Finding best route...";
    document.getElementById("swapBtn").textContent = "Getting quote...";
    document.getElementById("swapBtn").disabled = true;
    
    // Prepare token addresses (use 0x0 for ETH)
    const tokenInAddress = swapFromToken === "ETH" ? ethers.ZeroAddress : fromToken.address;
    const tokenOutAddress = swapToToken === "ETH" ? ethers.ZeroAddress : toToken.address;
    
    // Convert amount to wei
    const maxDecimals = fromToken?.decimals || 18;
    const truncated = parseFloat(amountIn).toFixed(maxDecimals);
    const swapAmount = ethers.parseUnits(truncated, maxDecimals);
    
    // Create zQuoter contract instance
    const quoter = new ethers.Contract(ZQUOTER_ADDRESS, ZQUOTER_ABI, provider);
    
    let quotesResult, bestQuote, allQuotes;
    try {
      // Get quotes from zQuoter (exactOut = false for exactIn mode)
      quotesResult = await quoter.getQuotes(
        false, // exactOut = false (we're doing exactIn)
        tokenInAddress,
        tokenOutAddress,
        swapAmount
      );
      
      bestQuote = quotesResult.best;
      allQuotes = quotesResult.quotes;
    } catch (quoterError) {
      console.error("Quoter error:", quoterError);
      // If quoter fails, show a more specific error
      document.getElementById("swapRoute").textContent = "Quoter unavailable";
      document.getElementById("swapBtn").textContent = "Network error";
      document.getElementById("swapBtn").disabled = true;
      return;
    }
    
    // Check if we got a valid quote
    if (!bestQuote || bestQuote.amountOut === 0n) {
      document.getElementById("swapRoute").textContent = "No route found";
      document.getElementById("swapBtn").textContent = "No liquidity";
      document.getElementById("swapBtn").disabled = true;
      document.getElementById("swapToAmount").value = "";
      updateSwapUSDValues();
      return;
    }
    
    // Format the output amount
    const outputAmount = ethers.formatUnits(bestQuote.amountOut, toToken?.decimals || 18);
    console.log(`Quote received: ${amountIn} ${swapFromToken} -> ${outputAmount} ${swapToToken}`);
    document.getElementById("swapToAmount").value = parseFloat(outputAmount).toFixed(6);
    
    // Update USD values
    updateSwapUSDValues();
    
    // Determine the source name
    const sourceNames = ["Uniswap V2", "Sushiswap", "zAMM"];
    const sourceName = sourceNames[bestQuote.source] || `AMM ${bestQuote.source}`;
    
    
    // Calculate minimum received with slippage
    const slippage = swapSlippage;
    const minOutput = parseFloat(outputAmount) * (1 - slippage / 100);
    
    // Estimate gas fee
    const gasPrice = await provider.getFeeData();
    const gasLimit = 200000n; // Estimated gas for swap
    const gasFee = gasPrice.gasPrice * gasLimit;
    const gasFeeETH = ethers.formatEther(gasFee);
    const gasFeeUSD = parseFloat(gasFeeETH) * (tokenPrices["ETH"]?.usd || 0);
    
    // Update UI with quote details
    document.getElementById("swapRoute").textContent = sourceName;
    document.getElementById("swapMinimum").textContent = `${minOutput.toFixed(6)} ${swapToToken}`;
    document.getElementById("swapGasFee").textContent = `$${gasFeeUSD.toFixed(2)}`;
    
    // Store the best quote for execution
    bestSwapRoute = {
      quote: bestQuote,
      tokenIn: tokenInAddress,
      tokenOut: tokenOutAddress,
      amountIn: swapAmount,
      amountOut: bestQuote.amountOut,
      sourceName,
      slippage
    };
    
    // Enable swap button
    document.getElementById("swapBtn").textContent = "Swap";
    document.getElementById("swapBtn").disabled = false;
    
  } catch (err) {
    console.error("Swap simulation error:", err);
    document.getElementById("swapRoute").textContent = "Error";
    document.getElementById("swapBtn").textContent = "Try again";
    document.getElementById("swapBtn").disabled = false;
  } finally {
    isSimulating = false;
  }
}

async function executeSwap() {
  if (!wallet || !bestSwapRoute) {
    showToast("No swap route available");
    return;
  }
  
  try {
    // Check if approval is needed for non-ETH tokens
    if (swapFromToken !== "ETH") {
      const fromToken = TOKENS[swapFromToken];
      const needsApproval = await checkAndRequestApproval(fromToken, bestSwapRoute.amountIn);
      if (!needsApproval) return;
    }
    
    // Create zQuoter contract instance
    const quoter = new ethers.Contract(ZQUOTER_ADDRESS, ZQUOTER_ABI, provider);
    
    // Get the swap calldata from buildBestSwap
    const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour deadline
    const slippageBps = Math.floor(bestSwapRoute.slippage * 100); // Convert % to basis points
    
    let swapData;
    try {
      swapData = await quoter.buildBestSwap(
        wallet.address,
        false, // exactOut = false
        bestSwapRoute.tokenIn,
        bestSwapRoute.tokenOut,
        bestSwapRoute.amountIn,
        slippageBps,
        deadline
      );
    } catch (err) {
      console.error("Failed to build swap:", err);
      showToast("Failed to prepare swap");
      return;
    }
    
    // Extract the calldata and value
    const { callData, msgValue } = swapData;
    
    // Show confirmation modal
    const modal = document.getElementById("swapConfirmModal");
    const fromToken = TOKENS[swapFromToken];
    const toToken = TOKENS[swapToToken];
    
    // Populate confirmation details
    const inputFormatted = ethers.formatUnits(bestSwapRoute.amountIn, fromToken?.decimals || 18);
    const outputFormatted = ethers.formatUnits(bestSwapRoute.amountOut, toToken?.decimals || 18);
    
    document.getElementById("confirmSwapFrom").textContent = `${parseFloat(inputFormatted).toFixed(6)} ${swapFromToken}`;
    document.getElementById("confirmSwapTo").textContent = `${parseFloat(outputFormatted).toFixed(6)} ${swapToToken}`;
    document.getElementById("confirmSwapRoute").textContent = bestSwapRoute.sourceName || "Best Route";
    document.getElementById("confirmSwapSlippage").textContent = `${swapSlippage}%`;
    
    const minOutput = bestSwapRoute.amountOut * BigInt(Math.floor((100 - swapSlippage) * 100)) / 10000n;
    const minFormatted = ethers.formatUnits(minOutput, toToken?.decimals || 18);
    document.getElementById("confirmSwapMinimum").textContent = `${parseFloat(minFormatted).toFixed(6)} ${swapToToken}`;
    
    const gasPrice = (await provider.getFeeData()).maxFeePerGas || ethers.parseUnits("30", "gwei");
    const gasLimit = 200000n; // Estimated
    const gasCost = gasLimit * gasPrice;
    const gasCostEth = ethers.formatEther(gasCost);
    document.getElementById("confirmSwapGas").textContent = `${parseFloat(gasCostEth).toFixed(5)} ETH`;
    
    const totalCostEth = swapFromToken === "ETH" 
      ? parseFloat(inputFormatted) + parseFloat(gasCostEth)
      : parseFloat(gasCostEth);
    document.getElementById("confirmSwapTotal").textContent = `${totalCostEth.toFixed(6)} ETH`;
    
    // Setup calldata display
    const calldataDisplay = document.getElementById("swapCalldataDisplay");
    if (calldataDisplay) calldataDisplay.value = callData;
    
    const toggleBtn = document.getElementById("toggleSwapCalldata");
    const calldataSection = document.getElementById("swapCalldataSection");
    if (toggleBtn) {
      toggleBtn.onclick = () => {
        if (calldataSection.classList.contains("hidden")) {
          calldataSection.classList.remove("hidden");
          toggleBtn.textContent = "Hide";
        } else {
          calldataSection.classList.add("hidden");
          toggleBtn.textContent = "Show";
        }
      };
    }
    
    modal.classList.remove("hidden");
    
    // Wait for user confirmation
    const userConfirmed = await new Promise(resolve => {
      const confirmBtn = document.getElementById("confirmSwapBtn");
      const cancelBtn = document.getElementById("cancelSwapBtn");
      
      const handleConfirm = () => {
        cleanup();
        resolve(true);
      };
      
      const handleCancel = () => {
        cleanup();
        resolve(false);
      };
      
      const cleanup = () => {
        confirmBtn.removeEventListener("click", handleConfirm);
        cancelBtn.removeEventListener("click", handleCancel);
        modal.classList.add("hidden");
      };
      
      confirmBtn.addEventListener("click", handleConfirm);
      cancelBtn.addEventListener("click", handleCancel);
    });
    
    if (!userConfirmed) {
      console.log("Swap cancelled by user");
      return;
    }
    
    // Execute the swap
    document.getElementById("swapStatus").innerHTML = '<div style="color: var(--warning)">Sending transaction...</div>';
    
    const tx = await wallet.sendTransaction({
      to: ZROUTER_ADDRESS,
      data: callData,
      value: msgValue
    });
    
    document.getElementById("swapStatus").innerHTML = `<div style="color: var(--info)">Transaction sent: ${tx.hash.slice(0, 10)}...</div>`;
    
    // Wait for confirmation
    const receipt = await tx.wait();
    
    if (receipt.status === 1) {
      // Create Etherscan link
      const etherscanUrl = `https://etherscan.io/tx/${tx.hash}`;
      document.getElementById("swapStatus").innerHTML = `
        <div style="color: var(--success)">
          ✓ Swap successful! 
          <a href="${etherscanUrl}" target="_blank" style="color: var(--accent); text-decoration: underline; margin-left: 8px;">
            View on Etherscan ↗
          </a>
        </div>`;
      showToast("Swap successful!");
      
      // Clear inputs and refresh balances
      document.getElementById("swapFromAmount").value = "";
      document.getElementById("swapToAmount").value = "";
      clearSwapQuote();
      await fetchAllBalances();
    } else {
      throw new Error("Transaction failed");
    }
    
  } catch (err) {
    console.error("Swap error:", err);
    document.getElementById("swapStatus").innerHTML = `<div style="color: var(--error)">✗ ${err.message || "Swap failed"}</div>`;
    showToast(`Swap failed: ${err.message || "Unknown error"}`);
  }
}
async function checkAndRequestApproval(token, amount) {
  if (!token || !token.address) return true;
  
  try {
    // Handle ERC6909 tokens (like ZAMM)
    if (token.isERC6909) {
      // Check operator approval for ERC6909
      const erc6909Contract = new ethers.Contract(
        token.address,
        [
          "function isOperator(address owner, address spender) view returns (bool)",
          "function setOperator(address spender, bool approved) returns (bool)"
        ],
        provider
      );
      
      const isApproved = await erc6909Contract.isOperator(wallet.address, ZROUTER_ADDRESS);
      
      if (isApproved) {
        return true; // Already approved as operator
      }
      
      // Show approval modal with details
      const approvalConfirmed = await showApprovalModal(token, true);
      
      if (!approvalConfirmed) return false;
      
      document.getElementById("swapStatus").innerHTML = '<div class="status">Setting operator approval...</div>';
      
      // Set operator approval for ERC6909
      const approveContract = new ethers.Contract(token.address, erc6909Contract.interface, wallet);
      const approveTx = await approveContract.setOperator(ZROUTER_ADDRESS, true);
      
      document.getElementById("swapStatus").innerHTML = `<div class="status">Approving... ${approveTx.hash.slice(0, 10)}...</div>`;
      await approveTx.wait();
      
      showToast(`${token.symbol} operator approval granted!`);
      return true;
      
    } else {
      // Standard ERC20 approval flow
      const tokenContract = new ethers.Contract(
        token.address,
        ["function allowance(address owner, address spender) view returns (uint256)"],
        provider
      );
      
      const allowance = await tokenContract.allowance(wallet.address, ZROUTER_ADDRESS);
      
      if (allowance >= amount) {
        return true; // Already approved
      }
      
      // Show approval modal with details
      const approvalConfirmed = await showApprovalModal(token, false);
      
      if (!approvalConfirmed) return false;
      
      document.getElementById("swapStatus").innerHTML = '<div class="status">Approving token...</div>';
      
      const approveContract = new ethers.Contract(
        token.address,
        ["function approve(address spender, uint256 amount) returns (bool)"],
        wallet
      );
      
      // Approve max amount to avoid future approvals
      const approveTx = await approveContract.approve(ZROUTER_ADDRESS, ethers.MaxUint256);
      
      document.getElementById("swapStatus").innerHTML = `<div class="status">Approving... ${approveTx.hash.slice(0, 10)}...</div>`;
      await approveTx.wait();
      
      showToast(`${token.symbol} approved for swapping!`);
      return true;
    }
    
  } catch (err) {
    console.error("Approval error:", err);
    document.getElementById("swapStatus").innerHTML = '<div class="status error">Approval failed</div>';
    showToast("Approval failed");
    return false;
  }
}

async function showApprovalModal(token, isERC6909) {
  return new Promise((resolve) => {
    // Create a simple approval modal
    const modalHtml = `
      <div id="approvalModal" class="modal">
        <div class="modal-content">
          <div class="modal-header">
            <h3>Approval Required</h3>
            <button class="modal-close" id="approvalModalClose">×</button>
          </div>
          <div class="modal-body">
            <div class="warning" style="margin-bottom: 16px;">
              ⚠️ First-time swap requires approval
            </div>
            <div class="confirm-row">
              <span class="confirm-label">Token:</span>
              <span class="confirm-value">${token.symbol}</span>
            </div>
            <div class="confirm-row">
              <span class="confirm-label">Contract:</span>
              <span class="confirm-value mono" style="font-size: 10px;">${token.address.slice(0, 6)}...${token.address.slice(-4)}</span>
            </div>
            <div class="confirm-row">
              <span class="confirm-label">Approval Type:</span>
              <span class="confirm-value">${isERC6909 ? 'ERC6909 Operator' : 'ERC20 Allowance'}</span>
            </div>
            <div class="confirm-row">
              <span class="confirm-label">Spender:</span>
              <span class="confirm-value mono" style="font-size: 10px;">zRouter: ${ZROUTER_ADDRESS.slice(0, 6)}...${ZROUTER_ADDRESS.slice(-4)}</span>
            </div>
            <div style="margin-top: 12px; padding: 12px; background: var(--info-bg); border: 1px solid var(--border); font-size: 11px;">
              ${isERC6909 
                ? 'This will grant zRouter permission to transfer your ERC6909 tokens (like ZAMM) for swapping.'
                : 'This will grant zRouter permission to spend your tokens for swapping. This is a one-time approval.'}
            </div>
          </div>
          <div class="modal-footer">
            <button id="confirmApproval" class="btn-confirm">Approve</button>
            <button id="cancelApproval" class="btn-cancel">Cancel</button>
          </div>
        </div>
      </div>
    `;
    
    // Add modal to page
    const modalDiv = document.createElement('div');
    modalDiv.innerHTML = modalHtml;
    document.body.appendChild(modalDiv);
    
    const confirmBtn = document.getElementById('confirmApproval');
    const cancelBtn = document.getElementById('cancelApproval');
    const closeBtn = document.getElementById('approvalModalClose');
    
    const cleanup = () => {
      document.body.removeChild(modalDiv);
      resolve(false);
    };
    
    const handleConfirm = () => {
      document.body.removeChild(modalDiv);
      resolve(true);
    };
    
    confirmBtn.addEventListener('click', handleConfirm);
    cancelBtn.addEventListener('click', cleanup);
    closeBtn.addEventListener('click', cleanup);
  });
}

// Initialize app with proper error handling
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    init().catch((err) => {
      console.error("Initialization error:", err);
      // Show user-friendly error
      const errorDiv = document.createElement('div');
      errorDiv.className = 'status error';
      errorDiv.textContent = 'Failed to initialize wallet. Please reload.';
      document.body.appendChild(errorDiv);
    });
  });
} else {
  init().catch((err) => {
    console.error("Initialization error:", err);
  });
}
