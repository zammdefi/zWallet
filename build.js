#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔨 Building smart standalone zWallet...');

// Read the base HTML
let html = fs.readFileSync(path.join(__dirname, 'extension', 'popup.html'), 'utf8');

// Read the popup.js content
let popupJs = fs.readFileSync(path.join(__dirname, 'extension', 'popup.js'), 'utf8');

// Read visual-id.js content if it exists
let visualIdJs = '';
const visualIdPath = path.join(__dirname, 'extension', 'visual-id.js');
if (fs.existsSync(visualIdPath)) {
  visualIdJs = fs.readFileSync(visualIdPath, 'utf8');
}

// Read eip7702.js content
let eip7702Js = '';
const eip7702Path = path.join(__dirname, 'extension', 'eip7702.js');
if (fs.existsSync(eip7702Path)) {
  eip7702Js = fs.readFileSync(eip7702Path, 'utf8');
}

// Read qrcode.js content
let qrcodeJs = '';
const qrcodePath = path.join(__dirname, 'extension', 'qrcode.js');
if (fs.existsSync(qrcodePath)) {
  qrcodeJs = fs.readFileSync(qrcodePath, 'utf8');
}

// Wrap Chrome API calls for standalone version
popupJs = popupJs.replace(/chrome\.storage\.local\.(get|set)/g, (match, method) => {
  if (method === 'get') {
    return `(typeof chrome !== 'undefined' && chrome.storage ? chrome.storage.local.get : (keys, callback) => callback({}))`;
  } else {
    return `(typeof chrome !== 'undefined' && chrome.storage ? chrome.storage.local.set : (data, callback) => callback && callback())`;
  }
});

// Handle chrome.tabs API
popupJs = popupJs.replace(/chrome\.tabs\.query/g, 
  `(typeof chrome !== 'undefined' && chrome.tabs ? chrome.tabs.query : (query, callback) => callback([]))`
);

popupJs = popupJs.replace(/chrome\.tabs\.sendMessage/g,
  `(typeof chrome !== 'undefined' && chrome.tabs ? chrome.tabs.sendMessage : () => Promise.reject('Not in extension'))`
);

// Handle chrome.runtime API
popupJs = popupJs.replace(/chrome\.runtime\.sendMessage/g,
  `(typeof chrome !== 'undefined' && chrome.runtime ? chrome.runtime.sendMessage : () => {})`
);

popupJs = popupJs.replace(/chrome\.runtime\.onMessage\.addListener/g,
  `(typeof chrome !== 'undefined' && chrome.runtime ? chrome.runtime.onMessage.addListener : () => {})`
);

// Remove extension-specific meta tags
html = html.replace(/<meta\s+http-equiv="Content-Security-Policy"[^>]*>/gi, '');

// Replace local ethers script with CDN version
html = html.replace(
  /<script src="ethers\.umd\.min\.js"><\/script>/g,
  '<script src="https://cdnjs.cloudflare.com/ajax/libs/ethers/6.15.0/ethers.umd.min.js" integrity="sha512-UXYETj+vXKSURF1UlgVRLzWRS9ZiQTv3lcL4rbeLyqTXCPNZC6PTLF/Ik3uxm2Zo+E109cUpJPZfLxJsCgKSng==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>'
);

// Remove individual script tags for modules we'll inline
html = html.replace(/<script src="visual-id\.js"><\/script>\s*/g, '');
html = html.replace(/<script src="eip7702\.js"><\/script>\s*/g, '');
html = html.replace(/<script src="qrcode\.js"><\/script>\s*/g, '');

// Add PWA service worker and install code
const pwaCode = `
// Simple service worker for offline functionality
const CACHE_NAME = 'zwallet-v1';
const urlsToCache = [
  './',
  'https://cdnjs.cloudflare.com/ajax/libs/ethers/6.15.0/ethers.umd.min.js'
];

// Inline service worker registration
if ('serviceWorker' in navigator) {
  // Create service worker from blob
  const swCode = \`
    self.addEventListener('install', event => {
      event.waitUntil(
        caches.open('\${CACHE_NAME}').then(cache => cache.addAll(\${JSON.stringify(urlsToCache)}))
      );
      self.skipWaiting();
    });

    self.addEventListener('activate', event => {
      event.waitUntil(
        caches.keys().then(cacheNames => 
          Promise.all(cacheNames.filter(name => name !== '\${CACHE_NAME}').map(name => caches.delete(name)))
        )
      );
      self.clients.claim();
    });

    self.addEventListener('fetch', event => {
      event.respondWith(
        caches.match(event.request).then(response => response || fetch(event.request))
      );
    });
  \`;
  
  const blob = new Blob([swCode], { type: 'application/javascript' });
  const swUrl = URL.createObjectURL(blob);
  navigator.serviceWorker.register(swUrl).catch(err => console.log('SW registration failed:', err));
}

// PWA Install prompt
let deferredPrompt;
const installButton = document.getElementById('installPWA');

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  if (window.matchMedia('(max-width: 768px)').matches && installButton) {
    installButton.classList.add('available');
  }
});

if (installButton) {
  installButton.addEventListener('click', async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      if (outcome === 'accepted') {
        installButton.classList.remove('available');
      }
      deferredPrompt = null;
    }
  });
}

window.addEventListener('appinstalled', () => {
  if (installButton) {
    installButton.classList.remove('available');
  }
});
`;

// Replace popup.js script tag with combined inline content
// Include all modules in the correct order
let combinedJs = '';
if (eip7702Js) combinedJs += eip7702Js + '\n\n';
if (qrcodeJs) combinedJs += qrcodeJs + '\n\n';
if (visualIdJs) combinedJs += visualIdJs + '\n\n';
combinedJs += popupJs;
combinedJs += '\n\n// PWA Support\n' + pwaCode;

html = html.replace(
  /<script src="popup\.js"><\/script>/g,
  `<script>\n${combinedJs}\n</script>`
);

// Make sure we don't have duplicate script tags
html = html.replace(/<script>\s*<\/script>/g, '');

// Add favicon if icon.txt exists
if (fs.existsSync(path.join(__dirname, 'icon.txt'))) {
  const iconBase64 = fs.readFileSync(path.join(__dirname, 'icon.txt'), 'utf8').trim();
  html = html.replace(
    '</title>',
    `</title>\n    <link rel="icon" type="image/png" href="data:image/png;base64,${iconBase64}">`
  );
}

// Add PWA manifest link and meta tags for mobile
html = html.replace(
  '</title>',
  `</title>
    <link rel="manifest" href="data:application/manifest+json;base64,${Buffer.from(JSON.stringify({
      "name": "zWallet - Web3 Wallet",
      "short_name": "zWallet",
      "description": "Your favorite new minimalist Ethereum wallet built for DeFi",
      "start_url": "./",
      "display": "standalone",
      "background_color": "#1a1a2e",
      "theme_color": "#B967DB",
      "orientation": "portrait-primary",
      "icons": [
        {
          "src": "data:image/svg+xml,%3Csvg width='192' height='192' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Crect width='100' height='100' fill='%231a1a2e'/%3E%3Cpolygon points='30,40 50,40 30,60' fill='%236B5B95'/%3E%3Cpolygon points='50,40 70,40 50,60' fill='%238A7FBE'/%3E%3Cpolygon points='30,60 50,60 30,80' fill='%238A7FBE'/%3E%3Cpolygon points='50,60 70,60 50,80' fill='%23B967DB'/%3E%3C/svg%3E",
          "sizes": "192x192",
          "type": "image/svg+xml"
        },
        {
          "src": "data:image/svg+xml,%3Csvg width='512' height='512' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Crect width='100' height='100' fill='%231a1a2e'/%3E%3Cpolygon points='30,40 50,40 30,60' fill='%236B5B95'/%3E%3Cpolygon points='50,40 70,40 50,60' fill='%238A7FBE'/%3E%3Cpolygon points='30,60 50,60 30,80' fill='%238A7FBE'/%3E%3Cpolygon points='50,60 70,60 50,80' fill='%23B967DB'/%3E%3C/svg%3E",
          "sizes": "512x512",
          "type": "image/svg+xml"
        }
      ]
    })).toString('base64')}">`
);

// Add standalone styles
const standaloneStyles = `
<style>
/* Standalone version styles */
body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

/* PWA Install Button */
#installPWA {
    display: none;
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 12px 20px;
    background: #B967DB;
    color: white;
    border: none;
    border-radius: 24px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 600;
    box-shadow: 0 4px 12px rgba(185, 103, 219, 0.4);
    z-index: 1000;
    animation: pulse 2s infinite;
}

#installPWA:hover {
    transform: scale(1.05);
    box-shadow: 0 6px 16px rgba(185, 103, 219, 0.5);
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.8; }
    100% { opacity: 1; }
}

@media (max-width: 768px) {
    #installPWA.available {
        display: flex;
        align-items: center;
        gap: 8px;
    }
}

.window {
    width: 100%;
    max-width: 480px;
    margin: 20px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    border-radius: 12px;
    overflow: hidden;
}

@media (max-width: 520px) {
    body {
        padding: 0;
        align-items: flex-start;
    }
    .window {
        margin: 0;
        max-width: 100%;
        min-height: 100vh;
        box-shadow: none;
        border-radius: 0;
    }
}
</style>`;

// Add standalone styles before closing head tag
html = html.replace('</head>', standaloneStyles + '\n</head>');

// Add PWA install button to body
html = html.replace(
  '<body>',
  `<body>
    <button id="installPWA">
      <span>📲</span>
      <span>Install App</span>
    </button>`
);

// Write the standalone file
fs.writeFileSync(path.join(__dirname, 'zWallet.html'), html);

// Get file size
const stats = fs.statSync(path.join(__dirname, 'zWallet.html'));
const fileSizeInKB = (stats.size / 1024).toFixed(1);

console.log(`✅ Built zWallet.html (${fileSizeInKB} KB)`);
console.log('📦 Ready to deploy to IPFS!');
console.log('');
console.log('🌐 Deploy options:');
console.log('  1. IPFS: ipfs add zWallet.html');
console.log('  2. GitHub Pages: commit and push');
console.log('  3. Vercel/Netlify: drag and drop');
console.log('  4. Local: open index.html in browser');