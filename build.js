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

// Replace popup.js script tag with combined inline content
// Include all modules in the correct order
let combinedJs = '';
if (eip7702Js) combinedJs += eip7702Js + '\n\n';
if (qrcodeJs) combinedJs += qrcodeJs + '\n\n';
if (visualIdJs) combinedJs += visualIdJs + '\n\n';
combinedJs += popupJs;

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