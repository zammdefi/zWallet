#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔨 Building smart standalone zWallet...');

// Read the base HTML
let html = fs.readFileSync(path.join(__dirname, 'extension', 'popup.html'), 'utf8');

// Read the popup.js content
const popupJs = fs.readFileSync(path.join(__dirname, 'extension', 'popup.js'), 'utf8');

// Remove extension-specific meta tags
html = html.replace(/<meta\s+http-equiv="Content-Security-Policy"[^>]*>/gi, '');

// Replace local ethers script with CDN version
html = html.replace(
  /<script src="ethers\.umd\.min\.js"><\/script>/g,
  '<script src="https://cdnjs.cloudflare.com/ajax/libs/ethers/6.7.0/ethers.umd.min.js" integrity="sha256-Jlrx7irtiV+Pl9aJ9t3aZ4iL6FcO6eYitSbJR4arfhI=" crossorigin="anonymous"></script>'
);

// Replace popup.js script tag with inline content
html = html.replace(
  /<script src="popup\.js"><\/script>/g,
  `<script>\n${popupJs}\n</script>`
);

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