#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔨 Building standalone zWallet...');

// Read the base HTML
let html = fs.readFileSync(path.join(__dirname, 'extension', 'popup.html'), 'utf8');

// Read all JavaScript modules
const jsFiles = [
  'visual-id.js',
  'qrcode.js', 
  'eip7702.js',
  'popup.js'
];

let combinedJs = '';
for (const file of jsFiles) {
  const filePath = path.join(__dirname, 'extension', file);
  if (fs.existsSync(filePath)) {
    const content = fs.readFileSync(filePath, 'utf8');
    combinedJs += `\n// ${file}\n${content}\n`;
  }
}

// Update CSP for standalone version - allow inline scripts and data URIs
html = html.replace(
  /<meta\s+http-equiv="Content-Security-Policy"[^>]*content="[^"]*"[^>]*>/gi,
  `<meta http-equiv="Content-Security-Policy" content="default-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src *; object-src 'none'; base-uri 'self'">`
);

// Remove individual script tags and replace with combined inline script
const scriptTags = jsFiles.map(f => `<script src="${f}"></script>`).join('\\s*');
const scriptRegex = new RegExp(scriptTags, 'g');
html = html.replace(scriptRegex, `<script>\n${combinedJs}\n</script>`);

// If script tags weren't found together, remove them individually and add combined at the end of head
jsFiles.forEach(file => {
  html = html.replace(new RegExp(`<script src="${file}"></script>\\s*`, 'g'), '');
});

// Add combined script before closing body if not already added
if (!html.includes(combinedJs.substring(0, 100))) {
  html = html.replace('</body>', `<script>\n${combinedJs}\n</script>\n</body>`);
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
console.log('  4. Local: open zWallet.html in browser');