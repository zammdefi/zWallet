#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Extension files that should be included in the zip
const EXTENSION_FILES = [
  'manifest.json',
  'popup.html',
  'popup.js',
  'background.js',
  'content.js',
  'inject.js',
  'eip7702.js',
  'qrcode.js',
  'visual-id.js',
  'icon.png',
  'icon16.png',
  'icon48.png',
  'icon128.png',
  'ethers.umd.min.js'
];

// Build function
function buildExtension() {
  console.log('🚀 Building Chrome Extension...\n');
  
  const extensionDir = path.join(__dirname, 'extension');
  const outputDir = __dirname;
  
  // Check if extension directory exists
  if (!fs.existsSync(extensionDir)) {
    console.error('❌ Extension directory not found!');
    process.exit(1);
  }
  
  // Verify all required files exist
  console.log('📋 Checking required files...');
  const missingFiles = [];
  
  for (const file of EXTENSION_FILES) {
    const filePath = path.join(extensionDir, file);
    if (!fs.existsSync(filePath)) {
      missingFiles.push(file);
    } else {
      console.log(`  ✓ ${file}`);
    }
  }
  
  if (missingFiles.length > 0) {
    console.error('\n❌ Missing required files:');
    missingFiles.forEach(file => console.error(`  - ${file}`));
    process.exit(1);
  }
  
  // Read manifest to get version
  const manifestPath = path.join(extensionDir, 'manifest.json');
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    console.error('❌ Failed to parse manifest.json:', error.message);
    process.exit(1);
  }
  const version = manifest.version || '0.0.6';
  
  console.log(`\n📦 Building zWallet v${version}...`);
  
  // Create zip filename with version
  const zipName = `zWallet-v${version}.zip`;
  const zipPath = path.join(outputDir, zipName);
  
  // Remove existing zip if it exists
  if (fs.existsSync(zipPath)) {
    fs.unlinkSync(zipPath);
    console.log(`  Removed existing ${zipName}`);
  }
  
  // Create file list for zip command with proper escaping
  const fileList = EXTENSION_FILES.map(f => `'extension/${f}'`).join(' ');
  
  try {
    // Create the zip file
    console.log('\n🗜️  Creating zip archive...');
    
    // Change to extension directory and create zip from there
    const zipCommand = `cd extension && zip -r ../${zipName} ${EXTENSION_FILES.join(' ')}`;
    
    console.log('  Running: ' + zipCommand);
    execSync(zipCommand, {
      cwd: __dirname,
      stdio: 'inherit' // Show zip command output
    });
    
    // Verify the zip file was created
    if (!fs.existsSync(zipPath)) {
      throw new Error('Zip file was not created');
    }
    
    // Get file size
    const stats = fs.statSync(zipPath);
    const fileSizeKB = (stats.size / 1024).toFixed(2);
    
    console.log(`\n✅ Build complete!`);
    console.log(`📁 Output: ${zipName} (${fileSizeKB} KB)`);
    console.log(`📍 Location: ${zipPath}`);
    
    // Instructions for next steps
    console.log('\n📝 Next steps:');
    console.log('1. Upload to IPFS: ipfs add ' + zipName);
    console.log('2. Install in Chrome: chrome://extensions/ → Developer mode → Load unpacked');
    console.log('3. Or distribute the zip file directly\n');
    
  } catch (error) {
    console.error('\n❌ Build failed:', error.message);
    process.exit(1);
  }
}

// Run the build
buildExtension();