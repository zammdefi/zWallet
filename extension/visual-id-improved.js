// Enhanced visual identifier for zWallet - optimized blockie-style avatar with proper QR capability

/**
 * Cache for generated visual identifiers to improve performance
 */
const visualCache = new Map();
const MAX_CACHE_SIZE = 100;

/**
 * Clear old cache entries when limit is reached
 */
function manageCacheSize() {
  if (visualCache.size > MAX_CACHE_SIZE) {
    const entriesToDelete = visualCache.size - MAX_CACHE_SIZE + 10;
    const keys = Array.from(visualCache.keys());
    for (let i = 0; i < entriesToDelete; i++) {
      visualCache.delete(keys[i]);
    }
  }
}

/**
 * Generate deterministic seed from address with better distribution
 * @param {string} address - Ethereum address
 * @returns {number[]} Array of seed values
 */
function generateSeeds(address) {
  if (!address || typeof address !== 'string') {
    throw new Error('Invalid address provided');
  }
  
  // Normalize address
  const normalized = address.toLowerCase().replace(/^0x/, '');
  
  // Generate multiple seeds for better randomness
  const seeds = [];
  for (let i = 0; i < 4; i++) {
    const slice = normalized.slice(i * 8, (i + 1) * 8).padEnd(8, '0');
    seeds.push(parseInt(slice, 16));
  }
  
  return seeds;
}

/**
 * Generate a blockie avatar using canvas with caching
 * @param {string} address - Ethereum address
 * @param {number} size - Size of the avatar (default: 64)
 * @param {Object} options - Additional options
 * @returns {string} Data URL of the generated avatar
 */
function createBlockie(address, size = 64, options = {}) {
  // Validate input
  if (!address || !/^0x[a-fA-F0-9]{40}$/.test(address)) {
    console.warn('Invalid Ethereum address for blockie generation');
    address = '0x0000000000000000000000000000000000000000';
  }
  
  // Check cache
  const cacheKey = `blockie_${address}_${size}_${JSON.stringify(options)}`;
  if (visualCache.has(cacheKey)) {
    return visualCache.get(cacheKey);
  }
  
  const {
    gridSize = 8,          // More detailed grid
    saturation = 70,       // Color saturation
    lightness = 50,        // Color lightness
    bgLightness = 85,      // Background lightness
    shape = 'circle',      // Shape: 'circle', 'square', 'hexagon'
    symmetric = true       // Mirror pattern
  } = options;
  
  const seeds = generateSeeds(address);
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d', { alpha: false });
  
  // Enable image smoothing for better quality
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  
  // Generate colors from seeds
  const hue1 = seeds[0] % 360;
  const hue2 = seeds[1] % 360;
  const hue3 = seeds[2] % 360;
  
  // Create gradient background
  const gradient = ctx.createRadialGradient(
    size / 2, size / 2, 0,
    size / 2, size / 2, size / Math.sqrt(2)
  );
  gradient.addColorStop(0, `hsl(${hue1}, ${saturation}%, ${bgLightness}%)`);
  gradient.addColorStop(0.5, `hsl(${hue2}, ${saturation}%, ${bgLightness + 5}%)`);
  gradient.addColorStop(1, `hsl(${hue3}, ${saturation}%, ${bgLightness - 5}%)`);
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, size, size);
  
  // Generate pattern
  const cellSize = size / gridSize;
  const halfGrid = symmetric ? Math.ceil(gridSize / 2) : gridSize;
  
  // Color palette
  const colors = [
    `hsl(${hue1}, ${saturation}%, ${lightness}%)`,
    `hsl(${hue2}, ${saturation}%, ${lightness - 10}%)`,
    `hsl(${hue3}, ${saturation}%, ${lightness + 10}%)`,
    `hsl(${(hue1 + hue2) / 2}, ${saturation - 10}%, ${lightness - 5}%)`
  ];
  
  // Draw pattern
  for (let y = 0; y < gridSize; y++) {
    for (let x = 0; x < halfGrid; x++) {
      const index = y * gridSize + x;
      const seedIndex = Math.floor(index / 32);
      const bitIndex = index % 32;
      const value = (seeds[seedIndex % seeds.length] >> bitIndex) & 3;
      
      if (value > 0) {
        ctx.fillStyle = colors[value % colors.length];
        
        const centerX = x * cellSize + cellSize / 2;
        const centerY = y * cellSize + cellSize / 2;
        
        // Draw shape
        ctx.save();
        drawShape(ctx, centerX, centerY, cellSize * 0.35, shape);
        ctx.fill();
        
        // Mirror if symmetric
        if (symmetric && x < gridSize / 2) {
          const mirrorX = (gridSize - 1 - x) * cellSize + cellSize / 2;
          drawShape(ctx, mirrorX, centerY, cellSize * 0.35, shape);
          ctx.fill();
        }
        ctx.restore();
      }
    }
  }
  
  // Add subtle border
  ctx.strokeStyle = `hsla(${hue1}, ${saturation}%, 30%, 0.2)`;
  ctx.lineWidth = 1;
  ctx.strokeRect(0.5, 0.5, size - 1, size - 1);
  
  const dataUrl = canvas.toDataURL('image/png');
  
  // Cache result
  visualCache.set(cacheKey, dataUrl);
  manageCacheSize();
  
  return dataUrl;
}

/**
 * Draw different shapes for variety
 */
function drawShape(ctx, x, y, radius, shape) {
  ctx.beginPath();
  
  switch (shape) {
    case 'square':
      ctx.rect(x - radius, y - radius, radius * 2, radius * 2);
      break;
      
    case 'hexagon':
      for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i;
        const px = x + radius * Math.cos(angle);
        const py = y + radius * Math.sin(angle);
        if (i === 0) {
          ctx.moveTo(px, py);
        } else {
          ctx.lineTo(px, py);
        }
      }
      ctx.closePath();
      break;
      
    case 'circle':
    default:
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      break;
  }
}

/**
 * Generate a proper QR code using the qrcode.js library if available
 * Falls back to simple pattern if library not loaded
 * @param {string} text - Text to encode
 * @param {number} size - Size of the QR code (default: 256)
 * @param {Object} options - Additional options
 * @returns {string} Data URL of the QR code
 */
function generateQRCode(text, size = 256, options = {}) {
  // Validate input
  if (!text || typeof text !== 'string') {
    throw new Error('Invalid text for QR code generation');
  }
  
  // Check cache
  const cacheKey = `qr_${text}_${size}_${JSON.stringify(options)}`;
  if (visualCache.has(cacheKey)) {
    return visualCache.get(cacheKey);
  }
  
  const {
    errorCorrectionLevel = 'M',
    margin = 4,
    darkColor = '#000000',
    lightColor = '#ffffff',
    logo = true,
    logoText = 'zW',
    logoSize = 0.2  // Logo size as percentage of QR size
  } = options;
  
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d', { alpha: false });
  
  // Try to use QRCode library if available
  if (typeof QRCode !== 'undefined' && QRCode.QRCodeModel) {
    try {
      const qr = new QRCode.QRCodeModel(QRCode.getTypeNumber(text), 
        QRCode.ErrorCorrectLevel[errorCorrectionLevel]);
      qr.addData(text);
      qr.make();
      
      const moduleCount = qr.getModuleCount();
      const cellSize = (size - margin * 2) / moduleCount;
      
      // Draw background
      ctx.fillStyle = lightColor;
      ctx.fillRect(0, 0, size, size);
      
      // Draw QR modules
      ctx.fillStyle = darkColor;
      for (let row = 0; row < moduleCount; row++) {
        for (let col = 0; col < moduleCount; col++) {
          if (qr.isDark(row, col)) {
            const x = margin + col * cellSize;
            const y = margin + row * cellSize;
            
            // Round corners for better appearance
            const radius = cellSize * 0.1;
            ctx.beginPath();
            ctx.moveTo(x + radius, y);
            ctx.lineTo(x + cellSize - radius, y);
            ctx.quadraticCurveTo(x + cellSize, y, x + cellSize, y + radius);
            ctx.lineTo(x + cellSize, y + cellSize - radius);
            ctx.quadraticCurveTo(x + cellSize, y + cellSize, x + cellSize - radius, y + cellSize);
            ctx.lineTo(x + radius, y + cellSize);
            ctx.quadraticCurveTo(x, y + cellSize, x, y + cellSize - radius);
            ctx.lineTo(x, y + radius);
            ctx.quadraticCurveTo(x, y, x + radius, y);
            ctx.fill();
          }
        }
      }
    } catch (error) {
      console.warn('QRCode library error, falling back to simple pattern', error);
      return generateSimpleQRPattern(canvas, ctx, text, size, options);
    }
  } else {
    // Fallback to simple pattern
    return generateSimpleQRPattern(canvas, ctx, text, size, options);
  }
  
  // Add logo if requested
  if (logo) {
    const logoSizePx = size * logoSize;
    const logoX = (size - logoSizePx) / 2;
    const logoY = (size - logoSizePx) / 2;
    const padding = logoSizePx * 0.1;
    
    // White background with rounded corners
    ctx.fillStyle = lightColor;
    const radius = logoSizePx * 0.1;
    ctx.beginPath();
    ctx.moveTo(logoX - padding + radius, logoY - padding);
    ctx.lineTo(logoX + logoSizePx + padding - radius, logoY - padding);
    ctx.quadraticCurveTo(logoX + logoSizePx + padding, logoY - padding, 
      logoX + logoSizePx + padding, logoY - padding + radius);
    ctx.lineTo(logoX + logoSizePx + padding, logoY + logoSizePx + padding - radius);
    ctx.quadraticCurveTo(logoX + logoSizePx + padding, logoY + logoSizePx + padding,
      logoX + logoSizePx + padding - radius, logoY + logoSizePx + padding);
    ctx.lineTo(logoX - padding + radius, logoY + logoSizePx + padding);
    ctx.quadraticCurveTo(logoX - padding, logoY + logoSizePx + padding,
      logoX - padding, logoY + logoSizePx + padding - radius);
    ctx.lineTo(logoX - padding, logoY - padding + radius);
    ctx.quadraticCurveTo(logoX - padding, logoY - padding,
      logoX - padding + radius, logoY - padding);
    ctx.fill();
    
    // Draw logo text
    ctx.fillStyle = darkColor;
    ctx.font = `bold ${logoSizePx * 0.4}px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(logoText, size / 2, size / 2);
  }
  
  const dataUrl = canvas.toDataURL('image/png');
  
  // Cache result
  visualCache.set(cacheKey, dataUrl);
  manageCacheSize();
  
  return dataUrl;
}

/**
 * Generate simple QR-like pattern as fallback
 */
function generateSimpleQRPattern(canvas, ctx, text, size, options) {
  const { darkColor = '#000000', lightColor = '#ffffff', margin = 4 } = options;
  
  // Fill background
  ctx.fillStyle = lightColor;
  ctx.fillRect(0, 0, size, size);
  
  // Create deterministic pattern
  const moduleCount = 25;
  const cellSize = (size - margin * 2) / moduleCount;
  const seeds = generateSeeds('0x' + Array.from(text).map(c => 
    c.charCodeAt(0).toString(16).padStart(2, '0')
  ).join(''));
  
  ctx.fillStyle = darkColor;
  
  // Draw position detection patterns
  const drawFinderPattern = (centerRow, centerCol) => {
    for (let r = -3; r <= 3; r++) {
      for (let c = -3; c <= 3; c++) {
        const absR = Math.abs(r);
        const absC = Math.abs(c);
        if (absR <= 3 && absC <= 3 && 
            (absR === 3 || absC === 3 || (absR <= 1 && absC <= 1))) {
          ctx.fillRect(
            margin + (centerCol + c) * cellSize,
            margin + (centerRow + r) * cellSize,
            cellSize,
            cellSize
          );
        }
      }
    }
  };
  
  // Draw finder patterns
  drawFinderPattern(3, 3);
  drawFinderPattern(3, moduleCount - 4);
  drawFinderPattern(moduleCount - 4, 3);
  
  // Draw timing patterns
  for (let i = 8; i < moduleCount - 8; i++) {
    if (i % 2 === 0) {
      ctx.fillRect(margin + 6 * cellSize, margin + i * cellSize, cellSize, cellSize);
      ctx.fillRect(margin + i * cellSize, margin + 6 * cellSize, cellSize, cellSize);
    }
  }
  
  // Fill data area with pattern
  for (let row = 0; row < moduleCount; row++) {
    for (let col = 0; col < moduleCount; col++) {
      // Skip finder pattern areas
      if ((row < 8 && col < 8) || 
          (row < 8 && col >= moduleCount - 8) ||
          (row >= moduleCount - 8 && col < 8)) {
        continue;
      }
      
      // Skip timing patterns
      if (row === 6 || col === 6) {
        continue;
      }
      
      // Generate pattern from seeds
      const index = row * moduleCount + col;
      const seedIndex = Math.floor(index / 32);
      const bitIndex = index % 32;
      const isDark = ((seeds[seedIndex % seeds.length] >> bitIndex) & 1) === 1;
      
      if (isDark) {
        ctx.fillRect(
          margin + col * cellSize,
          margin + row * cellSize,
          cellSize,
          cellSize
        );
      }
    }
  }
  
  return canvas.toDataURL('image/png');
}

/**
 * Generate a combined visual ID card with blockie and QR code
 * @param {string} address - Ethereum address
 * @param {Object} options - Options for customization
 * @returns {string} Data URL of the ID card
 */
function generateIDCard(address, options = {}) {
  const {
    width = 400,
    height = 200,
    showAddress = true,
    showNetwork = true,
    network = 'Ethereum',
    theme = 'light'
  } = options;
  
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { alpha: false });
  
  // Theme colors
  const themes = {
    light: {
      bg: '#ffffff',
      fg: '#000000',
      accent: '#0052ff',
      border: '#e0e0e0'
    },
    dark: {
      bg: '#1a1a1a',
      fg: '#ffffff',
      accent: '#4080ff',
      border: '#333333'
    }
  };
  
  const colors = themes[theme] || themes.light;
  
  // Background
  ctx.fillStyle = colors.bg;
  ctx.fillRect(0, 0, width, height);
  
  // Border
  ctx.strokeStyle = colors.border;
  ctx.lineWidth = 2;
  ctx.strokeRect(1, 1, width - 2, height - 2);
  
  // Generate blockie
  const blockieSize = Math.min(height - 40, 120);
  const blockieData = createBlockie(address, blockieSize);
  const blockieImg = new Image();
  blockieImg.src = blockieData;
  
  // Generate QR code
  const qrSize = blockieSize;
  const qrData = generateQRCode(address, qrSize, { logo: true });
  const qrImg = new Image();
  qrImg.src = qrData;
  
  // Draw images when loaded
  Promise.all([
    new Promise(resolve => blockieImg.onload = resolve),
    new Promise(resolve => qrImg.onload = resolve)
  ]).then(() => {
    // Draw blockie
    ctx.drawImage(blockieImg, 20, (height - blockieSize) / 2);
    
    // Draw QR code
    ctx.drawImage(qrImg, width - qrSize - 20, (height - qrSize) / 2);
    
    // Draw text info
    ctx.fillStyle = colors.fg;
    ctx.font = 'bold 14px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    ctx.textAlign = 'center';
    
    if (showNetwork) {
      ctx.fillText(network, width / 2, 40);
    }
    
    if (showAddress) {
      ctx.font = '12px monospace';
      const shortAddress = address.slice(0, 8) + '...' + address.slice(-6);
      ctx.fillText(shortAddress, width / 2, height - 30);
    }
    
    // Add "zWallet" branding
    ctx.font = 'bold 16px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    ctx.fillStyle = colors.accent;
    ctx.fillText('zWallet', width / 2, height / 2);
  });
  
  return canvas.toDataURL('image/png');
}

/**
 * Clear visual cache
 */
function clearVisualCache() {
  visualCache.clear();
}

// Export for use (both module and global)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    createBlockie,
    generateQRCode,
    generateIDCard,
    clearVisualCache
  };
} else {
  window.zWalletVisual = {
    createBlockie,
    generateQRCode,
    generateSimpleQR: generateQRCode, // Backward compatibility
    generateIDCard,
    clearVisualCache
  };
}