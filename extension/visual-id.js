// Minimal visual identifier for zWallet - combines blockie-style avatar with QR capability

// Generate a simple blockie avatar using canvas
function createBlockie(address, size = 64) {
  const seed = parseInt(address.slice(2, 10), 16);
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  
  // Generate colors from address
  const hue1 = (seed % 360);
  const hue2 = ((seed >> 8) % 360);
  
  // Background gradient
  const gradient = ctx.createLinearGradient(0, 0, size, size);
  gradient.addColorStop(0, `hsl(${hue1}, 70%, 85%)`);
  gradient.addColorStop(1, `hsl(${hue2}, 70%, 90%)`);
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, size, size);
  
  // Generate pattern
  const gridSize = 5;
  const cellSize = size / gridSize;
  
  for (let y = 0; y < gridSize; y++) {
    for (let x = 0; x < Math.ceil(gridSize / 2); x++) {
      const index = y * gridSize + x;
      const value = (seed >> (index % 32)) & 3;
      
      if (value > 0) {
        const colorIndex = value - 1;
        const colors = [
          `hsl(${hue1}, 70%, 50%)`,
          `hsl(${hue2}, 70%, 40%)`,
          `hsl(${(hue1 + hue2) / 2}, 60%, 45%)`
        ];
        
        ctx.fillStyle = colors[colorIndex];
        
        // Draw circles for a softer look
        const centerX = x * cellSize + cellSize / 2;
        const centerY = y * cellSize + cellSize / 2;
        const radius = cellSize * 0.4;
        
        // Left side
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
        ctx.fill();
        
        // Mirror on right side
        const mirrorX = (gridSize - 1 - x) * cellSize + cellSize / 2;
        ctx.beginPath();
        ctx.arc(mirrorX, centerY, radius, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }
  
  return canvas.toDataURL();
}

// Simple QR code for addresses (minimal implementation)
function generateSimpleQR(text, size = 256) {
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  
  // White background
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, size, size);
  
  // For simplicity, create a data matrix pattern based on the text
  // This is a simplified version - for production use a proper QR library
  const moduleCount = 21; // Simplified QR version 1
  const cellSize = size / (moduleCount + 8); // Add quiet zone
  const margin = cellSize * 4;
  
  // Create a simple hash-based pattern
  const data = text.split('').map(c => c.charCodeAt(0));
  
  ctx.fillStyle = '#000000';
  
  // Position detection patterns (corners)
  const drawPositionPattern = (row, col) => {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const absR = Math.abs(r <= 3 ? r : r - 6);
        const absC = Math.abs(c <= 3 ? c : c - 6);
        if (absR <= 1 || absC <= 1 || (absR === 2 && absC === 2)) {
          ctx.fillRect(
            margin + (col + c) * cellSize,
            margin + (row + r) * cellSize,
            cellSize,
            cellSize
          );
        }
      }
    }
  };
  
  drawPositionPattern(0, 0);
  drawPositionPattern(0, moduleCount - 7);
  drawPositionPattern(moduleCount - 7, 0);
  
  // Data area (simplified)
  for (let row = 0; row < moduleCount; row++) {
    for (let col = 0; col < moduleCount; col++) {
      // Skip position patterns
      if ((row < 8 && col < 8) || 
          (row < 8 && col >= moduleCount - 8) ||
          (row >= moduleCount - 8 && col < 8)) {
        continue;
      }
      
      // Generate deterministic pattern from address
      const index = row * moduleCount + col;
      const byte = data[index % data.length] || 0;
      const bit = (byte >> (index % 8)) & 1;
      
      if (bit) {
        ctx.fillRect(
          margin + col * cellSize,
          margin + row * cellSize,
          cellSize,
          cellSize
        );
      }
    }
  }
  
  // Add logo in center
  const logoSize = cellSize * 5;
  const logoX = (size - logoSize) / 2;
  const logoY = (size - logoSize) / 2;
  
  // White background for logo
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(logoX - cellSize, logoY - cellSize, logoSize + cellSize * 2, logoSize + cellSize * 2);
  
  // Draw "zW" text as logo
  ctx.fillStyle = '#000000';
  ctx.font = `bold ${logoSize * 0.4}px monospace`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('zW', size / 2, size / 2);
  
  return canvas.toDataURL();
}

// Export for use
window.zWalletVisual = { createBlockie, generateSimpleQR };