/**
 * Simple QR Code generator for Ethereum addresses
 * Minimal implementation that works with MetaMask and other wallets
 */

(function() {
  'use strict';

  // QR Code error correction levels
  const ECL = { L: 1, M: 0, Q: 3, H: 2 };
  
  // Mode indicators
  const MODE = {
    NUMERIC: 0b0001,
    ALPHANUMERIC: 0b0010,
    BYTE: 0b0100,
    KANJI: 0b1000
  };

  // Alphanumeric character map
  const ALPHANUMERIC_MAP = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

  class SimpleQR {
    constructor(text) {
      this.text = text;
      this.mode = this.getMode(text);
      this.version = this.getMinVersion(text);
      this.size = this.version * 4 + 17;
      this.modules = [];
      
      // Initialize modules
      for (let i = 0; i < this.size; i++) {
        this.modules[i] = new Array(this.size).fill(null);
      }
      
      this.setupFunctionModules();
      this.addData(text);
      this.mask = this.getBestMask();
      this.applyMask(this.mask);
      this.addFormatInfo();
    }
    
    getMode(text) {
      // For Ethereum addresses, use byte mode
      return MODE.BYTE;
    }
    
    getMinVersion(text) {
      // Version 3 can hold up to 77 bytes in byte mode with L error correction
      // Ethereum addresses are 42 characters (including 0x)
      return 3;
    }
    
    setupFunctionModules() {
      // Add finder patterns
      this.addFinderPattern(0, 0);
      this.addFinderPattern(this.size - 7, 0);
      this.addFinderPattern(0, this.size - 7);
      
      // Add separators
      this.addSeparators();
      
      // Add timing patterns
      for (let i = 8; i < this.size - 8; i++) {
        this.modules[6][i] = i % 2 === 0;
        this.modules[i][6] = i % 2 === 0;
      }
      
      // Add dark module
      this.modules[4 * this.version + 9][8] = true;
      
      // Add alignment pattern for version 3
      if (this.version >= 2) {
        const pos = [6, 22]; // Alignment positions for version 3
        this.addAlignmentPattern(pos[1], pos[1]);
      }
    }
    
    addFinderPattern(row, col) {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          if (row + r < 0 || this.size <= row + r) continue;
          if (col + c < 0 || this.size <= col + c) continue;
          
          if ((0 <= r && r <= 6 && (c === 0 || c === 6)) ||
              (0 <= c && c <= 6 && (r === 0 || r === 6)) ||
              (2 <= r && r <= 4 && 2 <= c && c <= 4)) {
            this.modules[row + r][col + c] = true;
          } else {
            this.modules[row + r][col + c] = false;
          }
        }
      }
    }
    
    addSeparators() {
      // Horizontal separators
      for (let i = 0; i < 8; i++) {
        this.modules[7][i] = false;
        this.modules[7][this.size - 8 + i] = false;
        this.modules[this.size - 8][i] = false;
      }
      
      // Vertical separators
      for (let i = 0; i < 7; i++) {
        this.modules[i][7] = false;
        this.modules[this.size - 1 - i][7] = false;
        this.modules[i][this.size - 8] = false;
      }
    }
    
    addAlignmentPattern(centerRow, centerCol) {
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          if (r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0)) {
            this.modules[centerRow + r][centerCol + c] = true;
          } else {
            this.modules[centerRow + r][centerCol + c] = false;
          }
        }
      }
    }
    
    addData(text) {
      const bits = this.encodeData(text);
      let index = 0;
      
      // Place data modules
      for (let col = this.size - 1; col > 0; col -= 2) {
        if (col === 6) col--;
        
        for (let vert = 0; vert < this.size; vert++) {
          for (let j = 0; j < 2; j++) {
            const c = col - j;
            const row = ((col + 1) & 2) === 0 ? this.size - 1 - vert : vert;
            
            if (this.modules[row][c] === null) {
              this.modules[row][c] = index < bits.length && bits[index];
              index++;
            }
          }
        }
      }
    }
    
    encodeData(text) {
      const bits = [];
      
      // Mode indicator (4 bits for byte mode)
      bits.push(false, true, false, false);
      
      // Character count (8 bits for version 1-9)
      const len = text.length;
      for (let i = 7; i >= 0; i--) {
        bits.push(((len >> i) & 1) === 1);
      }
      
      // Data
      for (let i = 0; i < text.length; i++) {
        const byte = text.charCodeAt(i);
        for (let j = 7; j >= 0; j--) {
          bits.push(((byte >> j) & 1) === 1);
        }
      }
      
      // Terminator
      for (let i = 0; i < 4; i++) bits.push(false);
      
      // Pad to byte boundary
      while (bits.length % 8 !== 0) bits.push(false);
      
      // Pad with alternating bytes
      const maxBits = this.getMaxDataBits();
      for (let pad = 0xEC; bits.length < maxBits; pad ^= 0xEC ^ 0x11) {
        for (let i = 7; i >= 0; i--) {
          bits.push(((pad >> i) & 1) === 1);
        }
      }
      
      return bits.slice(0, maxBits);
    }
    
    getMaxDataBits() {
      // Version 3, error correction L: 77 bytes = 616 bits
      return 616;
    }
    
    getBestMask() {
      // For simplicity, use mask pattern 0
      return 0;
    }
    
    applyMask(mask) {
      const maskFunc = [
        (i, j) => (i + j) % 2 === 0,
        (i, j) => i % 2 === 0,
        (i, j) => j % 3 === 0,
        (i, j) => (i + j) % 3 === 0,
        (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
        (i, j) => (i * j) % 2 + (i * j) % 3 === 0,
        (i, j) => ((i * j) % 2 + (i * j) % 3) % 2 === 0,
        (i, j) => ((i + j) % 2 + (i * j) % 3) % 2 === 0
      ][mask];
      
      for (let row = 0; row < this.size; row++) {
        for (let col = 0; col < this.size; col++) {
          if (this.modules[row][col] === null) continue;
          if (this.isFunction(row, col)) continue;
          
          if (maskFunc(row, col)) {
            this.modules[row][col] = !this.modules[row][col];
          }
        }
      }
    }
    
    isFunction(row, col) {
      // Check if position is part of function patterns
      if (row === 6 || col === 6) return true; // Timing
      if (row < 9 && col < 9) return true; // Top-left finder
      if (row < 9 && col >= this.size - 8) return true; // Top-right finder
      if (row >= this.size - 8 && col < 9) return true; // Bottom-left finder
      
      // Alignment pattern for version 3
      if (this.version >= 2) {
        const pos = 22;
        if (row >= pos - 2 && row <= pos + 2 && col >= pos - 2 && col <= pos + 2) {
          return true;
        }
      }
      
      // Dark module and format info areas
      if (row === this.size - 8 && col === 8) return true;
      
      return false;
    }
    
    addFormatInfo() {
      // Format bits: error correction level (2 bits) + mask pattern (3 bits)
      let data = (ECL.L << 3) | this.mask;
      
      // BCH error correction
      let rem = data;
      for (let i = 0; i < 10; i++) {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
      }
      const bits = (data << 10 | rem) ^ 0x5412; // XOR with mask
      
      // Place format bits
      for (let i = 0; i <= 5; i++) {
        this.modules[8][i] = ((bits >> i) & 1) === 1;
      }
      this.modules[8][7] = ((bits >> 6) & 1) === 1;
      this.modules[8][8] = ((bits >> 7) & 1) === 1;
      this.modules[7][8] = ((bits >> 8) & 1) === 1;
      for (let i = 9; i < 15; i++) {
        this.modules[14 - i][8] = ((bits >> i) & 1) === 1;
      }
      
      // Second copy
      for (let i = 0; i < 8; i++) {
        this.modules[this.size - 1 - i][8] = ((bits >> i) & 1) === 1;
      }
      for (let i = 8; i < 15; i++) {
        this.modules[8][this.size - 15 + i] = ((bits >> i) & 1) === 1;
      }
    }
    
    toCanvas(size = 256) {
      const scale = Math.floor(size / (this.size + 8));
      const canvas = document.createElement('canvas');
      const canvasSize = (this.size + 8) * scale;
      canvas.width = canvasSize;
      canvas.height = canvasSize;
      
      const ctx = canvas.getContext('2d');
      
      // White background
      ctx.fillStyle = '#FFFFFF';
      ctx.fillRect(0, 0, canvasSize, canvasSize);
      
      // Black modules
      ctx.fillStyle = '#000000';
      for (let row = 0; row < this.size; row++) {
        for (let col = 0; col < this.size; col++) {
          if (this.modules[row][col]) {
            ctx.fillRect(
              (col + 4) * scale,
              (row + 4) * scale,
              scale,
              scale
            );
          }
        }
      }
      
      return canvas;
    }
  }
  
  // Export global function
  window.generateQRCode = function(text, size) {
    try {
      const qr = new SimpleQR(text);
      const canvas = qr.toCanvas(size);
      return canvas.toDataURL('image/png');
    } catch (e) {
      console.error('QR generation error:', e);
      return null;
    }
  };
})();