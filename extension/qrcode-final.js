/*!
 * Minimal QR Code Generator for zWallet
 * Specifically optimized for Ethereum addresses and MetaMask Mobile compatibility
 */
(function() {

// QR Code generator - minimal implementation
var QRCode = function(text, level) {
  level = level || 'M';
  
  var qr = {
    version: 0,
    errorCorrectLevel: {'L':1,'M':0,'Q':3,'H':2}[level],
    modules: null,
    moduleCount: 0,
    dataCache: null,
    dataList: []
  };
  
  // Determine minimum version for text
  qr.version = getMinimumVersion(text);
  qr.moduleCount = qr.version * 4 + 17;
  
  // Initialize modules
  qr.modules = new Array(qr.moduleCount);
  for (var row = 0; row < qr.moduleCount; row++) {
    qr.modules[row] = new Array(qr.moduleCount);
    for (var col = 0; col < qr.moduleCount; col++) {
      qr.modules[row][col] = null;
    }
  }
  
  // Setup position patterns
  setupPositionProbePattern(qr, 0, 0);
  setupPositionProbePattern(qr, qr.moduleCount - 7, 0);
  setupPositionProbePattern(qr, 0, qr.moduleCount - 7);
  setupPositionAdjustPattern(qr);
  setupTimingPattern(qr);
  
  // Encode data
  var data = createData(qr, text);
  mapData(qr, data, 0);
  
  return qr;
};

function getMinimumVersion(text) {
  // For Ethereum addresses (42 chars), we need version 3
  // Version 3 can hold up to 77 bytes in byte mode with M error correction
  if (text.length <= 25) return 2;
  if (text.length <= 47) return 3;
  if (text.length <= 77) return 4;
  return 5;
}

function setupPositionProbePattern(qr, row, col) {
  for (var r = -1; r <= 7; r++) {
    if (row + r <= -1 || qr.moduleCount <= row + r) continue;
    
    for (var c = -1; c <= 7; c++) {
      if (col + c <= -1 || qr.moduleCount <= col + c) continue;
      
      if ((0 <= r && r <= 6 && (c == 0 || c == 6)) ||
          (0 <= c && c <= 6 && (r == 0 || r == 6)) ||
          (2 <= r && r <= 4 && 2 <= c && c <= 4)) {
        qr.modules[row + r][col + c] = true;
      } else {
        qr.modules[row + r][col + c] = false;
      }
    }
  }
}

function setupPositionAdjustPattern(qr) {
  var pos = getPatternPosition(qr.version);
  
  for (var i = 0; i < pos.length; i++) {
    for (var j = 0; j < pos.length; j++) {
      var row = pos[i];
      var col = pos[j];
      
      if (qr.modules[row][col] != null) {
        continue;
      }
      
      for (var r = -2; r <= 2; r++) {
        for (var c = -2; c <= 2; c++) {
          if (r == -2 || r == 2 || c == -2 || c == 2 ||
              (r == 0 && c == 0)) {
            qr.modules[row + r][col + c] = true;
          } else {
            qr.modules[row + r][col + c] = false;
          }
        }
      }
    }
  }
}

function getPatternPosition(version) {
  var positions = [
    [],
    [6, 18],
    [6, 22],
    [6, 26],
    [6, 30],
    [6, 34]
  ];
  return positions[version] || [];
}

function setupTimingPattern(qr) {
  for (var r = 8; r < qr.moduleCount - 8; r++) {
    if (qr.modules[r][6] != null) {
      continue;
    }
    qr.modules[r][6] = (r % 2 == 0);
  }
  
  for (var c = 8; c < qr.moduleCount - 8; c++) {
    if (qr.modules[6][c] != null) {
      continue;
    }
    qr.modules[6][c] = (c % 2 == 0);
  }
}

function createData(qr, text) {
  var buffer = [];
  
  // Mode indicator for byte mode
  buffer.push(4, 4);
  
  // Character count indicator
  var lengthBits = 8; // 8 bits for version 1-9
  buffer.push(text.length, lengthBits);
  
  // Convert text to bytes
  for (var i = 0; i < text.length; i++) {
    buffer.push(text.charCodeAt(i), 8);
  }
  
  // Terminator
  if (buffer.length < getMaxLength(qr) * 8) {
    buffer.push(0, 4);
  }
  
  // Padding
  while (buffer.length % 8 != 0) {
    buffer.push(0, 1);
  }
  
  // Padding bytes
  var totalDataCount = getMaxLength(qr);
  var data = [];
  
  for (var i = 0; i < buffer.length; i += 8) {
    var byte = 0;
    for (var j = 0; j < 8; j++) {
      if (i + j < buffer.length && buffer[i + j]) {
        byte |= (1 << (7 - j));
      }
    }
    data.push(byte);
  }
  
  // Add padding patterns
  var padBytes = [0xEC, 0x11];
  var padIndex = 0;
  
  while (data.length < totalDataCount) {
    data.push(padBytes[padIndex]);
    padIndex = (padIndex + 1) % 2;
  }
  
  return data;
}

function getMaxLength(qr) {
  // Data capacity for byte mode with M error correction
  var capacities = [0, 14, 26, 42, 62, 84];
  return capacities[qr.version] || 100;
}

function mapData(qr, data, maskPattern) {
  var inc = -1;
  var row = qr.moduleCount - 1;
  var bitIndex = 7;
  var byteIndex = 0;
  
  for (var col = qr.moduleCount - 1; col > 0; col -= 2) {
    if (col == 6) col--;
    
    while (true) {
      for (var c = 0; c < 2; c++) {
        if (qr.modules[row][col - c] == null) {
          var dark = false;
          
          if (byteIndex < data.length) {
            dark = (((data[byteIndex] >>> bitIndex) & 1) == 1);
          }
          
          var mask = getMask(maskPattern, row, col - c);
          if (mask) {
            dark = !dark;
          }
          
          qr.modules[row][col - c] = dark;
          bitIndex--;
          
          if (bitIndex == -1) {
            byteIndex++;
            bitIndex = 7;
          }
        }
      }
      
      row += inc;
      
      if (row < 0 || qr.moduleCount <= row) {
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
}

function getMask(maskPattern, i, j) {
  // Use mask pattern 0 (checkerboard)
  return (i + j) % 2 == 0;
}

// Export function
window.generateQRCode = function(text, size) {
  size = size || 256;
  
  // CRITICAL: MetaMask Mobile scans ONLY the plain address
  // Remove any prefix and ensure lowercase
  text = text.replace(/^ethereum:/i, '').toLowerCase();
  
  try {
    var qr = QRCode(text, 'M');
    var moduleCount = qr.moduleCount;
    var cellSize = Math.floor(size / moduleCount);
    var margin = Math.floor((size - cellSize * moduleCount) / 2);
    
    var canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    
    var ctx = canvas.getContext('2d');
    
    // White background
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    
    // Draw modules
    ctx.fillStyle = '#000000';
    
    for (var row = 0; row < moduleCount; row++) {
      for (var col = 0; col < moduleCount; col++) {
        if (qr.modules[row][col]) {
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
    
  } catch (e) {
    console.error('QR generation error:', e);
    return null;
  }
};

})();