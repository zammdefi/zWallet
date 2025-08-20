// Quick test to see what splitSignature returns

// Example signature from ethers v6
const testSig = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1b";

console.log("Testing ethers.splitSignature behavior:");
console.log("Input signature:", testSig);

// What splitSignature should return:
// - v: number (27 or 28)  
// - r: hex string with 0x prefix (66 chars total)
// - s: hex string with 0x prefix (66 chars total)

// Manual extraction that should always work:
function manualSplitSignature(signature) {
    // Remove 0x prefix if present
    const sig = signature.startsWith('0x') ? signature.slice(2) : signature;
    
    // Signature should be 65 bytes = 130 hex chars
    if (sig.length !== 130) {
        throw new Error(`Invalid signature length: ${sig.length} (expected 130)`);
    }
    
    const r = '0x' + sig.slice(0, 64);  // First 32 bytes
    const s = '0x' + sig.slice(64, 128); // Next 32 bytes
    let v = parseInt(sig.slice(128, 130), 16); // Last byte
    
    // Normalize v to 27/28 if it's 0/1
    if (v === 0 || v === 1) {
        v += 27;
    }
    
    return { v, r, s };
}

const result = manualSplitSignature(testSig);
console.log("Manual split result:");
console.log("  v:", result.v, typeof result.v);
console.log("  r:", result.r, "length:", result.r.length);
console.log("  s:", result.s, "length:", result.s.length);

// This is what the extension should use for compatibility