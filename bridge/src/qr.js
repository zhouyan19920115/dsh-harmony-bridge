// A small QR Code encoder (byte mode, error correction level M) written from the specification.
//
// The bridge prints a pairing QR code into the terminal so the phone can scan it. No npm
// dependency is used: the encoder below implements Reed-Solomon over GF(256), the function
// patterns, the eight data masks and the penalty scoring that picks the best mask.

/** Error correction levels with their format bits. */
const ECC = {
  L: { ordinal: 0, formatBits: 1 },
  M: { ordinal: 1, formatBits: 0 },
  Q: { ordinal: 2, formatBits: 3 },
  H: { ordinal: 3, formatBits: 2 },
};

/** Error correction codewords per block, indexed by [level][version]. Index 0 is unused. */
const ECC_CODEWORDS_PER_BLOCK = {
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
};

/** Number of error correction blocks, indexed by [level][version]. Index 0 is unused. */
const NUM_ERROR_CORRECTION_BLOCKS = {
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
};

const MIN_VERSION = 1;
const MAX_VERSION = 40;

/** Number of raw data modules (bits) of a version, i.e. everything that is not a function pattern. */
function numRawDataModules(version) {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

/** Total number of codewords (data + ECC) of a version. */
function numRawCodewords(version) {
  return Math.floor(numRawDataModules(version) / 8);
}

/** Number of data codewords available for a version/level. */
export function numDataCodewords(version, level = 'M') {
  return numRawCodewords(version) - ECC_CODEWORDS_PER_BLOCK[level][version] * NUM_ERROR_CORRECTION_BLOCKS[level][version];
}

/** Positions of the alignment pattern centres. */
function alignmentPatternPositions(version) {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const result = [6];
  for (let pos = version * 4 + 10; result.length < count; pos -= step) result.splice(1, 0, pos);
  return result;
}

/* ------------------------------------------------------------------ Reed-Solomon over GF(256) */

function gfMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i -= 1) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function rsComputeDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i += 1) {
    for (let j = 0; j < result.length; j += 1) {
      result[j] = gfMultiply(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}

function rsComputeRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const byte of data) {
    const factor = byte ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < result.length; i += 1) result[i] ^= gfMultiply(divisor[i], factor);
  }
  return result;
}

/** Compute the ECC codewords for one block. */
export function reedSolomon(data, eccLength) {
  return rsComputeRemainder(data, rsComputeDivisor(eccLength));
}

/* --------------------------------------------------------------------------- data encoding */

/** Pick the smallest version that can hold `byteLength` bytes at the given level. */
export function chooseVersion(byteLength, level = 'M') {
  for (let version = MIN_VERSION; version <= MAX_VERSION; version += 1) {
    const countBits = version <= 9 ? 8 : 16;
    const requiredBits = 4 + countBits + byteLength * 8;
    if (requiredBits <= numDataCodewords(version, level) * 8) return version;
  }
  throw new Error(`qr: ${byteLength} bytes do not fit into a version ${MAX_VERSION} ${level} code`);
}

/** Encode the payload into data codewords (mode indicator, count, bytes, terminator, padding). */
export function encodeDataCodewords(bytes, version, level = 'M') {
  const capacityBits = numDataCodewords(version, level) * 8;
  const bits = [];
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i -= 1) bits.push((value >>> i) & 1);
  };

  push(0b0100, 4); // byte mode
  push(bytes.length, version <= 9 ? 8 : 16);
  for (const byte of bytes) push(byte, 8);

  const terminator = Math.min(4, capacityBits - bits.length);
  push(0, terminator);
  while (bits.length % 8 !== 0) bits.push(0);

  let padIndex = 0;
  while (bits.length < capacityBits) {
    push(padIndex % 2 === 0 ? 0xec : 0x11, 8);
    padIndex += 1;
  }

  const out = new Uint8Array(capacityBits / 8);
  for (let i = 0; i < bits.length; i += 1) out[i >>> 3] |= bits[i] << (7 - (i & 7));
  return out;
}

/** Split into blocks, add ECC, and interleave the codewords. */
export function addEccAndInterleave(data, version, level = 'M') {
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[level][version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[level][version];
  const rawCodewords = numRawCodewords(version);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const divisor = rsComputeDivisor(blockEccLen);
  const blocks = [];
  let offset = 0;
  for (let i = 0; i < numBlocks; i += 1) {
    const dataLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
    const block = data.subarray(offset, offset + dataLen);
    offset += dataLen;
    const ecc = rsComputeRemainder(block, divisor);
    const full = new Uint8Array(shortBlockLen + 1);
    full.set(block, 0);
    full.set(ecc, full.length - blockEccLen);
    blocks.push(full);
  }

  const result = new Uint8Array(rawCodewords);
  let cursor = 0;
  for (let i = 0; i < blocks[0].length; i += 1) {
    for (let j = 0; j < blocks.length; j += 1) {
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) result[cursor++] = blocks[j][i];
    }
  }
  return result;
}

/* ------------------------------------------------------------------------- module placement */

/** The eight data mask predicates, evaluated per module (x = column, y = row). */
const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

/** 15-bit format information (5 data bits + BCH(15,5), masked with 0x5412). */
export function formatBits(level, mask) {
  const data = (ECC[level].formatBits << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i += 1) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

/** 18-bit version information (6 data bits + BCH(18,6)). */
export function versionBits(version) {
  let rem = version;
  for (let i = 0; i < 12; i += 1) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | rem;
}

class QrMatrix {
  constructor(version) {
    this.version = version;
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Uint8Array(this.size));
    this.isFunction = Array.from({ length: this.size }, () => new Uint8Array(this.size));
  }

  setFunction(x, y, dark) {
    if (x < 0 || y < 0 || x >= this.size || y >= this.size) return;
    this.modules[y][x] = dark ? 1 : 0;
    this.isFunction[y][x] = 1;
  }

  drawFinder(x, y) {
    for (let dy = -4; dy <= 4; dy += 1) {
      for (let dx = -4; dx <= 4; dx += 1) {
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        this.setFunction(x + dx, y + dy, distance !== 2 && distance !== 4);
      }
    }
  }

  drawAlignment(x, y) {
    for (let dy = -2; dy <= 2; dy += 1) {
      for (let dx = -2; dx <= 2; dx += 1) {
        this.setFunction(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }

  drawFormatBits(mask, level) {
    const bits = formatBits(level, mask);
    const bit = (index) => ((bits >>> index) & 1) === 1;
    for (let i = 0; i <= 5; i += 1) this.setFunction(8, i, bit(i));
    this.setFunction(8, 7, bit(6));
    this.setFunction(8, 8, bit(7));
    this.setFunction(7, 8, bit(8));
    for (let i = 9; i < 15; i += 1) this.setFunction(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i += 1) this.setFunction(this.size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i += 1) this.setFunction(8, this.size - 15 + i, bit(i));
    this.setFunction(8, this.size - 8, true);
  }

  drawVersionBits() {
    if (this.version < 7) return;
    const bits = versionBits(this.version);
    for (let i = 0; i < 18; i += 1) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.setFunction(a, b, dark);
      this.setFunction(b, a, dark);
    }
  }

  drawFunctionPatterns(level) {
    for (let i = 0; i < this.size; i += 1) {
      this.setFunction(6, i, i % 2 === 0);
      this.setFunction(i, 6, i % 2 === 0);
    }
    this.drawFinder(3, 3);
    this.drawFinder(this.size - 4, 3);
    this.drawFinder(3, this.size - 4);

    const positions = alignmentPatternPositions(this.version);
    const last = positions.length - 1;
    for (let i = 0; i < positions.length; i += 1) {
      for (let j = 0; j < positions.length; j += 1) {
        const isCorner = (i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0);
        if (!isCorner) this.drawAlignment(positions[i], positions[j]);
      }
    }

    this.drawFormatBits(0, level);
    this.drawVersionBits();
  }

  drawCodewords(data) {
    let bitIndex = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < this.size; vert += 1) {
        for (let j = 0; j < 2; j += 1) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (this.isFunction[y][x] === 0 && bitIndex < data.length * 8) {
            this.modules[y][x] = (data[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1;
            bitIndex += 1;
          }
        }
      }
    }
  }

  applyMask(mask) {
    for (let y = 0; y < this.size; y += 1) {
      for (let x = 0; x < this.size; x += 1) {
        if (this.isFunction[y][x] === 1) continue;
        if (MASKS[mask](x, y)) this.modules[y][x] ^= 1;
      }
    }
  }

  penalty() {
    const size = this.size;
    const modules = this.modules;
    let result = 0;

    const addHistory = (runLength, history) => {
      const value = history[0] === 0 ? runLength + size : runLength;
      for (let i = history.length - 1; i > 0; i -= 1) history[i] = history[i - 1];
      history[0] = value;
    };
    const countPatterns = (history) => {
      const n = history[1];
      const core = n > 0 && history[2] === n && history[3] === n * 3 && history[4] === n && history[5] === n;
      return (core && history[0] >= n * 4 && history[6] >= n ? 1 : 0)
        + (core && history[6] >= n * 4 && history[0] >= n ? 1 : 0);
    };
    const terminate = (color, runLength, history) => {
      let length = runLength;
      if (color) {
        addHistory(length, history);
        length = 0;
      }
      addHistory(length + size, history);
      return countPatterns(history);
    };

    for (let y = 0; y < size; y += 1) {
      let runColor = false;
      let runLength = 0;
      const history = new Array(7).fill(0);
      for (let x = 0; x < size; x += 1) {
        if (modules[y][x] === (runColor ? 1 : 0)) {
          runLength += 1;
          if (runLength === 5) result += 3;
          else if (runLength > 5) result += 1;
        } else {
          addHistory(runLength, history);
          if (!runColor) result += countPatterns(history) * 40;
          runColor = modules[y][x] === 1;
          runLength = 1;
        }
      }
      result += terminate(runColor, runLength, history) * 40;
    }

    for (let x = 0; x < size; x += 1) {
      let runColor = false;
      let runLength = 0;
      const history = new Array(7).fill(0);
      for (let y = 0; y < size; y += 1) {
        if (modules[y][x] === (runColor ? 1 : 0)) {
          runLength += 1;
          if (runLength === 5) result += 3;
          else if (runLength > 5) result += 1;
        } else {
          addHistory(runLength, history);
          if (!runColor) result += countPatterns(history) * 40;
          runColor = modules[y][x] === 1;
          runLength = 1;
        }
      }
      result += terminate(runColor, runLength, history) * 40;
    }

    for (let y = 0; y < size - 1; y += 1) {
      for (let x = 0; x < size - 1; x += 1) {
        const color = modules[y][x];
        if (color === modules[y][x + 1] && color === modules[y + 1][x] && color === modules[y + 1][x + 1]) result += 3;
      }
    }

    let dark = 0;
    for (const row of modules) for (const value of row) dark += value;
    const total = size * size;
    const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    result += k * 10;
    return result;
  }
}

/**
 * Encode `text` into a QR matrix.
 * Returns `{ version, level, size, modules }` where `modules` is a `boolean[][]` (row-major).
 */
export function encodeQR(text, { level = 'M' } = {}) {
  if (!ECC[level]) throw new Error(`qr: unsupported error correction level ${level}`);
  const bytes = Buffer.from(String(text), 'utf8');
  const version = chooseVersion(bytes.length, level);
  const data = encodeDataCodewords(bytes, version, level);
  const codewords = addEccAndInterleave(data, version, level);

  let best = null;
  for (let mask = 0; mask < 8; mask += 1) {
    const matrix = new QrMatrix(version);
    matrix.drawFunctionPatterns(level);
    matrix.drawCodewords(codewords);
    matrix.applyMask(mask);
    matrix.drawFormatBits(mask, level);
    const score = matrix.penalty();
    if (best === null || score < best.score) best = { score, matrix, mask };
  }

  const modules = [];
  for (let y = 0; y < best.matrix.size; y += 1) {
    const row = [];
    for (let x = 0; x < best.matrix.size; x += 1) row.push(best.matrix.modules[y][x] === 1);
    modules.push(row);
  }
  return { version, level, size: best.matrix.size, mask: best.mask, modules };
}

/**
 * Render a QR matrix as text that can be printed in a terminal.
 * Half-block characters keep the modules roughly square in a monospace font.
 */
export function renderQrText(matrix, { quietZone = 3 } = {}) {
  const size = matrix.size;
  const total = size + quietZone * 2;
  const dark = (x, y) => {
    const realX = x - quietZone;
    const realY = y - quietZone;
    if (realX < 0 || realY < 0 || realX >= size || realY >= size) return false;
    return matrix.modules[realY][realX];
  };

  const lines = [];
  for (let y = 0; y < total; y += 2) {
    let line = '';
    for (let x = 0; x < total; x += 1) {
      const top = dark(x, y);
      const bottom = y + 1 < total ? dark(x, y + 1) : false;
      if (top && bottom) line += '█';
      else if (top) line += '▀';
      else if (bottom) line += '▄';
      else line += ' ';
    }
    lines.push(line);
  }
  return lines.join('\n');
}

/** Convenience: encode and render in one call. */
export function qrToText(text, options = {}) {
  const matrix = encodeQR(text, options);
  return { matrix, text: renderQrText(matrix, options) };
}
