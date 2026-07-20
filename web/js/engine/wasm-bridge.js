/**
 * Darlene-X_2.0 WASM bridge — loads local hotpath.wasm for packing/entropy heuristics.
 * Falls back to pure JS if WASM fails. Never phones home.
 */
(function (global) {
  'use strict';

  const state = {
    ready: false,
    mode: 'js-fallback',
    exports: null,
    memory: null,
  };

  function jsUniqueBytes(bytes) {
    const seen = new Uint8Array(256);
    for (let i = 0; i < bytes.length; i++) seen[bytes[i]] = 1;
    let n = 0;
    for (let i = 0; i < 256; i++) n += seen[i];
    return n;
  }

  function jsPackedScore(bytes) {
    if (bytes.length < 64) return 0;
    const u = jsUniqueBytes(bytes);
    if (u <= 80) return 0;
    return Math.min(100, Math.floor(((u - 80) * 100) / 176));
  }

  function ensureCapacity(needed) {
    // Keep 1MiB scratch for histograms at end of first 256 pages (16MiB).
    const pagesNeeded = Math.ceil((needed + 0x100400) / 65536);
    const current = state.memory.buffer.byteLength / 65536;
    if (pagesNeeded > current) {
      state.memory.grow(pagesNeeded - current);
    }
  }

  function analyzeBuffer(bytes) {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (!state.ready || !state.exports) {
      const unique = jsUniqueBytes(view);
      const packed = jsPackedScore(view);
      return { uniqueBytes: unique, packedScore: packed, backend: 'js' };
    }

    // Cap WASM copy size to keep UI responsive (first 4 MiB is enough for heuristic).
    const len = Math.min(view.length, 4 * 1024 * 1024);
    ensureCapacity(len);
    const mem = new Uint8Array(state.memory.buffer);
    mem.set(view.subarray(0, len), 0);
    const unique = state.exports.unique_bytes(len) >>> 0;
    const packed = state.exports.packed_score(len) >>> 0;
    const fold = state.exports.xor_fold(len) >>> 0;
    return { uniqueBytes: unique, packedScore: packed, xorFold: fold, backend: 'wasm', scannedBytes: len };
  }

  async function init(wasmUrl) {
    try {
      const url = wasmUrl || 'wasm/hotpath.wasm';
      const resp = await fetch(url);
      if (!resp.ok) throw new Error('wasm fetch ' + resp.status);
      const buf = await resp.arrayBuffer();
      const { instance } = await WebAssembly.instantiate(buf, {});
      state.exports = instance.exports;
      state.memory = instance.exports.memory;
      state.ready = true;
      state.mode = 'wasm';
      return state;
    } catch (err) {
      console.warn('[DarleneWASM] using JS fallback:', err.message || err);
      state.ready = false;
      state.mode = 'js-fallback';
      return state;
    }
  }

  global.DarleneWASM = {
    init,
    analyzeBuffer,
    getStatus: () => ({ ...state, ready: state.ready, mode: state.mode }),
  };
})(typeof window !== 'undefined' ? window : globalThis);
