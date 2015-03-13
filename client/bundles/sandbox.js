// @pinf-bundle-ignore: 
PINF.bundle("", function(require, global) {
// @pinf-bundle-header: {"helper":"amd-ish"}
function wrapAMD(callback) {
    var amdRequireImplementation = null;
    function define(id, dependencies, moduleInitializer) {
        if (typeof dependencies === "undefined" && typeof moduleInitializer === "undefined") {
            if (typeof id === "function") {
                moduleInitializer = id;
            } else {
                var exports = id;
                moduleInitializer = function() { return exports; }
            }
            dependencies = ["require", "exports", "module"];
            id = null;
        } else
        if (Array.isArray(id) && typeof dependencies === "function" && typeof moduleInitializer === "undefined") {
            moduleInitializer = dependencies;
            dependencies = id;
            id = null;
        } else
        if (typeof id === "string" && typeof dependencies === "function" && typeof moduleInitializer === "undefined") {
            moduleInitializer = dependencies;
            dependencies = ["require", "exports", "module"];
        }
        return function(realRequire, exports, module) {
            function require(id) {
                if (Array.isArray(id)) {
                    var apis = [];
                    var callback = arguments[1];
                    id.forEach(function(moduleId, index) {
                        realRequire.async(moduleId, function(api) {
                            apis[index] = api
                            if (apis.length === id.length) {
                                if (callback) callback.apply(null, apis);
                            }
                        }, function(err) {
                            throw err;
                        });
                    });
                } else {
                    return realRequire(id);
                }
            }
            require.toUrl = function(id) {
                return realRequire.sandbox.id.replace(/\/[^\/]*$/, "") + realRequire.id(id);
            }
            require.sandbox = realRequire.sandbox;
            require.id = realRequire.id;
            if (typeof amdRequireImplementation !== "undefined") {
                amdRequireImplementation = require;
            }
            if (typeof moduleInitializer === "function") {
                return moduleInitializer.apply(moduleInitializer, dependencies.map(function(name) {
                    if (name === "require") return require;
                    if (name === "exports") return exports;
                    if (name === "module") return module;
                    return require(name);
                }));
            } else
            if (typeof dependencies === "object") {
                return dependencies;
            }
        }
    }
    define.amd = { jQuery: true };
    require.def = define;
    var exports = null;
    function wrappedDefine() {
        exports = define.apply(null, arguments);
    }
    wrappedDefine.amd = { jQuery: true };
    function amdRequire() {
        return amdRequireImplementation.apply(null, arguments);
    }
    amdRequire.def = wrappedDefine
    callback(amdRequire, wrappedDefine);
    return exports;
}
// @pinf-bundle-module: {"file":"sandbox.js","mtime":1423123918,"wrapper":"commonjs","format":"commonjs","id":"/sandbox.js"}
require.memoize("/sandbox.js", 
function(require, exports, module) {var __dirname = '';

const SJCL = require("sjcl");
const ECC = require("./ecc");
const STORE = require("store");
const SHA1 = require("./sha1");


exports.main = function() {
	return exports;
}

exports.sandbox = function(sandboxIdentifier, sandboxOptions, loadedCallback, errorCallback) {

	if (!sandboxIdentifier) {
		if (errorCallback) return errorCallback(new Error("'sandboxIdentifier' not specified"));
		throw new Error("'sandboxIdentifier' not specified");
	}

	if (typeof sandboxOptions === "function" && typeof loadedCallback === "function" && typeof errorCallback === "undefined") {
		errorCallback = loadedCallback;
		loadedCallback = sandboxOptions;
		sandboxOptions = {};
	} else
	if (typeof sandboxOptions === "function" && typeof loadedCallback === "undefined") {
		loadedCallback = sandboxOptions;
		sandboxOptions = {};
	} else {
		sandboxOptions = sandboxOptions || {};
	}

	if (typeof sandboxOptions.secure !== "object") {
		return errorCallback(new Error("'secure' property not set!"));
	}
	if (typeof sandboxOptions.secure.bundles !== "object") {
		return errorCallback(new Error("'secure.bundles' property not set!"));
	}

	var signatures = {};
	sandboxOptions.secure.bundles.filter(function(bundle) {
		return /^eccver:/.test(bundle) && !/^eccver:\*$/.test(bundle);
	}).map(function (bundle) {
		var key = bundle.match(/^eccver:(.{7})/)[1];
		if (!signatures[key]) {
			signatures[key] = [];
		}
		signatures[key].push(bundle);
	});

	// TODO: Keep track of different instances of `PINF.bundle()`
	//       so we can allow multiple secure sandboxes at the same time.
	var _orig_bundle_handler = PINF.setActiveBundleHandler(function(uid, callback, meta) {

		if (!meta || typeof meta !== "object") {
			throw new Error("No meta data supplied for bundle '" + uid + "'!");
		}

		// TODO: To make this secure we have to generate a key in our singleton and sign
		//       the value in the store with it. That way when verifying we can detect if the
		//       user verified it.
		var cacheKey = "pinf-loader-secure-js." + SJCL.codec.hex.fromBits(SJCL.hash.sha256.hash(JSON.stringify(meta)));

		if (STORE.get(cacheKey) === true) {
			return _orig_bundle_handler(uid, callback);
		}

		var verified = false;

		// NOTE: For the following verification implementation to work,
		//       the return value of `callback.toString()` must be an
		//       EXACT copy of the source code sent to the browser
		//       by the server.

		// A signature is preferred but optional.

		if (typeof meta.signature === "string") {
			var signatureParts = meta.signature.split(":");
			if (signatureParts[0] !== "ecc") {
				throw new Error("Signature type '" + signatureParts[0] + "' used by bundle '" + uid + "' not supported!");
			}
			if (signatures[signatureParts[1]]) {
				signatures[signatureParts[1]].forEach(function (verifier) {
					if (verified) return;
					if (!/^eccver:/.test(verifier)) return;
					if (ECC.verify(verifier.split(":")[1], SJCL.codec.hex.toBits(signatureParts[2]), callback.toString())) {
						verified = true;
					}
				});
				if (!verified) {
					throw new Error("Bundle signature supplied for bundle '" + uid + "' does not match signature calculated using verifier '" + signatureParts[1] + "' based on toString() for bundle payload!");
				}
			}
		}

		// A hash is required at minimum.

		if (!verified) {

			if (typeof meta.hash !== "string") {
				throw new Error("No hash supplied for bundle '" + uid + "'!");
			}

			var hashParts = meta.hash.split(":");

			if (typeof SJCL.hash[hashParts[0]] === "undefined") {
				throw new Error("Hash type '" + hashParts[0] + "' used by bundle '" + uid + "' not supported!");
			}

			// TODO: Why does this hash not match the sha1 hash from NodeJS?
			console.log("HASH 1", (new SHA1(callback.toString(), "TEXT")).getHash("SHA-1", "HEX"));

/*
			if (hashParts[1] !== SJCL.codec.hex.fromBits(SJCL.hash[hashParts[0]].hash(callback.toString()))) {
				throw new Error("Bundle hash supplied for bundle '" + uid + "' does not match calculated hash from toString() of bundle payload!");
			}
*/
			if (sandboxOptions.secure.bundles.indexOf(meta.hash) === -1) {
				if (sandboxOptions.secure.bundles.indexOf(hashParts[0] + ":*") === -1) {
					throw new Error("Hash '" + meta.hash + "' used by bundle '" + uid + "' not declared in 'secure.bundles'!");
				}
			}
		}

		STORE.set(cacheKey, true);

		return _orig_bundle_handler(uid, callback);
	});

	return require.sandbox(sandboxIdentifier, sandboxOptions, loadedCallback, errorCallback);
}

}
, {"filename":"sandbox.js"});
// @pinf-bundle-module: {"file":"../node_modules/sjcl/sjcl.js","mtime":1425932300,"wrapper":"commonjs/leaky","format":"leaky","id":"74aebe51583a1aa6e83b78461af89adfd8bb7cda-sjcl/sjcl.js"}
require.memoize("74aebe51583a1aa6e83b78461af89adfd8bb7cda-sjcl/sjcl.js", 
function(require, exports, module) {var __dirname = '../node_modules/sjcl';
/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

"use strict";
/*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape, module, require, Uint32Array */

/** @namespace The Stanford Javascript Crypto Library, top-level namespace. */
var sjcl = {
  /** @namespace Symmetric ciphers. */
  cipher: {},

  /** @namespace Hash functions.  Right now only SHA256 is implemented. */
  hash: {},

  /** @namespace Key exchange functions.  Right now only SRP is implemented. */
  keyexchange: {},
  
  /** @namespace Block cipher modes of operation. */
  mode: {},

  /** @namespace Miscellaneous.  HMAC and PBKDF2. */
  misc: {},
  
  /**
   * @namespace Bit array encoders and decoders.
   *
   * @description
   * The members of this namespace are functions which translate between
   * SJCL's bitArrays and other objects (usually strings).  Because it
   * isn't always clear which direction is encoding and which is decoding,
   * the method names are "fromBits" and "toBits".
   */
  codec: {},
  
  /** @namespace Exceptions. */
  exception: {
    /** @constructor Ciphertext is corrupt. */
    corrupt: function(message) {
      this.toString = function() { return "CORRUPT: "+this.message; };
      this.message = message;
    },
    
    /** @constructor Invalid parameter. */
    invalid: function(message) {
      this.toString = function() { return "INVALID: "+this.message; };
      this.message = message;
    },
    
    /** @constructor Bug or missing feature in SJCL. @constructor */
    bug: function(message) {
      this.toString = function() { return "BUG: "+this.message; };
      this.message = message;
    },

    /** @constructor Something isn't ready. */
    notReady: function(message) {
      this.toString = function() { return "NOT READY: "+this.message; };
      this.message = message;
    }
  }
};

if(typeof module !== 'undefined' && module.exports){
  module.exports = sjcl;
}
/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */
sjcl.cipher.aes = function (key) {
  if (!this._tables[0][0][0]) {
    this._precompute();
  }
  
  var i, j, tmp,
    encKey, decKey,
    sbox = this._tables[0][4], decTable = this._tables[1],
    keyLen = key.length, rcon = 1;
  
  if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
    throw new sjcl.exception.invalid("invalid aes key size");
  }
  
  this._key = [encKey = key.slice(0), decKey = []];
  
  // schedule encryption keys
  for (i = keyLen; i < 4 * keyLen + 28; i++) {
    tmp = encKey[i-1];
    
    // apply sbox
    if (i%keyLen === 0 || (keyLen === 8 && i%keyLen === 4)) {
      tmp = sbox[tmp>>>24]<<24 ^ sbox[tmp>>16&255]<<16 ^ sbox[tmp>>8&255]<<8 ^ sbox[tmp&255];
      
      // shift rows and add rcon
      if (i%keyLen === 0) {
        tmp = tmp<<8 ^ tmp>>>24 ^ rcon<<24;
        rcon = rcon<<1 ^ (rcon>>7)*283;
      }
    }
    
    encKey[i] = encKey[i-keyLen] ^ tmp;
  }
  
  // schedule decryption keys
  for (j = 0; i; j++, i--) {
    tmp = encKey[j&3 ? i : i - 4];
    if (i<=4 || j<4) {
      decKey[j] = tmp;
    } else {
      decKey[j] = decTable[0][sbox[tmp>>>24      ]] ^
                  decTable[1][sbox[tmp>>16  & 255]] ^
                  decTable[2][sbox[tmp>>8   & 255]] ^
                  decTable[3][sbox[tmp      & 255]];
    }
  }
};

sjcl.cipher.aes.prototype = {
  // public
  /* Something like this might appear here eventually
  name: "AES",
  blockSize: 4,
  keySizes: [4,6,8],
  */
  
  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
  encrypt:function (data) { return this._crypt(data,0); },
  
  /**
   * Decrypt an array of 4 big-endian words.
   * @param {Array} data The ciphertext.
   * @return {Array} The plaintext.
   */
  decrypt:function (data) { return this._crypt(data,1); },
  
  /**
   * The expanded S-box and inverse S-box tables.  These will be computed
   * on the client so that we don't have to send them down the wire.
   *
   * There are two tables, _tables[0] is for encryption and
   * _tables[1] is for decryption.
   *
   * The first 4 sub-tables are the expanded S-box with MixColumns.  The
   * last (_tables[01][4]) is the S-box itself.
   *
   * @private
   */
  _tables: [[[],[],[],[],[]],[[],[],[],[],[]]],

  /**
   * Expand the S-box tables.
   *
   * @private
   */
  _precompute: function () {
   var encTable = this._tables[0], decTable = this._tables[1],
       sbox = encTable[4], sboxInv = decTable[4],
       i, x, xInv, d=[], th=[], x2, x4, x8, s, tEnc, tDec;

    // Compute double and third tables
   for (i = 0; i < 256; i++) {
     th[( d[i] = i<<1 ^ (i>>7)*283 )^i]=i;
   }
   
   for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
     // Compute sbox
     s = xInv ^ xInv<<1 ^ xInv<<2 ^ xInv<<3 ^ xInv<<4;
     s = s>>8 ^ s&255 ^ 99;
     sbox[x] = s;
     sboxInv[s] = x;
     
     // Compute MixColumns
     x8 = d[x4 = d[x2 = d[x]]];
     tDec = x8*0x1010101 ^ x4*0x10001 ^ x2*0x101 ^ x*0x1010100;
     tEnc = d[s]*0x101 ^ s*0x1010100;
     
     for (i = 0; i < 4; i++) {
       encTable[i][x] = tEnc = tEnc<<24 ^ tEnc>>>8;
       decTable[i][s] = tDec = tDec<<24 ^ tDec>>>8;
     }
   }
   
   // Compactify.  Considerable speedup on Firefox.
   for (i = 0; i < 5; i++) {
     encTable[i] = encTable[i].slice(0);
     decTable[i] = decTable[i].slice(0);
   }
  },
  
  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  _crypt:function (input, dir) {
    if (input.length !== 4) {
      throw new sjcl.exception.invalid("invalid aes block size");
    }
    
    var key = this._key[dir],
        // state variables a,b,c,d are loaded with pre-whitened data
        a = input[0]           ^ key[0],
        b = input[dir ? 3 : 1] ^ key[1],
        c = input[2]           ^ key[2],
        d = input[dir ? 1 : 3] ^ key[3],
        a2, b2, c2,
        
        nInnerRounds = key.length/4 - 2,
        i,
        kIndex = 4,
        out = [0,0,0,0],
        table = this._tables[dir],
        
        // load up the tables
        t0    = table[0],
        t1    = table[1],
        t2    = table[2],
        t3    = table[3],
        sbox  = table[4];
 
    // Inner rounds.  Cribbed from OpenSSL.
    for (i = 0; i < nInnerRounds; i++) {
      a2 = t0[a>>>24] ^ t1[b>>16 & 255] ^ t2[c>>8 & 255] ^ t3[d & 255] ^ key[kIndex];
      b2 = t0[b>>>24] ^ t1[c>>16 & 255] ^ t2[d>>8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
      c2 = t0[c>>>24] ^ t1[d>>16 & 255] ^ t2[a>>8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
      d  = t0[d>>>24] ^ t1[a>>16 & 255] ^ t2[b>>8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
      kIndex += 4;
      a=a2; b=b2; c=c2;
    }
        
    // Last round.
    for (i = 0; i < 4; i++) {
      out[dir ? 3&-i : i] =
        sbox[a>>>24      ]<<24 ^ 
        sbox[b>>16  & 255]<<16 ^
        sbox[c>>8   & 255]<<8  ^
        sbox[d      & 255]     ^
        key[kIndex++];
      a2=a; a=b; b=c; c=d; d=a2;
    }
    
    return out;
  }
};

/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Arrays of bits, encoded as arrays of Numbers.
 *
 * @description
 * <p>
 * These objects are the currency accepted by SJCL's crypto functions.
 * </p>
 *
 * <p>
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 * </p>
 *
 * <p>
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 * </p>
 */
sjcl.bitArray = {
  /**
   * Array slices in units of bits.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
   * slice until the end of the array.
   * @return {bitArray} The requested slice.
   */
  bitSlice: function (a, bstart, bend) {
    a = sjcl.bitArray._shiftRight(a.slice(bstart/32), 32 - (bstart & 31)).slice(1);
    return (bend === undefined) ? a : sjcl.bitArray.clamp(a, bend-bstart);
  },

  /**
   * Extract a number packed into a bit array.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} length The length of the number to extract.
   * @return {Number} The requested slice.
   */
  extract: function(a, bstart, blength) {
    // FIXME: this Math.floor is not necessary at all, but for some reason
    // seems to suppress a bug in the Chromium JIT.
    var x, sh = Math.floor((-bstart-blength) & 31);
    if ((bstart + blength - 1 ^ bstart) & -32) {
      // it crosses a boundary
      x = (a[bstart/32|0] << (32 - sh)) ^ (a[bstart/32+1|0] >>> sh);
    } else {
      // within a single word
      x = a[bstart/32|0] >>> sh;
    }
    return x & ((1<<blength) - 1);
  },

  /**
   * Concatenate two bit arrays.
   * @param {bitArray} a1 The first array.
   * @param {bitArray} a2 The second array.
   * @return {bitArray} The concatenation of a1 and a2.
   */
  concat: function (a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }
    
    var last = a1[a1.length-1], shift = sjcl.bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return sjcl.bitArray._shiftRight(a2, shift, last|0, a1.slice(0,a1.length-1));
    }
  },

  /**
   * Find the length of an array of bits.
   * @param {bitArray} a The array.
   * @return {Number} The length of a, in bits.
   */
  bitLength: function (a) {
    var l = a.length, x;
    if (l === 0) { return 0; }
    x = a[l - 1];
    return (l-1) * 32 + sjcl.bitArray.getPartial(x);
  },

  /**
   * Truncate an array.
   * @param {bitArray} a The array.
   * @param {Number} len The length to truncate to, in bits.
   * @return {bitArray} A new array, truncated to len bits.
   */
  clamp: function (a, len) {
    if (a.length * 32 < len) { return a; }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l-1] = sjcl.bitArray.partial(len, a[l-1] & 0x80000000 >> (len-1), 1);
    }
    return a;
  },

  /**
   * Make a partial word for a bit array.
   * @param {Number} len The number of bits in the word.
   * @param {Number} x The bits.
   * @param {Number} [0] _end Pass 1 if x has already been shifted to the high side.
   * @return {Number} The partial word.
   */
  partial: function (len, x, _end) {
    if (len === 32) { return x; }
    return (_end ? x|0 : x << (32-len)) + len * 0x10000000000;
  },

  /**
   * Get the number of bits used by a partial word.
   * @param {Number} x The partial word.
   * @return {Number} The number of bits used by the partial word.
   */
  getPartial: function (x) {
    return Math.round(x/0x10000000000) || 32;
  },

  /**
   * Compare two arrays for equality in a predictable amount of time.
   * @param {bitArray} a The first array.
   * @param {bitArray} b The second array.
   * @return {boolean} true if a == b; false otherwise.
   */
  equal: function (a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
      return false;
    }
    var x = 0, i;
    for (i=0; i<a.length; i++) {
      x |= a[i]^b[i];
    }
    return (x === 0);
  },

  /** Shift an array right.
   * @param {bitArray} a The array to shift.
   * @param {Number} shift The number of bits to shift.
   * @param {Number} [carry=0] A byte to carry in
   * @param {bitArray} [out=[]] An array to prepend to the output.
   * @private
   */
  _shiftRight: function (a, shift, carry, out) {
    var i, last2=0, shift2;
    if (out === undefined) { out = []; }
    
    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }
    
    for (i=0; i<a.length; i++) {
      out.push(carry | a[i]>>>shift);
      carry = a[i] << (32-shift);
    }
    last2 = a.length ? a[a.length-1] : 0;
    shift2 = sjcl.bitArray.getPartial(last2);
    out.push(sjcl.bitArray.partial(shift+shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(),1));
    return out;
  },
  
  /** xor a block of 4 words together.
   * @private
   */
  _xor4: function(x,y) {
    return [x[0]^y[0],x[1]^y[1],x[2]^y[2],x[3]^y[3]];
  }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
 
/** @namespace UTF-8 strings */
sjcl.codec.utf8String = {
  /** Convert from a bitArray to a UTF-8 string. */
  fromBits: function (arr) {
    var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      out += String.fromCharCode(tmp >>> 24);
      tmp <<= 8;
    }
    return decodeURIComponent(escape(out));
  },
  
  /** Convert from a UTF-8 string to a bitArray. */
  toBits: function (str) {
    str = unescape(encodeURIComponent(str));
    var out = [], i, tmp=0;
    for (i=0; i<str.length; i++) {
      tmp = tmp << 8 | str.charCodeAt(i);
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      out.push(sjcl.bitArray.partial(8*(i&3), tmp));
    }
    return out;
  }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Hexadecimal */
sjcl.codec.hex = {
  /** Convert from a bitArray to a hex string. */
  fromBits: function (arr) {
    var out = "", i;
    for (i=0; i<arr.length; i++) {
      out += ((arr[i]|0)+0xF00000000000).toString(16).substr(4);
    }
    return out.substr(0, sjcl.bitArray.bitLength(arr)/4);//.replace(/(.{8})/g, "$1 ");
  },
  /** Convert from a hex string to a bitArray. */
  toBits: function (str) {
    var i, out=[], len;
    str = str.replace(/\s|0x/g, "");
    len = str.length;
    str = str + "00000000";
    for (i=0; i<str.length; i+=8) {
      out.push(parseInt(str.substr(i,8),16)^0);
    }
    return sjcl.bitArray.clamp(out, len*4);
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Base64 encoding/decoding */
sjcl.codec.base64 = {
  /** The base64 alphabet.
   * @private
   */
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  
  /** Convert from a bitArray to a base64 string. */
  fromBits: function (arr, _noEquals, _url) {
    var out = "", i, bits=0, c = sjcl.codec.base64._chars, ta=0, bl = sjcl.bitArray.bitLength(arr);
    if (_url) {
      c = c.substr(0,62) + '-_';
    }
    for (i=0; out.length * 6 <= bl; ) {
      out += c.charAt((ta ^ arr[i]>>>bits) >>> 26);
      if (bits < 6) {
        ta = arr[i] << (6-bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }
    while ((out.length & 3) && !_noEquals) { out += "="; }
    return out;
  },
  
  /** Convert from a base64 string to a bitArray */
  toBits: function(str, _url) {
    str = str.replace(/\s|=/g,'');
    var out = [], i, bits=0, c = sjcl.codec.base64._chars, ta=0, x;
    if (_url) {
      c = c.substr(0,62) + '-_';
    }
    for (i=0; i<str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base64!");
      }
      if (bits > 26) {
        bits -= 26;
        out.push(ta ^ x>>>bits);
        ta  = x << (32-bits);
      } else {
        bits += 6;
        ta ^= x << (32-bits);
      }
    }
    if (bits&56) {
      out.push(sjcl.bitArray.partial(bits&56, ta, 1));
    }
    return out;
  }
};

sjcl.codec.base64url = {
  fromBits: function (arr) { return sjcl.codec.base64.fromBits(arr,1,1); },
  toBits: function (str) { return sjcl.codec.base64.toBits(str,1); }
};
/** @fileOverview Javascript SHA-256 implementation.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * Special thanks to Aldo Cortesi for pointing out several bugs in
 * this code.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Context for a SHA-256 operation in progress.
 * @constructor
 * @class Secure Hash Algorithm, 256 bits.
 */
sjcl.hash.sha256 = function (hash) {
  if (!this._key[0]) { this._precompute(); }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 16 big-endian words.
 */
sjcl.hash.sha256.hash = function (data) {
  return (new sjcl.hash.sha256()).update(data).finalize();
};

sjcl.hash.sha256.prototype = {
  /**
   * The hash's block size, in bits.
   * @constant
   */
  blockSize: 512,
   
  /**
   * Reset the hash state.
   * @return this
   */
  reset:function () {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  
  /**
   * Input several words to the hash.
   * @param {bitArray|String} data the data to hash.
   * @return this
   */
  update: function (data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data),
        ol = this._length,
        nl = this._length = ol + sjcl.bitArray.bitLength(data);
    for (i = 512+ol & -512; i <= nl; i+= 512) {
      this._block(b.splice(0,16));
    }
    return this;
  },
  
  /**
   * Complete hashing and output the hash value.
   * @return {bitArray} The hash value, an array of 8 big-endian words.
   */
  finalize:function () {
    var i, b = this._buffer, h = this._h;

    // Round out and push the buffer
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1,1)]);
    
    // Round out the buffer to a multiple of 16 words, less the 2 length words.
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }
    
    // append the length
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);

    while (b.length) {
      this._block(b.splice(0,16));
    }

    this.reset();
    return h;
  },

  /**
   * The SHA-256 initialization vector, to be precomputed.
   * @private
   */
  _init:[],
  /*
  _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
  */
  
  /**
   * The SHA-256 hash key, to be precomputed.
   * @private
   */
  _key:[],
  /*
  _key:
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
  */


  /**
   * Function to precompute _init and _key.
   * @private
   */
  _precompute: function () {
    var i = 0, prime = 2, factor;

    function frac(x) { return (x-Math.floor(x)) * 0x100000000 | 0; }

    outer: for (; i<64; prime++) {
      for (factor=2; factor*factor <= prime; factor++) {
        if (prime % factor === 0) {
          // not a prime
          continue outer;
        }
      }
      
      if (i<8) {
        this._init[i] = frac(Math.pow(prime, 1/2));
      }
      this._key[i] = frac(Math.pow(prime, 1/3));
      i++;
    }
  },
  
  /**
   * Perform one cycle of SHA-256.
   * @param {bitArray} words one block of words.
   * @private
   */
  _block:function (words) {  
    var i, tmp, a, b,
      w = words.slice(0),
      h = this._h,
      k = this._key,
      h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3],
      h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];

    /* Rationale for placement of |0 :
     * If a value can overflow is original 32 bits by a factor of more than a few
     * million (2^23 ish), there is a possibility that it might overflow the
     * 53-bit mantissa and lose precision.
     *
     * To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
     * propagates around the loop, and on the hash state h[].  I don't believe
     * that the clamps on h4 and on h0 are strictly necessary, but it's close
     * (for h4 anyway), and better safe than sorry.
     *
     * The clamps on h[] are necessary for the output to be correct even in the
     * common case and for short inputs.
     */
    for (i=0; i<64; i++) {
      // load up the input word for this round
      if (i<16) {
        tmp = w[i];
      } else {
        a   = w[(i+1 ) & 15];
        b   = w[(i+14) & 15];
        tmp = w[i&15] = ((a>>>7  ^ a>>>18 ^ a>>>3  ^ a<<25 ^ a<<14) + 
                         (b>>>17 ^ b>>>19 ^ b>>>10 ^ b<<15 ^ b<<13) +
                         w[i&15] + w[(i+9) & 15]) | 0;
      }
      
      tmp = (tmp + h7 + (h4>>>6 ^ h4>>>11 ^ h4>>>25 ^ h4<<26 ^ h4<<21 ^ h4<<7) +  (h6 ^ h4&(h5^h6)) + k[i]); // | 0;
      
      // shift register
      h7 = h6; h6 = h5; h5 = h4;
      h4 = h3 + tmp | 0;
      h3 = h2; h2 = h1; h1 = h0;

      h0 = (tmp +  ((h1&h2) ^ (h3&(h1^h2))) + (h1>>>2 ^ h1>>>13 ^ h1>>>22 ^ h1<<30 ^ h1<<19 ^ h1<<10)) | 0;
    }

    h[0] = h[0]+h0 | 0;
    h[1] = h[1]+h1 | 0;
    h[2] = h[2]+h2 | 0;
    h[3] = h[3]+h3 | 0;
    h[4] = h[4]+h4 | 0;
    h[5] = h[5]+h5 | 0;
    h[6] = h[6]+h6 | 0;
    h[7] = h[7]+h7 | 0;
  }
};


/** @fileOverview CCM mode implementation.
 *
 * Special thanks to Roy Nicholson for pointing out a bug in our
 * implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace CTR mode with CBC MAC. */
sjcl.mode.ccm = {
  /** The name of the mode.
   * @constant
   */
  name: "ccm",
  
  /** Encrypt in CCM mode.
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=64] the desired tag length, in bits.
   * @return {bitArray} The encrypted data, an array of bytes.
   */
  encrypt: function(prf, plaintext, iv, adata, tlen) {
    var L, out = plaintext.slice(0), tag, w=sjcl.bitArray, ivl = w.bitLength(iv) / 8, ol = w.bitLength(out) / 8;
    tlen = tlen || 64;
    adata = adata || [];
    
    if (ivl < 7) {
      throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
    }
    
    // compute the length of the length
    for (L=2; L<4 && ol >>> 8*L; L++) {}
    if (L < 15 - ivl) { L = 15-ivl; }
    iv = w.clamp(iv,8*(15-L));
    
    // compute the tag
    tag = sjcl.mode.ccm._computeTag(prf, plaintext, iv, adata, tlen, L);
    
    // encrypt
    out = sjcl.mode.ccm._ctrMode(prf, out, iv, tag, tlen, L);
    
    return w.concat(out.data, out.tag);
  },
  
  /** Decrypt in CCM mode.
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [[]] adata The authenticated data.
   * @param {Number} [64] tlen the desired tag length, in bits.
   * @return {bitArray} The decrypted data.
   */
  decrypt: function(prf, ciphertext, iv, adata, tlen) {
    tlen = tlen || 64;
    adata = adata || [];
    var L,
        w=sjcl.bitArray,
        ivl = w.bitLength(iv) / 8,
        ol = w.bitLength(ciphertext), 
        out = w.clamp(ciphertext, ol - tlen),
        tag = w.bitSlice(ciphertext, ol - tlen), tag2;
    

    ol = (ol - tlen) / 8;
        
    if (ivl < 7) {
      throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
    }
    
    // compute the length of the length
    for (L=2; L<4 && ol >>> 8*L; L++) {}
    if (L < 15 - ivl) { L = 15-ivl; }
    iv = w.clamp(iv,8*(15-L));
    
    // decrypt
    out = sjcl.mode.ccm._ctrMode(prf, out, iv, tag, tlen, L);
    
    // check the tag
    tag2 = sjcl.mode.ccm._computeTag(prf, out.data, iv, adata, tlen, L);
    if (!w.equal(out.tag, tag2)) {
      throw new sjcl.exception.corrupt("ccm: tag doesn't match");
    }
    
    return out.data;
  },

  /* Compute the (unencrypted) authentication tag, according to the CCM specification
   * @param {Object} prf The pseudorandom function.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} adata The authenticated data.
   * @param {Number} tlen the desired tag length, in bits.
   * @return {bitArray} The tag, but not yet encrypted.
   * @private
   */
  _computeTag: function(prf, plaintext, iv, adata, tlen, L) {
    // compute B[0]
    var mac, tmp, i, macData = [], w=sjcl.bitArray, xor = w._xor4;

    tlen /= 8;
  
    // check tag length and message length
    if (tlen % 2 || tlen < 4 || tlen > 16) {
      throw new sjcl.exception.invalid("ccm: invalid tag length");
    }
  
    if (adata.length > 0xFFFFFFFF || plaintext.length > 0xFFFFFFFF) {
      // I don't want to deal with extracting high words from doubles.
      throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data");
    }

    // mac the flags
    mac = [w.partial(8, (adata.length ? 1<<6 : 0) | (tlen-2) << 2 | L-1)];

    // mac the iv and length
    mac = w.concat(mac, iv);
    mac[3] |= w.bitLength(plaintext)/8;
    mac = prf.encrypt(mac);
    
  
    if (adata.length) {
      // mac the associated data.  start with its length...
      tmp = w.bitLength(adata)/8;
      if (tmp <= 0xFEFF) {
        macData = [w.partial(16, tmp)];
      } else if (tmp <= 0xFFFFFFFF) {
        macData = w.concat([w.partial(16,0xFFFE)], [tmp]);
      } // else ...
    
      // mac the data itself
      macData = w.concat(macData, adata);
      for (i=0; i<macData.length; i += 4) {
        mac = prf.encrypt(xor(mac, macData.slice(i,i+4).concat([0,0,0])));
      }
    }
  
    // mac the plaintext
    for (i=0; i<plaintext.length; i+=4) {
      mac = prf.encrypt(xor(mac, plaintext.slice(i,i+4).concat([0,0,0])));
    }

    return w.clamp(mac, tlen * 8);
  },

  /** CCM CTR mode.
   * Encrypt or decrypt data and tag with the prf in CCM-style CTR mode.
   * May mutate its arguments.
   * @param {Object} prf The PRF.
   * @param {bitArray} data The data to be encrypted or decrypted.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} tag The authentication tag.
   * @param {Number} tlen The length of th etag, in bits.
   * @param {Number} L The CCM L value.
   * @return {Object} An object with data and tag, the en/decryption of data and tag values.
   * @private
   */
  _ctrMode: function(prf, data, iv, tag, tlen, L) {
    var enc, i, w=sjcl.bitArray, xor = w._xor4, ctr, l = data.length, bl=w.bitLength(data);

    // start the ctr
    ctr = w.concat([w.partial(8,L-1)],iv).concat([0,0,0]).slice(0,4);
    
    // en/decrypt the tag
    tag = w.bitSlice(xor(tag,prf.encrypt(ctr)), 0, tlen);
  
    // en/decrypt the data
    if (!l) { return {tag:tag, data:[]}; }
    
    for (i=0; i<l; i+=4) {
      ctr[3]++;
      enc = prf.encrypt(ctr);
      data[i]   ^= enc[0];
      data[i+1] ^= enc[1];
      data[i+2] ^= enc[2];
      data[i+3] ^= enc[3];
    }
    return { tag:tag, data:w.clamp(data,bl) };
  }
};
/** @fileOverview OCB 2.0 implementation
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace
 * Phil Rogaway's Offset CodeBook mode, version 2.0.
 * May be covered by US and international patents.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
sjcl.mode.ocb2 = {
  /** The name of the mode.
   * @constant
   */
  name: "ocb2",
  
  /** Encrypt in OCB mode, version 2.0.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=64] the desired tag length, in bits.
   * @param [false] premac 1 if the authentication data is pre-macced with PMAC.
   * @return The encrypted data, an array of bytes.
   * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits.
   */
  encrypt: function(prp, plaintext, iv, adata, tlen, premac) {
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("ocb iv must be 128 bits");
    }
    var i,
        times2 = sjcl.mode.ocb2._times2,
        w = sjcl.bitArray,
        xor = w._xor4,
        checksum = [0,0,0,0],
        delta = times2(prp.encrypt(iv)),
        bi, bl,
        output = [],
        pad;
        
    adata = adata || [];
    tlen  = tlen || 64;
  
    for (i=0; i+4 < plaintext.length; i+=4) {
      /* Encrypt a non-final block */
      bi = plaintext.slice(i,i+4);
      checksum = xor(checksum, bi);
      output = output.concat(xor(delta,prp.encrypt(xor(delta, bi))));
      delta = times2(delta);
    }
    
    /* Chop out the final block */
    bi = plaintext.slice(i);
    bl = w.bitLength(bi);
    pad = prp.encrypt(xor(delta,[0,0,0,bl]));
    bi = w.clamp(xor(bi.concat([0,0,0]),pad), bl);
    
    /* Checksum the final block, and finalize the checksum */
    checksum = xor(checksum,xor(bi.concat([0,0,0]),pad));
    checksum = prp.encrypt(xor(checksum,xor(delta,times2(delta))));
    
    /* MAC the header */
    if (adata.length) {
      checksum = xor(checksum, premac ? adata : sjcl.mode.ocb2.pmac(prp, adata));
    }
    
    return output.concat(w.concat(bi, w.clamp(checksum, tlen)));
  },
  
  /** Decrypt in OCB mode.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=64] the desired tag length, in bits.
   * @param {boolean} [premac=false] true if the authentication data is pre-macced with PMAC.
   * @return The decrypted data, an array of bytes.
   * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits.
   * @throws {sjcl.exception.corrupt} if if the message is corrupt.
   */
  decrypt: function(prp, ciphertext, iv, adata, tlen, premac) {
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("ocb iv must be 128 bits");
    }
    tlen  = tlen || 64;
    var i,
        times2 = sjcl.mode.ocb2._times2,
        w = sjcl.bitArray,
        xor = w._xor4,
        checksum = [0,0,0,0],
        delta = times2(prp.encrypt(iv)),
        bi, bl,
        len = sjcl.bitArray.bitLength(ciphertext) - tlen,
        output = [],
        pad;
        
    adata = adata || [];
  
    for (i=0; i+4 < len/32; i+=4) {
      /* Decrypt a non-final block */
      bi = xor(delta, prp.decrypt(xor(delta, ciphertext.slice(i,i+4))));
      checksum = xor(checksum, bi);
      output = output.concat(bi);
      delta = times2(delta);
    }
    
    /* Chop out and decrypt the final block */
    bl = len-i*32;
    pad = prp.encrypt(xor(delta,[0,0,0,bl]));
    bi = xor(pad, w.clamp(ciphertext.slice(i),bl).concat([0,0,0]));
    
    /* Checksum the final block, and finalize the checksum */
    checksum = xor(checksum, bi);
    checksum = prp.encrypt(xor(checksum, xor(delta, times2(delta))));
    
    /* MAC the header */
    if (adata.length) {
      checksum = xor(checksum, premac ? adata : sjcl.mode.ocb2.pmac(prp, adata));
    }
    
    if (!w.equal(w.clamp(checksum, tlen), w.bitSlice(ciphertext, len))) {
      throw new sjcl.exception.corrupt("ocb: tag doesn't match");
    }
    
    return output.concat(w.clamp(bi,bl));
  },
  
  /** PMAC authentication for OCB associated data.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} adata The authenticated data.
   */
  pmac: function(prp, adata) {
    var i,
        times2 = sjcl.mode.ocb2._times2,
        w = sjcl.bitArray,
        xor = w._xor4,
        checksum = [0,0,0,0],
        delta = prp.encrypt([0,0,0,0]),
        bi;
        
    delta = xor(delta,times2(times2(delta)));
 
    for (i=0; i+4<adata.length; i+=4) {
      delta = times2(delta);
      checksum = xor(checksum, prp.encrypt(xor(delta, adata.slice(i,i+4))));
    }
    
    bi = adata.slice(i);
    if (w.bitLength(bi) < 128) {
      delta = xor(delta,times2(delta));
      bi = w.concat(bi,[0x80000000|0,0,0,0]);
    }
    checksum = xor(checksum, bi);
    return prp.encrypt(xor(times2(xor(delta,times2(delta))), checksum));
  },
  
  /** Double a block of words, OCB style.
   * @private
   */
  _times2: function(x) {
    return [x[0]<<1 ^ x[1]>>>31,
            x[1]<<1 ^ x[2]>>>31,
            x[2]<<1 ^ x[3]>>>31,
            x[3]<<1 ^ (x[0]>>>31)*0x87];
  }
};
/** @fileOverview GCM mode implementation.
 *
 * @author Juho Vähä-Herttua
 */

/** @namespace Galois/Counter mode. */
sjcl.mode.gcm = {
  /** The name of the mode.
   * @constant
   */
  name: "gcm",
  
  /** Encrypt in GCM mode.
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @return {bitArray} The encrypted data, an array of bytes.
   */
  encrypt: function (prf, plaintext, iv, adata, tlen) {
    var out, data = plaintext.slice(0), w=sjcl.bitArray;
    tlen = tlen || 128;
    adata = adata || [];

    // encrypt and tag
    out = sjcl.mode.gcm._ctrMode(true, prf, data, adata, iv, tlen);

    return w.concat(out.data, out.tag);
  },
  
  /** Decrypt in GCM mode.
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @return {bitArray} The decrypted data.
   */
  decrypt: function (prf, ciphertext, iv, adata, tlen) {
    var out, data = ciphertext.slice(0), tag, w=sjcl.bitArray, l=w.bitLength(data);
    tlen = tlen || 128;
    adata = adata || [];

    // Slice tag out of data
    if (tlen <= l) {
      tag = w.bitSlice(data, l-tlen);
      data = w.bitSlice(data, 0, l-tlen);
    } else {
      tag = data;
      data = [];
    }

    // decrypt and tag
    out = sjcl.mode.gcm._ctrMode(false, prf, data, adata, iv, tlen);

    if (!w.equal(out.tag, tag)) {
      throw new sjcl.exception.corrupt("gcm: tag doesn't match");
    }
    return out.data;
  },

  /* Compute the galois multiplication of X and Y
   * @private
   */
  _galoisMultiply: function (x, y) {
    var i, j, xi, Zi, Vi, lsb_Vi, w=sjcl.bitArray, xor=w._xor4;

    Zi = [0,0,0,0];
    Vi = y.slice(0);

    // Block size is 128 bits, run 128 times to get Z_128
    for (i=0; i<128; i++) {
      xi = (x[Math.floor(i/32)] & (1 << (31-i%32))) !== 0;
      if (xi) {
        // Z_i+1 = Z_i ^ V_i
        Zi = xor(Zi, Vi);
      }

      // Store the value of LSB(V_i)
      lsb_Vi = (Vi[3] & 1) !== 0;

      // V_i+1 = V_i >> 1
      for (j=3; j>0; j--) {
        Vi[j] = (Vi[j] >>> 1) | ((Vi[j-1]&1) << 31);
      }
      Vi[0] = Vi[0] >>> 1;

      // If LSB(V_i) is 1, V_i+1 = (V_i >> 1) ^ R
      if (lsb_Vi) {
        Vi[0] = Vi[0] ^ (0xe1 << 24);
      }
    }
    return Zi;
  },

  _ghash: function(H, Y0, data) {
    var Yi, i, l = data.length;

    Yi = Y0.slice(0);
    for (i=0; i<l; i+=4) {
      Yi[0] ^= 0xffffffff&data[i];
      Yi[1] ^= 0xffffffff&data[i+1];
      Yi[2] ^= 0xffffffff&data[i+2];
      Yi[3] ^= 0xffffffff&data[i+3];
      Yi = sjcl.mode.gcm._galoisMultiply(Yi, H);
    }
    return Yi;
  },

  /** GCM CTR mode.
   * Encrypt or decrypt data and tag with the prf in GCM-style CTR mode.
   * @param {Boolean} encrypt True if encrypt, false if decrypt.
   * @param {Object} prf The PRF.
   * @param {bitArray} data The data to be encrypted or decrypted.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata The associated data to be tagged.
   * @param {Number} tlen The length of the tag, in bits.
   */
  _ctrMode: function(encrypt, prf, data, adata, iv, tlen) {
    var H, J0, S0, enc, i, ctr, tag, last, l, bl, abl, ivbl, w=sjcl.bitArray;

    // Calculate data lengths
    l = data.length;
    bl = w.bitLength(data);
    abl = w.bitLength(adata);
    ivbl = w.bitLength(iv);

    // Calculate the parameters
    H = prf.encrypt([0,0,0,0]);
    if (ivbl === 96) {
      J0 = iv.slice(0);
      J0 = w.concat(J0, [1]);
    } else {
      J0 = sjcl.mode.gcm._ghash(H, [0,0,0,0], iv);
      J0 = sjcl.mode.gcm._ghash(H, J0, [0,0,Math.floor(ivbl/0x100000000),ivbl&0xffffffff]);
    }
    S0 = sjcl.mode.gcm._ghash(H, [0,0,0,0], adata);

    // Initialize ctr and tag
    ctr = J0.slice(0);
    tag = S0.slice(0);

    // If decrypting, calculate hash
    if (!encrypt) {
      tag = sjcl.mode.gcm._ghash(H, S0, data);
    }

    // Encrypt all the data
    for (i=0; i<l; i+=4) {
       ctr[3]++;
       enc = prf.encrypt(ctr);
       data[i]   ^= enc[0];
       data[i+1] ^= enc[1];
       data[i+2] ^= enc[2];
       data[i+3] ^= enc[3];
    }
    data = w.clamp(data, bl);

    // If encrypting, calculate hash
    if (encrypt) {
      tag = sjcl.mode.gcm._ghash(H, S0, data);
    }

    // Calculate last block from bit lengths, ugly because bitwise operations are 32-bit
    last = [
      Math.floor(abl/0x100000000), abl&0xffffffff,
      Math.floor(bl/0x100000000), bl&0xffffffff
    ];

    // Calculate the final tag block
    tag = sjcl.mode.gcm._ghash(H, tag, last);
    enc = prf.encrypt(J0);
    tag[0] ^= enc[0];
    tag[1] ^= enc[1];
    tag[2] ^= enc[2];
    tag[3] ^= enc[3];

    return { tag:w.bitSlice(tag, 0, tlen), data:data };
  }
};
/** @fileOverview HMAC implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** HMAC with the specified hash function.
 * @constructor
 * @param {bitArray} key the key for HMAC.
 * @param {Object} [hash=sjcl.hash.sha256] The hash function to use.
 */
sjcl.misc.hmac = function (key, Hash) {
  this._hash = Hash = Hash || sjcl.hash.sha256;
  var exKey = [[],[]], i,
      bs = Hash.prototype.blockSize / 32;
  this._baseHash = [new Hash(), new Hash()];

  if (key.length > bs) {
    key = Hash.hash(key);
  }
  
  for (i=0; i<bs; i++) {
    exKey[0][i] = key[i]^0x36363636;
    exKey[1][i] = key[i]^0x5C5C5C5C;
  }
  
  this._baseHash[0].update(exKey[0]);
  this._baseHash[1].update(exKey[1]);
  this._resultHash = new Hash(this._baseHash[0]);
};

/** HMAC with the specified hash function.  Also called encrypt since it's a prf.
 * @param {bitArray|String} data The data to mac.
 */
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (data) {
  if (!this._updated) {
    this.update(data);
    return this.digest(data);
  } else {
    throw new sjcl.exception.invalid("encrypt on already updated hmac called!");
  }
};

sjcl.misc.hmac.prototype.reset = function () {
  this._resultHash = new this._hash(this._baseHash[0]);
  this._updated = false;
};

sjcl.misc.hmac.prototype.update = function (data) {
  this._updated = true;
  this._resultHash.update(data);
};

sjcl.misc.hmac.prototype.digest = function () {
  var w = this._resultHash.finalize(), result = new (this._hash)(this._baseHash[1]).update(w).finalize();

  this.reset();

  return result;
};/** @fileOverview Password-based key-derivation function, version 2.0.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** Password-Based Key-Derivation Function, version 2.0.
 *
 * Generate keys from passwords using PBKDF2-HMAC-SHA256.
 *
 * This is the method specified by RSA's PKCS #5 standard.
 *
 * @param {bitArray|String} password  The password.
 * @param {bitArray|String} salt The salt.  Should have lots of entropy.
 * @param {Number} [count=1000] The number of iterations.  Higher numbers make the function slower but more secure.
 * @param {Number} [length] The length of the derived key.  Defaults to the
                            output size of the hash function.
 * @param {Object} [Prff=sjcl.misc.hmac] The pseudorandom function family.
 * @return {bitArray} the derived key.
 */
sjcl.misc.pbkdf2 = function (password, salt, count, length, Prff) {
  count = count || 1000;
  
  if (length < 0 || count < 0) {
    throw sjcl.exception.invalid("invalid params to pbkdf2");
  }
  
  if (typeof password === "string") {
    password = sjcl.codec.utf8String.toBits(password);
  }
  
  if (typeof salt === "string") {
    salt = sjcl.codec.utf8String.toBits(salt);
  }
  
  Prff = Prff || sjcl.misc.hmac;
  
  var prf = new Prff(password),
      u, ui, i, j, k, out = [], b = sjcl.bitArray;

  for (k = 1; 32 * out.length < (length || 1); k++) {
    u = ui = prf.encrypt(b.concat(salt,[k]));
    
    for (i=1; i<count; i++) {
      ui = prf.encrypt(ui);
      for (j=0; j<ui.length; j++) {
        u[j] ^= ui[j];
      }
    }
    
    out = out.concat(u);
  }

  if (length) { out = b.clamp(out, length); }

  return out;
};
/** @fileOverview Random number generator.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Michael Brooks
 */

/** @constructor
 * @class Random number generator
 * @description
 * <b>Use sjcl.random as a singleton for this class!</b>
 * <p>
 * This random number generator is a derivative of Ferguson and Schneier's
 * generator Fortuna.  It collects entropy from various events into several
 * pools, implemented by streaming SHA-256 instances.  It differs from
 * ordinary Fortuna in a few ways, though.
 * </p>
 *
 * <p>
 * Most importantly, it has an entropy estimator.  This is present because
 * there is a strong conflict here between making the generator available
 * as soon as possible, and making sure that it doesn't "run on empty".
 * In Fortuna, there is a saved state file, and the system is likely to have
 * time to warm up.
 * </p>
 *
 * <p>
 * Second, because users are unlikely to stay on the page for very long,
 * and to speed startup time, the number of pools increases logarithmically:
 * a new pool is created when the previous one is actually used for a reseed.
 * This gives the same asymptotic guarantees as Fortuna, but gives more
 * entropy to early reseeds.
 * </p>
 *
 * <p>
 * The entire mechanism here feels pretty klunky.  Furthermore, there are
 * several improvements that should be made, including support for
 * dedicated cryptographic functions that may be present in some browsers;
 * state files in local storage; cookies containing randomness; etc.  So
 * look for improvements in future versions.
 * </p>
 */
sjcl.prng = function(defaultParanoia) {
  
  /* private */
  this._pools                   = [new sjcl.hash.sha256()];
  this._poolEntropy             = [0];
  this._reseedCount             = 0;
  this._robins                  = {};
  this._eventId                 = 0;
  
  this._collectorIds            = {};
  this._collectorIdNext         = 0;
  
  this._strength                = 0;
  this._poolStrength            = 0;
  this._nextReseed              = 0;
  this._key                     = [0,0,0,0,0,0,0,0];
  this._counter                 = [0,0,0,0];
  this._cipher                  = undefined;
  this._defaultParanoia         = defaultParanoia;
  
  /* event listener stuff */
  this._collectorsStarted       = false;
  this._callbacks               = {progress: {}, seeded: {}};
  this._callbackI               = 0;
  
  /* constants */
  this._NOT_READY               = 0;
  this._READY                   = 1;
  this._REQUIRES_RESEED         = 2;

  this._MAX_WORDS_PER_BURST     = 65536;
  this._PARANOIA_LEVELS         = [0,48,64,96,128,192,256,384,512,768,1024];
  this._MILLISECONDS_PER_RESEED = 30000;
  this._BITS_PER_RESEED         = 80;
};
 
sjcl.prng.prototype = {
  /** Generate several random words, and return them in an array.
   * A word consists of 32 bits (4 bytes)
   * @param {Number} nwords The number of words to generate.
   */
  randomWords: function (nwords, paranoia) {
    var out = [], i, readiness = this.isReady(paranoia), g;
  
    if (readiness === this._NOT_READY) {
      throw new sjcl.exception.notReady("generator isn't seeded");
    } else if (readiness & this._REQUIRES_RESEED) {
      this._reseedFromPools(!(readiness & this._READY));
    }
  
    for (i=0; i<nwords; i+= 4) {
      if ((i+1) % this._MAX_WORDS_PER_BURST === 0) {
        this._gate();
      }
   
      g = this._gen4words();
      out.push(g[0],g[1],g[2],g[3]);
    }
    this._gate();
  
    return out.slice(0,nwords);
  },
  
  setDefaultParanoia: function (paranoia, allowZeroParanoia) {
    if (paranoia === 0 && allowZeroParanoia !== "Setting paranoia=0 will ruin your security; use it only for testing") {
      throw "Setting paranoia=0 will ruin your security; use it only for testing";
    }

    this._defaultParanoia = paranoia;
  },
  
  /**
   * Add entropy to the pools.
   * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
   * @param {Number} estimatedEntropy The estimated entropy of data, in bits
   * @param {String} source The source of the entropy, eg "mouse"
   */
  addEntropy: function (data, estimatedEntropy, source) {
    source = source || "user";
  
    var id,
      i, tmp,
      t = (new Date()).valueOf(),
      robin = this._robins[source],
      oldReady = this.isReady(), err = 0, objName;
      
    id = this._collectorIds[source];
    if (id === undefined) { id = this._collectorIds[source] = this._collectorIdNext ++; }
      
    if (robin === undefined) { robin = this._robins[source] = 0; }
    this._robins[source] = ( this._robins[source] + 1 ) % this._pools.length;
  
    switch(typeof(data)) {
      
    case "number":
      if (estimatedEntropy === undefined) {
        estimatedEntropy = 1;
      }
      this._pools[robin].update([id,this._eventId++,1,estimatedEntropy,t,1,data|0]);
      break;
      
    case "object":
      objName = Object.prototype.toString.call(data);
      if (objName === "[object Uint32Array]") {
        tmp = [];
        for (i = 0; i < data.length; i++) {
          tmp.push(data[i]);
        }
        data = tmp;
      } else {
        if (objName !== "[object Array]") {
          err = 1;
        }
        for (i=0; i<data.length && !err; i++) {
          if (typeof(data[i]) !== "number") {
            err = 1;
          }
        }
      }
      if (!err) {
        if (estimatedEntropy === undefined) {
          /* horrible entropy estimator */
          estimatedEntropy = 0;
          for (i=0; i<data.length; i++) {
            tmp= data[i];
            while (tmp>0) {
              estimatedEntropy++;
              tmp = tmp >>> 1;
            }
          }
        }
        this._pools[robin].update([id,this._eventId++,2,estimatedEntropy,t,data.length].concat(data));
      }
      break;
      
    case "string":
      if (estimatedEntropy === undefined) {
       /* English text has just over 1 bit per character of entropy.
        * But this might be HTML or something, and have far less
        * entropy than English...  Oh well, let's just say one bit.
        */
       estimatedEntropy = data.length;
      }
      this._pools[robin].update([id,this._eventId++,3,estimatedEntropy,t,data.length]);
      this._pools[robin].update(data);
      break;
      
    default:
      err=1;
    }
    if (err) {
      throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
    }
  
    /* record the new strength */
    this._poolEntropy[robin] += estimatedEntropy;
    this._poolStrength += estimatedEntropy;
  
    /* fire off events */
    if (oldReady === this._NOT_READY) {
      if (this.isReady() !== this._NOT_READY) {
        this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
      }
      this._fireEvent("progress", this.getProgress());
    }
  },
  
  /** Is the generator ready? */
  isReady: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ (paranoia !== undefined) ? paranoia : this._defaultParanoia ];
  
    if (this._strength && this._strength >= entropyRequired) {
      return (this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date()).valueOf() > this._nextReseed) ?
        this._REQUIRES_RESEED | this._READY :
        this._READY;
    } else {
      return (this._poolStrength >= entropyRequired) ?
        this._REQUIRES_RESEED | this._NOT_READY :
        this._NOT_READY;
    }
  },
  
  /** Get the generator's progress toward readiness, as a fraction */
  getProgress: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ paranoia ? paranoia : this._defaultParanoia ];
  
    if (this._strength >= entropyRequired) {
      return 1.0;
    } else {
      return (this._poolStrength > entropyRequired) ?
        1.0 :
        this._poolStrength / entropyRequired;
    }
  },
  
  /** start the built-in entropy collectors */
  startCollectors: function () {
    if (this._collectorsStarted) { return; }
  
    this._eventListener = {
      loadTimeCollector: this._bind(this._loadTimeCollector),
      mouseCollector: this._bind(this._mouseCollector),
      keyboardCollector: this._bind(this._keyboardCollector),
      accelerometerCollector: this._bind(this._accelerometerCollector)
    }

    if (window.addEventListener) {
      window.addEventListener("load", this._eventListener.loadTimeCollector, false);
      window.addEventListener("mousemove", this._eventListener.mouseCollector, false);
      window.addEventListener("keypress", this._eventListener.keyboardCollector, false);
      window.addEventListener("devicemotion", this._eventListener.accelerometerCollector, false);
    } else if (document.attachEvent) {
      document.attachEvent("onload", this._eventListener.loadTimeCollector);
      document.attachEvent("onmousemove", this._eventListener.mouseCollector);
      document.attachEvent("keypress", this._eventListener.keyboardCollector);
    } else {
      throw new sjcl.exception.bug("can't attach event");
    }
  
    this._collectorsStarted = true;
  },
  
  /** stop the built-in entropy collectors */
  stopCollectors: function () {
    if (!this._collectorsStarted) { return; }
  
    if (window.removeEventListener) {
      window.removeEventListener("load", this._eventListener.loadTimeCollector, false);
      window.removeEventListener("mousemove", this._eventListener.mouseCollector, false);
      window.removeEventListener("keypress", this._eventListener.keyboardCollector, false);
      window.removeEventListener("devicemotion", this._eventListener.accelerometerCollector, false);
    } else if (document.detachEvent) {
      document.detachEvent("onload", this._eventListener.loadTimeCollector);
      document.detachEvent("onmousemove", this._eventListener.mouseCollector);
      document.detachEvent("keypress", this._eventListener.keyboardCollector);
    }

    this._collectorsStarted = false;
  },
  
  /* use a cookie to store entropy.
  useCookie: function (all_cookies) {
      throw new sjcl.exception.bug("random: useCookie is unimplemented");
  },*/
  
  /** add an event listener for progress or seeded-ness. */
  addEventListener: function (name, callback) {
    this._callbacks[name][this._callbackI++] = callback;
  },
  
  /** remove an event listener for progress or seeded-ness */
  removeEventListener: function (name, cb) {
    var i, j, cbs=this._callbacks[name], jsTemp=[];

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */

    for (j in cbs) {
      if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
        jsTemp.push(j);
      }
    }

    for (i=0; i<jsTemp.length; i++) {
      j = jsTemp[i];
      delete cbs[j];
    }
  },
  
  _bind: function (func) {
    var that = this;
    return function () {
      func.apply(that, arguments);
    };
  },

  /** Generate 4 random words, no reseed, no gate.
   * @private
   */
  _gen4words: function () {
    for (var i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
    return this._cipher.encrypt(this._counter);
  },
  
  /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
   * @private
   */
  _gate: function () {
    this._key = this._gen4words().concat(this._gen4words());
    this._cipher = new sjcl.cipher.aes(this._key);
  },
  
  /** Reseed the generator with the given words
   * @private
   */
  _reseed: function (seedWords) {
    this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
    this._cipher = new sjcl.cipher.aes(this._key);
    for (var i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
  },
  
  /** reseed the data from the entropy pools
   * @param full If set, use all the entropy pools in the reseed.
   */
  _reseedFromPools: function (full) {
    var reseedData = [], strength = 0, i;
  
    this._nextReseed = reseedData[0] =
      (new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;
    
    for (i=0; i<16; i++) {
      /* On some browsers, this is cryptographically random.  So we might
       * as well toss it in the pot and stir...
       */
      reseedData.push(Math.random()*0x100000000|0);
    }
    
    for (i=0; i<this._pools.length; i++) {
     reseedData = reseedData.concat(this._pools[i].finalize());
     strength += this._poolEntropy[i];
     this._poolEntropy[i] = 0;
   
     if (!full && (this._reseedCount & (1<<i))) { break; }
    }
  
    /* if we used the last pool, push a new one onto the stack */
    if (this._reseedCount >= 1 << this._pools.length) {
     this._pools.push(new sjcl.hash.sha256());
     this._poolEntropy.push(0);
    }
  
    /* how strong was this reseed? */
    this._poolStrength -= strength;
    if (strength > this._strength) {
      this._strength = strength;
    }
  
    this._reseedCount ++;
    this._reseed(reseedData);
  },
  
  _keyboardCollector: function () {
    this._addCurrentTimeToEntropy(1);
  },
  
  _mouseCollector: function (ev) {
    var x = ev.x || ev.clientX || ev.offsetX || 0, y = ev.y || ev.clientY || ev.offsetY || 0;
    sjcl.random.addEntropy([x,y], 2, "mouse");
    this._addCurrentTimeToEntropy(0);
  },
  
  _loadTimeCollector: function () {
    this._addCurrentTimeToEntropy(2);
  },

  _addCurrentTimeToEntropy: function (estimatedEntropy) {
    if (window && window.performance && typeof window.performance.now === "function") {
      //how much entropy do we want to add here?
      sjcl.random.addEntropy(window.performance.now(), estimatedEntropy, "loadtime");
    } else {
      sjcl.random.addEntropy((new Date()).valueOf(), estimatedEntropy, "loadtime");
    }
  },
  _accelerometerCollector: function (ev) {
    var ac = ev.accelerationIncludingGravity.x||ev.accelerationIncludingGravity.y||ev.accelerationIncludingGravity.z;
    if(window.orientation){
      var or = window.orientation;
      if (typeof or === "number") {
        sjcl.random.addEntropy(or, 1, "accelerometer");
      }
    }
    if (ac) {
      sjcl.random.addEntropy(ac, 2, "accelerometer");
    }
    this._addCurrentTimeToEntropy(0);
  },

  _fireEvent: function (name, arg) {
    var j, cbs=sjcl.random._callbacks[name], cbsTemp=[];
    /* TODO: there is a race condition between removing collectors and firing them */

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */

    for (j in cbs) {
      if (cbs.hasOwnProperty(j)) {
        cbsTemp.push(cbs[j]);
      }
    }

    for (j=0; j<cbsTemp.length; j++) {
      cbsTemp[j](arg);
    }
  }
};

/** an instance for the prng.
* @see sjcl.prng
*/
sjcl.random = new sjcl.prng(6);

(function(){
  // function for getting nodejs crypto module. catches and ignores errors.
  function getCryptoModule() {
    try {
      return require('__SYSTEM__/crypto');
    }
    catch (e) {
      return null;
    }
  }

  try {
    var buf, crypt, ab;

    // get cryptographically strong entropy depending on runtime environment
    if (typeof module !== 'undefined' && module.exports && (crypt = getCryptoModule()) && crypt.randomBytes) {
      buf = crypt.randomBytes(1024/8);
      buf = new Uint32Array(new Uint8Array(buf).buffer);
      sjcl.random.addEntropy(buf, 1024, "crypto.randomBytes");

    } else if (window && Uint32Array) {
      ab = new Uint32Array(32);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(ab);
      } else if (window.msCrypto && window.msCrypto.getRandomValues) {
        window.msCrypto.getRandomValues(ab);
      } else {
        return;
      }

      // get cryptographically strong entropy in Webkit
      sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");

    } else {
      // no getRandomValues :-(
    }
  } catch (e) {
    if (typeof window !== 'undefined' && window.console) {
      console.log("There was an error collecting entropy from the browser:");
      console.log(e);
      //we do not want the library to fail due to randomness not being maintained.
    }
  }
}());
/** @fileOverview Convenince functions centered around JSON encapsulation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
 
 /** @namespace JSON encapsulation */
 sjcl.json = {
  /** Default values for encryption */
  defaults: { v:1, iter:1000, ks:128, ts:64, mode:"ccm", adata:"", cipher:"aes" },

  /** Simple encryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} plaintext The data to encrypt.
   * @param {Object} [params] The parameters including tag, iv and salt.
   * @param {Object} [rp] A returned version with filled-in parameters.
   * @return {Object} The cipher raw data.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   */
  _encrypt: function (password, plaintext, params, rp) {
    params = params || {};
    rp = rp || {};

    var j = sjcl.json, p = j._add({ iv: sjcl.random.randomWords(4,0) },
                                  j.defaults), tmp, prp, adata;
    j._add(p, params);
    adata = p.adata;
    if (typeof p.salt === "string") {
      p.salt = sjcl.codec.base64.toBits(p.salt);
    }
    if (typeof p.iv === "string") {
      p.iv = sjcl.codec.base64.toBits(p.iv);
    }

    if (!sjcl.mode[p.mode] ||
        !sjcl.cipher[p.cipher] ||
        (typeof password === "string" && p.iter <= 100) ||
        (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
        (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
        (p.iv.length < 2 || p.iv.length > 4)) {
      throw new sjcl.exception.invalid("json encrypt: invalid parameters");
    }

    if (typeof password === "string") {
      tmp = sjcl.misc.cachedPbkdf2(password, p);
      password = tmp.key.slice(0,p.ks/32);
      p.salt = tmp.salt;
    } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.publicKey) {
      tmp = password.kem();
      p.kemtag = tmp.tag;
      password = tmp.key.slice(0,p.ks/32);
    }
    if (typeof plaintext === "string") {
      plaintext = sjcl.codec.utf8String.toBits(plaintext);
    }
    if (typeof adata === "string") {
      adata = sjcl.codec.utf8String.toBits(adata);
    }
    prp = new sjcl.cipher[p.cipher](password);

    /* return the json data */
    j._add(rp, p);
    rp.key = password;

    /* do the encryption */
    p.ct = sjcl.mode[p.mode].encrypt(prp, plaintext, p.iv, adata, p.ts);

    //return j.encode(j._subtract(p, j.defaults));
    return p;
  },

  /** Simple encryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} plaintext The data to encrypt.
   * @param {Object} [params] The parameters including tag, iv and salt.
   * @param {Object} [rp] A returned version with filled-in parameters.
   * @return {String} The ciphertext serialized data.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   */
  encrypt: function (password, plaintext, params, rp) {
    var j = sjcl.json, p = j._encrypt.apply(j, arguments);
    return j.encode(p);
  },

  /** Simple decryption function.
   * @param {String|bitArray} password The password or key.
   * @param {Object} ciphertext The cipher raw data to decrypt.
   * @param {Object} [params] Additional non-default parameters.
   * @param {Object} [rp] A returned object with filled parameters.
   * @return {String} The plaintext.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
   */
  _decrypt: function (password, ciphertext, params, rp) {
    params = params || {};
    rp = rp || {};

    var j = sjcl.json, p = j._add(j._add(j._add({},j.defaults),ciphertext), params, true), ct, tmp, prp, adata=p.adata;
    if (typeof p.salt === "string") {
      p.salt = sjcl.codec.base64.toBits(p.salt);
    }
    if (typeof p.iv === "string") {
      p.iv = sjcl.codec.base64.toBits(p.iv);
    }

    if (!sjcl.mode[p.mode] ||
        !sjcl.cipher[p.cipher] ||
        (typeof password === "string" && p.iter <= 100) ||
        (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
        (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
        (!p.iv) ||
        (p.iv.length < 2 || p.iv.length > 4)) {
      throw new sjcl.exception.invalid("json decrypt: invalid parameters");
    }

    if (typeof password === "string") {
      tmp = sjcl.misc.cachedPbkdf2(password, p);
      password = tmp.key.slice(0,p.ks/32);
      p.salt  = tmp.salt;
    } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.secretKey) {
      password = password.unkem(sjcl.codec.base64.toBits(p.kemtag)).slice(0,p.ks/32);
    }
    if (typeof adata === "string") {
      adata = sjcl.codec.utf8String.toBits(adata);
    }
    prp = new sjcl.cipher[p.cipher](password);

    /* do the decryption */
    ct = sjcl.mode[p.mode].decrypt(prp, p.ct, p.iv, adata, p.ts);

    /* return the json data */
    j._add(rp, p);
    rp.key = password;

    return sjcl.codec.utf8String.fromBits(ct);
  },

  /** Simple decryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} ciphertext The ciphertext to decrypt.
   * @param {Object} [params] Additional non-default parameters.
   * @param {Object} [rp] A returned object with filled parameters.
   * @return {String} The plaintext.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
   */
  decrypt: function (password, ciphertext, params, rp) {
    var j = sjcl.json;
    return j._decrypt(password, j.decode(ciphertext), params, rp);
  },
  
  /** Encode a flat structure into a JSON string.
   * @param {Object} obj The structure to encode.
   * @return {String} A JSON string.
   * @throws {sjcl.exception.invalid} if obj has a non-alphanumeric property.
   * @throws {sjcl.exception.bug} if a parameter has an unsupported type.
   */
  encode: function (obj) {
    var i, out='{', comma='';
    for (i in obj) {
      if (obj.hasOwnProperty(i)) {
        if (!i.match(/^[a-z0-9]+$/i)) {
          throw new sjcl.exception.invalid("json encode: invalid property name");
        }
        out += comma + '"' + i + '":';
        comma = ',';

        switch (typeof obj[i]) {
          case 'number':
          case 'boolean':
            out += obj[i];
            break;

          case 'string':
            out += '"' + escape(obj[i]) + '"';
            break;

          case 'object':
            out += '"' + sjcl.codec.base64.fromBits(obj[i],0) + '"';
            break;

          default:
            throw new sjcl.exception.bug("json encode: unsupported type");
        }
      }
    }
    return out+'}';
  },
  
  /** Decode a simple (flat) JSON string into a structure.  The ciphertext,
   * adata, salt and iv will be base64-decoded.
   * @param {String} str The string.
   * @return {Object} The decoded structure.
   * @throws {sjcl.exception.invalid} if str isn't (simple) JSON.
   */
  decode: function (str) {
    str = str.replace(/\s/g,'');
    if (!str.match(/^\{.*\}$/)) { 
      throw new sjcl.exception.invalid("json decode: this isn't json!");
    }
    var a = str.replace(/^\{|\}$/g, '').split(/,/), out={}, i, m;
    for (i=0; i<a.length; i++) {
      if (!(m=a[i].match(/^(?:(["']?)([a-z][a-z0-9]*)\1):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i))) {
        throw new sjcl.exception.invalid("json decode: this isn't json!");
      }
      if (m[3]) {
        out[m[2]] = parseInt(m[3],10);
      } else {
        out[m[2]] = m[2].match(/^(ct|salt|iv)$/) ? sjcl.codec.base64.toBits(m[4]) : unescape(m[4]);
      }
    }
    return out;
  },
  
  /** Insert all elements of src into target, modifying and returning target.
   * @param {Object} target The object to be modified.
   * @param {Object} src The object to pull data from.
   * @param {boolean} [requireSame=false] If true, throw an exception if any field of target differs from corresponding field of src.
   * @return {Object} target.
   * @private
   */
  _add: function (target, src, requireSame) {
    if (target === undefined) { target = {}; }
    if (src === undefined) { return target; }
    var i;
    for (i in src) {
      if (src.hasOwnProperty(i)) {
        if (requireSame && target[i] !== undefined && target[i] !== src[i]) {
          throw new sjcl.exception.invalid("required parameter overridden");
        }
        target[i] = src[i];
      }
    }
    return target;
  },
  
  /** Remove all elements of minus from plus.  Does not modify plus.
   * @private
   */
  _subtract: function (plus, minus) {
    var out = {}, i;

    for (i in plus) {
      if (plus.hasOwnProperty(i) && plus[i] !== minus[i]) {
        out[i] = plus[i];
      }
    }

    return out;
  },
  
  /** Return only the specified elements of src.
   * @private
   */
  _filter: function (src, filter) {
    var out = {}, i;
    for (i=0; i<filter.length; i++) {
      if (src[filter[i]] !== undefined) {
        out[filter[i]] = src[filter[i]];
      }
    }
    return out;
  }
};

/** Simple encryption function; convenient shorthand for sjcl.json.encrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} plaintext The data to encrypt.
 * @param {Object} [params] The parameters including tag, iv and salt.
 * @param {Object} [rp] A returned version with filled-in parameters.
 * @return {String} The ciphertext.
 */
sjcl.encrypt = sjcl.json.encrypt;

/** Simple decryption function; convenient shorthand for sjcl.json.decrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} ciphertext The ciphertext to decrypt.
 * @param {Object} [params] Additional non-default parameters.
 * @param {Object} [rp] A returned object with filled parameters.
 * @return {String} The plaintext.
 */
sjcl.decrypt = sjcl.json.decrypt;

/** The cache for cachedPbkdf2.
 * @private
 */
sjcl.misc._pbkdf2Cache = {};

/** Cached PBKDF2 key derivation.
 * @param {String} password The password.
 * @param {Object} [obj] The derivation params (iteration count and optional salt).
 * @return {Object} The derived data in key, the salt in salt.
 */
sjcl.misc.cachedPbkdf2 = function (password, obj) {
  var cache = sjcl.misc._pbkdf2Cache, c, cp, str, salt, iter;
  
  obj = obj || {};
  iter = obj.iter || 1000;
  
  /* open the cache for this password and iteration count */
  cp = cache[password] = cache[password] || {};
  c = cp[iter] = cp[iter] || { firstSalt: (obj.salt && obj.salt.length) ?
                     obj.salt.slice(0) : sjcl.random.randomWords(2,0) };
          
  salt = (obj.salt === undefined) ? c.firstSalt : obj.salt;
  
  c[salt] = c[salt] || sjcl.misc.pbkdf2(password, salt, obj.iter);
  return { key: c[salt].slice(0), salt:salt.slice(0) };
};


/**
 * @constructor
 * Constructs a new bignum from another bignum, a number or a hex string.
 */
sjcl.bn = function(it) {
  this.initWith(it);
};

sjcl.bn.prototype = {
  radix: 24,
  maxMul: 8,
  _class: sjcl.bn,
  
  copy: function() {
    return new this._class(this);
  },

  /**
   * Initializes this with it, either as a bn, a number, or a hex string.
   */
  initWith: function(it) {
    var i=0, k;
    switch(typeof it) {
    case "object":
      this.limbs = it.limbs.slice(0);
      break;
      
    case "number":
      this.limbs = [it];
      this.normalize();
      break;
      
    case "string":
      it = it.replace(/^0x/, '');
      this.limbs = [];
      // hack
      k = this.radix / 4;
      for (i=0; i < it.length; i+=k) {
        this.limbs.push(parseInt(it.substring(Math.max(it.length - i - k, 0), it.length - i),16));
      }
      break;

    default:
      this.limbs = [0];
    }
    return this;
  },

  /**
   * Returns true if "this" and "that" are equal.  Calls fullReduce().
   * Equality test is in constant time.
   */
  equals: function(that) {
    if (typeof that === "number") { that = new this._class(that); }
    var difference = 0, i;
    this.fullReduce();
    that.fullReduce();
    for (i = 0; i < this.limbs.length || i < that.limbs.length; i++) {
      difference |= this.getLimb(i) ^ that.getLimb(i);
    }
    return (difference === 0);
  },
  
  /**
   * Get the i'th limb of this, zero if i is too large.
   */
  getLimb: function(i) {
    return (i >= this.limbs.length) ? 0 : this.limbs[i];
  },
  
  /**
   * Constant time comparison function.
   * Returns 1 if this >= that, or zero otherwise.
   */
  greaterEquals: function(that) {
    if (typeof that === "number") { that = new this._class(that); }
    var less = 0, greater = 0, i, a, b;
    i = Math.max(this.limbs.length, that.limbs.length) - 1;
    for (; i>= 0; i--) {
      a = this.getLimb(i);
      b = that.getLimb(i);
      greater |= (b - a) & ~less;
      less |= (a - b) & ~greater;
    }
    return (greater | ~less) >>> 31;
  },
  
  /**
   * Convert to a hex string.
   */
  toString: function() {
    this.fullReduce();
    var out="", i, s, l = this.limbs;
    for (i=0; i < this.limbs.length; i++) {
      s = l[i].toString(16);
      while (i < this.limbs.length - 1 && s.length < 6) {
        s = "0" + s;
      }
      out = s + out;
    }
    return "0x"+out;
  },
  
  /** this += that.  Does not normalize. */
  addM: function(that) {
    if (typeof(that) !== "object") { that = new this._class(that); }
    var i, l=this.limbs, ll=that.limbs;
    for (i=l.length; i<ll.length; i++) {
      l[i] = 0;
    }
    for (i=0; i<ll.length; i++) {
      l[i] += ll[i];
    }
    return this;
  },
  
  /** this *= 2.  Requires normalized; ends up normalized. */
  doubleM: function() {
    var i, carry=0, tmp, r=this.radix, m=this.radixMask, l=this.limbs;
    for (i=0; i<l.length; i++) {
      tmp = l[i];
      tmp = tmp+tmp+carry;
      l[i] = tmp & m;
      carry = tmp >> r;
    }
    if (carry) {
      l.push(carry);
    }
    return this;
  },
  
  /** this /= 2, rounded down.  Requires normalized; ends up normalized. */
  halveM: function() {
    var i, carry=0, tmp, r=this.radix, l=this.limbs;
    for (i=l.length-1; i>=0; i--) {
      tmp = l[i];
      l[i] = (tmp+carry)>>1;
      carry = (tmp&1) << r;
    }
    if (!l[l.length-1]) {
      l.pop();
    }
    return this;
  },

  /** this -= that.  Does not normalize. */
  subM: function(that) {
    if (typeof(that) !== "object") { that = new this._class(that); }
    var i, l=this.limbs, ll=that.limbs;
    for (i=l.length; i<ll.length; i++) {
      l[i] = 0;
    }
    for (i=0; i<ll.length; i++) {
      l[i] -= ll[i];
    }
    return this;
  },
  
  mod: function(that) {
    var neg = !this.greaterEquals(new sjcl.bn(0));
    
    that = new sjcl.bn(that).normalize(); // copy before we begin
    var out = new sjcl.bn(this).normalize(), ci=0;
    
    if (neg) out = (new sjcl.bn(0)).subM(out).normalize();
    
    for (; out.greaterEquals(that); ci++) {
      that.doubleM();
    }
    
    if (neg) out = that.sub(out).normalize();
    
    for (; ci > 0; ci--) {
      that.halveM();
      if (out.greaterEquals(that)) {
        out.subM(that).normalize();
      }
    }
    return out.trim();
  },
  
  /** return inverse mod prime p.  p must be odd. Binary extended Euclidean algorithm mod p. */
  inverseMod: function(p) {
    var a = new sjcl.bn(1), b = new sjcl.bn(0), x = new sjcl.bn(this), y = new sjcl.bn(p), tmp, i, nz=1;
    
    if (!(p.limbs[0] & 1)) {
      throw (new sjcl.exception.invalid("inverseMod: p must be odd"));
    }
    
    // invariant: y is odd
    do {
      if (x.limbs[0] & 1) {
        if (!x.greaterEquals(y)) {
          // x < y; swap everything
          tmp = x; x = y; y = tmp;
          tmp = a; a = b; b = tmp;
        }
        x.subM(y);
        x.normalize();
        
        if (!a.greaterEquals(b)) {
          a.addM(p);
        }
        a.subM(b);
      }
      
      // cut everything in half
      x.halveM();
      if (a.limbs[0] & 1) {
        a.addM(p);
      }
      a.normalize();
      a.halveM();
      
      // check for termination: x ?= 0
      for (i=nz=0; i<x.limbs.length; i++) {
        nz |= x.limbs[i];
      }
    } while(nz);
    
    if (!y.equals(1)) {
      throw (new sjcl.exception.invalid("inverseMod: p and x must be relatively prime"));
    }
    
    return b;
  },
  
  /** this + that.  Does not normalize. */
  add: function(that) {
    return this.copy().addM(that);
  },

  /** this - that.  Does not normalize. */
  sub: function(that) {
    return this.copy().subM(that);
  },
  
  /** this * that.  Normalizes and reduces. */
  mul: function(that) {
    if (typeof(that) === "number") { that = new this._class(that); }
    var i, j, a = this.limbs, b = that.limbs, al = a.length, bl = b.length, out = new this._class(), c = out.limbs, ai, ii=this.maxMul;

    for (i=0; i < this.limbs.length + that.limbs.length + 1; i++) {
      c[i] = 0;
    }
    for (i=0; i<al; i++) {
      ai = a[i];
      for (j=0; j<bl; j++) {
        c[i+j] += ai * b[j];
      }
     
      if (!--ii) {
        ii = this.maxMul;
        out.cnormalize();
      }
    }
    return out.cnormalize().reduce();
  },

  /** this ^ 2.  Normalizes and reduces. */
  square: function() {
    return this.mul(this);
  },

  /** this ^ n.  Uses square-and-multiply.  Normalizes and reduces. */
  power: function(l) {
    if (typeof(l) === "number") {
      l = [l];
    } else if (l.limbs !== undefined) {
      l = l.normalize().limbs;
    }
    var i, j, out = new this._class(1), pow = this;

    for (i=0; i<l.length; i++) {
      for (j=0; j<this.radix; j++) {
        if (l[i] & (1<<j)) {
          out = out.mul(pow);
        }
        pow = pow.square();
      }
    }
    
    return out;
  },

  /** this * that mod N */
  mulmod: function(that, N) {
    return this.mod(N).mul(that.mod(N)).mod(N);
  },

  /** this ^ x mod N */
  powermod: function(x, N) {
    var result = new sjcl.bn(1), a = new sjcl.bn(this), k = new sjcl.bn(x);
    while (true) {
      if (k.limbs[0] & 1) { result = result.mulmod(a, N); }
      k.halveM();
      if (k.equals(0)) { break; }
      a = a.mulmod(a, N);
    }
    return result.normalize().reduce();
  },

  trim: function() {
    var l = this.limbs, p;
    do {
      p = l.pop();
    } while (l.length && p === 0);
    l.push(p);
    return this;
  },
  
  /** Reduce mod a modulus.  Stubbed for subclassing. */
  reduce: function() {
    return this;
  },

  /** Reduce and normalize. */
  fullReduce: function() {
    return this.normalize();
  },
  
  /** Propagate carries. */
  normalize: function() {
    var carry=0, i, pv = this.placeVal, ipv = this.ipv, l, m, limbs = this.limbs, ll = limbs.length, mask = this.radixMask;
    for (i=0; i < ll || (carry !== 0 && carry !== -1); i++) {
      l = (limbs[i]||0) + carry;
      m = limbs[i] = l & mask;
      carry = (l-m)*ipv;
    }
    if (carry === -1) {
      limbs[i-1] -= pv;
    }
    return this;
  },

  /** Constant-time normalize. Does not allocate additional space. */
  cnormalize: function() {
    var carry=0, i, ipv = this.ipv, l, m, limbs = this.limbs, ll = limbs.length, mask = this.radixMask;
    for (i=0; i < ll-1; i++) {
      l = limbs[i] + carry;
      m = limbs[i] = l & mask;
      carry = (l-m)*ipv;
    }
    limbs[i] += carry;
    return this;
  },
  
  /** Serialize to a bit array */
  toBits: function(len) {
    this.fullReduce();
    len = len || this.exponent || this.bitLength();
    var i = Math.floor((len-1)/24), w=sjcl.bitArray, e = (len + 7 & -8) % this.radix || this.radix,
        out = [w.partial(e, this.getLimb(i))];
    for (i--; i >= 0; i--) {
      out = w.concat(out, [w.partial(Math.min(this.radix,len), this.getLimb(i))]);
      len -= this.radix;
    }
    return out;
  },
  
  /** Return the length in bits, rounded up to the nearest byte. */
  bitLength: function() {
    this.fullReduce();
    var out = this.radix * (this.limbs.length - 1),
        b = this.limbs[this.limbs.length - 1];
    for (; b; b >>>= 1) {
      out ++;
    }
    return out+7 & -8;
  }
};

/** @memberOf sjcl.bn
* @this { sjcl.bn }
*/
sjcl.bn.fromBits = function(bits) {
  var Class = this, out = new Class(), words=[], w=sjcl.bitArray, t = this.prototype,
      l = Math.min(this.bitLength || 0x100000000, w.bitLength(bits)), e = l % t.radix || t.radix;
  
  words[0] = w.extract(bits, 0, e);
  for (; e < l; e += t.radix) {
    words.unshift(w.extract(bits, e, t.radix));
  }

  out.limbs = words;
  return out;
};



sjcl.bn.prototype.ipv = 1 / (sjcl.bn.prototype.placeVal = Math.pow(2,sjcl.bn.prototype.radix));
sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1;

/**
 * Creates a new subclass of bn, based on reduction modulo a pseudo-Mersenne prime,
 * i.e. a prime of the form 2^e + sum(a * 2^b),where the sum is negative and sparse.
 */
sjcl.bn.pseudoMersennePrime = function(exponent, coeff) {
  /** @constructor 
  * @private
  */
  function p(it) {
    this.initWith(it);
    /*if (this.limbs[this.modOffset]) {
      this.reduce();
    }*/
  }

  var ppr = p.prototype = new sjcl.bn(), i, tmp, mo;
  mo = ppr.modOffset = Math.ceil(tmp = exponent / ppr.radix);
  ppr.exponent = exponent;
  ppr.offset = [];
  ppr.factor = [];
  ppr.minOffset = mo;
  ppr.fullMask = 0;
  ppr.fullOffset = [];
  ppr.fullFactor = [];
  ppr.modulus = p.modulus = new sjcl.bn(Math.pow(2,exponent));
  
  ppr.fullMask = 0|-Math.pow(2, exponent % ppr.radix);

  for (i=0; i<coeff.length; i++) {
    ppr.offset[i] = Math.floor(coeff[i][0] / ppr.radix - tmp);
    ppr.fullOffset[i] = Math.ceil(coeff[i][0] / ppr.radix - tmp);
    ppr.factor[i] = coeff[i][1] * Math.pow(1/2, exponent - coeff[i][0] + ppr.offset[i] * ppr.radix);
    ppr.fullFactor[i] = coeff[i][1] * Math.pow(1/2, exponent - coeff[i][0] + ppr.fullOffset[i] * ppr.radix);
    ppr.modulus.addM(new sjcl.bn(Math.pow(2,coeff[i][0])*coeff[i][1]));
    ppr.minOffset = Math.min(ppr.minOffset, -ppr.offset[i]); // conservative
  }
  ppr._class = p;
  ppr.modulus.cnormalize();

  /** Approximate reduction mod p.  May leave a number which is negative or slightly larger than p.
   * @memberof sjcl.bn
   * @this { sjcl.bn }
   */
  ppr.reduce = function() {
    var i, k, l, mo = this.modOffset, limbs = this.limbs, off = this.offset, ol = this.offset.length, fac = this.factor, ll;

    i = this.minOffset;
    while (limbs.length > mo) {
      l = limbs.pop();
      ll = limbs.length;
      for (k=0; k<ol; k++) {
        limbs[ll+off[k]] -= fac[k] * l;
      }
      
      i--;
      if (!i) {
        limbs.push(0);
        this.cnormalize();
        i = this.minOffset;
      }
    }
    this.cnormalize();

    return this;
  };
  
  /** @memberof sjcl.bn
  * @this { sjcl.bn }
  */
  ppr._strongReduce = (ppr.fullMask === -1) ? ppr.reduce : function() {
    var limbs = this.limbs, i = limbs.length - 1, k, l;
    this.reduce();
    if (i === this.modOffset - 1) {
      l = limbs[i] & this.fullMask;
      limbs[i] -= l;
      for (k=0; k<this.fullOffset.length; k++) {
        limbs[i+this.fullOffset[k]] -= this.fullFactor[k] * l;
      }
      this.normalize();
    }
  };

  /** mostly constant-time, very expensive full reduction.
   * @memberof sjcl.bn
   * @this { sjcl.bn }
   */
  ppr.fullReduce = function() {
    var greater, i;
    // massively above the modulus, may be negative
    
    this._strongReduce();
    // less than twice the modulus, may be negative

    this.addM(this.modulus);
    this.addM(this.modulus);
    this.normalize();
    // probably 2-3x the modulus
    
    this._strongReduce();
    // less than the power of 2.  still may be more than
    // the modulus

    // HACK: pad out to this length
    for (i=this.limbs.length; i<this.modOffset; i++) {
      this.limbs[i] = 0;
    }
    
    // constant-time subtract modulus
    greater = this.greaterEquals(this.modulus);
    for (i=0; i<this.limbs.length; i++) {
      this.limbs[i] -= this.modulus.limbs[i] * greater;
    }
    this.cnormalize();

    return this;
  };


  /** @memberof sjcl.bn
  * @this { sjcl.bn }
  */
  ppr.inverse = function() {
    return (this.power(this.modulus.sub(2)));
  };

  p.fromBits = sjcl.bn.fromBits;

  return p;
};

// a small Mersenne prime
var sbp = sjcl.bn.pseudoMersennePrime;
sjcl.bn.prime = {
  p127: sbp(127, [[0,-1]]),

  // Bernstein's prime for Curve25519
  p25519: sbp(255, [[0,-19]]),

  // Koblitz primes
  p192k: sbp(192, [[32,-1],[12,-1],[8,-1],[7,-1],[6,-1],[3,-1],[0,-1]]),
  p224k: sbp(224, [[32,-1],[12,-1],[11,-1],[9,-1],[7,-1],[4,-1],[1,-1],[0,-1]]),
  p256k: sbp(256, [[32,-1],[9,-1],[8,-1],[7,-1],[6,-1],[4,-1],[0,-1]]),

  // NIST primes
  p192: sbp(192, [[0,-1],[64,-1]]),
  p224: sbp(224, [[0,1],[96,-1]]),
  p256: sbp(256, [[0,-1],[96,1],[192,1],[224,-1]]),
  p384: sbp(384, [[0,-1],[32,1],[96,-1],[128,-1]]),
  p521: sbp(521, [[0,-1]])
};

sjcl.bn.random = function(modulus, paranoia) {
  if (typeof modulus !== "object") { modulus = new sjcl.bn(modulus); }
  var words, i, l = modulus.limbs.length, m = modulus.limbs[l-1]+1, out = new sjcl.bn();
  while (true) {
    // get a sequence whose first digits make sense
    do {
      words = sjcl.random.randomWords(l, paranoia);
      if (words[l-1] < 0) { words[l-1] += 0x100000000; }
    } while (Math.floor(words[l-1] / m) === Math.floor(0x100000000 / m));
    words[l-1] %= m;

    // mask off all the limbs
    for (i=0; i<l-1; i++) {
      words[i] &= modulus.radixMask;
    }

    // check the rest of the digitssj
    out.limbs = words;
    if (!out.greaterEquals(modulus)) {
      return out;
    }
  }
};

/**
 * base class for all ecc operations.
 */
sjcl.ecc = {};

/**
 * Represents a point on a curve in affine coordinates.
 * @constructor
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 * @param {bigInt} x The x coordinate.
 * @param {bigInt} y The y coordinate.
 */
sjcl.ecc.point = function(curve,x,y) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    this.x = x;
    this.y = y;
    this.isIdentity = false;
  }
  this.curve = curve;
};



sjcl.ecc.point.prototype = {
  toJac: function() {
    return new sjcl.ecc.pointJac(this.curve, this.x, this.y, new this.curve.field(1));
  },

  mult: function(k) {
    return this.toJac().mult(k, this).toAffine();
  },
  
  /**
   * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply this by.
   * @param {bigInt} k2 The coefficient to multiply affine2 this by.
   * @param {sjcl.ecc.point} affine The other point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
   */
  mult2: function(k, k2, affine2) {
    return this.toJac().mult2(k, this, k2, affine2).toAffine();
  },
  
  multiples: function() {
    var m, i, j;
    if (this._multiples === undefined) {
      j = this.toJac().doubl();
      m = this._multiples = [new sjcl.ecc.point(this.curve), this, j.toAffine()];
      for (i=3; i<16; i++) {
        j = j.add(this);
        m.push(j.toAffine());
      }
    }
    return this._multiples;
  },

  isValid: function() {
    return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
  },

  toBits: function() {
    return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
  }
};

/**
 * Represents a point on a curve in Jacobian coordinates. Coordinates can be specified as bigInts or strings (which
 * will be converted to bigInts).
 *
 * @constructor
 * @param {bigInt/string} x The x coordinate.
 * @param {bigInt/string} y The y coordinate.
 * @param {bigInt/string} z The z coordinate.
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 */
sjcl.ecc.pointJac = function(curve, x, y, z) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    this.x = x;
    this.y = y;
    this.z = z;
    this.isIdentity = false;
  }
  this.curve = curve;
};

sjcl.ecc.pointJac.prototype = {
  /**
   * Adds S and T and returns the result in Jacobian coordinates. Note that S must be in Jacobian coordinates and T must be in affine coordinates.
   * @param {sjcl.ecc.pointJac} S One of the points to add, in Jacobian coordinates.
   * @param {sjcl.ecc.point} T The other point to add, in affine coordinates.
   * @return {sjcl.ecc.pointJac} The sum of the two points, in Jacobian coordinates. 
   */
  add: function(T) {
    var S = this, sz2, c, d, c2, x1, x2, x, y1, y2, y, z;
    if (S.curve !== T.curve) {
      throw("sjcl.ecc.add(): Points must be on the same curve to add them!");
    }

    if (S.isIdentity) {
      return T.toJac();
    } else if (T.isIdentity) {
      return S;
    }

    sz2 = S.z.square();
    c = T.x.mul(sz2).subM(S.x);

    if (c.equals(0)) {
      if (S.y.equals(T.y.mul(sz2.mul(S.z)))) {
        // same point
        return S.doubl();
      } else {
        // inverses
        return new sjcl.ecc.pointJac(S.curve);
      }
    }
    
    d = T.y.mul(sz2.mul(S.z)).subM(S.y);
    c2 = c.square();

    x1 = d.square();
    x2 = c.square().mul(c).addM( S.x.add(S.x).mul(c2) );
    x  = x1.subM(x2);

    y1 = S.x.mul(c2).subM(x).mul(d);
    y2 = S.y.mul(c.square().mul(c));
    y  = y1.subM(y2);

    z  = S.z.mul(c);

    return new sjcl.ecc.pointJac(this.curve,x,y,z);
  },
  
  /**
   * doubles this point.
   * @return {sjcl.ecc.pointJac} The doubled point.
   */
  doubl: function() {
    if (this.isIdentity) { return this; }

    var
      y2 = this.y.square(),
      a  = y2.mul(this.x.mul(4)),
      b  = y2.square().mul(8),
      z2 = this.z.square(),
      c  = this.curve.a.toString() == (new sjcl.bn(-3)).toString() ?
                this.x.sub(z2).mul(3).mul(this.x.add(z2)) :
                this.x.square().mul(3).add(z2.square().mul(this.curve.a)),
      x  = c.square().subM(a).subM(a),
      y  = a.sub(x).mul(c).subM(b),
      z  = this.y.add(this.y).mul(this.z);
    return new sjcl.ecc.pointJac(this.curve, x, y, z);
  },

  /**
   * Returns a copy of this point converted to affine coordinates.
   * @return {sjcl.ecc.point} The converted point.
   */
  toAffine: function() {
    if (this.isIdentity || this.z.equals(0)) {
      return new sjcl.ecc.point(this.curve);
    }
    var zi = this.z.inverse(), zi2 = zi.square();
    return new sjcl.ecc.point(this.curve, this.x.mul(zi2).fullReduce(), this.y.mul(zi2.mul(zi)).fullReduce());
  },
  
  /**
   * Multiply this point by k and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply by.
   * @param {sjcl.ecc.point} affine This point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication, in Jacobian coordinates.
   */
  mult: function(k, affine) {
    if (typeof(k) === "number") {
      k = [k];
    } else if (k.limbs !== undefined) {
      k = k.normalize().limbs;
    }
    
    var i, j, out = new sjcl.ecc.point(this.curve).toJac(), multiples = affine.multiples();

    for (i=k.length-1; i>=0; i--) {
      for (j=sjcl.bn.prototype.radix-4; j>=0; j-=4) {
        out = out.doubl().doubl().doubl().doubl().add(multiples[k[i]>>j & 0xF]);
      }
    }
    
    return out;
  },
  
  /**
   * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply this by.
   * @param {sjcl.ecc.point} affine This point in affine coordinates.
   * @param {bigInt} k2 The coefficient to multiply affine2 this by.
   * @param {sjcl.ecc.point} affine The other point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
   */
  mult2: function(k1, affine, k2, affine2) {
    if (typeof(k1) === "number") {
      k1 = [k1];
    } else if (k1.limbs !== undefined) {
      k1 = k1.normalize().limbs;
    }
    
    if (typeof(k2) === "number") {
      k2 = [k2];
    } else if (k2.limbs !== undefined) {
      k2 = k2.normalize().limbs;
    }
    
    var i, j, out = new sjcl.ecc.point(this.curve).toJac(), m1 = affine.multiples(),
        m2 = affine2.multiples(), l1, l2;

    for (i=Math.max(k1.length,k2.length)-1; i>=0; i--) {
      l1 = k1[i] | 0;
      l2 = k2[i] | 0;
      for (j=sjcl.bn.prototype.radix-4; j>=0; j-=4) {
        out = out.doubl().doubl().doubl().doubl().add(m1[l1>>j & 0xF]).add(m2[l2>>j & 0xF]);
      }
    }
    
    return out;
  },

  isValid: function() {
    var z2 = this.z.square(), z4 = z2.square(), z6 = z4.mul(z2);
    return this.y.square().equals(
             this.curve.b.mul(z6).add(this.x.mul(
               this.curve.a.mul(z4).add(this.x.square()))));
  }
};

/**
 * Construct an elliptic curve. Most users will not use this and instead start with one of the NIST curves defined below.
 *
 * @constructor
 * @param {bigInt} p The prime modulus.
 * @param {bigInt} r The prime order of the curve.
 * @param {bigInt} a The constant a in the equation of the curve y^2 = x^3 + ax + b (for NIST curves, a is always -3).
 * @param {bigInt} x The x coordinate of a base point of the curve.
 * @param {bigInt} y The y coordinate of a base point of the curve.
 */
sjcl.ecc.curve = function(Field, r, a, b, x, y) {
  this.field = Field;
  this.r = new sjcl.bn(r);
  this.a = new Field(a);
  this.b = new Field(b);
  this.G = new sjcl.ecc.point(this, new Field(x), new Field(y));
};

sjcl.ecc.curve.prototype.fromBits = function (bits) {
  var w = sjcl.bitArray, l = this.field.prototype.exponent + 7 & -8,
      p = new sjcl.ecc.point(this, this.field.fromBits(w.bitSlice(bits, 0, l)),
                             this.field.fromBits(w.bitSlice(bits, l, 2*l)));
  if (!p.isValid()) {
    throw new sjcl.exception.corrupt("not on the curve!");
  }
  return p;
};

sjcl.ecc.curves = {
  c192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192,
    "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",
    -3,
    "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),

  c224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224,
    "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
    -3,
    "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),

  c256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256,
    "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    -3,
    "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),

  c384: new sjcl.ecc.curve(
    sjcl.bn.prime.p384,
    "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    -3,
    "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),

  k192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192k,
    "0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d",
    0,
    3,
    "0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
    "0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"),

  k224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224k,
    "0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
    0,
    5,
    "0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
    "0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5"),

  k256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256k,
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    0,
    7,
    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

};

/** our basicKey classes
*/
sjcl.ecc.basicKey = {
  /** ecc publicKey. 
  * @constructor
  * @param {curve} curve the elliptic curve
  * @param {point} point the point on the curve
  */
  publicKey: function(curve, point) {
    this._curve = curve;
    this._curveBitLength = curve.r.bitLength();
    if (point instanceof Array) {
      this._point = curve.fromBits(point);
    } else {
      this._point = point;
    }

    /** get this keys point data
    * @return x and y as bitArrays
    */
    this.get = function() {
      var pointbits = this._point.toBits();
      var len = sjcl.bitArray.bitLength(pointbits);
      var x = sjcl.bitArray.bitSlice(pointbits, 0, len/2);
      var y = sjcl.bitArray.bitSlice(pointbits, len/2);
      return { x: x, y: y };
    };
  },

  /** ecc secretKey
  * @constructor
  * @param {curve} curve the elliptic curve
  * @param exponent
  */
  secretKey: function(curve, exponent) {
    this._curve = curve;
    this._curveBitLength = curve.r.bitLength();
    this._exponent = exponent;

    /** get this keys exponent data
    * @return {bitArray} exponent
    */
    this.get = function () {
      return this._exponent.toBits();
    };
  }
};

/** @private */
sjcl.ecc.basicKey.generateKeys = function(cn) {
  return function generateKeys(curve, paranoia, sec) {
    curve = curve || 256;

    if (typeof curve === "number") {
      curve = sjcl.ecc.curves['c'+curve];
      if (curve === undefined) {
        throw new sjcl.exception.invalid("no such curve");
      }
    }
    sec = sec || sjcl.bn.random(curve.r, paranoia);

    var pub = curve.G.mult(sec);
    return { pub: new sjcl.ecc[cn].publicKey(curve, pub),
             sec: new sjcl.ecc[cn].secretKey(curve, sec) };
  };
};

/** elGamal keys */
sjcl.ecc.elGamal = {
  /** generate keys
  * @function
  * @param curve
  * @param {int} paranoia Paranoia for generation (default 6)
  * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
  */
  generateKeys: sjcl.ecc.basicKey.generateKeys("elGamal"),
  /** elGamal publicKey. 
  * @constructor
  * @augments sjcl.ecc.basicKey.publicKey
  */
  publicKey: function (curve, point) {
    sjcl.ecc.basicKey.publicKey.apply(this, arguments);
  },
  /** elGamal secretKey
  * @constructor
  * @augments sjcl.ecc.basicKey.secretKey
  */
  secretKey: function (curve, exponent) {
    sjcl.ecc.basicKey.secretKey.apply(this, arguments);
  }
};

sjcl.ecc.elGamal.publicKey.prototype = {
  /** Kem function of elGamal Public Key
  * @param paranoia paranoia to use for randomization.
  * @return {object} key and tag. unkem(tag) with the corresponding secret key results in the key returned.
  */
  kem: function(paranoia) {
    var sec = sjcl.bn.random(this._curve.r, paranoia),
        tag = this._curve.G.mult(sec).toBits(),
        key = sjcl.hash.sha256.hash(this._point.mult(sec).toBits());
    return { key: key, tag: tag };
  }
};

sjcl.ecc.elGamal.secretKey.prototype = {
  /** UnKem function of elGamal Secret Key
  * @param {bitArray} tag The Tag to decrypt.
  * @return {bitArray} decrypted key.
  */
  unkem: function(tag) {
    return sjcl.hash.sha256.hash(this._curve.fromBits(tag).mult(this._exponent).toBits());
  },

  /** Diffie-Hellmann function
  * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
  * @return {bitArray} diffie-hellmann result for this key combination.
  */
  dh: function(pk) {
    return sjcl.hash.sha256.hash(pk._point.mult(this._exponent).toBits());
  }
};

/** ecdsa keys */
sjcl.ecc.ecdsa = {
  /** generate keys
  * @function
  * @param curve
  * @param {int} paranoia Paranoia for generation (default 6)
  * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
  */
  generateKeys: sjcl.ecc.basicKey.generateKeys("ecdsa")
};

/** ecdsa publicKey. 
* @constructor
* @augments sjcl.ecc.basicKey.publicKey
*/
sjcl.ecc.ecdsa.publicKey = function (curve, point) {
  sjcl.ecc.basicKey.publicKey.apply(this, arguments);
};

/** specific functions for ecdsa publicKey. */
sjcl.ecc.ecdsa.publicKey.prototype = {
  /** Diffie-Hellmann function
  * @param {bitArray} hash hash to verify. 
  * @param {bitArray} rs signature bitArray.
  * @param {boolean}  fakeLegacyVersion use old legacy version
  */
  verify: function(hash, rs, fakeLegacyVersion) {
    if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
      hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
    }
    var w = sjcl.bitArray,
        R = this._curve.r,
        l = this._curveBitLength,
        r = sjcl.bn.fromBits(w.bitSlice(rs,0,l)),
        ss = sjcl.bn.fromBits(w.bitSlice(rs,l,2*l)),
        s = fakeLegacyVersion ? ss : ss.inverseMod(R),
        hG = sjcl.bn.fromBits(hash).mul(s).mod(R),
        hA = r.mul(s).mod(R),
        r2 = this._curve.G.mult2(hG, hA, this._point).x;
    if (r.equals(0) || ss.equals(0) || r.greaterEquals(R) || ss.greaterEquals(R) || !r2.equals(r)) {
      if (fakeLegacyVersion === undefined) {
        return this.verify(hash, rs, true);
      } else {
        throw (new sjcl.exception.corrupt("signature didn't check out"));
      }
    }
    return true;
  }
};

/** ecdsa secretKey
* @constructor
* @augments sjcl.ecc.basicKey.publicKey
*/
sjcl.ecc.ecdsa.secretKey = function (curve, exponent) {
  sjcl.ecc.basicKey.secretKey.apply(this, arguments);
};

/** specific functions for ecdsa secretKey. */
sjcl.ecc.ecdsa.secretKey.prototype = {
  /** Diffie-Hellmann function
  * @param {bitArray} hash hash to sign. 
  * @param {int} paranoia paranoia for random number generation
  * @param {boolean} fakeLegacyVersion use old legacy version
  */
  sign: function(hash, paranoia, fakeLegacyVersion, fixedKForTesting) {
    if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
      hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
    }
    var R  = this._curve.r,
        l  = R.bitLength(),
        k  = fixedKForTesting || sjcl.bn.random(R.sub(1), paranoia).add(1),
        r  = this._curve.G.mult(k).x.mod(R),
        ss = sjcl.bn.fromBits(hash).add(r.mul(this._exponent)),
        s  = fakeLegacyVersion ? ss.inverseMod(R).mul(k).mod(R)
             : ss.mul(k.inverseMod(R)).mod(R);
    return sjcl.bitArray.concat(r.toBits(l), s.toBits(l));
  }
};
return {
    sjcl: (typeof sjcl !== "undefined") ? sjcl : null,
    module: (typeof module !== "undefined") ? module : null,
    Math: (typeof Math !== "undefined") ? Math : null,
    String: (typeof String !== "undefined") ? String : null,
    decodeURIComponent: (typeof decodeURIComponent !== "undefined") ? decodeURIComponent : null,
    escape: (typeof escape !== "undefined") ? escape : null,
    unescape: (typeof unescape !== "undefined") ? unescape : null,
    encodeURIComponent: (typeof encodeURIComponent !== "undefined") ? encodeURIComponent : null,
    parseInt: (typeof parseInt !== "undefined") ? parseInt : null,
    Object: (typeof Object !== "undefined") ? Object : null,
    window: (typeof window !== "undefined") ? window : null,
    document: (typeof document !== "undefined") ? document : null,
    require: (typeof require !== "undefined") ? require : null,
    console: (typeof console !== "undefined") ? console : null,
    sbp: (typeof sbp !== "undefined") ? sbp : null
};
}
, {"filename":"../node_modules/sjcl/sjcl.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/index.js","mtime":1383545607,"wrapper":"commonjs","format":"commonjs","id":"/__SYSTEM__/crypto.js"}
require.memoize("/__SYSTEM__/crypto.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify';
var Buffer = require('__SYSTEM__/buffer').Buffer
var sha = require('./sha')
var sha256 = require('./sha256')
var rng = require('./rng')
var md5 = require('./md5')

var algorithms = {
  sha1: sha,
  sha256: sha256,
  md5: md5
}

var blocksize = 64
var zeroBuffer = new Buffer(blocksize); zeroBuffer.fill(0)
function hmac(fn, key, data) {
  if(!Buffer.isBuffer(key)) key = new Buffer(key)
  if(!Buffer.isBuffer(data)) data = new Buffer(data)

  if(key.length > blocksize) {
    key = fn(key)
  } else if(key.length < blocksize) {
    key = Buffer.concat([key, zeroBuffer], blocksize)
  }

  var ipad = new Buffer(blocksize), opad = new Buffer(blocksize)
  for(var i = 0; i < blocksize; i++) {
    ipad[i] = key[i] ^ 0x36
    opad[i] = key[i] ^ 0x5C
  }

  var hash = fn(Buffer.concat([ipad, data]))
  return fn(Buffer.concat([opad, hash]))
}

function hash(alg, key) {
  alg = alg || 'sha1'
  var fn = algorithms[alg]
  var bufs = []
  var length = 0
  if(!fn) error('algorithm:', alg, 'is not yet supported')
  return {
    update: function (data) {
      if(!Buffer.isBuffer(data)) data = new Buffer(data)
        
      bufs.push(data)
      length += data.length
      return this
    },
    digest: function (enc) {
      var buf = Buffer.concat(bufs)
      var r = key ? hmac(fn, key, buf) : fn(buf)
      bufs = null
      return enc ? r.toString(enc) : r
    }
  }
}

function error () {
  var m = [].slice.call(arguments).join(' ')
  throw new Error([
    m,
    'we accept pull requests',
    'http://github.com/dominictarr/crypto-browserify'
    ].join('\n'))
}

exports.createHash = function (alg) { return hash(alg) }
exports.createHmac = function (alg, key) { return hash(alg, key) }
exports.randomBytes = function(size, callback) {
  if (callback && callback.call) {
    try {
      callback.call(this, undefined, new Buffer(rng(size)))
    } catch (err) { callback(err) }
  } else {
    return new Buffer(rng(size))
  }
}

function each(a, f) {
  for(var i in a)
    f(a[i], i)
}

// the least I can do is make error messages for the rest of the node.js/crypto api.
each(['createCredentials'
, 'createCipher'
, 'createCipheriv'
, 'createDecipher'
, 'createDecipheriv'
, 'createSign'
, 'createVerify'
, 'createDiffieHellman'
, 'pbkdf2'], function (name) {
  exports[name] = function () {
    error('sorry,', name, 'is not implemented yet')
  }
})

}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/index.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/buffer-browserify/index.js","mtime":1418900069,"wrapper":"commonjs","format":"commonjs","id":"/__SYSTEM__/buffer.js"}
require.memoize("/__SYSTEM__/buffer.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/buffer-browserify';
var assert;
exports.Buffer = Buffer;
exports.SlowBuffer = Buffer;
Buffer.poolSize = 8192;
exports.INSPECT_MAX_BYTES = 50;

function stringtrim(str) {
  if (str.trim) return str.trim();
  return str.replace(/^\s+|\s+$/g, '');
}

function Buffer(subject, encoding, offset) {
  if(!assert) assert= require('__SYSTEM__/assert');
  if (!(this instanceof Buffer)) {
    return new Buffer(subject, encoding, offset);
  }
  this.parent = this;
  this.offset = 0;

  // Work-around: node's base64 implementation
  // allows for non-padded strings while base64-js
  // does not..
  if (encoding == "base64" && typeof subject == "string") {
    subject = stringtrim(subject);
    while (subject.length % 4 != 0) {
      subject = subject + "="; 
    }
  }

  var type;

  // Are we slicing?
  if (typeof offset === 'number') {
    this.length = coerce(encoding);
    // slicing works, with limitations (no parent tracking/update)
    // check https://github.com/toots/buffer-browserify/issues/19
    for (var i = 0; i < this.length; i++) {
        this[i] = subject.get(i+offset);
    }
  } else {
    // Find the length
    switch (type = typeof subject) {
      case 'number':
        this.length = coerce(subject);
        break;

      case 'string':
        this.length = Buffer.byteLength(subject, encoding);
        break;

      case 'object': // Assume object is an array
        this.length = coerce(subject.length);
        break;

      default:
        throw new TypeError('First argument needs to be a number, ' +
                            'array or string.');
    }

    // Treat array-ish objects as a byte array.
    if (isArrayIsh(subject)) {
      for (var i = 0; i < this.length; i++) {
        if (subject instanceof Buffer) {
          this[i] = subject.readUInt8(i);
        }
        else {
          // Round-up subject[i] to a UInt8.
          // e.g.: ((-432 % 256) + 256) % 256 = (-176 + 256) % 256
          //                                  = 80
          this[i] = ((subject[i] % 256) + 256) % 256;
        }
      }
    } else if (type == 'string') {
      // We are a string
      this.length = this.write(subject, 0, encoding);
    } else if (type === 'number') {
      for (var i = 0; i < this.length; i++) {
        this[i] = 0;
      }
    }
  }
}

Buffer.prototype.get = function get(i) {
  if (i < 0 || i >= this.length) throw new Error('oob');
  return this[i];
};

Buffer.prototype.set = function set(i, v) {
  if (i < 0 || i >= this.length) throw new Error('oob');
  return this[i] = v;
};

Buffer.byteLength = function (str, encoding) {
  switch (encoding || "utf8") {
    case 'hex':
      return str.length / 2;

    case 'utf8':
    case 'utf-8':
      return utf8ToBytes(str).length;

    case 'ascii':
    case 'binary':
      return str.length;

    case 'base64':
      return base64ToBytes(str).length;

    default:
      throw new Error('Unknown encoding');
  }
};

Buffer.prototype.utf8Write = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten =  blitBuffer(utf8ToBytes(string), this, offset, length);
};

Buffer.prototype.asciiWrite = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten =  blitBuffer(asciiToBytes(string), this, offset, length);
};

Buffer.prototype.binaryWrite = Buffer.prototype.asciiWrite;

Buffer.prototype.base64Write = function (string, offset, length) {
  var bytes, pos;
  return Buffer._charsWritten = blitBuffer(base64ToBytes(string), this, offset, length);
};

Buffer.prototype.base64Slice = function (start, end) {
  var bytes = Array.prototype.slice.apply(this, arguments)
  return require("base64-js").fromByteArray(bytes);
};

Buffer.prototype.utf8Slice = function () {
  var bytes = Array.prototype.slice.apply(this, arguments);
  var res = "";
  var tmp = "";
  var i = 0;
  while (i < bytes.length) {
    if (bytes[i] <= 0x7F) {
      res += decodeUtf8Char(tmp) + String.fromCharCode(bytes[i]);
      tmp = "";
    } else
      tmp += "%" + bytes[i].toString(16);

    i++;
  }

  return res + decodeUtf8Char(tmp);
}

Buffer.prototype.asciiSlice = function () {
  var bytes = Array.prototype.slice.apply(this, arguments);
  var ret = "";
  for (var i = 0; i < bytes.length; i++)
    ret += String.fromCharCode(bytes[i]);
  return ret;
}

Buffer.prototype.binarySlice = Buffer.prototype.asciiSlice;

Buffer.prototype.inspect = function() {
  var out = [],
      len = this.length;
  for (var i = 0; i < len; i++) {
    out[i] = toHex(this[i]);
    if (i == exports.INSPECT_MAX_BYTES) {
      out[i + 1] = '...';
      break;
    }
  }
  return '<Buffer ' + out.join(' ') + '>';
};


Buffer.prototype.hexSlice = function(start, end) {
  var len = this.length;

  if (!start || start < 0) start = 0;
  if (!end || end < 0 || end > len) end = len;

  var out = '';
  for (var i = start; i < end; i++) {
    out += toHex(this[i]);
  }
  return out;
};


Buffer.prototype.toString = function(encoding, start, end) {
  encoding = String(encoding || 'utf8').toLowerCase();
  start = +start || 0;
  if (typeof end == 'undefined') end = this.length;

  // Fastpath empty strings
  if (+end == start) {
    return '';
  }

  switch (encoding) {
    case 'hex':
      return this.hexSlice(start, end);

    case 'utf8':
    case 'utf-8':
      return this.utf8Slice(start, end);

    case 'ascii':
      return this.asciiSlice(start, end);

    case 'binary':
      return this.binarySlice(start, end);

    case 'base64':
      return this.base64Slice(start, end);

    case 'ucs2':
    case 'ucs-2':
      return this.ucs2Slice(start, end);

    default:
      throw new Error('Unknown encoding');
  }
};


Buffer.prototype.hexWrite = function(string, offset, length) {
  offset = +offset || 0;
  var remaining = this.length - offset;
  if (!length) {
    length = remaining;
  } else {
    length = +length;
    if (length > remaining) {
      length = remaining;
    }
  }

  // must be an even number of digits
  var strLen = string.length;
  if (strLen % 2) {
    throw new Error('Invalid hex string');
  }
  if (length > strLen / 2) {
    length = strLen / 2;
  }
  for (var i = 0; i < length; i++) {
    var b = parseInt(string.substr(i * 2, 2), 16);
    if (isNaN(b)) throw new Error('Invalid hex string');
    this[offset + i] = b;
  }
  Buffer._charsWritten = i * 2;
  return i;
};


Buffer.prototype.write = function(string, offset, length, encoding) {
  // Support both (string, offset, length, encoding)
  // and the legacy (string, encoding, offset, length)
  if (isFinite(offset)) {
    if (!isFinite(length)) {
      encoding = length;
      length = undefined;
    }
  } else {  // legacy
    var swap = encoding;
    encoding = offset;
    offset = length;
    length = swap;
  }

  offset = +offset || 0;
  var remaining = this.length - offset;
  if (!length) {
    length = remaining;
  } else {
    length = +length;
    if (length > remaining) {
      length = remaining;
    }
  }
  encoding = String(encoding || 'utf8').toLowerCase();

  switch (encoding) {
    case 'hex':
      return this.hexWrite(string, offset, length);

    case 'utf8':
    case 'utf-8':
      return this.utf8Write(string, offset, length);

    case 'ascii':
      return this.asciiWrite(string, offset, length);

    case 'binary':
      return this.binaryWrite(string, offset, length);

    case 'base64':
      return this.base64Write(string, offset, length);

    case 'ucs2':
    case 'ucs-2':
      return this.ucs2Write(string, offset, length);

    default:
      throw new Error('Unknown encoding');
  }
};

// slice(start, end)
function clamp(index, len, defaultValue) {
  if (typeof index !== 'number') return defaultValue;
  index = ~~index;  // Coerce to integer.
  if (index >= len) return len;
  if (index >= 0) return index;
  index += len;
  if (index >= 0) return index;
  return 0;
}

Buffer.prototype.slice = function(start, end) {
  var len = this.length;
  start = clamp(start, len, 0);
  end = clamp(end, len, len);
  return new Buffer(this, end - start, +start);
};

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function(target, target_start, start, end) {
  var source = this;
  start || (start = 0);
  if (end === undefined || isNaN(end)) {
    end = this.length;
  }
  target_start || (target_start = 0);

  if (end < start) throw new Error('sourceEnd < sourceStart');

  // Copy 0 bytes; we're done
  if (end === start) return 0;
  if (target.length == 0 || source.length == 0) return 0;

  if (target_start < 0 || target_start >= target.length) {
    throw new Error('targetStart out of bounds');
  }

  if (start < 0 || start >= source.length) {
    throw new Error('sourceStart out of bounds');
  }

  if (end < 0 || end > source.length) {
    throw new Error('sourceEnd out of bounds');
  }

  // Are we oob?
  if (end > this.length) {
    end = this.length;
  }

  if (target.length - target_start < end - start) {
    end = target.length - target_start + start;
  }

  var temp = [];
  for (var i=start; i<end; i++) {
    assert.ok(typeof this[i] !== 'undefined', "copying undefined buffer bytes!");
    temp.push(this[i]);
  }

  for (var i=target_start; i<target_start+temp.length; i++) {
    target[i] = temp[i-target_start];
  }
};

// fill(value, start=0, end=buffer.length)
Buffer.prototype.fill = function fill(value, start, end) {
  value || (value = 0);
  start || (start = 0);
  end || (end = this.length);

  if (typeof value === 'string') {
    value = value.charCodeAt(0);
  }
  if (!(typeof value === 'number') || isNaN(value)) {
    throw new Error('value is not a number');
  }

  if (end < start) throw new Error('end < start');

  // Fill 0 bytes; we're done
  if (end === start) return 0;
  if (this.length == 0) return 0;

  if (start < 0 || start >= this.length) {
    throw new Error('start out of bounds');
  }

  if (end < 0 || end > this.length) {
    throw new Error('end out of bounds');
  }

  for (var i = start; i < end; i++) {
    this[i] = value;
  }
}

// Static methods
Buffer.isBuffer = function isBuffer(b) {
  return b instanceof Buffer;
};

Buffer.concat = function (list, totalLength) {
  if (!isArray(list)) {
    throw new Error("Usage: Buffer.concat(list, [totalLength])\n \
      list should be an Array.");
  }

  if (list.length === 0) {
    return new Buffer(0);
  } else if (list.length === 1) {
    return list[0];
  }

  if (typeof totalLength !== 'number') {
    totalLength = 0;
    for (var i = 0; i < list.length; i++) {
      var buf = list[i];
      totalLength += buf.length;
    }
  }

  var buffer = new Buffer(totalLength);
  var pos = 0;
  for (var i = 0; i < list.length; i++) {
    var buf = list[i];
    buf.copy(buffer, pos);
    pos += buf.length;
  }
  return buffer;
};

Buffer.isEncoding = function(encoding) {
  switch ((encoding + '').toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
    case 'raw':
      return true;

    default:
      return false;
  }
};

// helpers

function coerce(length) {
  // Coerce length to a number (possibly NaN), round up
  // in case it's fractional (e.g. 123.456) then do a
  // double negate to coerce a NaN to 0. Easy, right?
  length = ~~Math.ceil(+length);
  return length < 0 ? 0 : length;
}

function isArray(subject) {
  return (Array.isArray ||
    function(subject){
      return {}.toString.apply(subject) == '[object Array]'
    })
    (subject)
}

function isArrayIsh(subject) {
  return isArray(subject) || Buffer.isBuffer(subject) ||
         subject && typeof subject === 'object' &&
         typeof subject.length === 'number';
}

function toHex(n) {
  if (n < 16) return '0' + n.toString(16);
  return n.toString(16);
}

function utf8ToBytes(str) {
  var byteArray = [];
  for (var i = 0; i < str.length; i++)
    if (str.charCodeAt(i) <= 0x7F)
      byteArray.push(str.charCodeAt(i));
    else {
      var h = encodeURIComponent(str.charAt(i)).substr(1).split('%');
      for (var j = 0; j < h.length; j++)
        byteArray.push(parseInt(h[j], 16));
    }

  return byteArray;
}

function asciiToBytes(str) {
  var byteArray = []
  for (var i = 0; i < str.length; i++ )
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push( str.charCodeAt(i) & 0xFF );

  return byteArray;
}

function base64ToBytes(str) {
  return require("base64-js").toByteArray(str);
}

function blitBuffer(src, dst, offset, length) {
  var pos, i = 0;
  while (i < length) {
    if ((i+offset >= dst.length) || (i >= src.length))
      break;

    dst[i + offset] = src[i];
    i++;
  }
  return i;
}

function decodeUtf8Char(str) {
  try {
    return decodeURIComponent(str);
  } catch (err) {
    return String.fromCharCode(0xFFFD); // UTF 8 invalid char
  }
}

// read/write bit-twiddling

Buffer.prototype.readUInt8 = function(offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return;

  return buffer[offset];
};

function readUInt16(buffer, offset, isBigEndian, noAssert) {
  var val = 0;


  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return 0;

  if (isBigEndian) {
    val = buffer[offset] << 8;
    if (offset + 1 < buffer.length) {
      val |= buffer[offset + 1];
    }
  } else {
    val = buffer[offset];
    if (offset + 1 < buffer.length) {
      val |= buffer[offset + 1] << 8;
    }
  }

  return val;
}

Buffer.prototype.readUInt16LE = function(offset, noAssert) {
  return readUInt16(this, offset, false, noAssert);
};

Buffer.prototype.readUInt16BE = function(offset, noAssert) {
  return readUInt16(this, offset, true, noAssert);
};

function readUInt32(buffer, offset, isBigEndian, noAssert) {
  var val = 0;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return 0;

  if (isBigEndian) {
    if (offset + 1 < buffer.length)
      val = buffer[offset + 1] << 16;
    if (offset + 2 < buffer.length)
      val |= buffer[offset + 2] << 8;
    if (offset + 3 < buffer.length)
      val |= buffer[offset + 3];
    val = val + (buffer[offset] << 24 >>> 0);
  } else {
    if (offset + 2 < buffer.length)
      val = buffer[offset + 2] << 16;
    if (offset + 1 < buffer.length)
      val |= buffer[offset + 1] << 8;
    val |= buffer[offset];
    if (offset + 3 < buffer.length)
      val = val + (buffer[offset + 3] << 24 >>> 0);
  }

  return val;
}

Buffer.prototype.readUInt32LE = function(offset, noAssert) {
  return readUInt32(this, offset, false, noAssert);
};

Buffer.prototype.readUInt32BE = function(offset, noAssert) {
  return readUInt32(this, offset, true, noAssert);
};


/*
 * Signed integer types, yay team! A reminder on how two's complement actually
 * works. The first bit is the signed bit, i.e. tells us whether or not the
 * number should be positive or negative. If the two's complement value is
 * positive, then we're done, as it's equivalent to the unsigned representation.
 *
 * Now if the number is positive, you're pretty much done, you can just leverage
 * the unsigned translations and return those. Unfortunately, negative numbers
 * aren't quite that straightforward.
 *
 * At first glance, one might be inclined to use the traditional formula to
 * translate binary numbers between the positive and negative values in two's
 * complement. (Though it doesn't quite work for the most negative value)
 * Mainly:
 *  - invert all the bits
 *  - add one to the result
 *
 * Of course, this doesn't quite work in Javascript. Take for example the value
 * of -128. This could be represented in 16 bits (big-endian) as 0xff80. But of
 * course, Javascript will do the following:
 *
 * > ~0xff80
 * -65409
 *
 * Whoh there, Javascript, that's not quite right. But wait, according to
 * Javascript that's perfectly correct. When Javascript ends up seeing the
 * constant 0xff80, it has no notion that it is actually a signed number. It
 * assumes that we've input the unsigned value 0xff80. Thus, when it does the
 * binary negation, it casts it into a signed value, (positive 0xff80). Then
 * when you perform binary negation on that, it turns it into a negative number.
 *
 * Instead, we're going to have to use the following general formula, that works
 * in a rather Javascript friendly way. I'm glad we don't support this kind of
 * weird numbering scheme in the kernel.
 *
 * (BIT-MAX - (unsigned)val + 1) * -1
 *
 * The astute observer, may think that this doesn't make sense for 8-bit numbers
 * (really it isn't necessary for them). However, when you get 16-bit numbers,
 * you do. Let's go back to our prior example and see how this will look:
 *
 * (0xffff - 0xff80 + 1) * -1
 * (0x007f + 1) * -1
 * (0x0080) * -1
 */
Buffer.prototype.readInt8 = function(offset, noAssert) {
  var buffer = this;
  var neg;

  if (!noAssert) {
    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to read beyond buffer length');
  }

  if (offset >= buffer.length) return;

  neg = buffer[offset] & 0x80;
  if (!neg) {
    return (buffer[offset]);
  }

  return ((0xff - buffer[offset] + 1) * -1);
};

function readInt16(buffer, offset, isBigEndian, noAssert) {
  var neg, val;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to read beyond buffer length');
  }

  val = readUInt16(buffer, offset, isBigEndian, noAssert);
  neg = val & 0x8000;
  if (!neg) {
    return val;
  }

  return (0xffff - val + 1) * -1;
}

Buffer.prototype.readInt16LE = function(offset, noAssert) {
  return readInt16(this, offset, false, noAssert);
};

Buffer.prototype.readInt16BE = function(offset, noAssert) {
  return readInt16(this, offset, true, noAssert);
};

function readInt32(buffer, offset, isBigEndian, noAssert) {
  var neg, val;

  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  val = readUInt32(buffer, offset, isBigEndian, noAssert);
  neg = val & 0x80000000;
  if (!neg) {
    return (val);
  }

  return (0xffffffff - val + 1) * -1;
}

Buffer.prototype.readInt32LE = function(offset, noAssert) {
  return readInt32(this, offset, false, noAssert);
};

Buffer.prototype.readInt32BE = function(offset, noAssert) {
  return readInt32(this, offset, true, noAssert);
};

function readFloat(buffer, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset + 3 < buffer.length,
        'Trying to read beyond buffer length');
  }

  return require('./buffer_ieee754').readIEEE754(buffer, offset, isBigEndian,
      23, 4);
}

Buffer.prototype.readFloatLE = function(offset, noAssert) {
  return readFloat(this, offset, false, noAssert);
};

Buffer.prototype.readFloatBE = function(offset, noAssert) {
  return readFloat(this, offset, true, noAssert);
};

function readDouble(buffer, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset + 7 < buffer.length,
        'Trying to read beyond buffer length');
  }

  return require('./buffer_ieee754').readIEEE754(buffer, offset, isBigEndian,
      52, 8);
}

Buffer.prototype.readDoubleLE = function(offset, noAssert) {
  return readDouble(this, offset, false, noAssert);
};

Buffer.prototype.readDoubleBE = function(offset, noAssert) {
  return readDouble(this, offset, true, noAssert);
};


/*
 * We have to make sure that the value is a valid integer. This means that it is
 * non-negative. It has no fractional component and that it does not exceed the
 * maximum allowed value.
 *
 *      value           The number to check for validity
 *
 *      max             The maximum value
 */
function verifuint(value, max) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value >= 0,
      'specified a negative value for writing an unsigned value');

  assert.ok(value <= max, 'value is larger than maximum value for type');

  assert.ok(Math.floor(value) === value, 'value has a fractional component');
}

Buffer.prototype.writeUInt8 = function(value, offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xff);
  }

  if (offset < buffer.length) {
    buffer[offset] = value;
  }
};

function writeUInt16(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xffff);
  }

  for (var i = 0; i < Math.min(buffer.length - offset, 2); i++) {
    buffer[offset + i] =
        (value & (0xff << (8 * (isBigEndian ? 1 - i : i)))) >>>
            (isBigEndian ? 1 - i : i) * 8;
  }

}

Buffer.prototype.writeUInt16LE = function(value, offset, noAssert) {
  writeUInt16(this, value, offset, false, noAssert);
};

Buffer.prototype.writeUInt16BE = function(value, offset, noAssert) {
  writeUInt16(this, value, offset, true, noAssert);
};

function writeUInt32(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'trying to write beyond buffer length');

    verifuint(value, 0xffffffff);
  }

  for (var i = 0; i < Math.min(buffer.length - offset, 4); i++) {
    buffer[offset + i] =
        (value >>> (isBigEndian ? 3 - i : i) * 8) & 0xff;
  }
}

Buffer.prototype.writeUInt32LE = function(value, offset, noAssert) {
  writeUInt32(this, value, offset, false, noAssert);
};

Buffer.prototype.writeUInt32BE = function(value, offset, noAssert) {
  writeUInt32(this, value, offset, true, noAssert);
};


/*
 * We now move onto our friends in the signed number category. Unlike unsigned
 * numbers, we're going to have to worry a bit more about how we put values into
 * arrays. Since we are only worrying about signed 32-bit values, we're in
 * slightly better shape. Unfortunately, we really can't do our favorite binary
 * & in this system. It really seems to do the wrong thing. For example:
 *
 * > -32 & 0xff
 * 224
 *
 * What's happening above is really: 0xe0 & 0xff = 0xe0. However, the results of
 * this aren't treated as a signed number. Ultimately a bad thing.
 *
 * What we're going to want to do is basically create the unsigned equivalent of
 * our representation and pass that off to the wuint* functions. To do that
 * we're going to do the following:
 *
 *  - if the value is positive
 *      we can pass it directly off to the equivalent wuint
 *  - if the value is negative
 *      we do the following computation:
 *         mb + val + 1, where
 *         mb   is the maximum unsigned value in that byte size
 *         val  is the Javascript negative integer
 *
 *
 * As a concrete value, take -128. In signed 16 bits this would be 0xff80. If
 * you do out the computations:
 *
 * 0xffff - 128 + 1
 * 0xffff - 127
 * 0xff80
 *
 * You can then encode this value as the signed version. This is really rather
 * hacky, but it should work and get the job done which is our goal here.
 */

/*
 * A series of checks to make sure we actually have a signed 32-bit number
 */
function verifsint(value, max, min) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value <= max, 'value larger than maximum allowed value');

  assert.ok(value >= min, 'value smaller than minimum allowed value');

  assert.ok(Math.floor(value) === value, 'value has a fractional component');
}

function verifIEEE754(value, max, min) {
  assert.ok(typeof (value) == 'number',
      'cannot write a non-number as a number');

  assert.ok(value <= max, 'value larger than maximum allowed value');

  assert.ok(value >= min, 'value smaller than minimum allowed value');
}

Buffer.prototype.writeInt8 = function(value, offset, noAssert) {
  var buffer = this;

  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7f, -0x80);
  }

  if (value >= 0) {
    buffer.writeUInt8(value, offset, noAssert);
  } else {
    buffer.writeUInt8(0xff + value + 1, offset, noAssert);
  }
};

function writeInt16(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 1 < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7fff, -0x8000);
  }

  if (value >= 0) {
    writeUInt16(buffer, value, offset, isBigEndian, noAssert);
  } else {
    writeUInt16(buffer, 0xffff + value + 1, offset, isBigEndian, noAssert);
  }
}

Buffer.prototype.writeInt16LE = function(value, offset, noAssert) {
  writeInt16(this, value, offset, false, noAssert);
};

Buffer.prototype.writeInt16BE = function(value, offset, noAssert) {
  writeInt16(this, value, offset, true, noAssert);
};

function writeInt32(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to write beyond buffer length');

    verifsint(value, 0x7fffffff, -0x80000000);
  }

  if (value >= 0) {
    writeUInt32(buffer, value, offset, isBigEndian, noAssert);
  } else {
    writeUInt32(buffer, 0xffffffff + value + 1, offset, isBigEndian, noAssert);
  }
}

Buffer.prototype.writeInt32LE = function(value, offset, noAssert) {
  writeInt32(this, value, offset, false, noAssert);
};

Buffer.prototype.writeInt32BE = function(value, offset, noAssert) {
  writeInt32(this, value, offset, true, noAssert);
};

function writeFloat(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 3 < buffer.length,
        'Trying to write beyond buffer length');

    verifIEEE754(value, 3.4028234663852886e+38, -3.4028234663852886e+38);
  }

  require('./buffer_ieee754').writeIEEE754(buffer, value, offset, isBigEndian,
      23, 4);
}

Buffer.prototype.writeFloatLE = function(value, offset, noAssert) {
  writeFloat(this, value, offset, false, noAssert);
};

Buffer.prototype.writeFloatBE = function(value, offset, noAssert) {
  writeFloat(this, value, offset, true, noAssert);
};

function writeDouble(buffer, value, offset, isBigEndian, noAssert) {
  if (!noAssert) {
    assert.ok(value !== undefined && value !== null,
        'missing value');

    assert.ok(typeof (isBigEndian) === 'boolean',
        'missing or invalid endian');

    assert.ok(offset !== undefined && offset !== null,
        'missing offset');

    assert.ok(offset + 7 < buffer.length,
        'Trying to write beyond buffer length');

    verifIEEE754(value, 1.7976931348623157E+308, -1.7976931348623157E+308);
  }

  require('./buffer_ieee754').writeIEEE754(buffer, value, offset, isBigEndian,
      52, 8);
}

Buffer.prototype.writeDoubleLE = function(value, offset, noAssert) {
  writeDouble(this, value, offset, false, noAssert);
};

Buffer.prototype.writeDoubleBE = function(value, offset, noAssert) {
  writeDouble(this, value, offset, true, noAssert);
};

}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/buffer-browserify/index.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin/assert.js","mtime":1379366460,"wrapper":"commonjs/leaky","format":"leaky","id":"/__SYSTEM__/assert.js"}
require.memoize("/__SYSTEM__/assert.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin';
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// UTILITY
var util = require('__SYSTEM__/util');
var shims = require('_shims');
var pSlice = Array.prototype.slice;

// 1. The assert module provides functions that throw
// AssertionError's when particular conditions are not met. The
// assert module must conform to the following interface.

var assert = module.exports = ok;

// 2. The AssertionError is defined in assert.
// new assert.AssertionError({ message: message,
//                             actual: actual,
//                             expected: expected })

assert.AssertionError = function AssertionError(options) {
  this.name = 'AssertionError';
  this.actual = options.actual;
  this.expected = options.expected;
  this.operator = options.operator;
  this.message = options.message || getMessage(this);
};

// assert.AssertionError instanceof Error
util.inherits(assert.AssertionError, Error);

function replacer(key, value) {
  if (util.isUndefined(value)) {
    return '' + value;
  }
  if (util.isNumber(value) && (isNaN(value) || !isFinite(value))) {
    return value.toString();
  }
  if (util.isFunction(value) || util.isRegExp(value)) {
    return value.toString();
  }
  return value;
}

function truncate(s, n) {
  if (util.isString(s)) {
    return s.length < n ? s : s.slice(0, n);
  } else {
    return s;
  }
}

function getMessage(self) {
  return truncate(JSON.stringify(self.actual, replacer), 128) + ' ' +
         self.operator + ' ' +
         truncate(JSON.stringify(self.expected, replacer), 128);
}

// At present only the three keys mentioned above are used and
// understood by the spec. Implementations or sub modules can pass
// other keys to the AssertionError's constructor - they will be
// ignored.

// 3. All of the following functions must throw an AssertionError
// when a corresponding condition is not met, with a message that
// may be undefined if not provided.  All assertion methods provide
// both the actual and expected values to the assertion error for
// display purposes.

function fail(actual, expected, message, operator, stackStartFunction) {
  throw new assert.AssertionError({
    message: message,
    actual: actual,
    expected: expected,
    operator: operator,
    stackStartFunction: stackStartFunction
  });
}

// EXTENSION! allows for well behaved errors defined elsewhere.
assert.fail = fail;

// 4. Pure assertion tests whether a value is truthy, as determined
// by !!guard.
// assert.ok(guard, message_opt);
// This statement is equivalent to assert.equal(true, !!guard,
// message_opt);. To test strictly for the value true, use
// assert.strictEqual(true, guard, message_opt);.

function ok(value, message) {
  if (!value) fail(value, true, message, '==', assert.ok);
}
assert.ok = ok;

// 5. The equality assertion tests shallow, coercive equality with
// ==.
// assert.equal(actual, expected, message_opt);

assert.equal = function equal(actual, expected, message) {
  if (actual != expected) fail(actual, expected, message, '==', assert.equal);
};

// 6. The non-equality assertion tests for whether two objects are not equal
// with != assert.notEqual(actual, expected, message_opt);

assert.notEqual = function notEqual(actual, expected, message) {
  if (actual == expected) {
    fail(actual, expected, message, '!=', assert.notEqual);
  }
};

// 7. The equivalence assertion tests a deep equality relation.
// assert.deepEqual(actual, expected, message_opt);

assert.deepEqual = function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    fail(actual, expected, message, 'deepEqual', assert.deepEqual);
  }
};

function _deepEqual(actual, expected) {
  // 7.1. All identical values are equivalent, as determined by ===.
  if (actual === expected) {
    return true;

  } else if (util.isBuffer(actual) && util.isBuffer(expected)) {
    if (actual.length != expected.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] !== expected[i]) return false;
    }

    return true;

  // 7.2. If the expected value is a Date object, the actual value is
  // equivalent if it is also a Date object that refers to the same time.
  } else if (util.isDate(actual) && util.isDate(expected)) {
    return actual.getTime() === expected.getTime();

  // 7.3 If the expected value is a RegExp object, the actual value is
  // equivalent if it is also a RegExp object with the same source and
  // properties (`global`, `multiline`, `lastIndex`, `ignoreCase`).
  } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
    return actual.source === expected.source &&
           actual.global === expected.global &&
           actual.multiline === expected.multiline &&
           actual.lastIndex === expected.lastIndex &&
           actual.ignoreCase === expected.ignoreCase;

  // 7.4. Other pairs that do not both pass typeof value == 'object',
  // equivalence is determined by ==.
  } else if (!util.isObject(actual) && !util.isObject(expected)) {
    return actual == expected;

  // 7.5 For all other Object pairs, including Array objects, equivalence is
  // determined by having the same number of owned properties (as verified
  // with Object.prototype.hasOwnProperty.call), the same set of keys
  // (although not necessarily the same order), equivalent values for every
  // corresponding key, and an identical 'prototype' property. Note: this
  // accounts for both named and indexed properties on Arrays.
  } else {
    return objEquiv(actual, expected);
  }
}

function isArguments(object) {
  return Object.prototype.toString.call(object) == '[object Arguments]';
}

function objEquiv(a, b) {
  if (util.isNullOrUndefined(a) || util.isNullOrUndefined(b))
    return false;
  // an identical 'prototype' property.
  if (a.prototype !== b.prototype) return false;
  //~~~I've managed to break Object.keys through screwy arguments passing.
  //   Converting to array solves the problem.
  if (isArguments(a)) {
    if (!isArguments(b)) {
      return false;
    }
    a = pSlice.call(a);
    b = pSlice.call(b);
    return _deepEqual(a, b);
  }
  try {
    var ka = shims.keys(a),
        kb = shims.keys(b),
        key, i;
  } catch (e) {//happens when one is a string literal and the other isn't
    return false;
  }
  // having the same number of owned properties (keys incorporates
  // hasOwnProperty)
  if (ka.length != kb.length)
    return false;
  //the same set of keys (although not necessarily the same order),
  ka.sort();
  kb.sort();
  //~~~cheap key test
  for (i = ka.length - 1; i >= 0; i--) {
    if (ka[i] != kb[i])
      return false;
  }
  //equivalent values for every corresponding key, and
  //~~~possibly expensive deep test
  for (i = ka.length - 1; i >= 0; i--) {
    key = ka[i];
    if (!_deepEqual(a[key], b[key])) return false;
  }
  return true;
}

// 8. The non-equivalence assertion tests for any deep inequality.
// assert.notDeepEqual(actual, expected, message_opt);

assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    fail(actual, expected, message, 'notDeepEqual', assert.notDeepEqual);
  }
};

// 9. The strict equality assertion tests strict equality, as determined by ===.
// assert.strictEqual(actual, expected, message_opt);

assert.strictEqual = function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(actual, expected, message, '===', assert.strictEqual);
  }
};

// 10. The strict non-equality assertion tests for strict inequality, as
// determined by !==.  assert.notStrictEqual(actual, expected, message_opt);

assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    fail(actual, expected, message, '!==', assert.notStrictEqual);
  }
};

function expectedException(actual, expected) {
  if (!actual || !expected) {
    return false;
  }

  if (Object.prototype.toString.call(expected) == '[object RegExp]') {
    return expected.test(actual);
  } else if (actual instanceof expected) {
    return true;
  } else if (expected.call({}, actual) === true) {
    return true;
  }

  return false;
}

function _throws(shouldThrow, block, expected, message) {
  var actual;

  if (util.isString(expected)) {
    message = expected;
    expected = null;
  }

  try {
    block();
  } catch (e) {
    actual = e;
  }

  message = (expected && expected.name ? ' (' + expected.name + ').' : '.') +
            (message ? ' ' + message : '.');

  if (shouldThrow && !actual) {
    fail(actual, expected, 'Missing expected exception' + message);
  }

  if (!shouldThrow && expectedException(actual, expected)) {
    fail(actual, expected, 'Got unwanted exception' + message);
  }

  if ((shouldThrow && actual && expected &&
      !expectedException(actual, expected)) || (!shouldThrow && actual)) {
    throw actual;
  }
}

// 11. Expected to throw an error:
// assert.throws(block, Error_opt, message_opt);

assert.throws = function(block, /*optional*/error, /*optional*/message) {
  _throws.apply(this, [true].concat(pSlice.call(arguments)));
};

// EXTENSION! This is annoying to write outside this module.
assert.doesNotThrow = function(block, /*optional*/message) {
  _throws.apply(this, [false].concat(pSlice.call(arguments)));
};

assert.ifError = function(err) { if (err) {throw err;}};
return {
    util: (typeof util !== "undefined") ? util : null,
    require: (typeof require !== "undefined") ? require : null,
    shims: (typeof shims !== "undefined") ? shims : null,
    pSlice: (typeof pSlice !== "undefined") ? pSlice : null,
    Array: (typeof Array !== "undefined") ? Array : null,
    assert: (typeof assert !== "undefined") ? assert : null,
    module: (typeof module !== "undefined") ? module : null,
    getMessage: (typeof getMessage !== "undefined") ? getMessage : null,
    Error: (typeof Error !== "undefined") ? Error : null,
    replacer: (typeof replacer !== "undefined") ? replacer : null,
    isNaN: (typeof isNaN !== "undefined") ? isNaN : null,
    isFinite: (typeof isFinite !== "undefined") ? isFinite : null,
    truncate: (typeof truncate !== "undefined") ? truncate : null,
    JSON: (typeof JSON !== "undefined") ? JSON : null,
    fail: (typeof fail !== "undefined") ? fail : null,
    ok: (typeof ok !== "undefined") ? ok : null,
    _deepEqual: (typeof _deepEqual !== "undefined") ? _deepEqual : null,
    objEquiv: (typeof objEquiv !== "undefined") ? objEquiv : null,
    isArguments: (typeof isArguments !== "undefined") ? isArguments : null,
    Object: (typeof Object !== "undefined") ? Object : null,
    expectedException: (typeof expectedException !== "undefined") ? expectedException : null,
    _throws: (typeof _throws !== "undefined") ? _throws : null
};
}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin/assert.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin/util.js","mtime":1381856208,"wrapper":"commonjs","format":"commonjs","id":"/__SYSTEM__/util.js"}
require.memoize("/__SYSTEM__/util.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin';
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var shims = require('_shims');

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};

/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  shims.forEach(array, function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = shims.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = shims.getOwnPropertyNames(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }

  shims.forEach(keys, function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = shims.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }

  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (shims.indexOf(ctx.seen, desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = shims.reduce(output, function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return shims.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) && objectToString(e) === '[object Error]';
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.binarySlice === 'function'
  ;
}
exports.isBuffer = isBuffer;

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = function(ctor, superCtor) {
  ctor.super_ = superCtor;
  ctor.prototype = shims.create(superCtor.prototype, {
    constructor: {
      value: ctor,
      enumerable: false,
      writable: true,
      configurable: true
    }
  });
};

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = shims.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin/util.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin/_shims.js","mtime":1379366460,"wrapper":"commonjs","format":"commonjs","id":"/__SYSTEM__/_shims.js"}
require.memoize("/__SYSTEM__/_shims.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin';


//
// The shims in this file are not fully implemented shims for the ES5
// features, but do work for the particular usecases there is in
// the other modules.
//

var toString = Object.prototype.toString;
var hasOwnProperty = Object.prototype.hasOwnProperty;

// Array.isArray is supported in IE9
function isArray(xs) {
  return toString.call(xs) === '[object Array]';
}
exports.isArray = typeof Array.isArray === 'function' ? Array.isArray : isArray;

// Array.prototype.indexOf is supported in IE9
exports.indexOf = function indexOf(xs, x) {
  if (xs.indexOf) return xs.indexOf(x);
  for (var i = 0; i < xs.length; i++) {
    if (x === xs[i]) return i;
  }
  return -1;
};

// Array.prototype.filter is supported in IE9
exports.filter = function filter(xs, fn) {
  if (xs.filter) return xs.filter(fn);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    if (fn(xs[i], i, xs)) res.push(xs[i]);
  }
  return res;
};

// Array.prototype.forEach is supported in IE9
exports.forEach = function forEach(xs, fn, self) {
  if (xs.forEach) return xs.forEach(fn, self);
  for (var i = 0; i < xs.length; i++) {
    fn.call(self, xs[i], i, xs);
  }
};

// Array.prototype.map is supported in IE9
exports.map = function map(xs, fn) {
  if (xs.map) return xs.map(fn);
  var out = new Array(xs.length);
  for (var i = 0; i < xs.length; i++) {
    out[i] = fn(xs[i], i, xs);
  }
  return out;
};

// Array.prototype.reduce is supported in IE9
exports.reduce = function reduce(array, callback, opt_initialValue) {
  if (array.reduce) return array.reduce(callback, opt_initialValue);
  var value, isValueSet = false;

  if (2 < arguments.length) {
    value = opt_initialValue;
    isValueSet = true;
  }
  for (var i = 0, l = array.length; l > i; ++i) {
    if (array.hasOwnProperty(i)) {
      if (isValueSet) {
        value = callback(value, array[i], i, array);
      }
      else {
        value = array[i];
        isValueSet = true;
      }
    }
  }

  return value;
};

// String.prototype.substr - negative index don't work in IE8
if ('ab'.substr(-1) !== 'b') {
  exports.substr = function (str, start, length) {
    // did we get a negative start, calculate how much it is from the beginning of the string
    if (start < 0) start = str.length + start;

    // call the original function
    return str.substr(start, length);
  };
} else {
  exports.substr = function (str, start, length) {
    return str.substr(start, length);
  };
}

// String.prototype.trim is supported in IE9
exports.trim = function (str) {
  if (str.trim) return str.trim();
  return str.replace(/^\s+|\s+$/g, '');
};

// Function.prototype.bind is supported in IE9
exports.bind = function () {
  var args = Array.prototype.slice.call(arguments);
  var fn = args.shift();
  if (fn.bind) return fn.bind.apply(fn, args);
  var self = args.shift();
  return function () {
    fn.apply(self, args.concat([Array.prototype.slice.call(arguments)]));
  };
};

// Object.create is supported in IE9
function create(prototype, properties) {
  var object;
  if (prototype === null) {
    object = { '__proto__' : null };
  }
  else {
    if (typeof prototype !== 'object') {
      throw new TypeError(
        'typeof prototype[' + (typeof prototype) + '] != \'object\''
      );
    }
    var Type = function () {};
    Type.prototype = prototype;
    object = new Type();
    object.__proto__ = prototype;
  }
  if (typeof properties !== 'undefined' && Object.defineProperties) {
    Object.defineProperties(object, properties);
  }
  return object;
}
exports.create = typeof Object.create === 'function' ? Object.create : create;

// Object.keys and Object.getOwnPropertyNames is supported in IE9 however
// they do show a description and number property on Error objects
function notObject(object) {
  return ((typeof object != "object" && typeof object != "function") || object === null);
}

function keysShim(object) {
  if (notObject(object)) {
    throw new TypeError("Object.keys called on a non-object");
  }

  var result = [];
  for (var name in object) {
    if (hasOwnProperty.call(object, name)) {
      result.push(name);
    }
  }
  return result;
}

// getOwnPropertyNames is almost the same as Object.keys one key feature
//  is that it returns hidden properties, since that can't be implemented,
//  this feature gets reduced so it just shows the length property on arrays
function propertyShim(object) {
  if (notObject(object)) {
    throw new TypeError("Object.getOwnPropertyNames called on a non-object");
  }

  var result = keysShim(object);
  if (exports.isArray(object) && exports.indexOf(object, 'length') === -1) {
    result.push('length');
  }
  return result;
}

var keys = typeof Object.keys === 'function' ? Object.keys : keysShim;
var getOwnPropertyNames = typeof Object.getOwnPropertyNames === 'function' ?
  Object.getOwnPropertyNames : propertyShim;

if (new Error().hasOwnProperty('description')) {
  var ERROR_PROPERTY_FILTER = function (obj, array) {
    if (toString.call(obj) === '[object Error]') {
      array = exports.filter(array, function (name) {
        return name !== 'description' && name !== 'number' && name !== 'message';
      });
    }
    return array;
  };

  exports.keys = function (object) {
    return ERROR_PROPERTY_FILTER(object, keys(object));
  };
  exports.getOwnPropertyNames = function (object) {
    return ERROR_PROPERTY_FILTER(object, getOwnPropertyNames(object));
  };
} else {
  exports.keys = keys;
  exports.getOwnPropertyNames = getOwnPropertyNames;
}

// Object.getOwnPropertyDescriptor - supported in IE8 but only on dom elements
function valueObject(value, key) {
  return { value: value[key] };
}

if (typeof Object.getOwnPropertyDescriptor === 'function') {
  try {
    Object.getOwnPropertyDescriptor({'a': 1}, 'a');
    exports.getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  } catch (e) {
    // IE8 dom element issue - use a try catch and default to valueObject
    exports.getOwnPropertyDescriptor = function (value, key) {
      try {
        return Object.getOwnPropertyDescriptor(value, key);
      } catch (e) {
        return valueObject(value, key);
      }
    };
  }
} else {
  exports.getOwnPropertyDescriptor = valueObject;
}

}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/builtin/_shims.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/buffer-browserify/buffer_ieee754.js","mtime":1418900069,"wrapper":"commonjs","format":"commonjs","id":"/__SYSTEM__/buffer_ieee754.js"}
require.memoize("/__SYSTEM__/buffer_ieee754.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/buffer-browserify';
exports.readIEEE754 = function(buffer, offset, isBE, mLen, nBytes) {
  var e, m,
      eLen = nBytes * 8 - mLen - 1,
      eMax = (1 << eLen) - 1,
      eBias = eMax >> 1,
      nBits = -7,
      i = isBE ? 0 : (nBytes - 1),
      d = isBE ? 1 : -1,
      s = buffer[offset + i];

  i += d;

  e = s & ((1 << (-nBits)) - 1);
  s >>= (-nBits);
  nBits += eLen;
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8);

  m = e & ((1 << (-nBits)) - 1);
  e >>= (-nBits);
  nBits += mLen;
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8);

  if (e === 0) {
    e = 1 - eBias;
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity);
  } else {
    m = m + Math.pow(2, mLen);
    e = e - eBias;
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
};

exports.writeIEEE754 = function(buffer, value, offset, isBE, mLen, nBytes) {
  var e, m, c,
      eLen = nBytes * 8 - mLen - 1,
      eMax = (1 << eLen) - 1,
      eBias = eMax >> 1,
      rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0),
      i = isBE ? (nBytes - 1) : 0,
      d = isBE ? -1 : 1,
      s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0;

  value = Math.abs(value);

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0;
    e = eMax;
  } else {
    e = Math.floor(Math.log(value) / Math.LN2);
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--;
      c *= 2;
    }
    if (e + eBias >= 1) {
      value += rt / c;
    } else {
      value += rt * Math.pow(2, 1 - eBias);
    }
    if (value * c >= 2) {
      e++;
      c /= 2;
    }

    if (e + eBias >= eMax) {
      m = 0;
      e = eMax;
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen);
      e = e + eBias;
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
      e = 0;
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8);

  e = (e << mLen) | m;
  eLen += mLen;
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8);

  buffer[offset + i - d] |= s * 128;
};

}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/buffer-browserify/buffer_ieee754.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/sha.js","mtime":1384879954,"wrapper":"commonjs/leaky","format":"leaky","id":"/__SYSTEM__/sha.js"}
require.memoize("/__SYSTEM__/sha.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify';
/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

var helpers = require('./helpers');

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

module.exports = function sha1(buf) {
  return helpers.hash(buf, core_sha1, 20, true);
};

return {
    helpers: (typeof helpers !== "undefined") ? helpers : null,
    require: (typeof require !== "undefined") ? require : null,
    core_sha1: (typeof core_sha1 !== "undefined") ? core_sha1 : null,
    Array: (typeof Array !== "undefined") ? Array : null,
    rol: (typeof rol !== "undefined") ? rol : null,
    safe_add: (typeof safe_add !== "undefined") ? safe_add : null,
    sha1_ft: (typeof sha1_ft !== "undefined") ? sha1_ft : null,
    j: (typeof j !== "undefined") ? j : null,
    sha1_kt: (typeof sha1_kt !== "undefined") ? sha1_kt : null,
    module: (typeof module !== "undefined") ? module : null
};
}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/sha.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/helpers.js","mtime":1383545597,"wrapper":"commonjs/leaky","format":"leaky","id":"/__SYSTEM__/helpers.js"}
require.memoize("/__SYSTEM__/helpers.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify';
var Buffer = require('__SYSTEM__/buffer').Buffer;
var intSize = 4;
var zeroBuffer = new Buffer(intSize); zeroBuffer.fill(0);
var chrsz = 8;

function toArray(buf, bigEndian) {
  if ((buf.length % intSize) !== 0) {
    var len = buf.length + (intSize - (buf.length % intSize));
    buf = Buffer.concat([buf, zeroBuffer], len);
  }

  var arr = [];
  var fn = bigEndian ? buf.readInt32BE : buf.readInt32LE;
  for (var i = 0; i < buf.length; i += intSize) {
    arr.push(fn.call(buf, i));
  }
  return arr;
}

function toBuffer(arr, size, bigEndian) {
  var buf = new Buffer(size);
  var fn = bigEndian ? buf.writeInt32BE : buf.writeInt32LE;
  for (var i = 0; i < arr.length; i++) {
    fn.call(buf, arr[i], i * 4, true);
  }
  return buf;
}

function hash(buf, fn, hashSize, bigEndian) {
  if (!Buffer.isBuffer(buf)) buf = new Buffer(buf);
  var arr = fn(toArray(buf, bigEndian), buf.length * chrsz);
  return toBuffer(arr, hashSize, bigEndian);
}

module.exports = { hash: hash };

return {
    Buffer: (typeof Buffer !== "undefined") ? Buffer : null,
    require: (typeof require !== "undefined") ? require : null,
    intSize: (typeof intSize !== "undefined") ? intSize : null,
    zeroBuffer: (typeof zeroBuffer !== "undefined") ? zeroBuffer : null,
    chrsz: (typeof chrsz !== "undefined") ? chrsz : null,
    toArray: (typeof toArray !== "undefined") ? toArray : null,
    i: (typeof i !== "undefined") ? i : null,
    toBuffer: (typeof toBuffer !== "undefined") ? toBuffer : null,
    hash: (typeof hash !== "undefined") ? hash : null,
    module: (typeof module !== "undefined") ? module : null
};
}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/helpers.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/sha256.js","mtime":1383545597,"wrapper":"commonjs/leaky","format":"leaky","id":"/__SYSTEM__/sha256.js"}
require.memoize("/__SYSTEM__/sha256.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify';

/**
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-256, as defined
 * in FIPS 180-2
 * Version 2.2-beta Copyright Angel Marin, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 *
 */

var helpers = require('./helpers');

var safe_add = function(x, y) {
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
};

var S = function(X, n) {
  return (X >>> n) | (X << (32 - n));
};

var R = function(X, n) {
  return (X >>> n);
};

var Ch = function(x, y, z) {
  return ((x & y) ^ ((~x) & z));
};

var Maj = function(x, y, z) {
  return ((x & y) ^ (x & z) ^ (y & z));
};

var Sigma0256 = function(x) {
  return (S(x, 2) ^ S(x, 13) ^ S(x, 22));
};

var Sigma1256 = function(x) {
  return (S(x, 6) ^ S(x, 11) ^ S(x, 25));
};

var Gamma0256 = function(x) {
  return (S(x, 7) ^ S(x, 18) ^ R(x, 3));
};

var Gamma1256 = function(x) {
  return (S(x, 17) ^ S(x, 19) ^ R(x, 10));
};

var core_sha256 = function(m, l) {
  var K = new Array(0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,0xE49B69C1,0xEFBE4786,0xFC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x6CA6351,0x14292967,0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2);
  var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
    var W = new Array(64);
    var a, b, c, d, e, f, g, h, i, j;
    var T1, T2;
  /* append padding */
  m[l >> 5] |= 0x80 << (24 - l % 32);
  m[((l + 64 >> 9) << 4) + 15] = l;
  for (var i = 0; i < m.length; i += 16) {
    a = HASH[0]; b = HASH[1]; c = HASH[2]; d = HASH[3]; e = HASH[4]; f = HASH[5]; g = HASH[6]; h = HASH[7];
    for (var j = 0; j < 64; j++) {
      if (j < 16) {
        W[j] = m[j + i];
      } else {
        W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
      }
      T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
      T2 = safe_add(Sigma0256(a), Maj(a, b, c));
      h = g; g = f; f = e; e = safe_add(d, T1); d = c; c = b; b = a; a = safe_add(T1, T2);
    }
    HASH[0] = safe_add(a, HASH[0]); HASH[1] = safe_add(b, HASH[1]); HASH[2] = safe_add(c, HASH[2]); HASH[3] = safe_add(d, HASH[3]);
    HASH[4] = safe_add(e, HASH[4]); HASH[5] = safe_add(f, HASH[5]); HASH[6] = safe_add(g, HASH[6]); HASH[7] = safe_add(h, HASH[7]);
  }
  return HASH;
};

module.exports = function sha256(buf) {
  return helpers.hash(buf, core_sha256, 32, true);
};

return {
    helpers: (typeof helpers !== "undefined") ? helpers : null,
    require: (typeof require !== "undefined") ? require : null,
    safe_add: (typeof safe_add !== "undefined") ? safe_add : null,
    S: (typeof S !== "undefined") ? S : null,
    R: (typeof R !== "undefined") ? R : null,
    Ch: (typeof Ch !== "undefined") ? Ch : null,
    Maj: (typeof Maj !== "undefined") ? Maj : null,
    Sigma0256: (typeof Sigma0256 !== "undefined") ? Sigma0256 : null,
    Sigma1256: (typeof Sigma1256 !== "undefined") ? Sigma1256 : null,
    Gamma0256: (typeof Gamma0256 !== "undefined") ? Gamma0256 : null,
    Gamma1256: (typeof Gamma1256 !== "undefined") ? Gamma1256 : null,
    core_sha256: (typeof core_sha256 !== "undefined") ? core_sha256 : null,
    module: (typeof module !== "undefined") ? module : null
};
}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/sha256.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/rng.js","mtime":1385529373,"wrapper":"commonjs/leaky","format":"leaky","id":"/__SYSTEM__/rng.js"}
require.memoize("/__SYSTEM__/rng.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify';
// Original code adapted from Robert Kieffer.
// details at https://github.com/broofa/node-uuid
(function() {
  var _global = this;

  var mathRNG, whatwgRNG;

  // NOTE: Math.random() does not guarantee "cryptographic quality"
  mathRNG = function(size) {
    var bytes = new Array(size);
    var r;

    for (var i = 0, r; i < size; i++) {
      if ((i & 0x03) == 0) r = Math.random() * 0x100000000;
      bytes[i] = r >>> ((i & 0x03) << 3) & 0xff;
    }

    return bytes;
  }

  if (_global.crypto && crypto.getRandomValues) {
    whatwgRNG = function(size) {
      var bytes = new Uint8Array(size);
      crypto.getRandomValues(bytes);
      return bytes;
    }
  }

  module.exports = whatwgRNG || mathRNG;

}())

return {
    Math: (typeof Math !== "undefined") ? Math : null,
    crypto: (typeof crypto !== "undefined") ? crypto : null,
    module: (typeof module !== "undefined") ? module : null
};
}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/rng.js"});
// @pinf-bundle-module: {"file":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/md5.js","mtime":1383545597,"wrapper":"commonjs/leaky","format":"leaky","id":"/__SYSTEM__/md5.js"}
require.memoize("/__SYSTEM__/md5.js", 
function(require, exports, module) {var __dirname = 'genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify';
/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

var helpers = require('./helpers');

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc") == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length
 */
function core_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);

}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

module.exports = function md5(buf) {
  return helpers.hash(buf, core_md5, 16);
};

return {
    helpers: (typeof helpers !== "undefined") ? helpers : null,
    require: (typeof require !== "undefined") ? require : null,
    md5_vm_test: (typeof md5_vm_test !== "undefined") ? md5_vm_test : null,
    hex_md5: (typeof hex_md5 !== "undefined") ? hex_md5 : null,
    core_md5: (typeof core_md5 !== "undefined") ? core_md5 : null,
    md5_ff: (typeof md5_ff !== "undefined") ? md5_ff : null,
    md5_gg: (typeof md5_gg !== "undefined") ? md5_gg : null,
    md5_hh: (typeof md5_hh !== "undefined") ? md5_hh : null,
    md5_ii: (typeof md5_ii !== "undefined") ? md5_ii : null,
    safe_add: (typeof safe_add !== "undefined") ? safe_add : null,
    Array: (typeof Array !== "undefined") ? Array : null,
    md5_cmn: (typeof md5_cmn !== "undefined") ? md5_cmn : null,
    bit_rol: (typeof bit_rol !== "undefined") ? bit_rol : null,
    module: (typeof module !== "undefined") ? module : null
};
}
, {"filename":"/genesis/os.inception/services/2-it.pinf/pinf-it-bundler/node_modules/browser-builtins/node_modules/crypto-browserify/md5.js"});
// @pinf-bundle-module: {"file":"ecc.js","mtime":1423006723,"wrapper":"commonjs/leaky","format":"leaky","id":"/ecc.js"}
require.memoize("/ecc.js", 
function(require, exports, module) {var __dirname = '';

// @source https://github.com/jpillora/eccjs/blob/11fece9ad4419be74a270095b1391da4d76c25e8/src/ecc.js

const SJCL = require("sjcl");

var ecc = {},
    DEFAULT_CURVE = 192,
    ENC_DEC = ecc.ENC_DEC = {},
    SIG_VER = ecc.SIG_VER = {},
    elg = eccAPI('elGamal'),
    dsa = eccAPI('ecdsa'),
    sha256 = hashAPI('sha256');

ecc.sjcl = SJCL;

ecc.generate = function(type, curve) {
  if(!curve)
    curve = DEFAULT_CURVE;
  var keys, pub, sec;
  if(type === ENC_DEC) {
    pub = 'enc';
    sec = 'dec';
    keys = elg.generate(curve);
  } else if(type === SIG_VER) {
    pub = 'ver';
    sec = 'sig';
    keys = dsa.generate(curve);
  } else
    throw "eccjs: generate: Unknown type";

  var newkeys = {};
  newkeys[pub] = exportPublic(keys.pub);
  newkeys[sec] = exportSecret(keys.sec);
  return newkeys;
};

var cache = {
  enc: {}, dec: {}, sig: {}, ver: {}
};

ecc.encrypt = function(enckey, plaintext) {
  var kem = cache.enc[enckey];

  if(!kem) {
    kem = cache.enc[enckey] = elg.importPublic(enckey).kem();
    kem.tagHex = SJCL.codec.hex.fromBits(kem.tag);
  }

  var obj = SJCL.json._encrypt(kem.key, plaintext);
  obj.tag = kem.tagHex;

  return JSON.stringify(obj);
};


ecc.decrypt = function(deckey, ciphertext) {
  var obj = JSON.parse(ciphertext);

  var kem = cache.dec[deckey];
  if(!kem) {
    kem = cache.dec[deckey] = elg.importSecret(deckey);
    kem.$keys = {};
  }

  var key = kem.$keys[obj.tag];
  if(!key)
    key = kem.$keys[obj.tag] = kem.unkem(SJCL.codec.hex.toBits(obj.tag));

  return SJCL.json._decrypt(key, obj);
};

ecc.sign = function(sigkey, text, hash) {
  var key = cache.sig[sigkey];
  if(!key)
    key = cache.sig[sigkey] = dsa.importSecret(sigkey);

  //hash first
  if(hash !== false)
    text = sha256.hash(text);

  return key.sign(text);
};

ecc.verify = function(verkey, signature, text, hash) {
  var key = cache.ver[verkey];
  if(!key)
    key = cache.ver[verkey] = dsa.importPublic(verkey);

  //hash first
  if(hash !== false)
    text = sha256.hash(text);

  try {
    return key.verify(text, signature);
  } catch(e) {
    return false;
  }
};


//ecc algorithm helpers
function eccAPI(algoName) {
  var algo = SJCL.ecc[algoName];
  if(!algo)
    throw new Error("Missing ECC algorithm: " + algoName);
  return {
    generate: function(curve) {
      var keys = algo.generateKeys(curve, 1);
      keys.pub.$curve = curve;
      keys.sec.$curve = curve;
      return keys;
    },
    importPublic: function(keyStr) {
      var key = extract(keyStr);
      return new algo.publicKey(key.curve, SJCL.codec.hex.toBits(key.hex));
    },
    importSecret: function(keyStr) {
      var key = extract(keyStr);
      return new algo.secretKey(key.curve, new SJCL.bn(key.hex));
    }
  };
}

function extract(str) {
  return {
    curve: SJCL.ecc.curves['c'+str.substr(0, 3)],
    hex: str.substr(3)
  };
}

function exportPublic(keyObj) {
  var obj = keyObj.get();
  return keyObj.$curve +
         SJCL.codec.hex.fromBits(obj.x) +
         SJCL.codec.hex.fromBits(obj.y);
}
function exportSecret(keyObj) {
  return keyObj.$curve + SJCL.codec.hex.fromBits(keyObj.get());
}

//hash algorithm helpers
function hashAPI(algoName) {
  var algo = SJCL.hash[algoName];
  if(!algo)
    throw new Error("Missing hash algorithm: " + algoName);
  return {
    hash: function(input) {
      return algo.hash(input);
    }
  };
}

module.exports = ecc;

return {
    SJCL: (typeof SJCL !== "undefined") ? SJCL : null,
    require: (typeof require !== "undefined") ? require : null,
    ecc: (typeof ecc !== "undefined") ? ecc : null,
    DEFAULT_CURVE: (typeof DEFAULT_CURVE !== "undefined") ? DEFAULT_CURVE : null,
    ENC_DEC: (typeof ENC_DEC !== "undefined") ? ENC_DEC : null,
    SIG_VER: (typeof SIG_VER !== "undefined") ? SIG_VER : null,
    elg: (typeof elg !== "undefined") ? elg : null,
    eccAPI: (typeof eccAPI !== "undefined") ? eccAPI : null,
    dsa: (typeof dsa !== "undefined") ? dsa : null,
    sha256: (typeof sha256 !== "undefined") ? sha256 : null,
    hashAPI: (typeof hashAPI !== "undefined") ? hashAPI : null,
    exportPublic: (typeof exportPublic !== "undefined") ? exportPublic : null,
    exportSecret: (typeof exportSecret !== "undefined") ? exportSecret : null,
    cache: (typeof cache !== "undefined") ? cache : null,
    JSON: (typeof JSON !== "undefined") ? JSON : null,
    extract: (typeof extract !== "undefined") ? extract : null,
    module: (typeof module !== "undefined") ? module : null
};
}
, {"filename":"ecc.js"});
// @pinf-bundle-module: {"file":null,"mtime":0,"wrapper":"json","format":"json","id":"/package.json"}
require.memoize("/package.json", 
{
    "main": "/sandbox.js",
    "mappings": {
        "sjcl": "74aebe51583a1aa6e83b78461af89adfd8bb7cda-sjcl",
        "store": "fead16835712bc873dda7a42db9dd87bb2d59825-store"
    },
    "dirpath": "."
}
, {"filename":"./package.json"});
// @pinf-bundle-module: {"file":null,"mtime":0,"wrapper":"json","format":"json","id":"74aebe51583a1aa6e83b78461af89adfd8bb7cda-sjcl/package.json"}
require.memoize("74aebe51583a1aa6e83b78461af89adfd8bb7cda-sjcl/package.json", 
{
    "main": "74aebe51583a1aa6e83b78461af89adfd8bb7cda-sjcl/sjcl.js",
    "dirpath": "../node_modules/sjcl"
}
, {"filename":"../node_modules/sjcl/package.json"});
// @pinf-bundle-module: {"file":"../node_modules/store/store.js","mtime":1416793335,"wrapper":"amd-ish","format":"amd-ish","id":"fead16835712bc873dda7a42db9dd87bb2d59825-store/store.js"}
require.memoize("fead16835712bc873dda7a42db9dd87bb2d59825-store/store.js", 
wrapAMD(function(require, define) {
;(function(win){
	var store = {},
		doc = win.document,
		localStorageName = 'localStorage',
		scriptTag = 'script',
		storage

	store.disabled = false
	store.version = '1.3.17'
	store.set = function(key, value) {}
	store.get = function(key, defaultVal) {}
	store.has = function(key) { return store.get(key) !== undefined }
	store.remove = function(key) {}
	store.clear = function() {}
	store.transact = function(key, defaultVal, transactionFn) {
		if (transactionFn == null) {
			transactionFn = defaultVal
			defaultVal = null
		}
		if (defaultVal == null) {
			defaultVal = {}
		}
		var val = store.get(key, defaultVal)
		transactionFn(val)
		store.set(key, val)
	}
	store.getAll = function() {}
	store.forEach = function() {}

	store.serialize = function(value) {
		return JSON.stringify(value)
	}
	store.deserialize = function(value) {
		if (typeof value != 'string') { return undefined }
		try { return JSON.parse(value) }
		catch(e) { return value || undefined }
	}

	// Functions to encapsulate questionable FireFox 3.6.13 behavior
	// when about.config::dom.storage.enabled === false
	// See https://github.com/marcuswestin/store.js/issues#issue/13
	function isLocalStorageNameSupported() {
		try { return (localStorageName in win && win[localStorageName]) }
		catch(err) { return false }
	}

	if (isLocalStorageNameSupported()) {
		storage = win[localStorageName]
		store.set = function(key, val) {
			if (val === undefined) { return store.remove(key) }
			storage.setItem(key, store.serialize(val))
			return val
		}
		store.get = function(key, defaultVal) {
			var val = store.deserialize(storage.getItem(key))
			return (val === undefined ? defaultVal : val)
		}
		store.remove = function(key) { storage.removeItem(key) }
		store.clear = function() { storage.clear() }
		store.getAll = function() {
			var ret = {}
			store.forEach(function(key, val) {
				ret[key] = val
			})
			return ret
		}
		store.forEach = function(callback) {
			for (var i=0; i<storage.length; i++) {
				var key = storage.key(i)
				callback(key, store.get(key))
			}
		}
	} else if (doc.documentElement.addBehavior) {
		var storageOwner,
			storageContainer
		// Since #userData storage applies only to specific paths, we need to
		// somehow link our data to a specific path.  We choose /favicon.ico
		// as a pretty safe option, since all browsers already make a request to
		// this URL anyway and being a 404 will not hurt us here.  We wrap an
		// iframe pointing to the favicon in an ActiveXObject(htmlfile) object
		// (see: http://msdn.microsoft.com/en-us/library/aa752574(v=VS.85).aspx)
		// since the iframe access rules appear to allow direct access and
		// manipulation of the document element, even for a 404 page.  This
		// document can be used instead of the current document (which would
		// have been limited to the current path) to perform #userData storage.
		try {
			storageContainer = new ActiveXObject('htmlfile')
			storageContainer.open()
			storageContainer.write('<'+scriptTag+'>document.w=window</'+scriptTag+'><iframe src="/favicon.ico"></iframe>')
			storageContainer.close()
			storageOwner = storageContainer.w.frames[0].document
			storage = storageOwner.createElement('div')
		} catch(e) {
			// somehow ActiveXObject instantiation failed (perhaps some special
			// security settings or otherwse), fall back to per-path storage
			storage = doc.createElement('div')
			storageOwner = doc.body
		}
		var withIEStorage = function(storeFunction) {
			return function() {
				var args = Array.prototype.slice.call(arguments, 0)
				args.unshift(storage)
				// See http://msdn.microsoft.com/en-us/library/ms531081(v=VS.85).aspx
				// and http://msdn.microsoft.com/en-us/library/ms531424(v=VS.85).aspx
				storageOwner.appendChild(storage)
				storage.addBehavior('#default#userData')
				storage.load(localStorageName)
				var result = storeFunction.apply(store, args)
				storageOwner.removeChild(storage)
				return result
			}
		}

		// In IE7, keys cannot start with a digit or contain certain chars.
		// See https://github.com/marcuswestin/store.js/issues/40
		// See https://github.com/marcuswestin/store.js/issues/83
		var forbiddenCharsRegex = new RegExp("[!\"#$%&'()*+,/\\\\:;<=>?@[\\]^`{|}~]", "g")
		function ieKeyFix(key) {
			return key.replace(/^d/, '___$&').replace(forbiddenCharsRegex, '___')
		}
		store.set = withIEStorage(function(storage, key, val) {
			key = ieKeyFix(key)
			if (val === undefined) { return store.remove(key) }
			storage.setAttribute(key, store.serialize(val))
			storage.save(localStorageName)
			return val
		})
		store.get = withIEStorage(function(storage, key, defaultVal) {
			key = ieKeyFix(key)
			var val = store.deserialize(storage.getAttribute(key))
			return (val === undefined ? defaultVal : val)
		})
		store.remove = withIEStorage(function(storage, key) {
			key = ieKeyFix(key)
			storage.removeAttribute(key)
			storage.save(localStorageName)
		})
		store.clear = withIEStorage(function(storage) {
			var attributes = storage.XMLDocument.documentElement.attributes
			storage.load(localStorageName)
			for (var i=0, attr; attr=attributes[i]; i++) {
				storage.removeAttribute(attr.name)
			}
			storage.save(localStorageName)
		})
		store.getAll = function(storage) {
			var ret = {}
			store.forEach(function(key, val) {
				ret[key] = val
			})
			return ret
		}
		store.forEach = withIEStorage(function(storage, callback) {
			var attributes = storage.XMLDocument.documentElement.attributes
			for (var i=0, attr; attr=attributes[i]; ++i) {
				callback(attr.name, store.deserialize(storage.getAttribute(attr.name)))
			}
		})
	}

	try {
		var testKey = '__storejs__'
		store.set(testKey, testKey)
		if (store.get(testKey) != testKey) { store.disabled = true }
		store.remove(testKey)
	} catch(e) {
		store.disabled = true
	}
	store.enabled = !store.disabled

	if (typeof module != 'undefined' && module.exports && this.module !== module) { module.exports = store }
	else if (typeof define === 'function' && define.amd) { define(store) }
	else { win.store = store }

})(Function('return this')());

})
, {"filename":"../node_modules/store/store.js"});
// @pinf-bundle-module: {"file":"sha1.js","mtime":1423121217,"wrapper":"amd-ish","format":"amd-ish","id":"/sha1.js"}
require.memoize("/sha1.js", 
wrapAMD(function(require, define) {
/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-2 as well as the corresponding HMAC implementation
 as defined in FIPS PUB 198a

 Copyright Brian Turek 2008-2015
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information

 Several functions taken from Paul Johnston
*/
'use strict';(function(D){function n(b,c,f){var a=0,d=[0],g="",e=null,g=f||"UTF8";if("UTF8"!==g&&"UTF16BE"!==g&&"UTF16LE"!==g)throw"encoding must be UTF8, UTF16BE, or UTF16LE";if("HEX"===c){if(0!==b.length%2)throw"srcString of HEX type must be in byte increments";e=v(b);a=e.binLen;d=e.value}else if("TEXT"===c)e=w(b,g),a=e.binLen,d=e.value;else if("B64"===c)e=x(b),a=e.binLen,d=e.value;else if("BYTES"===c)e=y(b),a=e.binLen,d=e.value;else throw"inputFormat must be HEX, TEXT, B64, or BYTES";this.getHash=
function(b,g,c,f){var e=null,h=d.slice(),m=a,p;3===arguments.length?"number"!==typeof c&&(f=c,c=1):2===arguments.length&&(c=1);if(c!==parseInt(c,10)||1>c)throw"numRounds must a integer >= 1";switch(g){case "HEX":e=z;break;case "B64":e=A;break;case "BYTES":e=B;break;default:throw"format must be HEX, B64, or BYTES";}if("SHA-1"===b)for(p=0;p<c;p+=1)h=t(h,m),m=160;else throw"Chosen SHA variant is not supported";return e(h,C(f))};this.getHMAC=function(c,b,e,f,r){var h,m,p,s,n=[],u=[];h=null;switch(f){case "HEX":f=
z;break;case "B64":f=A;break;case "BYTES":f=B;break;default:throw"outputFormat must be HEX, B64, or BYTES";}if("SHA-1"===e)m=64,s=160;else throw"Chosen SHA variant is not supported";if("HEX"===b)h=v(c),p=h.binLen,h=h.value;else if("TEXT"===b)h=w(c,g),p=h.binLen,h=h.value;else if("B64"===b)h=x(c),p=h.binLen,h=h.value;else if("BYTES"===b)h=y(c),p=h.binLen,h=h.value;else throw"inputFormat must be HEX, TEXT, B64, or BYTES";c=8*m;b=m/4-1;if(m<p/8){if("SHA-1"===e)h=t(h,p);else throw"Unexpected error in HMAC implementation";
for(;h.length<=b;)h.push(0);h[b]&=4294967040}else if(m>p/8){for(;h.length<=b;)h.push(0);h[b]&=4294967040}for(m=0;m<=b;m+=1)n[m]=h[m]^909522486,u[m]=h[m]^1549556828;if("SHA-1"===e)e=t(u.concat(t(n.concat(d),c+a)),c+s);else throw"Unexpected error in HMAC implementation";return f(e,C(r))}}function w(b,c){var f=[],a,d=[],g=0,e,k,q;if("UTF8"===c)for(e=0;e<b.length;e+=1)for(a=b.charCodeAt(e),d=[],128>a?d.push(a):2048>a?(d.push(192|a>>>6),d.push(128|a&63)):55296>a||57344<=a?d.push(224|a>>>12,128|a>>>6&63,
128|a&63):(e+=1,a=65536+((a&1023)<<10|b.charCodeAt(e)&1023),d.push(240|a>>>18,128|a>>>12&63,128|a>>>6&63,128|a&63)),k=0;k<d.length;k+=1){for(q=g>>>2;f.length<=q;)f.push(0);f[q]|=d[k]<<24-g%4*8;g+=1}else if("UTF16BE"===c||"UTF16LE"===c)for(e=0;e<b.length;e+=1){a=b.charCodeAt(e);"UTF16LE"===c&&(k=a&255,a=k<<8|a>>8);for(q=g>>>2;f.length<=q;)f.push(0);f[q]|=a<<16-g%4*8;g+=2}return{value:f,binLen:8*g}}function v(b){var c=[],f=b.length,a,d,g;if(0!==f%2)throw"String of HEX type must be in byte increments";
for(a=0;a<f;a+=2){d=parseInt(b.substr(a,2),16);if(isNaN(d))throw"String of HEX type contains invalid characters";for(g=a>>>3;c.length<=g;)c.push(0);c[a>>>3]|=d<<24-a%8*4}return{value:c,binLen:4*f}}function y(b){var c=[],f,a,d;for(a=0;a<b.length;a+=1)f=b.charCodeAt(a),d=a>>>2,c.length<=d&&c.push(0),c[d]|=f<<24-a%4*8;return{value:c,binLen:8*b.length}}function x(b){var c=[],f=0,a,d,g,e,k;if(-1===b.search(/^[a-zA-Z0-9=+\/]+$/))throw"Invalid character in base-64 string";d=b.indexOf("=");b=b.replace(/\=/g,
"");if(-1!==d&&d<b.length)throw"Invalid '=' found in base-64 string";for(d=0;d<b.length;d+=4){k=b.substr(d,4);for(g=e=0;g<k.length;g+=1)a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(k[g]),e|=a<<18-6*g;for(g=0;g<k.length-1;g+=1){for(a=f>>>2;c.length<=a;)c.push(0);c[a]|=(e>>>16-8*g&255)<<24-f%4*8;f+=1}}return{value:c,binLen:8*f}}function z(b,c){var f="",a=4*b.length,d,g;for(d=0;d<a;d+=1)g=b[d>>>2]>>>8*(3-d%4),f+="0123456789abcdef".charAt(g>>>4&15)+"0123456789abcdef".charAt(g&
15);return c.outputUpper?f.toUpperCase():f}function A(b,c){var f="",a=4*b.length,d,g,e;for(d=0;d<a;d+=3)for(e=d+1>>>2,g=b.length<=e?0:b[e],e=d+2>>>2,e=b.length<=e?0:b[e],e=(b[d>>>2]>>>8*(3-d%4)&255)<<16|(g>>>8*(3-(d+1)%4)&255)<<8|e>>>8*(3-(d+2)%4)&255,g=0;4>g;g+=1)f=8*d+6*g<=32*b.length?f+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(e>>>6*(3-g)&63):f+c.b64Pad;return f}function B(b){var c="",f=4*b.length,a,d;for(a=0;a<f;a+=1)d=b[a>>>2]>>>8*(3-a%4)&255,c+=String.fromCharCode(d);
return c}function C(b){var c={outputUpper:!1,b64Pad:"="};try{b.hasOwnProperty("outputUpper")&&(c.outputUpper=b.outputUpper),b.hasOwnProperty("b64Pad")&&(c.b64Pad=b.b64Pad)}catch(f){}if("boolean"!==typeof c.outputUpper)throw"Invalid outputUpper formatting option";if("string"!==typeof c.b64Pad)throw"Invalid b64Pad formatting option";return c}function r(b,c){return b<<c|b>>>32-c}function s(b,c){var f=(b&65535)+(c&65535);return((b>>>16)+(c>>>16)+(f>>>16)&65535)<<16|f&65535}function u(b,c,f,a,d){var g=
(b&65535)+(c&65535)+(f&65535)+(a&65535)+(d&65535);return((b>>>16)+(c>>>16)+(f>>>16)+(a>>>16)+(d>>>16)+(g>>>16)&65535)<<16|g&65535}function t(b,c){var f=[],a,d,g,e,k,q,n,l,t,h=[1732584193,4023233417,2562383102,271733878,3285377520];for(a=(c+65>>>9<<4)+15;b.length<=a;)b.push(0);b[c>>>5]|=128<<24-c%32;b[a]=c;t=b.length;for(n=0;n<t;n+=16){a=h[0];d=h[1];g=h[2];e=h[3];k=h[4];for(l=0;80>l;l+=1)f[l]=16>l?b[l+n]:r(f[l-3]^f[l-8]^f[l-14]^f[l-16],1),q=20>l?u(r(a,5),d&g^~d&e,k,1518500249,f[l]):40>l?u(r(a,5),d^
g^e,k,1859775393,f[l]):60>l?u(r(a,5),d&g^d&e^g&e,k,2400959708,f[l]):u(r(a,5),d^g^e,k,3395469782,f[l]),k=e,e=g,g=r(d,30),d=a,a=q;h[0]=s(a,h[0]);h[1]=s(d,h[1]);h[2]=s(g,h[2]);h[3]=s(e,h[3]);h[4]=s(k,h[4])}return h}"function"===typeof define&&define.amd?define(function(){return n}):"undefined"!==typeof exports?"undefined"!==typeof module&&module.exports?module.exports=exports=n:exports=n:D.jsSHA=n})(this);
})
, {"filename":"sha1.js"});
// @pinf-bundle-module: {"file":null,"mtime":0,"wrapper":"json","format":"json","id":"fead16835712bc873dda7a42db9dd87bb2d59825-store/package.json"}
require.memoize("fead16835712bc873dda7a42db9dd87bb2d59825-store/package.json", 
{
    "main": "fead16835712bc873dda7a42db9dd87bb2d59825-store/store.js",
    "directories": {
        "lib": "."
    },
    "dirpath": "../node_modules/store"
}
, {"filename":"../node_modules/store/package.json"});
// @pinf-bundle-ignore: 
});
// @pinf-bundle-report: {}