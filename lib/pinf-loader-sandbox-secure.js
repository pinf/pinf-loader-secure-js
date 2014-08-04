
const SJCL = require("sjcl");


exports.main = function() {

	console.log("main in pinf-loader-sandbox-secure.js called!");
/*
console.log("SJCL API:", SJCL);

// @see https://github.com/bitwiseshiftleft/sjcl/issues/134

var keys = SJCL.ecc.elGamal.generateKeys(384, 1); //choose a stronger/weaker curve

var pubkem = keys.pub.kem(); //KEM is Key Encapsulation Mechanism
var pubkey = pubkem.key;
var seckey = keys.sec.unkem(pubkem.tag); //tag is used to derive the secret (private) key

var plain = "hello world!";
var cipher = SJCL.encrypt(pubkey, plain); //defaults to AES
var result = SJCL.decrypt(seckey, cipher);

console.log(plain === result); //true


var keys = SJCL.ecc.ecdsa.generateKeys(384, 1); //choose a stronger/weaker curve

var hashOfPlainText = "abc123"; //dummy hash

var signature = keys.sec.sign(hashOfPlainText);

console.log(keys.pub.verify(hashOfPlainText, signature)) //=> true

//console.log(keys.pub.verify("abc124", signature)) //=> throws "signature didn't check out"
*/


	var sandbox = function(sandboxIdentifier, sandboxOptions, loadedCallback, errorCallback) {

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
			throw new Error("'secure' property not set!");
		}
		if (typeof sandboxOptions.secure.bundles !== "object") {
			throw new Error("'secure.bundles' property not set!");
		}


		// TODO: Keep track of different instances of `PINF.bundle()`
		//       so we can allow multiple secure sandboxes at the same time.

		var _orig_bundle = PINF.bundle;
		PINF.bundle = function(uid, callback, meta) {

			if (!meta || typeof meta !== "object") {
				throw new Error("No meta data supplied for bundle '" + uid + "'!");
			}

			if (typeof meta.hash !== "string") {
				throw new Error("No hash supplied for bundle '" + uid + "'!");
			}

			var hashParts = meta.hash.split(":");
			if (typeof SJCL.hash[hashParts[0]] === "undefined") {
				throw new Error("Hash type '" + hashParts[0] + "' used by bundle '" + uid + "' not supported!");
			}
			if (hashParts[1] !== SJCL.codec.hex.fromBits(SJCL.hash[hashParts[0]].hash(callback.toString()))) {
				throw new Error("Bundle hash supplied for bundle '" + uid + "' does not match calculated hash from toString()!");
			}
			if (sandboxOptions.secure.bundles.indexOf(meta.hash) === -1) {
				throw new Error("Hash '" + meta.hash + "' used by bundle '" + uid + "' not declared in 'secure.bundles'!");
			}

			return _orig_bundle(uid, callback);
		}

		return require.sandbox(sandboxIdentifier, sandboxOptions, loadedCallback, errorCallback);
	}



	return sandbox("/test/assets/bundles/HelloWorld.js", {
		secure: {
			bundles: [
				"sha256:71c28170686b0ac19fa5b1ddcccbbdacdedc8edfa47f1687fc9f534f1076cf97"
			]
		}
	}, function(sandbox) {

		return sandbox.main();

	}, function (err) {
		console.error("Error while loading bundle '/test/assets/bundles/HelloWorld.js':", err.stack);
	});

}
