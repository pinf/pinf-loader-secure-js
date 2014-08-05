
const SJCL = require("sjcl");
const ECC = require("./ecc");


exports.main = function(options) {

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

		var signatures = {};
		sandboxOptions.secure.bundles.filter(function(bundle) {
			return /^eccver:/.test(bundle);
		}).map(function (bundle) {
			var key = bundle.match(/^eccver:(.{7})/)[1];
			if (!signatures[key]) {
				signatures[key] = [];
			}
			signatures[key].push(bundle);
		});

		// TODO: Keep track of different instances of `PINF.bundle()`
		//       so we can allow multiple secure sandboxes at the same time.

		var _orig_bundle = PINF.bundle;
		PINF.bundle = function(uid, callback, meta) {

			if (!meta || typeof meta !== "object") {
				throw new Error("No meta data supplied for bundle '" + uid + "'!");
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
				if (hashParts[1] !== SJCL.codec.hex.fromBits(SJCL.hash[hashParts[0]].hash(callback.toString()))) {
					throw new Error("Bundle hash supplied for bundle '" + uid + "' does not match calculated hash from toString() of bundle payload!");
				}
				if (sandboxOptions.secure.bundles.indexOf(meta.hash) === -1) {
					if (sandboxOptions.secure.bundles.indexOf(hashParts[0] + ":*") === -1) {
						throw new Error("Hash '" + meta.hash + "' used by bundle '" + uid + "' not declared in 'secure.bundles'!");
					}
				}
			}

			return _orig_bundle(uid, callback);
		}

		return require.sandbox(sandboxIdentifier, sandboxOptions, loadedCallback, errorCallback);
	}


	return sandbox("/test/assets/bundles/HelloWorld.js", options, function(sandbox) {

		return sandbox.main();

	}, function (err) {
		console.error("Error while loading bundle '/test/assets/bundles/HelloWorld.js':", err.stack);
	});

}
