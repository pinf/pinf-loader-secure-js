
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs");
const SJCL = require("sjcl");
const ECC = require("../client/ecc");


exports.Bundles = function(rootPath, options) {

	ASSERT.equal(typeof options, "object");
	ASSERT.equal(typeof options.keys, "object");
	ASSERT.equal(typeof options.keys.sig, "string");
	ASSERT.equal(typeof options.keys.ver, "string");

	return function (req, res, next) {
		var path = PATH.join(rootPath, req.params[0]);
		if (!/\.js$/.test(path)) {
			return next();
		}
		return FS.exists(path, function(exists) {
			if (!exists) {
				res.writeHed(404);
				return res.end();
			}
			return FS.readFile(path, "utf8", function(err, data) {
				if (err) return next(err);

				var m = data.match(/^[\s\n\t]*(PINF\.bundle\(([^,]+),\s*function\s*\(\s*require\s*\)\s*\{)([\w\W\n\s\t]+?)(\}\);?)[\s\n\t]*$/);
				if (!m) {
					return next(new Error("Could not parse bundle!"));
				}

				var functionToStringEquivalent = [
					'function (require) {',
					m[3],
					'}'
				].join("");

				data = [
					// TODO: Generate a UID for the bundle.
					'PINF.bundle(' + m[2] + ', function(require) {',
						m[3],
					'}, ' + JSON.stringify({
						"hash": "sha256:" + SJCL.codec.hex.fromBits(SJCL.hash.sha256.hash(functionToStringEquivalent)),
						"signature": "ecc:" + options.keys.ver.substring(0, 7) + ":" + SJCL.codec.hex.fromBits(ECC.sign(options.keys.sig, functionToStringEquivalent))
					}, null, 4) + ');'
				].join("");

				res.writeHead(200, {
					"Content-Type": "application/javascript",
					"Content-Length": data.length
				});
				return res.end(data);
			});
		});
	};
}
