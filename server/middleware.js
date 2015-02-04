
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


	function wrapBundle (data, callback) {

		var m = data.match(/^[\s\n\t\S]*(PINF\.bundle\(([^,]+),\s*function\s*\(\s*require\s*\)\s*\{)([\w\W\n\s\t\S]+)(\}\);?)[\s\n\t\S]*$/);
		if (!m) {
			console.log("data", data);
			return callback(new Error("Could not parse bundle!"));
		}

		try {
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

			return callback(null, data);
		} catch (err) {
			return callback(err);
		}
	}


	if (typeof rootPath === "function") {

		return function (req, res, next) {

			// @see https://github.com/No9/harmon/blob/master/index.js
			var _write = res.write;
			var _writeHead = res.writeHead;
			var _end = res.end;
			var buffer = [];
			res.writeHead = function (code, headers) {
			    res.removeHeader('Content-Length');
			    if (headers) {
			      delete headers['content-length'];
			    }
				_writeHead.call(res, code, headers);
			}
		    res.write = function (data, encoding) {
		    	buffer.push(data.toString());
		    };
		    res.end = function (data, encoding) {
		    	if (data) {
			    	buffer.push(data.toString());
			    }
				return wrapBundle(buffer.join(""), function (err, data) {
					if (err) return next(err);

					res.setHeader("Content-Type", "application/javascript");

				    _write.call(res, data);
				    _end.call(res);
				});
		    };

			return rootPath(req, res, next);
		};
	}


	return function (req, res, next) {
		var path = PATH.join(rootPath, req.params[0]);
		if (!/\.js$/.test(path)) {
			return next();
		}
		return FS.exists(path, function(exists) {
			if (!exists) {
				console.log("Path not found:", path);
				res.writeHead(404);
				return res.end();
			}
			return FS.readFile(path, "utf8", function(err, data) {
				if (err) return next(err);

				return wrapBundle(data, function (err, data) {
					if (err) return next(err);

					res.writeHead(200, {
						"Content-Type": "application/javascript"
// TODO: Set length once we encode response properly and know exact length.
//						"Content-Length": data.length
					});
					return res.end(data);
				});
			});
		});
	};
}
