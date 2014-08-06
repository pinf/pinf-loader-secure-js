*Status: DEV*

A Secured PINF JavaScript Loader
================================

A [PINF JavaScript Loader](https://github.com/pinf/pinf-loader-js) Sandbox
and middleware that polices bundles and resources to allow only declared
and known assets into a sandbox.

Uses the [Stanford Javascript Crypto Library](https://github.com/bitwiseshiftleft/sjcl)
and [eccjs](https://github.com/jpillora/eccjs) to verify checksums and signatures.

The weight of the client sandbox security layer currently comes in at
around **25KB minified and gzipped**. With some optimization this *may* be
reduced to 20KB.

Uses `[Function].toString()` to calculate the hash and signature of a bundle of
code before executing it.


Install
-------

`package.json`

	{
		"mappings": {
			"pinf-loader-secure-client": "./client",
			"pinf-loader-secure-server": "./server"			
		}
	}


Usage
-----

`common.js`

	const ECC = require("pinf-loader-secure-client/ecc");

	const KEYS = ECC.generate(ECC.SIG_VER);

`server.js`

	const PATH = require("path");
	const MIDDLEWARE = require("pinf-loader-secure-server/middleware");

	app.get(/^\/bundles\/(.+)$/, MIDDLEWARE.Bundles(
		PATH.join(__dirname, "bundles"),
		{
			keys: KEYS
		}
	));

Where `MIDDLEWARE.Bundles` will serve bundles from the specified directory
and add a checksum and signature (based on `KEYS`) to the bundle response.

`client.js`

	const SECURE = require("pinf-loader-secure");

	exports.main = function() {
		return SECURE.sandbox("/bundles/HelloWorld.js", {
			secure: {
				bundles: [
					"sha256:*"
					"eccver:" + KEYS.ver
				]
			}
		}, function(sandbox) {
			// `sandbox` can only load declared assets
		});
	}

Where the `secure.bundles` option to `SECURE.sandbox` may contain specific
hashes or public signature verification keys:

	sha256:bac527c23788f5c395d2...
	eccver:192af5fcf63f386a9099...

or allow any type of hash or signature:

	sha256:*
	eccver:*


Development
-----------

NOTE: The development environment for this project is implemented using
PINF conventions and libraries and serves as a reference implementation
for how to code portable bundles using PINF technology. Expect still some changes.

Install:

    npm install

Run:

    node workspace/server.js
    open http://localhost:3000/
    # Look for 'Hello World' in console

Publish:

	npm run-script build
	# Commit code


License
=======

[UNLICENSE](http://unlicense.org/)
