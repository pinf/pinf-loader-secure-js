
const PATH = require("path");
const PINF = require("pinf-for-nodejs");
const EXPRESS = require("express");
const COMPRESSION = require("compression");
const SEND = require("send");
const HTTP = require("http");
const MIDDLEWARE = require("../server/middleware");


return PINF.main(function(options, callback) {

	var keys = {
		sig: "192c09756cb8eb593ebc4d6cba98a2954e618c7a5b49aade246",
		ver: "192af5fcf63f386a909980755373aee633791f50da355948c5e9473d215ce47b19a34cbd147af09165f5fcb09b49064e816"
	};

	var app = EXPRESS();

	app.use(COMPRESSION());

	app.get(/^\/lib\/pinf-loader-js\/(.+)$/, function (req, res, next) {
		return SEND(req, req.params[0], {
			root: PATH.join(__dirname, "../node_modules/pinf-for-nodejs/node_modules/pinf-loader-js")
		}).on("error", next).pipe(res);
	});

	app.get(/^\/test\/assets\/bundles\/(.+)$/, MIDDLEWARE.Bundles(
		PATH.join(__dirname, "../test/assets/bundles"),
		{
			keys: keys
		}
	));

	app.get(/^\/workspace\/client(\/app.+)$/, PINF.hoist(PATH.join(__dirname, "../workspace/client/program.json"), options.$pinf.makeOptions({
		debug: true,
		verbose: true,
		PINF_RUNTIME: "",
        $pinf: options.$pinf
    })));

	app.get(/\/client(\/sandbox.+)$/, PINF.hoist(PATH.join(__dirname, "../client/program.json"), options.$pinf.makeOptions({
		debug: true,
		verbose: true,
		PINF_RUNTIME: "",
        $pinf: options.$pinf
    })));

	app.get(/^\/$/, function (req, res, next) {
		var html = [
			'<script src="/lib/pinf-loader-js/loader.js"></script>',
			'<script>',
				'PINF.sandbox("/workspace/client/app.js", function (sandbox) {',
					'sandbox.main(' + JSON.stringify({
						secure: {
							bundles: [
//								"sha256:*"
								"eccver:" + keys.ver
							]
						}
					}, null, 4) + ');',
				'}, function (err) {',
					'console.error("Error while loading bundle \'/workspace/client/app.js\':", err.stack);',
				'});',
			'</script>'
		];
		return res.end(html.join("\n"));
	});

	HTTP.createServer(app).listen(3000)

}, module);
