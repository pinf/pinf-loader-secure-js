
const PATH = require("path");
const PINF = require("pinf-for-nodejs");
const EXPRESS = require("express");
const COMPRESSION = require("compression");
const SEND = require("send");
const HTTP = require("http");


return PINF.main(function(options, callback) {

	var app = EXPRESS();

	app.use(COMPRESSION());

	app.get(/^\/lib\/pinf-loader-js\/(.+)$/, function (req, res, next) {
		return SEND(req, req.params[0])
			.root(PATH.join(__dirname, "node_modules/pinf-for-nodejs/node_modules/pinf-loader-js"))
			.on("error", next)
			.pipe(res);
	});

	app.get(/^\/workspace\/client(\/app.+)$/, PINF.hoist(PATH.join(__dirname, "workspace/client/program.json"), options.$pinf.makeOptions({
		debug: true,
		verbose: true,
		PINF_RUNTIME: "",
        $pinf: options.$pinf
    })));

	app.get(/(\/lib\/pinf-loader-sandbox-secure.+)$/, PINF.hoist(PATH.join(__dirname, "program.json"), options.$pinf.makeOptions({
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
					'sandbox.main();',
				'}, function (err) {',
					'console.error("Error while loading bundle \'/workspace/client/app.js\':", err.stack);',
				'});',
			'</script>'
		];
		return res.end(html.join("\n"));
	});

	HTTP.createServer(app).listen(3000)

}, module);
