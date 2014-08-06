
const SECURE = require("pinf-loader-secure");


exports.main = function(options) {

	var uri = "/test/assets/bundles/HelloWorld.js";

	return SECURE.sandbox(uri, options, function(sandbox) {

		return sandbox.main();

	}, function (err) {
		console.error("Error while loading bundle '" + uri + "':", err.stack);
	});

}
