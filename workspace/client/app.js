
exports.main = function(options) {

	var uri = "/client/sandbox.js";

	return require.sandbox(uri, {

	}, function(sandbox) {

		return sandbox.main(options);

	}, function (err) {
		console.error("Error while loading bundle '" + uri + "':", err.stack);
	});
}
