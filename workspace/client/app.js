
exports.main = function() {

	return require.sandbox("/lib/pinf-loader-sandbox-secure.js", {

	}, function(sandbox) {

		return sandbox.main();

	}, function (err) {
		console.error("Error while loading bundle '/lib/pinf-loader-sandbox-secure.js':", err.stack);
	});
}
