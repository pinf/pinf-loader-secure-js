
PINF.bundle("", function(require) {
	require.memoize("/main.js", function(require, exports, module) {
		exports.main = function(options) {
			console.log("Hello World");
		}
	});
}, {
	"hash": "sha256:71c28170686b0ac19fa5b1ddcccbbdacdedc8edfa47f1687fc9f534f1076cf97"
});
