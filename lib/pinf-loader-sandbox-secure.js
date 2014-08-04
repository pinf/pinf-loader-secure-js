
const SJCL = require("sjcl");


exports.main = function() {

	console.log("main in pinf-loader-sandbox-secure.js called!");

console.log("SJCL API:", SJCL);

// @see https://github.com/bitwiseshiftleft/sjcl/issues/134

var keys = SJCL.ecc.elGamal.generateKeys(384, 1); //choose a stronger/weaker curve

var pubkem = keys.pub.kem(); //KEM is Key Encapsulation Mechanism
var pubkey = pubkem.key;
var seckey = keys.sec.unkem(pubkem.tag); //tag is used to derive the secret (private) key

var plain = "hello world!";
var cipher = SJCL.encrypt(pubkey, plain); //defaults to AES
var result = SJCL.decrypt(seckey, cipher);

console.log(plain === result); //true


var keys = SJCL.ecc.ecdsa.generateKeys(384, 1); //choose a stronger/weaker curve

var hashOfPlainText = "abc123"; //dummy hash

var signature = keys.sec.sign(hashOfPlainText);

console.log(keys.pub.verify(hashOfPlainText, signature)) //=> true

//console.log(keys.pub.verify("abc124", signature)) //=> throws "signature didn't check out"

}
