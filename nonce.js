var crypto = require('crypto');

/**
 * @param {number=} opt_size byte size. default is 20 bytes.
 * @return {string} generated base64 random string.
 * @throws {Error} Throws if crypto cannot generate random data.
 * @see http://nodejs.org/api/crypto.html#crypto_crypto_randombytes_size_callback
 */
function generateNonceValue(opt_size) {
  var size = opt_size || 20;
  return crypto.randomBytes(size).toString('base64');
}

exports.generateNonceValue = generateNonceValue;
