var _ = require('lodash');

var Hash = require('../crypto/hash');
var PublicKey = require('../publickey');

var Escrow = {};

Escrow.getMerkleRoot = function getMerkleRoot(hashes) {
  if (hashes.length === 1) {
    return hashes[0];
  }
  const parentHashes = _.chunk(hashes, 2).map(hashPair => {
    // swapping the order of the hashes allows us to not need an OP_NOT in the bitcoin script
    // for each level of the merkle tree.
    return Hash.sha256ripemd160(new Buffer.concat([hashPair[1], hashPair[0]]));
  });
  return getMerkleRoot(parentHashes);
};

Escrow.generateMerkleRootFromPublicKeys = function(publicKeys) {
  const numLevels = Math.ceil(Math.log2(publicKeys.length));
  const numItems = Math.pow(2, numLevels);
  const sortedPublicKeys = publicKeys
    .map(publicKey => publicKey.toString('hex'))
    .sort()
    .map(publicKeyString => PublicKey.fromString(publicKeyString).toBuffer());
  const zeros = Array(numItems - publicKeys.length).fill(Buffer.from('0', 'hex'));
  const leaves = sortedPublicKeys.concat(zeros).map(value => {
    return Hash.sha256ripemd160(value);
  });
  const merkleRoot = Escrow.getMerkleRoot(leaves);
  return merkleRoot;
};

var generateSingleInputPublicKeyValidationScript = function(inputPublicKey) {
  return `OP_DUP OP_HASH160 ${inputPublicKey} OP_EQUALVERIFY`;
};

var generateListBasedInputPublicKeyValidationScript = function(inputPublicKeys) {
  const pubKeys = inputPublicKeys.join(' ');
  const dropOpCode = inputPublicKeys.length === 3 ? 'OP_2DROP' : 'OP_DROP';
  return `OP_TOALTSTACK OP_DUP OP_HASH160 ${pubKeys} OP_FROMALTSTACK OP_ROLL <${
    inputPublicKeys.length
  }> OP_ROLL OP_EQUALVERIFY ${dropOpCode}`;
};

var generateMerkleBasedInputPublicKeyValidationScript = function(inputPublicKeys) {};

Escrow.generateInputPublicKeyValidationScript = function(inputPublicKeys) {};

module.exports = Escrow;
