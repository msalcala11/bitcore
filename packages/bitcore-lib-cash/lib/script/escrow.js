var Escrow = {};

var generateMerkleRootFromPublicKeys = function(publicKeys) {};

var generateSingleInputPublicKeyValidationScript = function(inputPublicKey) {
  return `OP_DUP OP_HASH160 ${inputPublicKey} OP_EQUALVERIFY`;
};

var generateListBasedInputPublicKeyValidationScript = function(inputPublicKeys) {
  const pubKeys = inputPublicKeys.join(' ');
  const dropOpCode = inputPublicKeys.length === 3 ? 'OP_2DROP' : 'OP_DROP';
  `OP_TOALTSTACK OP_DUP OP_HASH160 ${pubKeys} OP_FROMALTSTACK OP_ROLL <${
    inputPublicKeys.length
  }> OP_ROLL OP_EQUALVERIFY ${dropOpCode}`;
};

var generateMerkleBasedInputPublicKeyValidationScript = function(inputPublicKeys) {};

Escrow.generateInputPublicKeyValidationScript = function(inputPublicKeys) {};

module.exports = Escrow;
