var Opcode = require('../opcode');
var _ = require('lodash');

var Hash = require('../crypto/hash');
var PublicKey = require('../publickey');

var Escrow = {};

var bufferFromNumber = function(n) {
  const hexString = n.toString(16);
  const fullHexString = `${hexString.length === 1 && n > 0 ? '0' : ''}${hexString}`;
  return Buffer.from(fullHexString, 'hex');
};

var getNumMerkleLevels = function(numPublicKeys) {
  return Math.ceil(Math.log2(numPublicKeys));
};

Escrow.getMerkleRoot = function getMerkleRoot(hashes) {
  if (hashes.length === 1) {
    return hashes[0];
  }
  const parentHashes = _.chunk(hashes, 2).map(hashPair => Hash.sha256ripemd160(new Buffer.concat(hashPair)));
  return getMerkleRoot(parentHashes);
};

Escrow.generateMerkleRootFromPublicKeys = function(publicKeys) {
  const numLevels = getNumMerkleLevels(publicKeys.length);
  const numItems = Math.pow(2, numLevels);
  const sortedPublicKeys = publicKeys
    .map(publicKey => publicKey.toString('hex'))
    .sort()
    .map(publicKeyString => PublicKey.fromString(publicKeyString).toBuffer());
  const zeros = Array(numItems - publicKeys.length).fill(Buffer.from('0', 'hex'));
  const leaves = sortedPublicKeys.concat(zeros).map(value => Hash.sha256ripemd160(value));
  return Escrow.getMerkleRoot(leaves);
};

var appendSingleInputPublicKeyValidationScript = function(redeemScript, inputPublicKey) {
  const inputPublicKeyHash = Hash.sha256ripemd160(inputPublicKey.toBuffer());
  redeemScript.add(Opcode.OP_DUP);
  redeemScript.add(Opcode.OP_HASH160);
  redeemScript.add(inputPublicKeyHash);
  redeemScript.add(Opcode.OP_EQUALVERIFY);
  return redeemScript;
};

var appendListBasedInputPublicKeyValidationScript = function(redeemScript, inputPublicKeys) {
  const publicKeyHashes = inputPublicKeys.map(publicKey => {
    return Hash.sha256ripemd160(publicKey.toBuffer());
  });
  const dropOpCode = inputPublicKeys.length === 3 ? Opcode.OP_2DROP : Opcode.OP_DROP;
  redeemScript.add(Opcode.OP_TOALTSTACK);
  redeemScript.add(Opcode.OP_DUP);
  redeemScript.add(Opcode.OP_HASH160);
  publicKeyHashes.forEach(publicKeyHash => redeemScript.add(publicKeyHash));
  redeemScript.add(Opcode.OP_FROMALTSTACK);
  redeemScript.add(Opcode.OP_ROLL);
  redeemScript.add(bufferFromNumber(inputPublicKeys.length));
  redeemScript.add(Opcode.OP_ROLL);
  redeemScript.add(Opcode.OP_EQUALVERIFY);
  redeemScript.add(dropOpCode);
  return redeemScript;
};

var appendMerkleBasedInputPublicKeyValidationScript = function(redeemScript, inputPublicKeys) {
  const numLevels = getNumMerkleLevels(inputPublicKeys.length);
  const rootHash = Escrow.generateMerkleRootFromPublicKeys(inputPublicKeys);
  redeemScript.add(bufferFromNumber(numLevels + 1));
  redeemScript.add(Opcode.OP_PICK);
  redeemScript.add(Opcode.OP_HASH160);
  Array(numLevels)
    .fill(0)
    .forEach((_, index) => {
      const leafIndexStackDepth = numLevels + 1 - index;
      const leafIndexOpCode = index === numLevels - 1 ? Opcode.OP_ROLL : Opcode.OP_PICK;
      redeemScript.add(bufferFromNumber(leafIndexStackDepth));
      redeemScript.add(leafIndexOpCode);
      if (index > 0) {
        redeemScript.add(bufferFromNumber(Math.pow(2, index)));
        redeemScript.add(Opcode.OP_DIV);
      }
      redeemScript.add(bufferFromNumber(2));
      redeemScript.add(Opcode.OP_MOD);
      redeemScript.add(Opcode.OP_NOTIF);
      redeemScript.add(Opcode.OP_SWAP);
      redeemScript.add(Opcode.OP_ENDIF);
      redeemScript.add(Opcode.OP_CAT);
      redeemScript.add(Opcode.OP_HASH160);
    });
  return redeemScript.add(rootHash).add(Opcode.OP_EQUALVERIFY);
};

Escrow.generateInputPublicKeyValidationScript = function(redeemScript, inputPublicKeys) {
  if (inputPublicKeys.length === 1) {
    return appendSingleInputPublicKeyValidationScript(redeemScript, inputPublicKeys[0]);
  }
  if ([2, 3].includes(inputPublicKeys.length)) {
    return appendListBasedInputPublicKeyValidationScript(redeemScript, inputPublicKeys);
  }
  return appendMerkleBasedInputPublicKeyValidationScript(redeemScript, inputPublicKeys);
};

module.exports = Escrow;
