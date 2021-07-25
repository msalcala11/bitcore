const { Script } = require('bitcore-lib');
var Opcode = require('../opcode');
var _ = require('lodash');

var Hash = require('../crypto/hash');
var PublicKey = require('../publickey');

var Escrow = {};

var bufferFromNumber = function(n) {
  const hexString = n.toString(16);
  const fullHexString = `${hexString.length === 1 ? '0' : ''}${hexString}`;
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

var generateSingleInputPublicKeyValidationScript = function(inputPublicKey) {
  const inputPublicKeyHash = Hash.sha256ripemd160(inputPublicKey.toBuffer());
  const script = new Script();
  script.add(Opcode.OP_DUP);
  script.add(Opcode.OP_HASH160);
  script.add(inputPublicKeyHash);
  script.add(Opcode.OP_EQUALVERIFY);
  return script.toString();
};

var generateListBasedInputPublicKeyValidationScript = function(inputPublicKeys) {
  const publicKeyHashes = inputPublicKeys.map(publicKey => {
    return Hash.sha256ripemd160(publicKey.toBuffer());
  });
  const script = new Script();
  const dropOpCode = inputPublicKeys.length === 3 ? Opcode.OP_2DROP : Opcode.OP_DROP;
  script.add(Opcode.OP_TOALTSTACK);
  script.add(Opcode.OP_DUP);
  script.add(Opcode.OP_HASH160);
  publicKeyHashes.forEach(publicKeyHash => script.add(publicKeyHash));
  script.add(Opcode.OP_FROMALTSTACK);
  script.add(Opcode.OP_ROLL);
  script.add(bufferFromNumber(inputPublicKeys.length));
  script.add(Opcode.OP_ROLL);
  script.add(Opcode.OP_EQUALVERIFY);
  script.add(dropOpCode);
  return script.toString();
};

var generateMerkleBasedInputPublicKeyValidationScript = function(inputPublicKeys) {
  const numLevels = getNumMerkleLevels(publicKeys.length);
  const rootHash = Escrow.generateMerkleRootFromPublicKeys(inputPublicKeys);
  const pubKeyHash = `<${numLevels}> OP_PICK OP_HASH160`;
  const rootProof = Array(numLevels)
    .map((_, index) => {
      const leafIndexStackDepth = numLevels - index;
      const leafIndexOpCode = index === numLevels - 1 ? 'OP_ROLL' : 'OP_PICK';
      const getLeafIndex = `<${leafIndexStackDepth}> ${leafIndexOpCode}`;
      const getParentIndex = index === 0 ? '' : `<${index * 2}> OP_DIV`;
      const swapItems = `<2> OP_MOD OP_NOTIF OP_SWAP OP_ENDIF`;
      const hashItems = `OP_CAT OP_HASH160`;
      return `${getLeafIndex} ${getParentIndex} ${swapItems} ${hashItems}`;
    })
    .join(' ');
  return `${pubKeyHash} ${rootProof} ${rootHash} OP_EQUALVERIFY`;
};

Escrow.generateInputPublicKeyValidationScript = function(inputPublicKeys) {
  if (inputPublicKeys.length === 1) {
    return generateSingleInputPublicKeyValidationScript(inputPublicKeys[0]);
  }
  if ([2, 3].includes(inputPublicKeys.length)) {
    return generateListBasedInputPublicKeyValidationScript(inputPublicKeys);
  }
  return generateMerkleBasedInputPublicKeyValidationScript(inputPublicKeys);
};

module.exports = Escrow;
