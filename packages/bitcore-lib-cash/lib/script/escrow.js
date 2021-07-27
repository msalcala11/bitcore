const _ = require('lodash');

const Hash = require('../crypto/hash');
const Opcode = require('../opcode');
const PublicKey = require('../publickey');

const Escrow = {};

const bufferFromNumber = function(n) {
  const hexString = n.toString(16);
  const fullHexString = `${hexString.length === 1 && n > 0 ? '0' : ''}${hexString}`;
  return Buffer.from(fullHexString, 'hex');
};

const getNumMerkleLevels = function(numPublicKeys) {
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
  const zeros = Array(numItems - publicKeys.length).fill(bufferFromNumber(0));
  const leaves = sortedPublicKeys.concat(zeros).map(value => Hash.sha256ripemd160(value));
  return Escrow.getMerkleRoot(leaves);
};

const generateSingleInputPublicKeyValidationOperations = function(inputPublicKey) {
  const inputPublicKeyHash = Hash.sha256ripemd160(inputPublicKey.toBuffer());
  return [Opcode.OP_DUP, Opcode.OP_HASH160, inputPublicKeyHash, Opcode.OP_EQUALVERIFY];
};

const generateListBasedInputPublicKeyValidationOperations = function(inputPublicKeys) {
  const publicKeyHashes = inputPublicKeys.map(publicKey => Hash.sha256ripemd160(publicKey.toBuffer()));
  const dropOpCode = inputPublicKeys.length === 3 ? Opcode.OP_2DROP : Opcode.OP_DROP;
  return [
    Opcode.OP_TOALTSTACK,
    Opcode.OP_DUP,
    Opcode.OP_HASH160,
    ...publicKeyHashes,
    Opcode.OP_FROMALTSTACK,
    Opcode.OP_ROLL,
    bufferFromNumber(inputPublicKeys.length),
    Opcode.OP_ROLL,
    Opcode.OP_EQUALVERIFY,
    dropOpCode
  ];
};

const generateMerkleBasedInputPublicKeyValidationOperations = function(inputPublicKeys) {
  const numLevels = getNumMerkleLevels(inputPublicKeys.length);
  const rootHash = Escrow.generateMerkleRootFromPublicKeys(inputPublicKeys);
  const merkleTreeConstructionOperationsForEachLevel = Array(numLevels)
    .fill()
    .map((_, levelIndex) => {
      const leafIndexStackDepth = numLevels + 1 - levelIndex;
      const leafIndexOpCode = levelIndex === numLevels - 1 ? Opcode.OP_ROLL : Opcode.OP_PICK;
      const divisor = Math.pow(2, levelIndex);
      const computeParentIndex = levelIndex > 0 ? [bufferFromNumber(divisor), Opcode.OP_DIV] : [];
      return [
        bufferFromNumber(leafIndexStackDepth),
        leafIndexOpCode,
        ...computeParentIndex,
        bufferFromNumber(2),
        Opcode.OP_MOD,
        Opcode.OP_NOTIF,
        Opcode.OP_SWAP,
        Opcode.OP_ENDIF,
        Opcode.OP_CAT,
        Opcode.OP_HASH160
      ];
    })
    .reduce((arr, item) => arr.concat(item), []);
  return [
    bufferFromNumber(numLevels + 1),
    Opcode.OP_PICK,
    Opcode.OP_HASH160,
    ...merkleTreeConstructionOperationsForEachLevel,
    rootHash,
    Opcode.OP_EQUALVERIFY
  ];
};

Escrow.generateInputPublicKeyValidationOperations = function(inputPublicKeys) {
  if (inputPublicKeys.length === 1) {
    return generateSingleInputPublicKeyValidationOperations(inputPublicKeys[0]);
  }
  if ([2, 3].includes(inputPublicKeys.length)) {
    return generateListBasedInputPublicKeyValidationOperations(inputPublicKeys);
  }
  return generateMerkleBasedInputPublicKeyValidationOperations(inputPublicKeys);
};

Escrow.generateRedeemScriptOperations = function(inputPublicKeys, reclaimPublicKey) {
  const checkCustomerReclaimPublicKey = [
    Opcode.OP_DUP,
    Opcode.OP_HASH160,
    Hash.sha256ripemd160(reclaimPublicKey.toBuffer()),
    Opcode.OP_EQUAL,
    Opcode.OP_IF,
    Opcode.OP_CHECKSIG,
    Opcode.OP_ELSE
  ];
  const checkInputPublicKey = Escrow.generateInputPublicKeyValidationOperations(inputPublicKeys);
  const ensureTransactionsAreUnique = [
    Opcode.OP_OVER,
    bufferFromNumber(4),
    Opcode.OP_PICK,
    Opcode.OP_EQUAL,
    Opcode.OP_NOT,
    Opcode.OP_VERIFY
  ];
  const ensureBothSignaturesAreValid = [
    Opcode.OP_DUP,
    Opcode.OP_TOALTSTACK,
    Opcode.OP_CHECKDATASIGVERIFY,
    Opcode.OP_FROMALTSTACK,
    Opcode.OP_CHECKDATASIG,
    Opcode.OP_ENDIF
  ];
  const allOperations = [
    ...checkCustomerReclaimPublicKey,
    ...checkInputPublicKey,
    ...ensureTransactionsAreUnique,
    ...ensureBothSignaturesAreValid
  ];
  return allOperations;
};

module.exports = Escrow;
