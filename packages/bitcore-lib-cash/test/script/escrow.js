'use strict';

var should = require('chai').should();
var expect = require('chai').expect;
var bitcore = require('../..');

var Hash = bitcore.crypto.Hash;

// var Script = bitcore.Script;
// var Networks = bitcore.Networks;
// var Opcode = bitcore.Opcode;
// var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;
// var Address = bitcore.Address;
var Escrow = require('../../lib/script/escrow');
console.log('escrowwwwww', Escrow);

describe('Escrow', function() {
  describe('#getMerkleRoot', () => {
    it('should properly hash a 2-level tree of zeros', () => {
      const zeroHashed = Hash.sha256ripemd160(Buffer.from('0', 'hex'));
      const merkleRoot = Escrow.getMerkleRoot([zeroHashed, zeroHashed, zeroHashed, zeroHashed]);
      merkleRoot.toString('hex').should.equal('bcd72713b594ea45d44512ca7912c625f7e69092');
    });
  });
  describe('#generateMerkleRootFromPublicKeys', () => {
    it.only('should work for 3 public keys', () => {
      const publicKeyStrings = [
        '03fb0ed01700a2e9303f76ec93c61114507d9ea9bb3704c873fa8c1c7f4fad0a49',
        '02cc0cbe9725cea57e475b8cf8fef5556df5c4a73a912a167ee3e170fa1172725a',
        '0312e866a0b1dd1221a79729907f45672ad0ee426f1234f5f44c447000daa42341'
      ];
      const publicKeys = publicKeyStrings.map(publicKeyString => PublicKey.fromString(publicKeyString));
      const merkleRoot = Escrow.generateMerkleRootFromPublicKeys(publicKeys);
      merkleRoot.toString('hex').should.equal('7f9a56485f322521d8194eebda9c63ceb079f7f1');
    });
  });
});
