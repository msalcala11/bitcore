'use strict';

var should = require('chai').should();
var expect = require('chai').expect;
var bitcore = require('../..');

var Hash = bitcore.crypto.Hash;

// var Script = bitcore.Script;
// var Networks = bitcore.Networks;
// var Opcode = bitcore.Opcode;
var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;
// var Address = bitcore.Address;
var Escrow = require('../../lib/script/escrow');
console.log('escrowwwwww', Escrow);

describe.only('Escrow', function() {
  describe('#getMerkleRoot', () => {
    it('should properly hash a 2-level tree of zeros', () => {
      const zeroHashed = Hash.sha256ripemd160(Buffer.from('0', 'hex'));
      const merkleRoot = Escrow.getMerkleRoot([zeroHashed, zeroHashed, zeroHashed, zeroHashed]);
      merkleRoot.toString('hex').should.equal('bcd72713b594ea45d44512ca7912c625f7e69092');
    });
  });
  describe('#generateMerkleRootFromPublicKeys', () => {
    it('should work for 3 public keys', () => {
      const publicKeyStrings = [
        '03fb0ed01700a2e9303f76ec93c61114507d9ea9bb3704c873fa8c1c7f4fad0a49',
        '02cc0cbe9725cea57e475b8cf8fef5556df5c4a73a912a167ee3e170fa1172725a',
        '0312e866a0b1dd1221a79729907f45672ad0ee426f1234f5f44c447000daa42341'
      ];
      const publicKeys = publicKeyStrings.map(publicKeyString => PublicKey.fromString(publicKeyString));
      const merkleRoot = Escrow.generateMerkleRootFromPublicKeys(publicKeys);
      merkleRoot.toString('hex').should.equal('8001321ef1822edc229a5387b181d6f8d18515cc');
    });
  });
  describe('#generateInputPublicKeyValidationScript', () => {
    it('should work for a single input public key', () => {
      const publicKey = PublicKey.fromString('03fb0ed01700a2e9303f76ec93c61114507d9ea9bb3704c873fa8c1c7f4fad0a49');
      const script = Escrow.generateInputPublicKeyValidationScript([publicKey]);
      script.should.equal(`OP_DUP OP_HASH160 20 0x2a42558df3ea6f2a438251374d7bd61c81f09f96 OP_EQUALVERIFY`);
    });
    it('should work for two input public keys', () => {
      const publicKeyStrings = [
        '02cc0cbe9725cea57e475b8cf8fef5556df5c4a73a912a167ee3e170fa1172725a',
        '0312e866a0b1dd1221a79729907f45672ad0ee426f1234f5f44c447000daa42341'
      ];
      const publicKeys = publicKeyStrings.map(publicKeyString => PublicKey.fromString(publicKeyString));
      const script = Escrow.generateInputPublicKeyValidationScript(publicKeys);
      script.should.equal(
        `OP_TOALTSTACK OP_DUP OP_HASH160 20 0xc5dd558db027f1e6efd37556d26d020a637303d6 20 0x5b4f8e5efc268d9c6d3d73d6993a795be259873f OP_FROMALTSTACK OP_ROLL 1 0x02 OP_ROLL OP_EQUALVERIFY OP_DROP`
      );
    });
    it('should work for three input public keys', () => {
      const publicKeyStrings = [
        '03fb0ed01700a2e9303f76ec93c61114507d9ea9bb3704c873fa8c1c7f4fad0a49',
        '02cc0cbe9725cea57e475b8cf8fef5556df5c4a73a912a167ee3e170fa1172725a',
        '0312e866a0b1dd1221a79729907f45672ad0ee426f1234f5f44c447000daa42341'
      ];
      const publicKeys = publicKeyStrings.map(publicKeyString => PublicKey.fromString(publicKeyString));
      const script = Escrow.generateInputPublicKeyValidationScript(publicKeys);
      script.should.equal(
        `OP_TOALTSTACK OP_DUP OP_HASH160 20 0x2a42558df3ea6f2a438251374d7bd61c81f09f96 20 0xc5dd558db027f1e6efd37556d26d020a637303d6 20 0x5b4f8e5efc268d9c6d3d73d6993a795be259873f OP_FROMALTSTACK OP_ROLL 1 0x03 OP_ROLL OP_EQUALVERIFY OP_2DROP`
      );
    });
    it('should work for four input public keys', () => {
      const publicKeyStrings = [
        '02bc1d5f978c6147dc70db39d88e33026f8e2d5cdb99b925944a06a1cce1be87c0',
        '03ebc008265ae249a805f647bf9623d74071ce66dbb3a8674cd1f99e1dfa81f550',
        '0269419378d0a7e5860495e95038da9b02203cb772ab5618c29d82ec8eae6a0781',
        '02f50aa80526676b0c6058c0daed0b6bbacfac17cf7879cd45130dc8dc3a3be873'
      ];
      const publicKeys = publicKeyStrings.map(publicKeyString => PublicKey.fromString(publicKeyString));
      const script = Escrow.generateInputPublicKeyValidationScript(publicKeys);
      script.should.equal(
        `1 0x03 OP_PICK OP_HASH160 1 0x03 OP_PICK 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 1 0x02 OP_ROLL 1 0x02 OP_DIV 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 20 0x13b0df96f790ce4188d3d6c30e75518e646d9d23 OP_EQUALVERIFY`
      );
    });
    it('should work for five input public keys', () => {
      const publicKeyStrings = [
        '033c7364c06498e9d31ac5ba32c5071080a25c481ba3222df32a1839cdc57c1036',
        '034c6f4984b35e4260e441c6eccb90f382e02c497aa1d2dc20029887272a37d2c4',
        '0284f6810dc878d9fda1843f05404f22dbc1d1837bba80efb011ebca832bbe728a',
        '0379116c71638ad1264d1c54faebb6a1c00f1bd187faf32707d02ae2252d706971',
        '03e62689382e81452f0b95220fff4443521dc4248938168280d76b79984876e61d'
      ];
      const publicKeys = publicKeyStrings.map(publicKeyString => PublicKey.fromString(publicKeyString));
      const script = Escrow.generateInputPublicKeyValidationScript(publicKeys);
      script.should.equal(
        `1 0x04 OP_PICK OP_HASH160 1 0x04 OP_PICK 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 1 0x03 OP_PICK 1 0x02 OP_DIV 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 1 0x02 OP_ROLL 1 0x04 OP_DIV 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 20 0x82a74acda5701d011090ad0039f2aa25a8724c85 OP_EQUALVERIFY`
      );
    });
    it('should work for nine public keys', () => {
      // const publicKeyStrings = Array(9)
      //   .fill(0)
      //   .map(() => {
      //     return new PrivateKey().toPublicKey().toString('hex');
      //   });
      const publicKeyStrings = [
        '03e1d90a373b55b97fb633868698b2368b343a96b595fdb7ec270be2d3978c754a',
        '03907a5e9d51332a6f0c2b24b3bffff2ab099a3f332aa8f578d1ff64305b44c8de',
        '03fe269d30823cc4cc54c1e6b4366ecef3a51085de9a81c69baa1889dd8433883f',
        '0276ae3947cab8b51e9e80d93fd8339af04ccc1731c917e75887d958bbfd3b9af7',
        '02270f250ad4680e3c12846d50e87cd940a0a054bbb1e396d2791f29ea26547b19',
        '02ea05929efe64d41ce0b12d65525ca9b56e477d948c9a3580dfa9ec37b6af6cdc',
        '0360971cda4738b25af57b8a7b50536df280c9ed1336c294ea9d60b44b49d982c9',
        '025d273be791dcd72f5bc81d15599fb54bb107c8a784d96bb3d2751d70d12c5d5d',
        '0301ce14bcadae1c49beec6575c00969888351c3cd20d0e6cb7713668ce8cc37d9'
      ];
      const publicKeys = publicKeyStrings.map(publicKeyString => PublicKey.fromString(publicKeyString));
      const script = Escrow.generateInputPublicKeyValidationScript(publicKeys);
      script.should.equal(
        `1 0x05 OP_PICK OP_HASH160 1 0x05 OP_PICK 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 1 0x04 OP_PICK 1 0x02 OP_DIV 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 1 0x03 OP_PICK 1 0x04 OP_DIV 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 1 0x02 OP_ROLL 1 0x08 OP_DIV 1 0x02 OP_MOD OP_NOTIF OP_SWAP OP_ENDIF OP_CAT OP_HASH160 20 0xa047442c13494553dbf18c98132605b0b708c71d OP_EQUALVERIFY`
      );
    });
  });
});
