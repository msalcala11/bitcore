'use strict';

var inherits = require('inherits');
var Input = require('./input');
var Output = require('../output');
var $ = require('../../util/preconditions');

var Script = require('../../script');
var Signature = require('../../crypto/signature');
var Sighash = require('../sighash');
var TransactionSignature = require('../signature');

/**
 * @constructor
 */
function EscrowInput(input, inputPublicKeys, reclaimPublicKey, signatures) {
  Input.apply(this, arguments);
  signatures = signatures || input.signatures || [];
  this.inputPublicKeys = inputPublicKeys;
  this.reclaimPublicKey = reclaimPublicKey;
  this.redeemScript = Script.buildEscrowOut(inputPublicKeys, reclaimPublicKey);
  $.checkState(Script.buildScriptHashOut(this.redeemScript).equals(this.output.script),
               'Provided public keys don\'t hash to the provided output');
  this.signatures = this._deserializeSignatures(signatures);
}
inherits(EscrowInput, Input);

EscrowInput.prototype.getSignatures = function(transaction, privateKey, index, sigtype, hashData, signingMethod) {
  if(this.reclaimPublicKey.toString() !== privateKey.publicKey.toString()) return [];
  $.checkState(this.output instanceof Output);
  sigtype = sigtype || (Signature.SIGHASH_ALL |  Signature.SIGHASH_FORKID);
  const signature = new TransactionSignature({
    publicKey: privateKey.publicKey,
    prevTxId: this.prevTxId,
    outputIndex: this.outputIndex,
    inputIndex: index,
    signature: Sighash.sign(transaction, privateKey, sigtype, index, this.redeemScript, this.output.satoshisBN, undefined, signingMethod),
    sigtype: sigtype
  });
  return [signature];
};

EscrowInput.prototype.addSignature = function(transaction, signature, signingMethod) {
  $.checkState(this.isValidSignature(transaction, signature, signingMethod));
  const signatureString = signature.signature.toBuffer('schnorr').toString('hex') + '41';
  const redeemScript = this.redeemScript.toHex();
  const redeemScriptBytes = redeemScript.length / 2;
  const redeemScriptPushPrefix = redeemScriptBytes > 75 ? `OP_PUSHDATA_1 ${redeemScriptBytes}` : `OP_PUSHBYTES_${redeemScriptBytes}`; 
  const reclaimScript = `OP_PUSHBYTES_${
      signatureString.length / 2
    } 0x${signatureString} OP_PUSHBYTES_33 0x${this.reclaimPublicKey.toString()} ${redeemScriptPushPrefix} 0x${redeemScript}`
      .replace(new RegExp('OP_PUSHBYTES_', 'g'), '')
      .replace(new RegExp('PUSHDATA_1', 'g'), 'PUSHDATA1');
  this.setScript(reclaimScript);
}

EscrowInput.prototype.isValidSignature = function(transaction, signature, signingMethod) {
  signingMethod = signingMethod || 'ecdsa';
  signature.signature.nhashtype = signature.sigtype;
  return Sighash.verify(
    transaction,
    signature.signature,
    signature.publicKey,
    signature.inputIndex,
    this.redeemScript,
    this.output.satoshisBN,
    undefined,
    signingMethod
  );
};

EscrowInput.prototype.clearSignatures = function() {
  this.signatures = [];
};

EscrowInput.prototype._deserializeSignatures = function(signatures) {
  return signatures.map(signature => new TransactionSignature(signature));
};

module.exports = EscrowInput;