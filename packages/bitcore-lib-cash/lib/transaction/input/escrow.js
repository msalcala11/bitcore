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
  $.checkState(
    Script.buildScriptHashOut(this.redeemScript).equals(this.output.script),
    "Provided public keys don't hash to the provided output"
  );
  this.signatures = this._deserializeSignatures(signatures);
}
inherits(EscrowInput, Input);

EscrowInput.prototype.getSignatures = function(transaction, privateKey, index, sigtype, hashData, signingMethod) {
  if (this.reclaimPublicKey.toString() !== privateKey.publicKey.toString()) return [];
  $.checkState(this.output instanceof Output);
  sigtype = sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;
  const signature = new TransactionSignature({
    publicKey: privateKey.publicKey,
    prevTxId: this.prevTxId,
    outputIndex: this.outputIndex,
    inputIndex: index,
    signature: Sighash.sign(
      transaction,
      privateKey,
      sigtype,
      index,
      this.redeemScript,
      this.output.satoshisBN,
      undefined,
      signingMethod
    ),
    sigtype: sigtype
  });
  return [signature];
};

EscrowInput.prototype.addSignature = function(transaction, signature, signingMethod) {
  $.checkState(this.isValidSignature(transaction, signature, signingMethod));
  const reclaimScript = Script.buildEscrowIn(this.reclaimPublicKey, signature.signature, this.redeemScript);
  this.setScript(reclaimScript);
  this.signatures = [signature];
};

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

EscrowInput.prototype.isFullySigned = function() {
  return this.signatures.length === 1;
};

EscrowInput.prototype._deserializeSignatures = function(signatures) {
  return signatures.map(signature => new TransactionSignature(signature));
};

module.exports = EscrowInput;
