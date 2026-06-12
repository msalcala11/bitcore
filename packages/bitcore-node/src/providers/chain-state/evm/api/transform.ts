import { MongoBound } from '../../../../models/base';
import { Config } from '../../../../services/config';
import { IEVMNetworkConfig } from '../../../../types/Config';
import { jsonStringify } from '../../../../utils';
import { TransformWithEventPipe } from '../../../../utils/streamWithEventPipe';
import { IEVMTransactionTransformed } from '../types';

const isFailedReceipt = (receipt?: { status?: boolean | number | string | bigint }) => {
  const status = receipt?.status;
  return status === false || status === 0 || status === 0n || status === '0' || status === '0x0';
};

export class EVMListTransactionsStream extends TransformWithEventPipe {
  constructor(private walletAddresses: Array<string>, private tokenAddress?: string) {
    super({ objectMode: true });
  }
  async _transform(transaction: MongoBound<IEVMTransactionTransformed>, _, done) {
    if (this.tokenAddress && isFailedReceipt(transaction.receipt)) {
      return done();
    }

    const baseTx = {
      id: transaction._id,
      txid: transaction.txid,
      fee: transaction.fee,
      height: transaction.blockHeight,
      from: transaction.from,
      initialFrom: transaction.initialFrom || transaction.from,
      gasPrice: transaction.gasPrice,
      gasLimit: transaction.gasLimit,
      receipt: transaction.receipt,
      address: transaction.to,
      blockTime: transaction.blockTimeNormalized,
      error: transaction.error,
      network: transaction.network,
      chain: transaction.chain,
      nonce: transaction.nonce,
      effects: transaction.effects,
      callStack: transaction.callStack
    } as any;

    // Add old properties if leanTxStorage is not enabled
    const config = Config.chainConfig({ chain: transaction.chain, network: transaction.network }) as IEVMNetworkConfig;
    if (!config || !config.leanTransactionStorage) {
      baseTx.abiType = transaction.abiType;
      baseTx.internal = transaction.internal;
      baseTx.calls = transaction.calls;
      baseTx.data = transaction.data ? transaction.data.toString() : '';
    }

    const matchingReceiveEffects = (transaction.effects || []).filter(effect =>
      this.walletAddresses.includes(effect.to) && effect.contractAddress == this.tokenAddress
    );
    const matchingSendEffects = (transaction.effects || []).filter(effect =>
      this.walletAddresses.includes(effect.from) && effect.contractAddress == this.tokenAddress
    );

    const sending = this.walletAddresses.includes(transaction.from);
    if (sending) {
      const sendingToOurself = this.walletAddresses.includes(transaction.to);
      if (!sendingToOurself) {
        baseTx.category = 'send';
        baseTx.satoshis = this.tokenAddress && matchingSendEffects.length
          ? -Number(matchingSendEffects.reduce((amount, effect) => amount + BigInt(effect.amount || 0), 0n))
          : -transaction.value;
        this.push(
          jsonStringify(baseTx) + '\n'
        );
      } else {
        baseTx.category = 'move';
        baseTx.satoshis = transaction.value;
        this.push(
          jsonStringify(baseTx) + '\n'
        );
      }
    } else {
      baseTx.category = 'receive'; // assume it's a receive, but may not be sent
      const weReceived = this.walletAddresses.includes(transaction.to);
      if (matchingReceiveEffects.length) {
        baseTx.satoshis = 0n;
        for (const effect of matchingReceiveEffects) {
          baseTx.satoshis += BigInt(effect.amount || 0);
        }
        this.push(
          jsonStringify(baseTx) + '\n'
        );
      } else if (weReceived) {
        // console.log(weReceived, weReceivedInternal, transaction.to, this.walletAddresses, transaction);
        baseTx.satoshis = BigInt(transaction.value || 0);
        this.push(
          jsonStringify(baseTx) + '\n'
        );
      }
    }
    return done();
  }
}

export class TxidDedupeTransform extends TransformWithEventPipe {
  private seenTxids = new Set<string>();

  constructor() {
    super({ objectMode: true });
  }

  _transform(transaction: MongoBound<IEVMTransactionTransformed>, _, done) {
    if (transaction.txid) {
      if (this.seenTxids.has(transaction.txid)) {
        return done();
      }
      this.seenTxids.add(transaction.txid);
    }
    this.push(transaction);
    return done();
  }
}
