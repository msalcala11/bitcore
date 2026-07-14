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
  private walletAddressSet: Set<string>;
  private tokenAddressLower?: string;

  constructor(walletAddresses: Array<string>, private tokenAddress?: string) {
    super({ objectMode: true });
    this.walletAddressSet = new Set(walletAddresses.map(address => address.toLowerCase()));
    this.tokenAddressLower = tokenAddress?.toLowerCase();
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

    // Rows we know are token transfers carry an explicit abiType so consumers (BWS, wallets)
    // don't have to re-infer it from effects: every row of a token-history stream, and native
    // rows whose top-level call hit a token contract that emitted a transfer.
    if (!baseTx.abiType && (this.tokenAddress || this.isTopLevelErc20Transfer(transaction))) {
      baseTx.abiType = { type: 'ERC20', name: 'transfer', params: [] };
    }

    const matchingReceiveEffects = (transaction.effects || []).filter(effect =>
      this.isWalletAddress(effect.to) &&
      this.matchesTokenAddress(effect.contractAddress) &&
      !this.isWalletMoveEffect(effect)
    );
    const matchingSendEffects = (transaction.effects || []).filter(effect =>
      this.isWalletAddress(effect.from) &&
      this.matchesTokenAddress(effect.contractAddress) &&
      !this.isWalletMoveEffect(effect)
    );

    const sending = this.isWalletAddress(transaction.from);
    if (sending) {
      const sendingToOurself = this.isWalletAddress(transaction.to);
      if (!sendingToOurself) {
        baseTx.category = 'send';
        baseTx.satoshis = this.tokenAddress && matchingSendEffects.length
          ? -matchingSendEffects.reduce((amount, effect) => amount + BigInt(effect.amount || 0), 0n)
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
      const weReceived = this.isWalletAddress(transaction.to);
      if (matchingReceiveEffects.length) {
        baseTx.satoshis = 0n;
        for (const effect of matchingReceiveEffects) {
          baseTx.satoshis += BigInt(effect.amount || 0);
        }
        this.push(
          jsonStringify(baseTx) + '\n'
        );
      } else if (weReceived) {
        baseTx.satoshis = BigInt(transaction.value || 0);
        this.push(
          jsonStringify(baseTx) + '\n'
        );
      }
    }
    return done();
  }

  private isWalletMoveEffect(effect: { from?: string; to?: string }) {
    return this.isWalletAddress(effect.from) && this.isWalletAddress(effect.to);
  }

  private isTopLevelErc20Transfer(transaction: MongoBound<IEVMTransactionTransformed>) {
    const txTo = transaction.to?.toLowerCase();
    const txFrom = transaction.from?.toLowerCase();
    if (!txTo || !txFrom) {
      return false;
    }
    // A native-value call to a token contract (e.g. Lido submit()) can emit Transfer logs
    // but is still a native send, not a token transfer.
    if (Number(transaction.value || 0) !== 0) {
      return false;
    }
    return !!transaction.effects?.some(effect =>
      effect.type === 'ERC20:transfer' &&
      effect.contractAddress?.toLowerCase() === txTo &&
      effect.from?.toLowerCase() === txFrom
    );
  }

  private isWalletAddress(address?: string) {
    return !!address && this.walletAddressSet.has(address.toLowerCase());
  }

  private matchesTokenAddress(contractAddress?: string) {
    if (!this.tokenAddressLower) {
      return !contractAddress;
    }
    return contractAddress?.toLowerCase() === this.tokenAddressLower;
  }
}

export class TxidDedupeTransform extends TransformWithEventPipe {
  private seenKeys = new Set<string>();
  private keyOrder = new Array<string>();
  private walletAddressSet: Set<string>;

  constructor(walletAddresses: Array<string> = [], private maxSeenKeys = 10_000) {
    super({ objectMode: true });
    this.walletAddressSet = new Set(walletAddresses.map(address => address.toLowerCase()));
  }

  _transform(transaction: MongoBound<IEVMTransactionTransformed>, _, done) {
    if (!transaction.receiptLogEffectsProcessed || !transaction.effects?.length) {
      this.push(transaction);
    } else if (transaction.txid) {
      const key = `${transaction.txid}:${this.getDirection(transaction)}`;
      if (this.seenKeys.has(key)) {
        return done();
      }
      this.rememberKey(key);
      this.push(transaction);
    } else {
      this.push(transaction);
    }
    return done();
  }

  private rememberKey(key: string) {
    this.seenKeys.add(key);
    this.keyOrder.push(key);
    if (this.keyOrder.length > this.maxSeenKeys) {
      const oldestKey = this.keyOrder.shift();
      if (oldestKey) {
        this.seenKeys.delete(oldestKey);
      }
    }
  }

  private getDirection(transaction: MongoBound<IEVMTransactionTransformed>) {
    const fromWallet = this.isWalletAddress(transaction.from);
    const toWallet = this.isWalletAddress(transaction.to);
    if (fromWallet && toWallet) {
      return 'move';
    }
    if (fromWallet) {
      return 'send';
    }
    if (toWallet) {
      return 'receive';
    }
    return 'other';
  }

  private isWalletAddress(address?: string) {
    return !!address && this.walletAddressSet.has(address.toLowerCase());
  }
}
