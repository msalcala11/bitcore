import { MongoBound } from '../../../../models/base';
import { Config } from '../../../../services/config';
import { IEVMNetworkConfig } from '../../../../types/Config';
import { jsonStringify } from '../../../../utils';
import { TransformWithEventPipe } from '../../../../utils/streamWithEventPipe';
import { EVMTransactionStorage } from '../models/transaction';
import { IEVMTransactionTransformed } from '../types';

export class EVMListTransactionsStream extends TransformWithEventPipe {
  private walletAddressSet: Set<string>;
  private tokenAddressLower?: string;

  constructor(walletAddresses: Array<string>, private tokenAddress?: string) {
    super({ objectMode: true });
    this.walletAddressSet = new Set(walletAddresses.map(address => address.toLowerCase()));
    this.tokenAddressLower = tokenAddress?.toLowerCase();
  }

  async _transform(transaction: MongoBound<IEVMTransactionTransformed>, _, done) {
    if (this.tokenAddress && EVMTransactionStorage.isFailedReceipt(transaction.receipt)) {
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
          : -BigInt(transaction.value || 0);
        this.push(
          jsonStringify(baseTx) + '\n'
        );
      } else {
        baseTx.category = 'move';
        baseTx.satoshis = BigInt(transaction.value || 0);
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
      } else {
        // Same-address self-transfers initiated by a third party (relayer, AA bundler)
        // are 'move' rows; sender-initiated ones land in the move branch above because
        // token pipelines rewrite to/from to the transfer endpoints. Transfers between
        // two DIFFERENT addresses of one query's address set intentionally emit nothing:
        // EVM wallets are queried per address, so each leg is served by its own query.
        const selfTransferEffects = (transaction.effects || []).filter(effect =>
          this.isWalletAddress(effect.to) &&
          effect.from?.toLowerCase() === effect.to?.toLowerCase() &&
          this.matchesTokenAddress(effect.contractAddress)
        );
        if (selfTransferEffects.length) {
          baseTx.category = 'move';
          baseTx.satoshis = selfTransferEffects.reduce((amount, effect) => amount + BigInt(effect.amount || 0), 0n);
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
  // Exact per-request dedupe: bounded by the rows one request streams. A capped window
  // here would let duplicates through for wallets with more rows than the cap.
  private seenKeys = new Set<string>();
  private walletAddressSet: Set<string>;

  constructor(walletAddresses: Array<string> = []) {
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
      this.seenKeys.add(key);
      this.push(transaction);
    } else {
      this.push(transaction);
    }
    return done();
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
