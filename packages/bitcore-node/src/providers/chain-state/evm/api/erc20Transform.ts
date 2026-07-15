import { Web3 } from '@bitpay-labs/crypto-wallet-core';
import { MongoBound } from '../../../../models/base';
import { TransformWithEventPipe } from '../../../../utils/streamWithEventPipe';
import { Effect, IEVMTransactionInProcess, IEVMTransactionTransformed } from '../types';

type TokenEffectTx = MongoBound<IEVMTransactionInProcess> & Pick<IEVMTransactionTransformed, 'initialFrom'>;

/**
 * Splits one tx into one row per token effect, rewriting the row to the transfer's
 * endpoints. callStack is how a requester can verify uniqueness in light of
 * duplicated txids.
 */
export function splitTxByTokenEffects(
  tx: TokenEffectTx,
  tokenEffects: Effect[]
): IEVMTransactionTransformed[] {
  const rows: IEVMTransactionTransformed[] = [];
  const rootSender = getRootSender(tx);
  for (const effect of tokenEffects) {
    const _tx: IEVMTransactionTransformed = Object.assign({}, tx);
    // Keep the exact string amount; Number() loses precision above 2^53.
    _tx.value = effect.amount as any;
    _tx.to = effect.to;
    _tx.from = effect.from;
    _tx.effects = [effect];
    if (tx.initialFrom === undefined && rootSender && !sameAddress(effect.from, rootSender)) {
      _tx.initialFrom = rootSender;
    }
    _tx.callStack = effect.callStack;
    rows.push(_tx);
  }
  return rows;
}

function getRootSender(tx: TokenEffectTx): string {
  if (tx.initialFrom !== undefined) {
    return tx.initialFrom;
  }
  const receiptFrom = tx.receipt?.from;
  if (typeof receiptFrom === 'string' && Web3.utils.isAddress(receiptFrom)) {
    return Web3.utils.toChecksumAddress(receiptFrom);
  }
  return tx.from;
}

function sameAddress(left?: string, right?: string) {
  return !!left && !!right && left.toLowerCase() === right.toLowerCase();
}

export class Erc20RelatedFilterTransform extends TransformWithEventPipe {
  constructor(private tokenAddress: string) {
    super({ objectMode: true });
  }

  async _transform(tx: MongoBound<IEVMTransactionInProcess>, _, done) {
    this.tokenAddress = Web3.utils.toChecksumAddress(this.tokenAddress);
    if (tx.effects && tx.effects.length) {
      // Get all effects where contractAddress is tokenAddress
      const tokenRelatedInternalTxs = tx.effects.filter(
        (effect: any) => effect.contractAddress?.toLowerCase() === this.tokenAddress.toLowerCase()
      );

      // Create a tx object for each erc20 transfer
      for (const row of splitTxByTokenEffects(tx, tokenRelatedInternalTxs)) {
        this.push(row);
      }
    }
    return done();
  }
}
