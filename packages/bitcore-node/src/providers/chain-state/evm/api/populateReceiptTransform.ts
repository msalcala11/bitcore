import { MongoBound } from '../../../../models/base';
import { TransformWithEventPipe } from '../../../../utils/streamWithEventPipe';
import { IEVMTransaction } from '../types';
import { BaseEVMStateProvider } from './csp';

type ReceiptEnrichment = Pick<IEVMTransaction, 'effects' | 'fee' | 'receipt' | 'receiptLogEffectsProcessed'>;

export class PopulateReceiptTransform extends TransformWithEventPipe {
  // Success-only, per-request memo: external providers emit one row per wallet address, so
  // the same txid can pass through more than once. Failures are not memoized, so a
  // transient RPC error on one row does not poison its duplicates.
  private enrichedTxs = new Map<string, ReceiptEnrichment>();

  constructor(private evm: BaseEVMStateProvider, private maxCachedTxids = 10_000) {
    super({ objectMode: true });
  }

  async _transform(tx: MongoBound<IEVMTransaction>, _, done) {
    const enrichment = tx.txid ? this.enrichedTxs.get(tx.txid) : undefined;
    if (enrichment) {
      this.applyEnrichment(tx, enrichment);
      this.push(tx);
      return done();
    }
    try {
      tx = await this.evm.populateReceipt(tx);
      if (tx.txid) {
        this.rememberEnrichment(tx.txid, this.snapshotEnrichment(tx));
      }
    } catch {/* ignore error; the row passes through unenriched and duplicates retry */}
    this.push(tx);
    return done();
  }

  private snapshotEnrichment(tx: MongoBound<IEVMTransaction>): ReceiptEnrichment {
    return {
      effects: this.cloneEffects(tx.effects),
      fee: tx.fee,
      receipt: this.cloneReceipt(tx.receipt),
      receiptLogEffectsProcessed: tx.receiptLogEffectsProcessed
    };
  }

  private applyEnrichment(tx: MongoBound<IEVMTransaction>, enrichment: ReceiptEnrichment) {
    if (enrichment.effects !== undefined) {
      tx.effects = this.cloneEffects(enrichment.effects);
    }
    if (enrichment.fee !== undefined) {
      tx.fee = enrichment.fee;
    }
    if (enrichment.receipt !== undefined) {
      tx.receipt = this.cloneReceipt(enrichment.receipt);
    }
    if (enrichment.receiptLogEffectsProcessed !== undefined) {
      tx.receiptLogEffectsProcessed = enrichment.receiptLogEffectsProcessed;
    }
  }

  private rememberEnrichment(txid: string, enrichment: ReceiptEnrichment) {
    if (this.enrichedTxs.size >= this.maxCachedTxids) {
      // Maps iterate in insertion order, so the first key is the oldest entry.
      const oldestTxid = this.enrichedTxs.keys().next().value;
      if (oldestTxid !== undefined) {
        this.enrichedTxs.delete(oldestTxid);
      }
    }
    this.enrichedTxs.set(txid, enrichment);
  }

  private cloneEffects(effects?: IEVMTransaction['effects']) {
    return effects?.map(effect => ({ ...effect }));
  }

  private cloneReceipt(receipt?: IEVMTransaction['receipt']) {
    return receipt ? { ...(receipt as any) } : receipt;
  }
}
