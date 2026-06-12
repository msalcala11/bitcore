import { MongoBound } from '../../../../models/base';
import { TransformWithEventPipe } from '../../../../utils/streamWithEventPipe';
import { IEVMTransaction } from '../types';
import { BaseEVMStateProvider } from './csp';

type ReceiptEnrichment = Pick<IEVMTransaction, 'effects' | 'fee' | 'receipt' | 'receiptLogEffectsProcessed' | 'receiptLogEffectsUnavailable'>;

export class PopulateReceiptTransform extends TransformWithEventPipe {
  private enrichedTxs = new Map<string, ReceiptEnrichment>();
  private failedTxs = new Set<string>();
  private cachedTxids = new Set<string>();
  private txidOrder = new Array<string>();

  constructor(private evm: BaseEVMStateProvider, private maxCachedTxids = 10_000) {
    super({ objectMode: true });
  }

  async _transform(tx: MongoBound<IEVMTransaction>, _, done) {
    if (tx.txid && this.failedTxs.has(tx.txid)) {
      this.push(tx);
      return done();
    }
    const cachedEnrichment = tx.txid ? this.enrichedTxs.get(tx.txid) : undefined;
    if (cachedEnrichment) {
      this.applyEnrichment(tx, cachedEnrichment);
      this.push(tx);
      return done();
    }
    try {
      tx = await this.evm.populateReceipt(tx);
      if (tx.txid) {
        this.rememberEnrichment(tx.txid, this.getEnrichment(tx));
      }
    } catch {
      if (tx.txid) {
        this.rememberFailure(tx.txid);
      }
    }
    this.push(tx);
    return done();
  }

  private getEnrichment(tx: MongoBound<IEVMTransaction>): ReceiptEnrichment {
    return {
      effects: tx.effects,
      fee: tx.fee,
      receipt: tx.receipt,
      receiptLogEffectsProcessed: tx.receiptLogEffectsProcessed,
      receiptLogEffectsUnavailable: tx.receiptLogEffectsUnavailable
    };
  }

  private applyEnrichment(tx: MongoBound<IEVMTransaction>, enrichment: ReceiptEnrichment) {
    if (enrichment.effects !== undefined) {
      tx.effects = enrichment.effects;
    }
    if (enrichment.fee !== undefined) {
      tx.fee = enrichment.fee;
    }
    if (enrichment.receipt !== undefined) {
      tx.receipt = enrichment.receipt;
    }
    if (enrichment.receiptLogEffectsProcessed !== undefined) {
      tx.receiptLogEffectsProcessed = enrichment.receiptLogEffectsProcessed;
    }
    if (enrichment.receiptLogEffectsUnavailable !== undefined) {
      tx.receiptLogEffectsUnavailable = enrichment.receiptLogEffectsUnavailable;
    }
  }

  private rememberEnrichment(txid: string, enrichment: ReceiptEnrichment) {
    this.enrichedTxs.set(txid, enrichment);
    this.rememberTxid(txid);
  }

  private rememberFailure(txid: string) {
    this.failedTxs.add(txid);
    this.rememberTxid(txid);
  }

  private rememberTxid(txid: string) {
    if (this.cachedTxids.has(txid)) {
      return;
    }
    this.cachedTxids.add(txid);
    this.txidOrder.push(txid);
    if (this.txidOrder.length > this.maxCachedTxids) {
      const oldestTxid = this.txidOrder.shift();
      if (oldestTxid) {
        this.cachedTxids.delete(oldestTxid);
        this.enrichedTxs.delete(oldestTxid);
        this.failedTxs.delete(oldestTxid);
      }
    }
  }
}
