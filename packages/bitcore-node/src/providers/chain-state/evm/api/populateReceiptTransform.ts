import logger from '../../../../logger';
import { MongoBound } from '../../../../models/base';
import { TransformWithEventPipe } from '../../../../utils/streamWithEventPipe';
import { IEVMTransaction } from '../types';
import { BaseEVMStateProvider } from './csp';
import { TokenHistoryMode, getWalletRelevantTokenEffects } from './transform';

type ReceiptEnrichment = Pick<IEVMTransaction, 'effects' | 'fee' | 'receipt' | 'receiptLogEffectsProcessed'>;

// Payload-free per-txid arithmetic mode. Tracked separately from the enrichment
// snapshot cache: evicting a (large) snapshot must never flip a (tiny) mode record,
// or a late duplicate would double-count legs the primary row already served.
type TokenTxMode = { kind: 'expanded' } | { kind: 'raw' };

export interface TokenExpansionOptions {
  walletAddresses: Array<string>;
  tokenAddress: string;
  /** Receipt fetch retries per unknown txid before pinning it raw (default 2). */
  receiptRetries?: number;
  receiptRetryDelayMs?: number;
  /** Consecutive fetch failures before the rest of the request serves raw (default 5). */
  breakerThreshold?: number;
  maxModeEntries?: number;
}

const DEFAULT_RECEIPT_RETRIES = 2;
const DEFAULT_RECEIPT_RETRY_DELAY_MS = 250;
const DEFAULT_BREAKER_THRESHOLD = 5;
const MAX_MODE_ENTRIES = 250_000;

export class PopulateReceiptTransform extends TransformWithEventPipe {
  // Success-only, per-request memo: external providers emit one row per wallet address,
  // so the same txid can pass through more than once. Failures are not memoized —
  // native/Gnosis duplicates retry, and token-mode failure state lives in txModes.
  private enrichedTxs = new Map<string, ReceiptEnrichment>();

  // Token mode only.
  private txModes = new Map<string, TokenTxMode>();
  private walletAddressSet: Set<string> = new Set();
  private tokenAddressLower = '';
  private consecutiveFailures = 0;
  private breakerOpen = false;
  private warnedAboutModeEviction = false;

  constructor(
    private evm: BaseEVMStateProvider,
    private tokenExpansion?: TokenExpansionOptions,
    private maxCachedTxids = 10_000
  ) {
    super({ objectMode: true });
    if (tokenExpansion) {
      this.walletAddressSet = new Set(tokenExpansion.walletAddresses.map(address => address.toLowerCase()));
      this.tokenAddressLower = tokenExpansion.tokenAddress.toLowerCase();
    }
  }

  async _transform(tx: MongoBound<IEVMTransaction>, _, done) {
    if (this.tokenExpansion && tx.txid) {
      return this._transformTokenMode(tx, done);
    }
    const enrichment = tx.txid ? this.enrichedTxs.get(tx.txid) : undefined;
    if (enrichment) {
      this.applyEnrichment(tx, enrichment);
      this.push(tx);
      return done();
    }
    try {
      tx = await this.evm.populateReceipt(tx);
      if (tx.txid && tx.receipt) {
        this.rememberEnrichment(tx.txid, this.snapshotEnrichment(tx));
      }
    } catch {/* ignore error; the row passes through unenriched and duplicates retry */}
    this.push(tx);
    return done();
  }

  /**
   * Token history: every row of a txid must serve in ONE arithmetic mode for the
   * request. 'expanded' rows carry the authoritative receipt-derived effect set (the
   * first row expands to every leg; duplicates drop); 'raw' rows serve their
   * provider-supplied amounts. Mixing modes within a txid double-counts legs, so the
   * first row's outcome is pinned for all of its duplicates.
   */
  private async _transformTokenMode(tx: MongoBound<IEVMTransaction>, done) {
    const txid = tx.txid;
    const mode = this.txModes.get(txid);
    if (mode) {
      if (mode.kind === 'expanded') {
        this.setMode(tx, 'drop');
      } else {
        // Metadata (receipt/fee) cloning is best-effort — a missing snapshot never
        // changes the arithmetic, the row just serves without the extra fields.
        const enrichment = this.enrichedTxs.get(txid);
        if (enrichment) {
          this.applyEnrichment(tx, enrichment);
        }
        this.setMode(tx, 'raw');
      }
      this.push(tx);
      return done();
    }

    let enriched = false;
    if (!this.breakerOpen) {
      try {
        tx = await this.evm.populateReceipt(tx, {
          retries: this.tokenExpansion!.receiptRetries ?? DEFAULT_RECEIPT_RETRIES,
          retryDelayMs: this.tokenExpansion!.receiptRetryDelayMs ?? DEFAULT_RECEIPT_RETRY_DELAY_MS
        });
        enriched = !!tx.receipt;
      } catch {/* pinned raw below */}
      if (enriched) {
        this.consecutiveFailures = 0;
        this.rememberEnrichment(txid, this.snapshotEnrichment(tx));
      } else {
        this.consecutiveFailures++;
        const threshold = this.tokenExpansion!.breakerThreshold ?? DEFAULT_BREAKER_THRESHOLD;
        if (this.consecutiveFailures >= threshold) {
          this.breakerOpen = true;
          logger.warn('PopulateReceiptTransform: %o consecutive receipt fetch failures; serving the remaining txids of this request as provider rows', this.consecutiveFailures);
        }
      }
    }

    const expandable = enriched &&
      !!tx.receiptLogEffectsProcessed &&
      getWalletRelevantTokenEffects(tx.effects, this.walletAddressSet, this.tokenAddressLower).length > 0;
    this.rememberMode(txid, expandable ? { kind: 'expanded' } : { kind: 'raw' });
    this.setMode(tx, expandable ? 'expand' : 'raw');
    this.push(tx);
    return done();
  }

  private setMode(tx: MongoBound<IEVMTransaction>, mode: TokenHistoryMode) {
    (tx as any).tokenHistoryMode = mode;
  }

  private rememberMode(txid: string, mode: TokenTxMode) {
    const maxModeEntries = this.tokenExpansion!.maxModeEntries ?? MAX_MODE_ENTRIES;
    if (this.txModes.size >= maxModeEntries) {
      if (!this.warnedAboutModeEviction) {
        this.warnedAboutModeEviction = true;
        logger.warn('PopulateReceiptTransform exceeded %o txid mode entries; evicting oldest — duplicate token history rows are possible for this request', maxModeEntries);
      }
      // Maps iterate in insertion order, so the first key is the oldest entry.
      const oldestTxid = this.txModes.keys().next().value;
      if (oldestTxid !== undefined) {
        this.txModes.delete(oldestTxid);
      }
    }
    this.txModes.set(txid, mode);
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
