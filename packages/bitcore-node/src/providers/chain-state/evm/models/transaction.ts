import { Utils, Web3 } from '@bitpay-labs/crypto-wallet-core';
import { ObjectID } from 'bson';
import { LoggifyClass } from '../../../../decorators/Loggify';
import logger from '../../../../logger';
import { MongoBound } from '../../../../models/base';
import { BaseTransaction } from '../../../../models/baseTransaction';
import { CacheStorage } from '../../../../models/cache';
import { EventStorage } from '../../../../models/events';
import { WalletAddressStorage } from '../../../../models/walletAddress';
import { Config } from '../../../../services/config';
import { Storage, StorageService } from '../../../../services/storage';
import { SpentHeightIndicators } from '../../../../types/Coin';
import { partition, uniqBy, valueOrDefault } from '../../../../utils';
import { ERC20Abi } from '../abi/erc20';
import { ERC721Abi } from '../abi/erc721';
import { InvoiceAbi } from '../abi/invoice';
import { MultisendAbi } from '../abi/multisend';
import { MultisigAbi } from '../abi/multisig';
import type { IEVMNetworkConfig } from '../../../../types/Config';
import type { StreamingFindOptions } from '../../../../types/Query';
import type { TransformOptions } from '../../../../types/TransformOptions';
import type { EVMTransactionJSON, Effect, IAbiDecodeResponse, IAbiDecodedData, IEVMBlock, IEVMCachedAddress, IEVMTransaction, IEVMTransactionInProcess, IEVMTransactionTransformed, ParsedAbiParams } from '../types';
import type { Web3Types } from '@bitpay-labs/crypto-wallet-core';


function requireUncached(module) {
  delete require.cache[require.resolve(module)];
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require(module);
}

const Erc20Decoder = requireUncached('abi-decoder');
Erc20Decoder.addABI(ERC20Abi);
function getErc20Decoder() {
  return Erc20Decoder;
}
const ERC20_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

export type ReceiptLogCompleteness =
  | { kind: 'complete' }
  | { kind: 'incomplete'; contracts: string[] };

export type ReceiptEffectOutcome =
  | { kind: 'derived'; completeness: ReceiptLogCompleteness }
  | { kind: 'not-derived'; reason: 'missing-logs' | 'effect-derivation-failed' };

type ReceiptEffectResult = {
  effects: Effect[];
  outcome: ReceiptEffectOutcome;
};

const Erc721Decoder = requireUncached('abi-decoder');
Erc721Decoder.addABI(ERC721Abi);
function getErc721Decoder() {
  return Erc721Decoder;
}

const InvoiceDecoder = requireUncached('abi-decoder');
InvoiceDecoder.addABI(InvoiceAbi);
function getInvoiceDecoder() {
  return InvoiceDecoder;
}

const MultisigDecoder = requireUncached('abi-decoder');
MultisigDecoder.addABI(MultisigAbi);
function getMultisigDecoder() {
  return MultisigDecoder;
}

const MultisendDecoder = requireUncached('abi-decoder');
MultisendDecoder.addABI(MultisendAbi);
function getMultisendDecoder() {
  return MultisendDecoder;
}

@LoggifyClass
export class EVMTransactionModel extends BaseTransaction<IEVMTransaction> {
  constructor(storage: StorageService = Storage) {
    super(storage);
  }

  async onConnect() {
    super.onConnect();
    this.collection.createIndex({ chain: 1, network: 1, to: 1 }, { background: true, sparse: true });
    this.collection.createIndex({ chain: 1, network: 1, from: 1 }, { background: true, sparse: true });
    this.collection.createIndex({ chain: 1, network: 1, from: 1, nonce: 1 }, { background: true, sparse: true });
    this.collection.createIndex(
      { chain: 1, network: 1, 'abiType.params.0.value': 1, blockTimeNormalized: 1 },
      {
        background: true,
        partialFilterExpression: { 'abiType.type': 'ERC20', 'abiType.name': 'transfer' }
      }
    );
    this.collection.createIndex(
      { chain: 1, network: 1, 'calls.abiType.params.value': 1, blockTimeNormalized: 1 },
      {
        background: true,
        partialFilterExpression: { 'calls.abiType.type': 'ERC20', 'calls.abiType.params.type': 'address' }
      }
    );
    this.collection.createIndex(
      { chain: 1, network: 1, 'internal.action.to': 1 },
      {
        background: true,
        sparse: true
      }
    );
    this.collection.createIndex(
      { chain: 1, network: 1, 'calls.to': 1 },
      {
        background: true,
        sparse: true
      }
    );
    this.collection.createIndex(
      { chain: 1, network: 1, 'effects.to': 1, blockTimeNormalized: 1 },
      {
        background: true,
        partialFilterExpression: { 'effects.to': { $exists: true } }
      }
    );
    this.collection.createIndex(
      { chain: 1, network: 1, 'effects.from': 1, blockTimeNormalized: 1 },
      {
        background: true,
        partialFilterExpression: { 'effects.from': { $exists: true } }
      }
    );
  }

  async batchImport(params: {
    txs: Array<IEVMTransactionInProcess>;
    failedReceiptTxids?: Set<string>;
    receiptEffectOutcomes?: Map<string, ReceiptEffectOutcome>;
    height: number;
    mempoolTime?: Date;
    blockTime?: Date;
    blockHash?: string;
    blockTimeNormalized?: Date;
    parentChain?: string;
    forkHeight?: number;
    chain: string;
    network: string;
    initialSyncComplete: boolean;
  }) {
    const operations = [] as Array<Promise<any>>;
    operations.push(this.pruneMempool({ ...params }));
    const txOps: any[] = await this.addTransactions({ ...params });
    logger.debug('Writing Transactions: %o', txOps.length);
    operations.push(
      ...partition(txOps, txOps.length / Config.get().maxPoolSize).map(txBatch =>
        this.collection.bulkWrite(
          txBatch.map(op => this.toMempoolSafeUpsert(op, params.height)),
          { ordered: false }
        )
      )
    );
    await Promise.all(operations);

    if (params.initialSyncComplete) {
      await this.expireBalanceCache(txOps);
    }

    // Create events for mempool txs
    if (params.height < SpentHeightIndicators.minimum) {
      for (const op of txOps) {
        const filter = op.updateOne.filter;
        const tx = { ...op.updateOne.update.$set, ...filter } as IEVMTransactionInProcess;
        await EventStorage.signalTx(tx);
        await EventStorage.signalAddressCoin({
          address: tx.to,
          coin: { value: Number(tx.value), address: tx.to, chain: params.chain, network: params.network, mintTxid: tx.txid }
        });
      }
    }
  }

  /**
   * Finds the wallet ids registered for any address the tx touches (to, from, and effect
   * endpoints). Used at sync time to tag txs, and by the repair paths (read-time
   * populateReceipt and the backfill script) to retag when late-derived effects add
   * addresses — history queries filter on the wallets tag, so an untagged repair would
   * be invisible to the wallet.
   */
  async getWalletsForTx(chain: string, network: string, tx: Partial<IEVMTransaction>): Promise<ObjectID[]> {
    const { tos, froms } = this.getAllTouchedAddresses(tx);
    const addresses = [...new Set(tos.concat(froms).map(a => a.address))];
    const walletAddys = await WalletAddressStorage.collection
      .find({ chain, network, address: { $in: addresses } })
      .toArray();
    return uniqBy(
      walletAddys.map(w => w.wallet),
      w => w.toHexString()
    );
  }

  /**
   * Returns the wallet ids that should be tagged on the tx but aren't yet.
   */
  async getNewWalletsForTx(chain: string, network: string, tx: Partial<IEVMTransaction>): Promise<ObjectID[]> {
    const newWallets = await this.getNewWalletsForTxs(chain, network, [tx]);
    return newWallets.get(tx) || [];
  }

  /**
   * Batch form of getNewWalletsForTx: one address lookup for the whole batch (e.g. a
   * block's worth of repaired txs) instead of one per tx.
   */
  async getNewWalletsForTxs(chain: string, network: string, txs: Array<Partial<IEVMTransaction>>): Promise<Map<Partial<IEVMTransaction>, ObjectID[]>> {
    const newWalletsByTx = new Map<Partial<IEVMTransaction>, ObjectID[]>();
    const addressesByTx = txs.map(tx => {
      const { tos, froms } = this.getAllTouchedAddresses(tx);
      return [...new Set(tos.concat(froms).map(a => a.address))];
    });
    const allAddresses = [...new Set(addressesByTx.flat())];
    const walletAddys = allAddresses.length
      ? await WalletAddressStorage.collection.find({ chain, network, address: { $in: allAddresses } }).toArray()
      : [];
    const walletsByAddress = new Map<string, ObjectID[]>();
    for (const walletAddy of walletAddys) {
      const wallets = walletsByAddress.get(walletAddy.address) || [];
      wallets.push(walletAddy.wallet);
      walletsByAddress.set(walletAddy.address, wallets);
    }
    for (const [i, tx] of txs.entries()) {
      const existing = new Set((tx.wallets || []).map(w => w.toHexString()));
      const wallets = uniqBy(
        addressesByTx[i].flatMap(address => walletsByAddress.get(address) || []),
        w => w.toHexString()
      ).filter(w => !existing.has(w.toHexString()));
      newWalletsByTx.set(tx, wallets);
    }
    return newWalletsByTx;
  }

  getAllTouchedAddresses(tx: Partial<IEVMTransaction>): { tos: IEVMCachedAddress[]; froms: IEVMCachedAddress[] } {
    const { to, from, effects } = tx;
    const toBatch = new Set<string>();
    const fromBatch = new Set<string>();
    const addToBatch = (batch: Set<string>, obj: IEVMCachedAddress) => {
      // Adds string representation to batch to guard uniqueness since {} != {} but '{}' == '{}'
      batch.add(JSON.stringify(obj));
    };
    addToBatch(toBatch, { address: to as string });
    addToBatch(fromBatch, { address: from as string });
    if (effects && effects.length) {
      for (const effect of effects) {
        // Handle internal value transfers
        if (!effect.contractAddress) {
          addToBatch(toBatch, { address: effect.to });
          addToBatch(fromBatch, { address: effect.from });
        } else if (effect.type == 'ERC20:transfer') {
          // Handle ERC20s
          addToBatch(toBatch, { address: effect.to, tokenAddress: effect.contractAddress });
          addToBatch(fromBatch, { address: effect.from, tokenAddress: effect.contractAddress });
        }
      }
    }

    // Convert Set made up of unique strings back to object representations
    const tos: IEVMCachedAddress[] = Array.from(toBatch).map(strObj => JSON.parse(strObj));
    const froms: IEVMCachedAddress[] = Array.from(fromBatch).map(strObj => JSON.parse(strObj));

    return { tos, froms };
  }

  async expireBalanceCache(txOps: Array<any>) {
    for (const op of txOps) {
      const { chain, network } = op.updateOne.filter;

      const { tos, froms } = this.getAllTouchedAddresses(op.updateOne.update.$set);
      const uniqueBatch = tos.concat(froms);
      for (const payload of uniqueBatch) {
        const lowerAddress = payload.address.toLowerCase();
        const cacheKey = payload.tokenAddress
          ? `getBalanceForAddress-${chain}-${network}-${lowerAddress}-${payload.tokenAddress.toLowerCase()}`
          : `getBalanceForAddress-${chain}-${network}-${lowerAddress}`;
        await CacheStorage.expire(cacheKey);
      }
    }
  }

  async addTransactions(params: {
    txs: Array<IEVMTransactionInProcess>;
    failedReceiptTxids?: Set<string>;
    receiptEffectOutcomes?: Map<string, ReceiptEffectOutcome>;
    height: number;
    blockTime?: Date;
    blockHash?: string;
    blockTimeNormalized?: Date;
    parentChain?: string;
    forkHeight?: number;
    initialSyncComplete: boolean;
    chain: string;
    network: string;
    mempoolTime?: Date;
  }) {
    const { blockTimeNormalized, chain, height, network, parentChain, forkHeight } = params;
    if (parentChain && forkHeight && height < forkHeight) {
      const parentTxs = await EVMTransactionStorage.collection
        .find({ blockHeight: height, chain: parentChain, network })
        .toArray();
      return parentTxs.map(parentTx => {
        return {
          updateOne: {
            filter: { txid: parentTx.txid, chain, network },
            update: {
              $set: {
                ...parentTx,
                wallets: new Array<ObjectID>()
              }
            },
            upsert: true,
            forceServerObjectId: true
          }
        };
      });
    } else {
      return Promise.all(
        // Get all "to" and "from" addresses so we can add the any corresponding wallets
        params.txs.map(async (tx: IEVMTransactionInProcess) => {
          const wallets = await this.getWalletsForTx(chain, network, tx);

          // If config value is set then only store needed tx properties
          let leanTx: IEVMTransaction | IEVMTransactionInProcess = EVMTransactionStorage.stripReceiptLogs(tx);
          if ((Config.chainConfig({ chain, network }) as IEVMNetworkConfig).leanTransactionStorage) {
            leanTx = EVMTransactionStorage.toLeanTransaction(leanTx);
          }
          const txid = tx.txid.toLowerCase();
          const update = this.buildReceiptPersistenceUpdate(
            {
              ...leanTx,
              blockTimeNormalized,
              wallets
            },
            params.receiptEffectOutcomes?.get(txid),
            params.failedReceiptTxids?.has(txid) === true
          );
          return {
            updateOne: {
              filter: { txid: tx.txid, chain, network },
              update,
              upsert: true,
              forceServerObjectId: true
            }
          };
        })
      );
    }
  }

  async pruneMempool(params: {
    txs: Array<IEVMTransactionInProcess>;
    height: number;
    parentChain?: string;
    forkHeight?: number;
    chain: string;
    network: string;
    initialSyncComplete: boolean;
  }) {
    const { chain, network, initialSyncComplete, txs } = params;
    if (!initialSyncComplete) {
      return;
    }
    for (const tx of txs) {
      await this.collection.update(
        {
          chain,
          network,
          from: tx.from,
          nonce: tx.nonce,
          txid: { $ne: tx.txid },
          blockHeight: SpentHeightIndicators.pending
        },
        { $set: { blockHeight: SpentHeightIndicators.conflicting, replacedByTxid: tx.txid } },
        { w: 0, j: false, multi: true }
      );
    }
    return;
  }

  getTransactions(params: { query: any; options: StreamingFindOptions<IEVMTransaction> }) {
    const originalQuery = params.query;
    const { query, options } = Storage.getFindOptions(this, params.options);
    const finalQuery = Object.assign({}, originalQuery, query);
    return this.collection.find(finalQuery, options).addCursorFlag('noCursorTimeout', true);
  }

  abiDecode(input: string) {
    try {
      const erc20Data: IAbiDecodeResponse = getErc20Decoder().decodeMethod(input);
      if (erc20Data) {
        return {
          type: 'ERC20',
          ...erc20Data
        };
      }
    } catch {/* ignore error */}
    try {
      const erc721Data: IAbiDecodeResponse = getErc721Decoder().decodeMethod(input);
      if (erc721Data) {
        return {
          type: 'ERC721',
          ...erc721Data
        };
      }
    } catch {/* ignore error */}
    try {
      const invoiceData: IAbiDecodeResponse = getInvoiceDecoder().decodeMethod(input);
      if (invoiceData) {
        return {
          type: 'INVOICE',
          ...invoiceData
        };
      }
    } catch {/* ignore error */}
    try {
      const multisendData: IAbiDecodeResponse = getMultisendDecoder().decodeMethod(input);
      if (multisendData) {
        return {
          type: 'MUTLISEND',
          ...multisendData
        };
      }
    } catch {/* ignore error */}
    try {
      const multisigData: IAbiDecodeResponse = getMultisigDecoder().decodeMethod(input);
      if (multisigData) {
        return {
          type: 'MULTISIG',
          ...multisigData
        };
      }
    } catch {/* ignore error */}
    return undefined;
  }

  /**
   * Creates an object with param names as keys instead of an array of objects
   * @param abi 
   * @returns object of abi param values that can be accessed with the name as a key
   */
  parseAbiParams(abi: IAbiDecodedData): ParsedAbiParams {
    const params = abi.params;
    const parsed = {} as ParsedAbiParams;
    for (const param of params) {
      const { value } = param;
      parsed[param.name] = value;
    }
    return parsed;
  }

  /**
   * Adds effects details object to in process txs
   */
  addEffectsToTxs(txs: IEVMTransactionInProcess[]): Map<string, ReceiptEffectOutcome> {
    const outcomes = new Map<string, ReceiptEffectOutcome>();
    for (const tx of txs) {
      const result = this.computeEffects(tx);
      this.commitReceiptEffectResult(tx, result);
      outcomes.set(tx.txid.toLowerCase(), result.outcome);
    }
    return outcomes;
  }

  /**
   * Creates an array of all effects for a given tx
   * @param tx A tx object that contains extra data that we don't want to store long term
   * @returns An array of all effects for the transaction
   */
  getEffects(tx: IEVMTransactionInProcess): Effect[] {
    const result = this.computeEffects(tx);
    this.commitReceiptEffectResult(tx, result);
    return result.effects;
  }

  /**
   * Computes effects transactionally. No receipt-derived fields on tx are changed
   * until the complete candidate and its completeness outcome are known.
   */
  private computeEffects(tx: IEVMTransactionInProcess): ReceiptEffectResult {
    const originalEffects = (tx.effects || []).map(effect => ({ ...effect }));
    const effects = [] as Effect[];
    try {
      if (this.isFailedReceipt(tx.receipt)) {
        return { effects, outcome: { kind: 'derived', completeness: { kind: 'complete' } } };
      }
      if (tx.calls?.length) { // Geth trace calls[]
        for (const call of tx.calls) {
          if (call.value && BigInt(call.value) > 0) {
            // Handle native asset transfer
            const effect = this._getEffectForNativeTransfer(BigInt(call.value).toString(), call.to, call.from, call.depth);
            effects.push(effect);
          }
          if (call.abiType) { // If there was a known ABI (ERC20, Invoice) transfer within the tx execution
            // Handle Abi related effects
            let effect: Effect | undefined;
            if (call.type === 'DELEGATECALL') { // Delegate calls are proxy calls within a smart contract
              // find parent call that's one level up. E.g. if depth = '0_1_2', then find '0_1'
              const parent = tx.calls.find(c => c.depth === call.depth.split('_').slice(0, -1).join('_')) || { to: tx.to, from: tx.from, input: null }; // Fallback to tx.to and tx.from if no parent found
              if (parent?.to === call.from && parent?.input === call.input) {
                // If parent is the same as the current call, then it's just a proxy call
                continue;
              }
              effect = this._getEffectForAbiType(call.abiType, parent.to, parent.from, call.depth);
            } else {
              effect = this._getEffectForAbiType(call.abiType, call.to, call.from, call.depth);
            }
            if (effect) {
              effects.push(effect);
            }
          }
        }
      } else if (tx.internal?.length) { // LEGACY: Used for converting old OpenEthereum/Parity db entries with internal[]
        for (const internalTx of tx.internal) {
          if (internalTx.action.value && BigInt(internalTx.action.value) > 0) {
            // Handle native asset transfer
            const effect = this._getEffectForNativeTransfer(BigInt(internalTx.action.value).toString(), internalTx.action.to, internalTx.action.from || tx.from, internalTx.traceAddress.join('_'));
            effects.push(effect);
          }
          if (internalTx.abiType) {
            // Handle Abi related effects
            const effect = this._getEffectForAbiType(internalTx.abiType, internalTx.action.to, internalTx.action.from || tx.from, internalTx.traceAddress.join('_'));
            if (effect) {
              effects.push(effect);
            }
          }
        }
      } else if (tx.abiType) { // We recognized upstream that this is a known ABI tx
        // Handle Abi related effects
        const effect = this._getEffectForAbiType(tx.abiType, tx.to, tx.from, '');
        if (effect) {
          effects.push(effect);
        }
      }
      return this.computeReceiptLogEffects(tx, effects);
    } catch (err) {
      logger.error('Error Getting Effects For TxId: %o ::%o', tx.txid, err);
      return {
        effects: originalEffects,
        outcome: { kind: 'not-derived', reason: 'effect-derivation-failed' }
      };
    }
  }

  private computeReceiptLogEffects(tx: IEVMTransactionInProcess, baseEffects: Effect[]): ReceiptEffectResult {
    if (this.isFailedReceipt(tx.receipt)) {
      return { effects: [], outcome: { kind: 'derived', completeness: { kind: 'complete' } } };
    }
    if (!tx.receipt || !Array.isArray(tx.receipt.logs)) {
      return {
        effects: baseEffects.map(effect => ({ ...effect })),
        outcome: { kind: 'not-derived', reason: 'missing-logs' }
      };
    }
    const logEffects: Effect[] = [];
    const unparseableContracts = new Set<string>();
    for (const [index, log] of tx.receipt.logs.entries()) {
      const { effect, unparseableContract } = this._parseErc20TransferLog(log, index);
      if (effect) {
        logEffects.push(effect);
      } else if (unparseableContract) {
        unparseableContracts.add(unparseableContract);
      }
    }
    // Receipt logs are authoritative for ERC20 transfers, so trace/abi-derived transfer
    // effects are replaced with log-derived ones — except for contracts that emitted a
    // Transfer we can't parse (non-canonical events, e.g. non-indexed params), where the
    // trace effect is the only signal available. Within such a contract, a trace effect
    // is still dropped when a parsed log effect covers the same transfer (same contract,
    // from, and to), so it can't double count alongside the log-derived one.
    const transferKey = (effect: Effect) =>
      `${effect.contractAddress?.toLowerCase()}|${effect.from?.toLowerCase()}|${effect.to?.toLowerCase()}`;
    const parsedTransferKeys = new Set(logEffects.map(transferKey));
    const filteredEffects = baseEffects.filter(effect => {
      return !this._isErc20TransferEffect(effect) ||
        (unparseableContracts.has(effect.contractAddress!.toLowerCase()) &&
          !parsedTransferKeys.has(transferKey(effect)));
    });
    const contracts = [...unparseableContracts].sort();
    return {
      effects: [...filteredEffects, ...logEffects],
      outcome: {
        kind: 'derived',
        completeness: contracts.length
          ? { kind: 'incomplete', contracts }
          : { kind: 'complete' }
      }
    };
  }

  /**
   * Backward-compatible mutating helper used by existing callers/tests. The candidate
   * effect array is committed only after receipt-log processing succeeds.
   */
  addReceiptLogEffects(tx: IEVMTransactionInProcess, effects: Effect[]): ReceiptEffectOutcome {
    let result: ReceiptEffectResult;
    try {
      result = this.computeReceiptLogEffects(tx, effects);
    } catch (err) {
      logger.error('Error Getting Receipt Effects For TxId: %o ::%o', tx.txid, err);
      result = {
        effects: effects.map(effect => ({ ...effect })),
        outcome: { kind: 'not-derived', reason: 'effect-derivation-failed' }
      };
    }
    this.commitReceiptEffectResult(tx, result);
    effects.splice(0, effects.length, ...result.effects);
    return result.outcome;
  }

  private commitReceiptEffectResult(tx: IEVMTransactionInProcess, result: ReceiptEffectResult) {
    tx.effects = result.effects.map(effect => ({ ...effect }));
    if (result.outcome.kind === 'derived') {
      tx.receiptLogEffectsProcessed = true;
      if (result.outcome.completeness.kind === 'incomplete') {
        tx.receiptLogEffectsIncompleteContracts = [...result.outcome.completeness.contracts];
      } else {
        delete tx.receiptLogEffectsIncompleteContracts;
      }
    } else {
      delete tx.receiptLogEffectsProcessed;
      delete tx.receiptLogEffectsIncompleteContracts;
    }
  }

  _isErc20TransferEffect(effect: Effect) {
    return effect.type === 'ERC20:transfer' && !!effect.contractAddress;
  }

  /**
   * Compatibility wrapper for callers that only consume fields to set. Persistence
   * paths must use deriveReceiptLogEffectsUpdate() so stale fields can be unset too.
   */
  deriveReceiptLogEffects(tx: IEVMTransactionInProcess): Partial<IEVMTransaction> {
    return this.deriveReceiptLogEffectsUpdate(tx).update.$set;
  }

  deriveReceiptLogEffectsUpdate(
    tx: IEVMTransactionInProcess,
    additionalSet: Partial<IEVMTransaction> = {}
  ): { outcome: ReceiptEffectOutcome; update: any } {
    let result: ReceiptEffectResult;
    if (tx.effects?.length) {
      const originalEffects = tx.effects.map(effect => ({ ...effect }));
      try {
        result = this.computeReceiptLogEffects(tx, originalEffects);
      } catch (err) {
        logger.error('Error Deriving Receipt Effects For TxId: %o ::%o', tx.txid, err);
        result = {
          effects: originalEffects,
          outcome: { kind: 'not-derived', reason: 'effect-derivation-failed' }
        };
      }
    } else {
      result = this.computeEffects(tx);
    }
    this.commitReceiptEffectResult(tx, result);
    // logs can be very large and are not currently needed for any use case in this codebase.
    this.stripReceiptLogs(tx);
    const setFields: Partial<IEVMTransaction> = {
      effects: tx.effects,
      receipt: tx.receipt,
      ...additionalSet
    };
    return {
      outcome: result.outcome,
      update: this.buildReceiptPersistenceUpdate(setFields, result.outcome)
    };
  }

  /**
   * Builds one conflict-free Mongo update for receipt state. Callers supply their
   * normal $set payload; this method owns every processed/completeness transition.
   */
  buildReceiptPersistenceUpdate(
    setFields: Record<string, any>,
    outcome?: ReceiptEffectOutcome,
    receiptFetchFailed = false
  ) {
    const $set = { ...setFields };
    const $setOnInsert = {} as Record<string, any>;
    const $unset = {} as Record<string, ''>;
    const unset = (field: string) => {
      delete $set[field];
      $unset[field] = '';
    };
    const setOnInsert = (field: string) => {
      if (Object.prototype.hasOwnProperty.call($set, field)) {
        $setOnInsert[field] = $set[field];
        delete $set[field];
      }
    };

    if (receiptFetchFailed) {
      // A transient receipt failure must make an existing row repairable without
      // replacing its last known-good receipt-derived state with trace-only fallbacks.
      // New rows still need usable fallback values, so route those fields through
      // $setOnInsert instead of dropping them entirely.
      setOnInsert('effects');
      setOnInsert('wallets');
      setOnInsert('fee');
      unset('receipt');
      unset('receiptLogEffectsProcessed');
      unset('receiptLogEffectsIncompleteContracts');
    } else if (outcome?.kind === 'derived') {
      $set.receiptLogEffectsProcessed = true;
      if (outcome.completeness.kind === 'incomplete') {
        $set.receiptLogEffectsIncompleteContracts = [...outcome.completeness.contracts];
      } else {
        unset('receiptLogEffectsIncompleteContracts');
      }
    } else if (outcome?.kind === 'not-derived') {
      unset('receiptLogEffectsProcessed');
      unset('receiptLogEffectsIncompleteContracts');
    }

    return {
      $set,
      ...(Object.keys($setOnInsert).length ? { $setOnInsert } : {}),
      ...(Object.keys($unset).length ? { $unset } : {})
    };
  }

  isFailedReceipt(receipt?: { status?: boolean | number | string | bigint }) {
    const status = receipt?.status;
    return status === false || status === 0 || status === 0n || status === '0' || status === '0x0';
  }

  _parseErc20TransferLog(log: any, index: number): { effect?: Effect; unparseableContract?: string } {
    const topics = log?.topics || log?.raw?.topics;
    const data = log?.data || log?.raw?.data;
    if (!Array.isArray(topics) || !topics.length || this._hexString(topics[0]).toLowerCase() !== ERC20_TRANSFER_TOPIC) {
      return {};
    }
    // Four topics with the Transfer signature is an ERC721 transfer, not an ERC20 one.
    if (topics.length > 3) {
      return {};
    }
    const contractAddress = this._hexString(log.address);
    const unparseableContract = /^0x[0-9a-fA-F]{40}$/.test(contractAddress) ? contractAddress.toLowerCase() : undefined;
    if (topics.length !== 3 || typeof data !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(data)) {
      return { unparseableContract };
    }
    const from = this._addressFromTopic(topics[1]);
    const to = this._addressFromTopic(topics[2]);
    if (!from || !to || !unparseableContract) {
      return { unparseableContract };
    }
    const amount = BigInt(data);
    if (amount === 0n) {
      // Not unparseable: a zero-amount transfer is intentionally excluded from effects.
      return {};
    }
    const logIndex = log.logIndex ?? index;
    return {
      effect: {
        type: 'ERC20:transfer',
        to: Web3.utils.toChecksumAddress(to),
        from: Web3.utils.toChecksumAddress(from),
        amount: amount.toString(),
        contractAddress: Web3.utils.toChecksumAddress(contractAddress),
        callStack: `log:${Number(logIndex)}`
      }
    };
  }

  _addressFromTopic(topic: any): string | undefined {
    const topicHex = this._hexString(topic).replace(/^0x/, '');
    if (topicHex.length < 40) {
      return;
    }
    return '0x' + topicHex.slice(-40);
  }

  _hexString(value: any) {
    if (Buffer.isBuffer(value)) {
      return '0x' + value.toString('hex');
    }
    return String(value || '');
  }

  /**
   * Creates an array of effects that are filtered for relevance to a given list of addresses
   * @param {IEVMTransactionInProcess} tx 
   * @param {Array<string>} addresses
   */
  getEffectsForAddresses(tx: IEVMTransactionInProcess, addresses: Array<string>): Effect[] {
    const effects = tx.receiptLogEffectsProcessed ? (tx.effects || []) : (tx.effects?.length ? tx.effects : this.getEffects(tx));
    const addySet = new Set(addresses.map(a => a.toLowerCase()));
    return effects.filter(effect => addySet.has(effect.to.toLowerCase()) || addySet.has(effect.from.toLowerCase()));
  }

  _getEffectForAbiType(abi: IAbiDecodedData, to: string, from: string, callStack: string): Effect | undefined {
    // Check that the params are valid before parsing
    if (!to || !from) return;
    if (`${abi.type}:${abi.name}` == 'ERC20:transfer') {
      const params = this.parseAbiParams(abi);
      const { _to, _value } = params;
      // Check that the params are valid before parsing
      if (!_to || !_value) return;
      return {
        type: 'ERC20:transfer',
        to: Web3.utils.toChecksumAddress(_to),
        from: Web3.utils.toChecksumAddress(from),
        amount: Web3.utils.fromWei(_value, 'wei'),
        contractAddress: Web3.utils.toChecksumAddress(to),
        callStack
      };
    } else if (`${abi.type}:${abi.name}` == 'ERC20:transferFrom') {
      const params = this.parseAbiParams(abi);
      const { _to, _from, _value } = params;
      // Check that the params are valid before parsing
      if (!_to || !_from || !_value) return;
      return {
        type: 'ERC20:transfer',
        to: Web3.utils.toChecksumAddress(_to),
        from: Web3.utils.toChecksumAddress(_from),
        amount: Web3.utils.fromWei(_value, 'wei'),
        contractAddress: Web3.utils.toChecksumAddress(to),
        callStack
      };
    } else if (`${abi.type}:${abi.name}` == 'MULTISIG:submitTransaction') {
      const params = this.parseAbiParams(abi);
      const { destination, value } = params;
      // Check that the params are valid before parsing
      if (!destination || !value) return;
      return {
        type: 'MULTISIG:submitTransaction',
        to: Web3.utils.toChecksumAddress(destination),
        from: Web3.utils.toChecksumAddress(from),
        amount: Web3.utils.fromWei(value, 'wei'),
        contractAddress: Web3.utils.toChecksumAddress(to),
        callStack
      };
    } else if (`${abi.type}:${abi.name}` == 'MULTISIG:confirmTransaction') {
      return {
        type: 'MULTISIG:confirmTransaction',
        to: '0x0',
        from: Web3.utils.toChecksumAddress(from),
        amount: '0',
        contractAddress: Web3.utils.toChecksumAddress(to),
        callStack
      };
    }
    return;
  }

  _getEffectForNativeTransfer(value: string, to: string, from: string, callStack: string): Effect {
    const effect = {
      to: Web3.utils.toChecksumAddress(to),
      from: Web3.utils.toChecksumAddress(from),
      amount: Web3.utils.fromWei(value, 'wei'),
      callStack
    };
    return effect;
  }
  /**
   * Receives any type of TX and returns a lean version without unused properties
   * @param tx - transaction to leanify
   */
  toLeanTransaction(tx: IEVMTransactionInProcess | IEVMTransaction): IEVMTransaction {
    this.stripReceiptLogs(tx);
    const removableProperties = ['data', 'internal', 'calls', 'abiType'];
    for (const prop of removableProperties) {
      if (tx[prop]) {
        delete tx[prop];
      }
    }
    return tx;
  }

  stripReceiptLogs<T extends IEVMTransactionInProcess | IEVMTransaction>(tx: T): T {
    if (tx.receipt?.logs) {
      delete tx.receipt.logs;
    }
    return tx;
  }

  convertRawTx(chain: string, network: string, tx: Partial<Web3Types.TransactionInfo>, block?: IEVMBlock): IEVMTransactionInProcess {
    if (!block) {
      const txid = tx.hash as string || '';
      const to = tx.to ? Web3.utils.toChecksumAddress(tx.to) : '';
      const from = tx.from ? Web3.utils.toChecksumAddress(tx.from) : '';
      const value = BigInt(tx.value!);
      const gas = BigInt(tx.gas || -1); // -1 indicates unknown
      const gasPrice = BigInt(tx.gasPrice || -1);
      const fee = gas < 0n || gasPrice < 0n ? -1n : gas * gasPrice;
      const abiType = this.abiDecode(tx.input as string);
      const nonce = BigInt(tx.nonce || 0);
      const convertedTx: IEVMTransactionInProcess = {
        chain,
        network,
        blockHeight: Number(valueOrDefault(tx.blockNumber, -1)),
        blockHash: valueOrDefault(tx.blockHash as string, undefined),
        data: Buffer.from(tx.input || '0x'),
        txid,
        blockTime: new Date(),
        blockTimeNormalized: new Date(),
        fee: Number(fee),
        transactionIndex: Number(tx.transactionIndex || 0),
        value: Number(value),
        wallets: [],
        to,
        from,
        gasLimit: Number(gas),
        gasPrice: Number(gasPrice),
        nonce: Number(nonce),
        internal: [],
        calls: []
      };
      if (abiType) {
        convertedTx.abiType = abiType;
      }
      return convertedTx;
    } else {
      const { hash: blockHash, time: blockTime, timeNormalized: blockTimeNormalized, height } = block;
      const noBlockTx = this.convertRawTx(chain, network, tx);
      return {
        ...noBlockTx,
        blockHeight: height,
        blockHash,
        blockTime,
        blockTimeNormalized
      };
    }
  }

  // Correct tx.data.toString() => 0xa9059cbb00000000000000000000000001503dfc5ad81bf630d83697e98601871bb211b60000000000000000000000000000000000000000000000000000000000002710
  // Incorrect: tx.data.toString('hex') => 307861393035396362623030303030303030303030303030303030303030303030303031353033646663356164383162663633306438333639376539383630313837316262323131623630303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303032373130

  _apiTransform(
    tx: IEVMTransactionInProcess | IEVMTransactionTransformed | Partial<MongoBound<IEVMTransactionTransformed>>,
    options?: TransformOptions
  ): EVMTransactionJSON | string {

    let transaction: EVMTransactionJSON = {
      txid: tx.txid || '',
      network: tx.network || '',
      chain: tx.chain || '',
      blockHeight: valueOrDefault(tx.blockHeight, -1),
      blockHash: tx.blockHash || '',
      blockTime: tx.blockTime ? tx.blockTime.toISOString() : '',
      blockTimeNormalized: tx.blockTimeNormalized ? tx.blockTimeNormalized.toISOString() : '',
      fee: valueOrDefault(tx.fee, -1),
      value: valueOrDefault(tx.value, -1),
      gasLimit: valueOrDefault(tx.gasLimit, -1),
      gasPrice: valueOrDefault(tx.gasPrice, -1),
      nonce: valueOrDefault(tx.nonce, 0),
      to: tx.to || '',
      from: tx.from || '',
      effects: tx.effects || []
    };
    if ('eventId' in tx && tx.eventId) {
      transaction.eventId = tx.eventId;
    }
    if ('tokenHistorySource' in tx && tx.tokenHistorySource) {
      transaction.tokenHistorySource = tx.tokenHistorySource;
    }
    if ('tokenHistoryIncomplete' in tx && tx.tokenHistoryIncomplete) {
      transaction.tokenHistoryIncomplete = true;
    }

    // Add non-lean properties if we aren't excluding them
    const config = Config.chainConfig({ chain: tx.chain as string, network: tx.network as string }) as IEVMNetworkConfig;
    if (config && !config.leanTransactionStorage) {
      const dataStr = tx.data ? tx.data.toString() : '';
      const decodedData = this.abiDecode(dataStr);
      const nonLeanProperties = {
        data: dataStr,
        abiType: tx.abiType || valueOrDefault(decodedData, undefined),
        internal: tx.internal
          ? tx.internal.map(t => ({ ...t, decodedData: this.abiDecode(t?.action?.input || '0x') }))
          : [],
        calls: tx.calls ? tx.calls.map(t => ({ ...t, decodedData: this.abiDecode(t.input || '0x') })) : []
      };
      transaction = Object.assign(transaction, nonLeanProperties);
    }

    if (options && options.object) {
      return transaction;
    }
    return JSON.stringify(transaction, Utils.BI.JSONStringifyBigIntReplacer);
  }
}
export const EVMTransactionStorage = new EVMTransactionModel();
