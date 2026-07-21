import { Utils } from '@bitpay-labs/crypto-wallet-core';
import logger from '../../../../logger';
import { wait } from '../../../../utils';
import type { IEVMTransactionInProcess, TxReceipt } from '../types';
import type { Web3 } from '@bitpay-labs/crypto-wallet-core';

const DEFAULT_RECEIPT_CONCURRENCY = 8;
const DEFAULT_RECEIPT_RETRIES = 3;
const DEFAULT_RECEIPT_RETRY_DELAY_MS = 250;
const blockReceiptsUnsupportedProviders = new WeakSet<object>();

export function getReceiptFetchConcurrency(configuredConcurrency?: number, workerCount = 1) {
  if (configuredConcurrency !== undefined && configuredConcurrency !== null) {
    return Math.max(1, configuredConcurrency);
  }
  return Math.max(1, Math.ceil(DEFAULT_RECEIPT_CONCURRENCY / Math.max(1, workerCount)));
}

export async function addReceiptsToTxs(
  web3: Web3,
  txs: IEVMTransactionInProcess[],
  opts: { concurrency?: number; retries?: number; retryDelayMs?: number } = {}
): Promise<Set<string>> {
  const failedTxids = new Set<string>();
  if (!txs.length) {
    return failedTxids;
  }

  // Use whatever the batch call returned and fetch only the misses individually.
  const blockReceipts = await getBlockReceipts(web3, txs);
  const missingTxs: IEVMTransactionInProcess[] = [];
  for (const tx of txs) {
    const receipt = blockReceipts?.get(tx.txid.toLowerCase());
    if (receipt) {
      try {
        setReceiptAndFee(tx, receipt);
        continue;
      } catch (err: any) {
        // A malformed item in an otherwise valid batch must not abort the block.
        // Retry this tx through the individually isolated path below.
        logger.warn('Ignoring malformed block receipt for tx %o: %o', tx.txid, err?.message || err);
      }
    }
    missingTxs.push(tx);
  }
  if (!missingTxs.length) {
    return failedTxids;
  }

  const concurrency = getReceiptFetchConcurrency(opts.concurrency);
  const workerCount = Math.min(concurrency, missingTxs.length);
  let nextIndex = 0;

  const workers = new Array(workerCount).fill(undefined).map(async () => {
    while (nextIndex < missingTxs.length) {
      const tx = missingTxs[nextIndex++];
      try {
        const receipt = await getReceiptWithRetry(web3, tx.txid, {
          retries: opts.retries ?? DEFAULT_RECEIPT_RETRIES,
          retryDelayMs: opts.retryDelayMs ?? DEFAULT_RECEIPT_RETRY_DELAY_MS
        });
        setReceiptAndFee(tx, receipt);
      } catch (err: any) {
        failedTxids.add(tx.txid.toLowerCase());
        // Preserve any last-known receipt/processed/completeness state carried by a
        // reused resync object. Persistence distinguishes authoritative existing rows
        // from new/pending rows and records that another receipt attempt is required.
        tx.receiptRepairPending = true;
        // Never fail block processing over a receipt: the tx is stored without
        // authoritative receipt-log updates, so it is repaired later by
        // scripts/backfillEvmReceiptLogEffects.js or on read.
        logger.warn('Continuing without receipt for tx %o: %o', tx.txid, err?.message || err);
      }
    }
  });

  await Promise.all(workers);
  return failedTxids;
}

async function getBlockReceipts(
  web3: Web3,
  txs: IEVMTransactionInProcess[]
): Promise<Map<string, any> | undefined> {
  const blockId = getBlockId(txs);
  if (!blockId) {
    return;
  }
  const provider = getReceiptProvider(web3);
  if (!provider || blockReceiptsUnsupportedProviders.has(provider)) {
    return;
  }

  let receipts: any;
  try {
    receipts = await requestBlockReceipts(provider, blockId);
  } catch (err) {
    if (isUnsupportedBlockReceiptsError(err)) {
      blockReceiptsUnsupportedProviders.add(provider);
    }
    return;
  }

  if (receipts === null) {
    return;
  }
  if (!Array.isArray(receipts)) {
    blockReceiptsUnsupportedProviders.add(provider);
    return;
  }

  const receiptsByTxid = new Map<string, any>();
  for (const receipt of receipts) {
    try {
      if (typeof receipt?.transactionHash === 'string' && receipt.transactionHash) {
        receiptsByTxid.set(receipt.transactionHash.toLowerCase(), receipt);
      } else if (receipt?.transactionHash != null) {
        logger.warn('Ignoring block receipt with malformed transactionHash: %o', receipt.transactionHash);
      }
    } catch (err: any) {
      // Isolate provider data errors to one item. The corresponding transaction will
      // be fetched individually by the caller.
      logger.warn('Ignoring malformed block receipt: %o', err?.message || err);
    }
  }
  // May be missing some of the block's txs; the caller fetches those individually.
  return receiptsByTxid;
}

function getBlockId(txs: IEVMTransactionInProcess[]) {
  const blockHash = txs[0].blockHash;
  if (blockHash && txs.every(tx => tx.blockHash === blockHash)) {
    return blockHash;
  }
  const blockHeight = txs[0].blockHeight;
  if (blockHeight !== undefined && blockHeight >= 0 && txs.every(tx => tx.blockHeight === blockHeight)) {
    return `0x${blockHeight.toString(16)}`;
  }
  return;
}

function getReceiptProvider(web3: Web3) {
  return (web3 as any).currentProvider || (web3.eth as any).currentProvider;
}

async function requestBlockReceipts(provider: any, blockId: string) {
  const payload = {
    jsonrpc: '2.0',
    id: Date.now(),
    method: 'eth_getBlockReceipts',
    params: [blockId]
  };
  if (provider?.request) {
    return unwrapRpcResponse(await provider.request(payload));
  }
  if (provider?.send) {
    return new Promise((resolve, reject) => {
      provider.send(payload, (err: any, response: any) => {
        if (err) {
          return reject(err);
        }
        try {
          return resolve(unwrapRpcResponse(response));
        } catch (responseError) {
          return reject(responseError);
        }
      });
    });
  }
}

function unwrapRpcResponse(response: any) {
  if (response?.error) {
    throw response.error;
  }
  if (response && typeof response === 'object' && 'result' in response) {
    return response.result;
  }
  return response;
}

function isUnsupportedBlockReceiptsError(err: any) {
  const code = err?.code ?? err?.error?.code;
  const message = String(err?.message || err?.error?.message || err || '').toLowerCase();
  const mentionsMethod = message.includes('method');
  return code === -32601 ||
    message.includes('method not found') ||
    message.includes('method not supported') ||
    (mentionsMethod && (
      message.includes('does not exist') ||
      message.includes('not available')
    ));
}

export async function getReceiptWithRetry(
  web3: Web3,
  txid: string,
  opts: { retries: number; retryDelayMs: number }
): Promise<any> {
  let lastError: any;
  for (let attempt = 0; attempt <= opts.retries; attempt++) {
    try {
      const receipt = await web3.eth.getTransactionReceipt(txid);
      if (receipt) {
        return receipt;
      }
      lastError = new Error(`Missing receipt for confirmed tx ${txid}`);
    } catch (err) {
      lastError = err;
    }

    if (attempt < opts.retries) {
      await wait(opts.retryDelayMs * Math.pow(2, attempt));
    }
  }

  const message = lastError?.message || lastError || 'unknown error';
  throw new Error(`Unable to fetch receipt for confirmed tx ${txid} after ${opts.retries + 1} attempts: ${message}`);
}

function setReceiptAndFee(tx: IEVMTransactionInProcess, receipt: any) {
  // Normalize and calculate before mutating the live tx so malformed provider data
  // cannot replace a last-known good receipt with a half-applied candidate.
  const normalizedReceipt = normalizeReceipt(receipt) as unknown as TxReceipt;
  const fee = computeReceiptFee(normalizedReceipt, tx.gasPrice);
  tx.receipt = normalizedReceipt;
  if (fee !== undefined) {
    tx.fee = fee;
  }
  delete tx.receiptRepairPending;
}

export function computeReceiptFee(receipt: any, fallbackGasPrice?: number | string | bigint): number | undefined {
  const gasUsed = toBigInt(receipt?.gasUsed);
  const gasPrice = toBigInt(receipt?.effectiveGasPrice ?? fallbackGasPrice);
  // OP Stack receipts report the L1 data charge separately from execution gas.
  const l1Fee = toBigInt(receipt?.l1Fee) ?? 0n;
  if (gasUsed === undefined || gasPrice === undefined || gasUsed < 0n || gasPrice < 0n || l1Fee < 0n) {
    return undefined;
  }
  return Number(gasUsed * gasPrice + l1Fee);
}

// Dropped from normalized receipts: logsBloom is 256 bytes of filter data nothing reads,
// and the original logs are replaced with their compact representation below.
// Every OTHER field is retained — chains bolt fee extensions onto receipts (OP Stack
// l1Fee/l1GasUsed/l1GasPrice/l1FeeScalar and Ecotone successors, Arbitrum gasUsedForL1)
// and an allowlist would silently destroy them. logs are compacted separately below and
// survive normalization: effects are derived from them, and only stripReceiptLogs at
// the persistence/API boundary removes them.
const RECEIPT_FIELD_BLOCKLIST = new Set(['logs', 'logsBloom']);

export function normalizeReceipt(receipt: any) {
  if (!receipt) {
    return receipt;
  }
  // BigInts scrub to decimal strings, not numbers: the known numeric fields are
  // re-normalized below, and unknown extension fields must not lose precision.
  const normalized = Utils.BI.scrubBigIntsInObject(receipt, 'string');
  const compactReceipt = {} as any;
  for (const field of Object.keys(normalized)) {
    if (RECEIPT_FIELD_BLOCKLIST.has(field)) {
      continue;
    }
    compactReceipt[field] = normalized[field];
  }
  if (compactReceipt.status !== undefined) {
    compactReceipt.status = normalizeReceiptStatus(compactReceipt.status);
  }
  for (const field of ['transactionIndex', 'blockNumber', 'cumulativeGasUsed', 'gasUsed', 'effectiveGasPrice']) {
    if (compactReceipt[field] !== undefined) {
      compactReceipt[field] = normalizeNumber(compactReceipt[field]);
    }
  }
  if (Array.isArray(normalized.logs)) {
    compactReceipt.logs = normalized.logs.map(log => {
      const compactLog = copyDefinedFields(log, [
        'address',
        'topics',
        'data',
        'logIndex',
        'transactionIndex',
        'transactionHash',
        'blockHash',
        'blockNumber'
      ]);
      for (const field of ['logIndex', 'transactionIndex', 'blockNumber']) {
        if (compactLog[field] !== undefined) {
          compactLog[field] = normalizeNumber(compactLog[field]);
        }
      }
      return compactLog;
    });
  }
  return compactReceipt;
}

function copyDefinedFields(source: any, fields: string[]) {
  const target = {} as any;
  for (const field of fields) {
    if (source?.[field] !== undefined && source?.[field] !== null) {
      target[field] = source[field];
    }
  }
  return target;
}

function normalizeReceiptStatus(status: any) {
  const normalizedStatus = typeof status === 'string' ? status.toLowerCase() : status;
  if (normalizedStatus === true || normalizedStatus === 1 || normalizedStatus === 1n || normalizedStatus === '1' || normalizedStatus === '0x1') {
    return true;
  }
  if (normalizedStatus === false || normalizedStatus === 0 || normalizedStatus === 0n || normalizedStatus === '0' || normalizedStatus === '0x0') {
    return false;
  }
  return status;
}

function normalizeNumber(value: any) {
  if (typeof value === 'bigint') {
    return Number(value);
  }
  if (typeof value === 'string') {
    if (value.startsWith('0x')) {
      return Number(BigInt(value));
    }
    if (/^\d+$/.test(value)) {
      return Number(value);
    }
  }
  return value;
}

function toBigInt(value: any): bigint | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  return BigInt(value);
}
