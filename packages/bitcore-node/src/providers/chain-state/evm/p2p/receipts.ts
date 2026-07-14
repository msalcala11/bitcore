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
) {
  if (!txs.length) {
    return;
  }

  // Use whatever the batch call returned and fetch only the misses individually.
  const blockReceipts = await getBlockReceipts(web3, txs);
  const missingTxs: IEVMTransactionInProcess[] = [];
  for (const tx of txs) {
    const receipt = blockReceipts?.get(tx.txid.toLowerCase());
    if (receipt) {
      setReceiptAndFee(tx, receipt);
    } else {
      missingTxs.push(tx);
    }
  }
  if (!missingTxs.length) {
    return;
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
        // Never fail block processing over a receipt: the tx is stored without
        // receipt-log effects (receiptLogEffectsProcessed stays unset), so it is
        // repaired later by scripts/backfillEvmReceiptLogEffects.js or on read.
        logger.warn('Continuing without receipt for tx %o: %o', tx.txid, err?.message || err);
      }
    }
  });

  await Promise.all(workers);
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
    if (receipt?.transactionHash) {
      receiptsByTxid.set(receipt.transactionHash.toLowerCase(), receipt);
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

async function getReceiptWithRetry(
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
  tx.receipt = normalizeReceipt(receipt) as unknown as TxReceipt;
  const fee = computeReceiptFee(tx.receipt, tx.gasPrice);
  if (fee !== undefined) {
    tx.fee = fee;
  }
}

export function computeReceiptFee(receipt: any, fallbackGasPrice?: number | string | bigint): number | undefined {
  const gasUsed = toBigInt(receipt?.gasUsed);
  const gasPrice = toBigInt(receipt?.effectiveGasPrice ?? fallbackGasPrice);
  if (gasUsed === undefined || gasPrice === undefined || gasUsed < 0n || gasPrice < 0n) {
    return undefined;
  }
  return Number(gasUsed * gasPrice);
}

export function normalizeReceipt(receipt: any) {
  if (!receipt) {
    return receipt;
  }
  const normalized = Utils.BI.scrubBigIntsInObject(receipt);
  const compactReceipt = copyDefinedFields(normalized, [
    'status',
    'transactionHash',
    'transactionIndex',
    'blockHash',
    'blockNumber',
    'contractAddress',
    'cumulativeGasUsed',
    'gasUsed',
    'effectiveGasPrice'
  ]);
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
