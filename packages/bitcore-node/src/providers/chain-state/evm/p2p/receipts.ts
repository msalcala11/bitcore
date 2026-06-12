import { Utils } from '@bitpay-labs/crypto-wallet-core';
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

  const blockReceipts = await getBlockReceipts(web3, txs);
  if (blockReceipts) {
    for (const tx of txs) {
      setReceiptAndFee(tx, blockReceipts.get(tx.txid.toLowerCase()));
    }
    return;
  }

  const concurrency = getReceiptFetchConcurrency(opts.concurrency);
  const workerCount = Math.min(concurrency, txs.length);
  let nextIndex = 0;

  const workers = new Array(workerCount).fill(undefined).map(async () => {
    while (nextIndex < txs.length) {
      const tx = txs[nextIndex++];
      const receipt = await getReceiptWithRetry(web3, tx.txid, {
        retries: opts.retries ?? DEFAULT_RECEIPT_RETRIES,
        retryDelayMs: opts.retryDelayMs ?? DEFAULT_RECEIPT_RETRY_DELAY_MS
      });
      setReceiptAndFee(tx, receipt);
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

  if (!Array.isArray(receipts)) {
    return;
  }

  const receiptsByTxid = new Map<string, any>();
  for (const receipt of receipts) {
    if (receipt?.transactionHash) {
      receiptsByTxid.set(receipt.transactionHash.toLowerCase(), receipt);
    }
  }

  for (const tx of txs) {
    if (!receiptsByTxid.has(tx.txid.toLowerCase())) {
      return;
    }
  }
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
  if (provider?.request) {
    return provider.request({ method: 'eth_getBlockReceipts', params: [blockId] });
  }
  if (provider?.send) {
    return new Promise((resolve, reject) => {
      provider.send({
        jsonrpc: '2.0',
        id: Date.now(),
        method: 'eth_getBlockReceipts',
        params: [blockId]
      }, (err: any, response: any) => {
        if (err) {
          return reject(err);
        }
        if (response?.error) {
          return reject(response.error);
        }
        return resolve(response?.result);
      });
    });
  }
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
  const gasUsed = toBigInt(receipt.gasUsed ?? tx.receipt.gasUsed);
  const gasPrice = toBigInt(receipt.effectiveGasPrice ?? (tx.receipt as any).effectiveGasPrice ?? tx.gasPrice);
  if (gasUsed !== undefined && gasPrice !== undefined && gasUsed >= 0n && gasPrice >= 0n) {
    tx.fee = Number(gasUsed * gasPrice);
  }
}

function normalizeReceipt(receipt: any) {
  const normalized = Utils.BI.scrubBigIntsInObject(receipt);
  normalized.status = normalizeReceiptStatus(normalized.status);
  for (const field of ['transactionIndex', 'blockNumber', 'cumulativeGasUsed', 'gasUsed', 'effectiveGasPrice']) {
    normalized[field] = normalizeNumber(normalized[field]);
  }
  if (normalized.logs?.length) {
    for (const log of normalized.logs) {
      log.logIndex = normalizeNumber(log.logIndex);
      log.transactionIndex = normalizeNumber(log.transactionIndex);
      log.blockNumber = normalizeNumber(log.blockNumber);
    }
  }
  return normalized;
}

function normalizeReceiptStatus(status: any) {
  const normalizedStatus = typeof status === 'string' ? status.toLowerCase() : status;
  if (normalizedStatus === '0x1') {
    return true;
  }
  if (normalizedStatus === '0x0') {
    return false;
  }
  return status;
}

function normalizeNumber(value: any) {
  if (typeof value === 'string' && value.startsWith('0x')) {
    return Number(BigInt(value));
  }
  return value;
}

function toBigInt(value: any): bigint | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  return BigInt(value);
}
