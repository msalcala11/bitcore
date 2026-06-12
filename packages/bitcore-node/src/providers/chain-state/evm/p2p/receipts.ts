import { Utils } from '@bitpay-labs/crypto-wallet-core';
import { wait } from '../../../../utils';
import type { IEVMTransactionInProcess, TxReceipt } from '../types';
import type { Web3 } from '@bitpay-labs/crypto-wallet-core';

const DEFAULT_RECEIPT_CONCURRENCY = 8;
const DEFAULT_RECEIPT_RETRIES = 3;
const DEFAULT_RECEIPT_RETRY_DELAY_MS = 250;

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
  tx.receipt = Utils.BI.scrubBigIntsInObject(receipt) as unknown as TxReceipt;
  const gasUsed = toBigInt(receipt.gasUsed ?? tx.receipt.gasUsed);
  const gasPrice = toBigInt(receipt.effectiveGasPrice ?? (tx.receipt as any).effectiveGasPrice ?? tx.gasPrice);
  if (gasUsed !== undefined && gasPrice !== undefined && gasUsed >= 0n && gasPrice >= 0n) {
    tx.fee = Number(gasUsed * gasPrice);
  }
}

function toBigInt(value: any): bigint | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  return BigInt(value);
}
