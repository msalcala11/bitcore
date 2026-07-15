#!/usr/bin/env node

import readline from 'readline';
import util from 'util';
import { computeBackfillExitCode } from '../build/src/providers/chain-state/evm/backfillExitCode.js';
import { EVMTransactionStorage } from '../build/src/providers/chain-state/evm/models/transaction.js';
import { addReceiptsToTxs } from '../build/src/providers/chain-state/evm/p2p/receipts.js';
import { Storage } from '../build/src/services/storage.js';

let shutdown = false;
const runtimeExitState = {
  skippedTransactions: 0,
  unwrittenTransactions: 0,
  interrupted: false
};
process.on('SIGINT', () => {
  if (shutdown) {
    console.log('Force exiting...');
    process.exit(1);
  }
  shutdown = true;
  runtimeExitState.interrupted = true;
  console.log('Gracefully shutting down...');
});

function usage(errMsg) {
  console.log('USAGE: ./backfillEvmReceiptLogEffects.js <options>');
  console.log('');
  console.log('Backfills receipt-log-derived ERC20 effects onto stored EVM transactions.');
  console.log('Idempotent: only txs without receiptLogEffectsProcessed are touched, so it is');
  console.log('safe to re-run; txs that fail (e.g. RPC errors) are retried on the next run.');
  console.log('');
  console.log('OPTIONS:');
  console.log('  --chain <value>          REQUIRED - e.g. ETH, MATIC...');
  console.log('  --network <value>        REQUIRED - e.g. mainnet, sepolia, regtest...');
  console.log('  --startHeight <value>    Block height to start from (default: 1)');
  console.log('  --endHeight <value>      Block height to stop at (default: local tip)');
  console.log('  --dryRun                 Report what would be updated without writing');
  console.log('  --yes                    Skip the confirmation prompt');
  console.log('');
  console.log('EXIT CODES:');
  console.log('  0  completed with nothing left to repair');
  console.log('  1  usage error or fatal error (nothing may have run)');
  console.log('  2  incomplete - skipped/unwritten txs or interrupted; re-run to retry');
  if (errMsg) {
    console.log('\nERROR: ' + errMsg);
    process.exit(1);
  }
  process.exit(0);
}

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  usage();
}

const chainIdx = args.indexOf('--chain');
const networkIdx = args.indexOf('--network');
const startHeightIdx = args.indexOf('--startHeight');
const endHeightIdx = args.indexOf('--endHeight');
const chain = args[chainIdx + 1]?.toUpperCase();
const network = args[networkIdx + 1]?.toLowerCase();
const startHeight = startHeightIdx === -1 ? 1 : parseInt(args[startHeightIdx + 1]);
const endHeight = endHeightIdx === -1 ? Infinity : parseInt(args[endHeightIdx + 1]);
const dryRun = args.includes('--dryRun');
const skipPrompt = args.includes('--yes');

if (chainIdx === -1 || networkIdx === -1) {
  usage('Missing required options.');
}

if (!chain || !network || isNaN(startHeight) || isNaN(endHeight)) {
  usage('Invalid option value(s).');
}

if (startHeight < 1 || endHeight < startHeight) {
  usage('Invalid height range.');
}

async function processBlockTxs(getWeb3, blockTxs) {
  // Legacy rows that still have their receipt logs stored don't need an RPC round trip.
  const txsNeedingReceipts = blockTxs.filter(tx => !Array.isArray(tx.receipt?.logs));
  if (txsNeedingReceipts.length) {
    // Tolerant of unfetchable receipts: those txs come back without one, are excluded
    // from readyTxs below, and stay in the repair query for the next run.
    await addReceiptsToTxs(await getWeb3(), txsNeedingReceipts);
  }
  const readyTxs = blockTxs.filter(tx => Array.isArray(tx.receipt?.logs));
  const updates = new Map();
  for (const tx of readyTxs) {
    // Only includes receiptLogEffectsProcessed when derivation completed, so partially
    // derived txs stay in this script's repair query for the next run.
    const update = EVMTransactionStorage.deriveReceiptLogEffects(tx);
    if (tx.fee !== undefined) {
      update.fee = tx.fee;
    }
    updates.set(tx, update);
  }
  // Late-derived effects can add addresses the sync-time tagging never saw; without a
  // retag the wallets-filtered history query can never surface the repaired tx. Batched:
  // one address lookup per block. Must run after derivation so it sees the new effects.
  const newWalletsByTx = readyTxs.length
    ? await EVMTransactionStorage.getNewWalletsForTxs(chain, network, readyTxs)
    : new Map();
  const ops = readyTxs.map(tx => {
    const updateOp = { $set: updates.get(tx) };
    const newWallets = newWalletsByTx.get(tx) || [];
    if (newWallets.length) {
      updateOp.$addToSet = { wallets: { $each: newWallets } };
    }
    return { updateOne: { filter: { _id: tx._id }, update: updateOp } };
  });
  let written = ops.length;
  if (!dryRun && ops.length) {
    try {
      const result = await EVMTransactionStorage.collection.bulkWrite(ops, { ordered: false });
      written = result.modifiedCount;
    } catch (err) {
      // Partial failures persist what they can; unwritten rows stay unflagged and are
      // retried on the next run.
      written = err?.result?.modifiedCount ?? err?.result?.nModified ?? 0;
      console.error(`\nPartial write failure for block ${blockTxs[0].blockHeight}: ${err.message || err}`);
    }
  }
  return {
    written,
    unfetchable: blockTxs.length - readyTxs.length,
    notModified: ops.length - written
  };
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
// Imported lazily so --help and arg validation work without RPC provider deps loaded.
let BaseEVMStateProvider;

console.log('Connecting to database...');

Storage.start()
  .then(async () => {
    const query = {
      chain,
      network,
      blockHeight: { $gte: startHeight, ...(endHeight !== Infinity ? { $lte: endHeight } : {}) },
      receiptLogEffectsProcessed: { $ne: true }
    };

    let totalCount = null;
    if (skipPrompt) {
      // No prompt to inform, so skip the extra counting pass over the height range.
      console.log(`Backfilling ${chain}:${network} transactions without receipt-log effects...${dryRun ? ' (dry run)' : ''}`);
    } else {
      totalCount = await EVMTransactionStorage.collection.countDocuments(query);
      console.log(`Found ${totalCount} ${chain}:${network} transactions without receipt-log effects.${dryRun ? ' (dry run)' : ''}`);
      if (!totalCount) {
        return;
      }
      const ans = await util.promisify(rl.question).call(rl, 'Would you like to continue? (Y/n) ');
      if (ans?.toLowerCase() === 'n') {
        return;
      }
    }

    // Lazy: a backfill over rows that all still have stored logs needs no RPC at all.
    let web3;
    const getWeb3 = async () => {
      if (!web3) {
        ({ BaseEVMStateProvider } = await import('../build/src/providers/chain-state/evm/api/csp.js'));
        const csp = new BaseEVMStateProvider(chain);
        ({ web3 } = await csp.getWeb3(network, { type: 'historical' }));
      }
      return web3;
    };

    const cursor = EVMTransactionStorage.collection
      .find(query)
      .sort({ blockHeight: 1 })
      .addCursorFlag('noCursorTimeout', true);

    let countUpdated = 0;
    let countSeen = 0;
    let blockTxs = [];

    const flushBlock = async () => {
      if (!blockTxs.length) {
        return;
      }
      const blockHeight = blockTxs[0].blockHeight;
      try {
        const { written, unfetchable, notModified } = await processBlockTxs(getWeb3, blockTxs);
        countUpdated += written;
        if (unfetchable) {
          runtimeExitState.skippedTransactions += unfetchable;
          console.error(`\n${unfetchable} tx(s) in block ${blockHeight} have unfetchable receipts (will retry on next run)`);
        }
        if (notModified) {
          runtimeExitState.unwrittenTransactions += notModified;
          console.error(`\n${notModified} tx(s) in block ${blockHeight} were not updated (write failure, or already repaired concurrently); retried on the next run only if still unflagged`);
        }
      } catch (err) {
        runtimeExitState.skippedTransactions += blockTxs.length;
        console.error(`\nFailed to backfill block ${blockHeight} (will retry on next run): ${err.message || err}`);
      }
      blockTxs = [];
    };

    for await (const tx of cursor) {
      if (shutdown) {
        break;
      }
      if (blockTxs.length && blockTxs[0].blockHeight !== tx.blockHeight) {
        await flushBlock();
      }
      blockTxs.push(tx);
      countSeen++;
      if (countSeen % 100 === 0 || countSeen === totalCount) {
        const percent = totalCount ? ` (${(countSeen / totalCount * 100).toFixed(2)}%)` : '';
        process.stdout.write(`Processing block ${tx.blockHeight}${percent} -- (${countUpdated} txs ${dryRun ? 'would be ' : ''}updated)...        \r`);
      }
    }
    if (!shutdown) {
      await flushBlock();
    }

    console.log(`\n${dryRun ? 'Would have updated' : 'Updated'} ${countUpdated} of ${countSeen} transactions.`);
    const countIncompleteTxs = runtimeExitState.skippedTransactions + runtimeExitState.unwrittenTransactions;
    if (countIncompleteTxs) {
      console.log(`${countIncompleteTxs} tx(s) were left unprocessed; re-run to retry them.`);
    }
    process.exitCode = computeBackfillExitCode(runtimeExitState);
  })
  .catch(err => {
    console.error(err);
    process.exitCode = computeBackfillExitCode({ ...runtimeExitState, fatal: true });
  })
  .finally(() => {
    rl.close();
    BaseEVMStateProvider?.teardownRpcs();
    Storage.stop();
  });
