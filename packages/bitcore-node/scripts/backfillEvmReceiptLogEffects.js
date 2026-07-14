#!/usr/bin/env node

import readline from 'readline';
import util from 'util';
import { EVMTransactionStorage } from '../build/src/providers/chain-state/evm/models/transaction.js';
import { addReceiptsToTxs } from '../build/src/providers/chain-state/evm/p2p/receipts.js';
import { Storage } from '../build/src/services/storage.js';

let shutdown = false;
process.on('SIGINT', () => {
  if (shutdown) {
    console.log('Force exiting...');
    process.exit(1);
  }
  shutdown = true;
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
  if (errMsg) {
    console.log('\nERROR: ' + errMsg);
  }
  process.exit();
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
    const web3 = await getWeb3();
    try {
      await addReceiptsToTxs(web3, txsNeedingReceipts);
    } catch {
      // One unfetchable receipt shouldn't poison the whole block: the batch call mutates
      // txs as it goes, so retry just the stragglers individually and process whatever
      // succeeded. Anything still missing stays in the repair query for the next run.
      for (const tx of txsNeedingReceipts.filter(tx => !Array.isArray(tx.receipt?.logs))) {
        try {
          await addReceiptsToTxs(web3, [tx]);
        } catch {/* left for the next run */}
      }
    }
  }
  const readyTxs = blockTxs.filter(tx => Array.isArray(tx.receipt?.logs));
  const ops = [];
  for (const tx of readyTxs) {
    // Only includes receiptLogEffectsProcessed when derivation completed, so partially
    // derived txs stay in this script's repair query for the next run.
    const update = EVMTransactionStorage.deriveReceiptLogEffects(tx);
    if (tx.fee !== undefined) {
      update.fee = tx.fee;
    }
    ops.push({ updateOne: { filter: { _id: tx._id }, update: { $set: update } } });
  }
  if (!dryRun && ops.length) {
    await EVMTransactionStorage.collection.bulkWrite(ops, { ordered: false });
  }
  return { updated: ops.length, skipped: blockTxs.length - readyTxs.length };
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
    let countSkippedTxs = 0;
    let blockTxs = [];

    const flushBlock = async () => {
      if (!blockTxs.length) {
        return;
      }
      const blockHeight = blockTxs[0].blockHeight;
      try {
        const { updated, skipped } = await processBlockTxs(getWeb3, blockTxs);
        countUpdated += updated;
        if (skipped) {
          countSkippedTxs += skipped;
          console.error(`\n${skipped} tx(s) in block ${blockHeight} have unfetchable receipts (will retry on next run)`);
        }
      } catch (err) {
        countSkippedTxs += blockTxs.length;
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
    if (countSkippedTxs) {
      console.log(`${countSkippedTxs} tx(s) were left unprocessed; re-run to retry them.`);
    }
  })
  .catch(console.error)
  .finally(() => {
    rl.close();
    BaseEVMStateProvider?.teardownRpcs();
    Storage.stop();
  });
