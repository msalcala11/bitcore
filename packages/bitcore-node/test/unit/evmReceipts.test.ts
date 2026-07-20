import { expect } from 'chai';
import { addReceiptsToTxs, computeReceiptFee, normalizeReceipt } from '../../src/providers/chain-state/evm/p2p/receipts';
import { EVMTransactionStorage } from '../../src/providers/chain-state/evm/models/transaction';

describe('normalizeReceipt', function() {
  const txid = '0xbaf62c1c4de9761a421608634a4ad0f7dfbfa3546227c0f4044322bdda095f43';
  const baseReceipt = () => ({
    status: '0x1',
    transactionHash: txid,
    transactionIndex: '0x0',
    blockHash: '0x0ce917ca8e25cccd7228a92895cc11c54fd61479dcec63c3234f16957e1970d9',
    blockNumber: '0xf0b294',
    from: '0xa81011Ae274eF6deBd3BDaB634102c7b6c2C452D',
    to: '0x4Fabb145d64652a948d72533023f6E7A623C7C53',
    contractAddress: null,
    cumulativeGasUsed: '0x1',
    gasUsed: '0x64',
    effectiveGasPrice: '0x14',
    logsBloom: '0x'.padEnd(514, '0'),
    type: '0x2',
    root: '0x4c6f7374207265636569707420726f6f74',
    logs: [{
      address: '0x4Fabb145d64652a948d72533023f6E7A623C7C53',
      topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'],
      data: '0x01',
      logIndex: '0x7',
      transactionIndex: '0x0',
      blockNumber: '0xf0b294',
      removed: false
    }]
  });

  it('drops only the bloom and original logs while retaining compact logs and receipt identity fields', function() {
    const receipt = normalizeReceipt(baseReceipt());

    expect(receipt.logsBloom).to.equal(undefined);
    expect(receipt.from).to.equal('0xa81011Ae274eF6deBd3BDaB634102c7b6c2C452D');
    expect(receipt.to).to.equal('0x4Fabb145d64652a948d72533023f6E7A623C7C53');
    // IEVMTransaction has no other transaction-type carrier, so EIP-2718 type must
    // remain on the normalized receipt.
    expect(receipt.type).to.equal('0x2');
    expect(receipt.root).to.equal('0x4c6f7374207265636569707420726f6f74');
    expect(receipt.contractAddress).to.equal(null);
    expect(receipt.status).to.equal(true);
    expect(receipt.blockNumber).to.equal(15774356);
    expect(receipt.gasUsed).to.equal(100);
    expect(receipt.effectiveGasPrice).to.equal(20);
    // Logs survive normalization — effects are derived from them downstream and only
    // stripReceiptLogs at the persistence boundary removes them.
    expect(receipt.logs).to.have.length(1);
    expect(receipt.logs[0].logIndex).to.equal(7);
    expect(receipt.logs[0].data).to.equal('0x01');
    expect(receipt.logs[0].removed).to.equal(undefined); // log fields stay compact
  });

  it('retains chain-specific receipt extensions like OP Stack L1 fee fields', function() {
    const receipt = normalizeReceipt({
      ...baseReceipt(),
      l1Fee: '0x2e94ae15c14e0',
      l1GasUsed: '0x640',
      l1GasPrice: '0x12a05f200',
      l1FeeScalar: '0.684',
      l1BaseFeeScalar: '0x1db0',
      l1BlobBaseFee: '0x1',
      l1BlobBaseFeeScalar: '0xa118b',
      gasUsedForL1: '0x21e8' // Arbitrum flavor
    });

    // Passed through untouched — no numeric coercion that could lose precision or
    // mangle decimal-string scalars.
    expect(receipt.l1Fee).to.equal('0x2e94ae15c14e0');
    expect(receipt.l1GasUsed).to.equal('0x640');
    expect(receipt.l1GasPrice).to.equal('0x12a05f200');
    expect(receipt.l1FeeScalar).to.equal('0.684');
    expect(receipt.l1BaseFeeScalar).to.equal('0x1db0');
    expect(receipt.l1BlobBaseFee).to.equal('0x1');
    expect(receipt.l1BlobBaseFeeScalar).to.equal('0xa118b');
    expect(receipt.gasUsedForL1).to.equal('0x21e8');
  });

  it('keeps every other receipt field through the persistence strip while logs are removed', function() {
    const tx: any = {
      txid,
      chain: 'ETH',
      network: 'mainnet',
      effects: [],
      receipt: normalizeReceipt({ ...baseReceipt(), l1Fee: '0x2e94ae15c14e0' })
    };

    const update = EVMTransactionStorage.deriveReceiptLogEffects(tx);

    expect((update.receipt as any).logs).to.equal(undefined);
    expect((update.receipt as any).logsBloom).to.equal(undefined);
    expect((update.receipt as any).from).to.equal('0xa81011Ae274eF6deBd3BDaB634102c7b6c2C452D');
    expect((update.receipt as any).to).to.equal('0x4Fabb145d64652a948d72533023f6E7A623C7C53');
    expect((update.receipt as any).type).to.equal('0x2');
    expect((update.receipt as any).root).to.equal('0x4c6f7374207265636569707420726f6f74');
    expect((update.receipt as any).contractAddress).to.equal(null);
    expect((update.receipt as any).l1Fee).to.equal('0x2e94ae15c14e0');
    expect((update.receipt as any).gasUsed).to.equal(100);
    expect(tx.receiptLogEffectsProcessed).to.equal(true);
    expect(tx.receiptLogEffectsIncompleteContracts).to.deep.equal([
      '0x4fabb145d64652a948d72533023f6e7a623c7c53'
    ]);
  });

  it('distinguishes missing logs, empty logs, and failed on-chain execution', function() {
    const fallbackEffect = { to: '0x1', from: '0x2', amount: '3', callStack: '0' };
    const missingLogsTx: any = {
      txid,
      chain: 'ETH',
      network: 'mainnet',
      effects: [fallbackEffect],
      receipt: { status: true },
      receiptLogEffectsProcessed: true,
      receiptLogEffectsIncompleteContracts: ['0xstale']
    };
    const emptyLogsTx: any = {
      ...missingLogsTx,
      effects: [fallbackEffect],
      receipt: { status: true, logs: [] }
    };
    const failedExecutionTx: any = {
      ...missingLogsTx,
      effects: [fallbackEffect],
      receipt: { status: false, logs: [] }
    };

    const missing = EVMTransactionStorage.deriveReceiptLogEffectsUpdate(missingLogsTx);
    const empty = EVMTransactionStorage.deriveReceiptLogEffectsUpdate(emptyLogsTx);
    const failed = EVMTransactionStorage.deriveReceiptLogEffectsUpdate(failedExecutionTx);

    expect(missing.outcome).to.deep.equal({ kind: 'not-derived', reason: 'missing-logs' });
    expect(missingLogsTx.effects).to.deep.equal([fallbackEffect]);
    expect(missing.update.$unset).to.deep.equal({
      receiptLogEffectsProcessed: '',
      receiptLogEffectsIncompleteContracts: ''
    });
    expect(empty.outcome).to.deep.equal({ kind: 'derived', completeness: { kind: 'complete' } });
    expect(emptyLogsTx.receiptLogEffectsProcessed).to.equal(true);
    expect(emptyLogsTx.receiptLogEffectsIncompleteContracts).to.equal(undefined);
    expect(failed.outcome).to.deep.equal({ kind: 'derived', completeness: { kind: 'complete' } });
    expect(failedExecutionTx.effects).to.deep.equal([]);
    expect(failedExecutionTx.receiptLogEffectsProcessed).to.equal(true);
  });

  it('scrubs bigint values safely', function() {
    const receipt = normalizeReceipt({
      status: 1n,
      gasUsed: 100n,
      l1Fee: 81916986694268812345678n // above 2^53: kept as a string, no precision loss
    });

    expect(receipt.status).to.equal(true);
    expect(receipt.gasUsed).to.equal(100);
    expect(receipt.l1Fee).to.equal('81916986694268812345678');
  });

  it('returns falsy receipts unchanged', function() {
    expect(normalizeReceipt(null)).to.equal(null);
    expect(normalizeReceipt(undefined)).to.equal(undefined);
  });
});

describe('computeReceiptFee', function() {
  it('adds an OP Stack L1 data fee to the execution fee', function() {
    expect(computeReceiptFee({ gasUsed: 10, effectiveGasPrice: 20, l1Fee: 50 })).to.equal(250);
    expect(computeReceiptFee({ gasUsed: '10', effectiveGasPrice: '20', l1Fee: '50' })).to.equal(250);
    expect(computeReceiptFee({ gasUsed: '0xa', effectiveGasPrice: '0x14', l1Fee: '0x32' })).to.equal(250);
  });

  it('treats a missing L1 data fee as zero', function() {
    expect(computeReceiptFee({ gasUsed: 10, effectiveGasPrice: 20 })).to.equal(200);
  });

  it('rejects negative fee components', function() {
    expect(computeReceiptFee({ gasUsed: 10, effectiveGasPrice: 20, l1Fee: -1 })).to.equal(undefined);
  });
});

describe('addReceiptsToTxs failure metadata', function() {
  it('returns normalized failed txids and clears stale in-memory receipt state', async function() {
    const tx: any = {
      txid: '0xABC',
      receiptLogEffectsProcessed: true,
      receiptLogEffectsIncompleteContracts: ['0xtoken']
    };
    const web3: any = {
      eth: {
        getTransactionReceipt: async () => null
      }
    };

    const failures = await addReceiptsToTxs(web3, [tx], {
      concurrency: 1,
      retries: 1,
      retryDelayMs: 0
    });

    expect([...failures]).to.deep.equal(['0xabc']);
    expect(tx.receipt).to.equal(undefined);
    expect(tx.receiptLogEffectsProcessed).to.equal(undefined);
    expect(tx.receiptLogEffectsIncompleteContracts).to.equal(undefined);
  });
});
