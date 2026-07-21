import { expect } from 'chai';
import sinon from 'sinon';
import { Web3 } from '@bitpay-labs/crypto-wallet-core';
import { PopulateReceiptTransform } from '../../src/providers/chain-state/evm/api/populateReceiptTransform';
import { EVMListTransactionsStream, TokenHistoryExpansionTransform } from '../../src/providers/chain-state/evm/api/transform';
import { Config } from '../../src/services/config';

describe('EVM token history completeness boundary', function() {
  const sandbox = sinon.createSandbox();
  const tokenAddress = Web3.utils.toChecksumAddress('0x4fabb145d64652a948d72533023f6e7a623c7c53');
  const walletAddress = Web3.utils.toChecksumAddress('0xa91cfe0dcad33f36f3c9428d48eccbd8a71951b4');

  beforeEach(function() {
    sandbox.stub(Config, 'chainConfig').returns({ leanTransactionStorage: false } as any);
  });

  afterEach(function() {
    sandbox.restore();
  });

  const effect = (amount: string, logIndex: number) => ({
    type: 'ERC20:transfer' as const,
    to: walletAddress,
    from: walletAddress,
    amount,
    contractAddress: tokenAddress,
    callStack: `log:${logIndex}`
  });

  const providerRow = (value: string, eventId: string) => ({
    txid: '0xpartial-self-transfer',
    chain: 'ETH',
    network: 'mainnet',
    from: walletAddress,
    to: walletAddress,
    value,
    effects: [],
    eventId
  });

  async function run(populateReceipt: (tx: any) => Promise<any>, rows: any[]) {
    const populate = new PopulateReceiptTransform({ populateReceipt } as any, {
      walletAddresses: [walletAddress],
      tokenAddress
    });
    const output: any[] = [];
    const stream = populate
      .pipe(new TokenHistoryExpansionTransform([walletAddress], tokenAddress))
      .pipe(new EVMListTransactionsStream([walletAddress], tokenAddress));
    const done = new Promise<void>((resolve, reject) => {
      stream
        .on('data', chunk => output.push(JSON.parse(chunk.toString())))
        .on('error', reject)
        .on('end', resolve);
    });
    for (const row of rows) {
      populate.write(row);
    }
    populate.end();
    await done;
    return output;
  }

  it('keeps provider amounts and identities when the requested contract is incomplete', async function() {
    const parsedEffect = effect('5', 7);
    const rows = await run(async tx => ({
      ...tx,
      receipt: { status: true },
      effects: [parsedEffect],
      receiptLogEffectsProcessed: true,
      receiptLogEffectsIncompleteContracts: [tokenAddress.toLowerCase()]
    }), [
      providerRow('9007199254740993', 'log:7'),
      providerRow('1', 'alchemy:opaque-8')
    ]);

    expect(rows.map(row => row.category)).to.deep.equal(['move', 'move']);
    expect(rows.map(row => row.satoshis)).to.deep.equal(['9007199254740993', '1']);
    expect(rows.map(row => row.eventId)).to.deep.equal(['log:7', 'alchemy:opaque-8']);
    expect(rows.map(row => row.tokenHistorySource)).to.deep.equal(['provider', 'provider']);
    expect(rows.map(row => row.tokenHistoryIncomplete)).to.deep.equal([true, true]);
    expect(rows.map(row => row.effects)).to.deep.equal([[parsedEffect], [parsedEffect]]);
  });

  it('uses canonical log identities for a complete expanded effect set', async function() {
    const effects = [effect('5', 7), effect('7', 8)];
    const rows = await run(async tx => ({
      ...tx,
      receipt: { status: true },
      effects,
      receiptLogEffectsProcessed: true
    }), [providerRow('5', 'alchemy:trigger')]);

    expect(rows.map(row => row.satoshis)).to.deep.equal(['5', '7']);
    expect(rows.map(row => row.eventId)).to.deep.equal(['log:7', 'log:8']);
    expect(rows.map(row => row.tokenHistorySource)).to.deep.equal(['derived', 'derived']);
    expect(rows.map(row => row.tokenHistoryIncomplete)).to.deep.equal([undefined, undefined]);
  });
});
