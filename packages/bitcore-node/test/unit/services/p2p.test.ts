import { expect } from 'chai';
import { EventEmitter } from 'events';
import * as sinon from 'sinon';
import { Web3 } from '@bitpay-labs/crypto-wallet-core';
import { Config } from '../../../src/services/config';
import { BaseP2PWorker, P2P } from '../../../src/services/p2p';
import { EVMP2pWorker } from '../../../src/providers/chain-state/evm/p2p/p2p';
import { BaseEVMStateProvider } from '../../../src/providers/chain-state/evm/api/csp';
import { unitAfterHelper, unitBeforeHelper } from '../../helpers/unit';
import { block } from '../../data/ETH/gethMainnet24486902';
import { Rpcs } from '../../../src/providers/chain-state/evm/p2p/rpcs';
import { addReceiptsToTxs, getReceiptFetchConcurrency } from '../../../src/providers/chain-state/evm/p2p/receipts';
import { MultiThreadSync } from '../../../src/providers/chain-state/evm/p2p/sync';

describe('P2P Service', function() {
  const sandbox = sinon.createSandbox();
  class MockP2PWorker extends BaseP2PWorker<any> {
    started = false;
  
    constructor(params) {
      super(params);
      this.started = true;
    }
  }
  
  before(unitBeforeHelper);
  after(unitAfterHelper);

  afterEach(() => {
    sandbox.restore();
  });

  it('should have a test which runs', function() {
    expect(true).to.equal(true);
  });

  it('should register a class', () => {
    const chain = 'TEST';
    const network = 'test';
    P2P.register(chain, network, MockP2PWorker);
    const registered = P2P.get(chain, network);
    expect(registered).to.deep.eq(MockP2PWorker);
  });

  it('should start the p2p class', async () => {
    const chain = 'TEST';
    const network = 'testnet';
    const fakeConfig = {};

    P2P.register(chain, network, MockP2PWorker);
    sandbox.stub(Config, 'chainNetworks').returns([{ chain, network }]);
    sandbox
      .stub(Config, 'chainConfig')
      .withArgs({ chain, network })
      .returns(fakeConfig);

    expect(P2P.workers).to.deep.eq([]);
    await P2P.start();
    expect(`Worker length: ${P2P.workers.length}`).to.eq('Worker length: 1');
    expect(P2P.workers[0]).to.exist;
    const worker = P2P.workers[0] as MockP2PWorker;
    expect(worker.started).to.eq(true);
    await P2P.stop();
    expect(P2P.workers).to.deep.eq([]);
  });

  it('should not start if disabled', async () => {
    const chain = 'TEST';
    const network = 'test';

    P2P.register(chain, network, MockP2PWorker);
    sandbox
      .stub(Config, 'isDisabled')
      .withArgs('p2p')
      .returns(true);
    expect(P2P.workers).to.deep.eq([]);
    await P2P.start();
    expect(P2P.workers.length).to.eq(0);
  });

  it('should not start if config has disabled', async () => {
    const chain = 'TEST';
    const network = 'testnet';
    const fakeConfig = { disabled: true };

    P2P.register(chain, network, MockP2PWorker);
    sandbox.stub(Config, 'chainNetworks').returns([{ chain, network }]);
    sandbox
      .stub(Config, 'chainConfig')
      .withArgs({ chain, network })
      .returns(fakeConfig);

    expect(P2P.workers).to.deep.eq([]);
    await P2P.start();
    expect(P2P.workers.length).to.eq(0);
  });

  it('should not start if config has chainSource other than p2p', async () => {
    const chain = 'TEST';
    const network = 'testnet';
    const fakeConfig = { chainSource: 'rpc' };

    P2P.register(chain, network, MockP2PWorker);
    sandbox.stub(Config, 'chainNetworks').returns([{ chain, network }]);
    sandbox
      .stub(Config, 'chainConfig')
      .withArgs({ chain, network })
      .returns(fakeConfig);

    expect(P2P.workers).to.deep.eq([]);
    await P2P.start();
    expect(P2P.workers.length).to.eq(0);
  });

  it('should convert an EVM block', async function() {
    sandbox.stub(Rpcs.geth.prototype, 'getTransactionsFromBlock').resolves([]);
    sandbox.stub(BaseEVMStateProvider, 'initializeRpcs');
    sandbox.stub(Config, 'get').returns({ chains: { ETH: { mainnet: {} } } });
    sandbox.stub(EVMP2pWorker.prototype, 'addReceiptsToTxs').resolves();
    class MockEVMP2pWorker extends EVMP2pWorker {
      protected rpc = new Rpcs.geth(sandbox.stub() as any);

      constructor(params) {
        super(params);
      }
    }
    
    const p2p = new MockEVMP2pWorker({ chain: 'ETH', network: 'mainnet', chainConfig: {} });
    const converted = await p2p.convertBlock(block as any);
    expect(converted.convertedTxs.every(tx => {
      return (tx.to === '' || tx.to === Web3.utils.toChecksumAddress(tx.to)) &&
        tx.from === Web3.utils.toChecksumAddress(tx.from);
    })).to.equal(true);
  });

  it('should fetch EVM receipts with bounded concurrency and retry', async function() {
    const txs = new Array(5).fill(undefined).map((_, idx) => ({ txid: `0x${idx}`, gasPrice: 50 })) as any[];
    const attempts: Record<string, number> = {};
    let active = 0;
    let maxActive = 0;
    const web3 = {
      eth: {
        getTransactionReceipt: sandbox.stub().callsFake(async (txid: string) => {
          attempts[txid] = (attempts[txid] || 0) + 1;
          active++;
          maxActive = Math.max(maxActive, active);
          await new Promise(resolve => setTimeout(resolve, 1));
          active--;
          if (txid === '0x2' && attempts[txid] === 1) {
            return null;
          }
          return {
            status: true,
            transactionHash: txid,
            transactionIndex: 0,
            blockHash: '0xblock',
            blockNumber: 1,
            cumulativeGasUsed: 1,
            gasUsed: 10,
            effectiveGasPrice: 20,
            logs: []
          };
        })
      }
    };

    await addReceiptsToTxs(web3 as any, txs, { concurrency: 2, retries: 1, retryDelayMs: 0 });

    expect(maxActive).to.equal(2);
    expect(web3.eth.getTransactionReceipt.callCount).to.equal(6);
    expect(txs.map(tx => tx.receipt.transactionHash)).to.deep.equal(['0x0', '0x1', '0x2', '0x3', '0x4']);
    expect(txs.map(tx => tx.fee)).to.deep.equal([200, 200, 200, 200, 200]);
  });

  it('should fetch all EVM receipts for a block in one RPC call when supported', async function() {
    const txs = new Array(3).fill(undefined).map((_, idx) => ({
      txid: `0x${idx}`,
      blockHash: '0xblock',
      blockHeight: 1,
      gasPrice: 50
    })) as any[];
    const receipts = txs.map(tx => ({
      status: '0x1',
      transactionHash: tx.txid,
      transactionIndex: '0x0',
      blockHash: '0xblock',
      blockNumber: '0x1',
      contractAddress: null,
      cumulativeGasUsed: '0x1',
      gasUsed: '0xa',
      effectiveGasPrice: '0x14',
      logsBloom: '0x'.padEnd(514, '0'),
      type: '0x2',
      logs: []
    }));
    const request = sandbox.stub().resolves({ jsonrpc: '2.0', id: 1, result: receipts });
    const web3 = {
      currentProvider: { request },
      eth: {
        getTransactionReceipt: sandbox.stub()
      }
    };

    await addReceiptsToTxs(web3 as any, txs, { concurrency: 2, retries: 1, retryDelayMs: 0 });

    expect(request.calledOnce).to.equal(true);
    const payload = request.firstCall.args[0];
    expect(payload.jsonrpc).to.equal('2.0');
    expect(payload.id).to.be.a('number');
    expect(payload.method).to.equal('eth_getBlockReceipts');
    expect(payload.params).to.deep.equal(['0xblock']);
    expect(web3.eth.getTransactionReceipt.called).to.equal(false);
    expect(txs.map(tx => tx.receipt.transactionHash)).to.deep.equal(['0x0', '0x1', '0x2']);
    expect(txs.map(tx => tx.receipt.status)).to.deep.equal([true, true, true]);
    expect(txs.map(tx => tx.receipt.gasUsed)).to.deep.equal([10, 10, 10]);
    expect((txs[0].receipt as any).effectiveGasPrice).to.equal(20);
    expect((txs[0].receipt as any).contractAddress).to.equal(undefined);
    expect((txs[0].receipt as any).logsBloom).to.equal(undefined);
    expect((txs[0].receipt as any).type).to.equal(undefined);
    expect(txs.map(tx => tx.fee)).to.deep.equal([200, 200, 200]);
  });

  it('should remember when an EVM provider does not support block receipts', async function() {
    const txs = [
      { txid: '0x0', blockHash: '0xblock0', blockHeight: 1, gasPrice: 50 },
      { txid: '0x1', blockHash: '0xblock1', blockHeight: 2, gasPrice: 50 }
    ] as any[];
    const request = sandbox.stub().rejects({ code: -32601, message: 'method not found' });
    const web3 = {
      currentProvider: { request },
      eth: {
        getTransactionReceipt: sandbox.stub().callsFake(async (txid: string) => ({
          status: true,
          transactionHash: txid,
          transactionIndex: 0,
          blockHash: '0xblock',
          blockNumber: 1,
          cumulativeGasUsed: 1,
          gasUsed: 10,
          effectiveGasPrice: 20,
          logs: []
        }))
      }
    };

    await addReceiptsToTxs(web3 as any, [txs[0]], { concurrency: 1, retries: 0, retryDelayMs: 0 });
    await addReceiptsToTxs(web3 as any, [txs[1]], { concurrency: 1, retries: 0, retryDelayMs: 0 });

    expect(request.calledOnce).to.equal(true);
    expect(web3.eth.getTransactionReceipt.callCount).to.equal(2);
    expect(txs.map(tx => tx.receipt.transactionHash)).to.deep.equal(['0x0', '0x1']);
  });

  it('should remember non-array block receipt responses as unsupported', async function() {
    const txs = [
      { txid: '0x0', blockHash: '0xblock0', blockHeight: 1, gasPrice: 50 },
      { txid: '0x1', blockHash: '0xblock1', blockHeight: 2, gasPrice: 50 }
    ] as any[];
    const request = sandbox.stub().resolves(null);
    const web3 = {
      currentProvider: { request },
      eth: {
        getTransactionReceipt: sandbox.stub().callsFake(async (txid: string) => ({
          status: true,
          transactionHash: txid,
          transactionIndex: 0,
          blockHash: '0xblock',
          blockNumber: 1,
          cumulativeGasUsed: 1,
          gasUsed: 10,
          effectiveGasPrice: 20,
          logs: []
        }))
      }
    };

    await addReceiptsToTxs(web3 as any, [txs[0]], { concurrency: 1, retries: 0, retryDelayMs: 0 });
    await addReceiptsToTxs(web3 as any, [txs[1]], { concurrency: 1, retries: 0, retryDelayMs: 0 });

    expect(request.calledOnce).to.equal(true);
    expect(web3.eth.getTransactionReceipt.callCount).to.equal(2);
    expect(txs.map(tx => tx.receipt.transactionHash)).to.deep.equal(['0x0', '0x1']);
  });

  it('should not treat block lookup errors as unsupported block receipts', async function() {
    const txs = [
      { txid: '0x0', blockHash: '0xblock0', blockHeight: 1, gasPrice: 50 },
      { txid: '0x1', blockHash: '0xblock1', blockHeight: 2, gasPrice: 50 }
    ] as any[];
    const request = sandbox.stub()
      .onFirstCall().rejects({ message: 'block 0xblock0 does not exist' })
      .onSecondCall().resolves([{
        status: true,
        transactionHash: '0x1',
        transactionIndex: 0,
        blockHash: '0xblock1',
        blockNumber: 2,
        cumulativeGasUsed: 1,
        gasUsed: 10,
        effectiveGasPrice: 20,
        logs: []
      }]);
    const web3 = {
      currentProvider: { request },
      eth: {
        getTransactionReceipt: sandbox.stub().callsFake(async (txid: string) => ({
          status: true,
          transactionHash: txid,
          transactionIndex: 0,
          blockHash: '0xblock0',
          blockNumber: 1,
          cumulativeGasUsed: 1,
          gasUsed: 10,
          effectiveGasPrice: 20,
          logs: []
        }))
      }
    };

    await addReceiptsToTxs(web3 as any, [txs[0]], { concurrency: 1, retries: 0, retryDelayMs: 0 });
    await addReceiptsToTxs(web3 as any, [txs[1]], { concurrency: 1, retries: 0, retryDelayMs: 0 });

    expect(request.callCount).to.equal(2);
    expect(web3.eth.getTransactionReceipt.callCount).to.equal(1);
    expect(txs.map(tx => tx.receipt.transactionHash)).to.deep.equal(['0x0', '0x1']);
  });

  it('should fall back to per-transaction EVM receipts when block receipts are incomplete', async function() {
    const txs = new Array(2).fill(undefined).map((_, idx) => ({
      txid: `0x${idx}`,
      blockHash: '0xblock',
      blockHeight: 1,
      gasPrice: 50
    })) as any[];
    const request = sandbox.stub().resolves([{
      status: true,
      transactionHash: '0x0',
      transactionIndex: 0,
      blockHash: '0xblock',
      blockNumber: 1,
      cumulativeGasUsed: 1,
      gasUsed: 10,
      effectiveGasPrice: 20,
      logs: []
    }]);
    const web3 = {
      currentProvider: { request },
      eth: {
        getTransactionReceipt: sandbox.stub().callsFake(async (txid: string) => ({
          status: true,
          transactionHash: txid,
          transactionIndex: 0,
          blockHash: '0xblock',
          blockNumber: 1,
          cumulativeGasUsed: 1,
          gasUsed: 10,
          effectiveGasPrice: 20,
          logs: []
        }))
      }
    };

    await addReceiptsToTxs(web3 as any, txs, { concurrency: 2, retries: 1, retryDelayMs: 0 });

    expect(request.calledOnce).to.equal(true);
    expect(web3.eth.getTransactionReceipt.callCount).to.equal(2);
    expect(txs.map(tx => tx.receipt.transactionHash)).to.deep.equal(['0x0', '0x1']);
  });

  it('should split default EVM receipt concurrency across sync workers', function() {
    expect(getReceiptFetchConcurrency()).to.equal(8);
    expect(getReceiptFetchConcurrency(undefined, 4)).to.equal(2);
    expect(getReceiptFetchConcurrency(undefined, 16)).to.equal(1);
    expect(getReceiptFetchConcurrency(6, 4)).to.equal(6);
    expect(getReceiptFetchConcurrency(0, 4)).to.equal(1);
  });

  it('should pass sync worker count to EVM receipt workers', async function() {
    const workerData: any[] = [];
    sandbox.stub(Config, 'get').returns({
      chains: {
        ETH: {
          mainnet: {
            threads: 3,
            providers: [{}]
          }
        }
      }
    });
    class MockMultiThreadSync extends MultiThreadSync {
      getWorkerThread(data) {
        workerData.push(data);
        const thread = Object.assign(new EventEmitter(), {
          threadId: workerData.length,
          postMessage: sandbox.stub().callsFake(() => {
            setImmediate(() => thread.emit('message', { message: 'ready' }));
          })
        });
        return thread as any;
      }
    }

    await new MockMultiThreadSync({ chain: 'ETH', network: 'mainnet' }).initializeThreads();

    expect(workerData).to.deep.equal([
      { chain: 'ETH', network: 'mainnet', receiptFetchWorkerCount: 3 },
      { chain: 'ETH', network: 'mainnet', receiptFetchWorkerCount: 3 },
      { chain: 'ETH', network: 'mainnet', receiptFetchWorkerCount: 3 }
    ]);
  });

  it('should fail explicitly when an EVM receipt remains missing', async function() {
    const txs = [{ txid: '0xmissing', gasPrice: 50 }] as any[];
    const web3 = {
      eth: {
        getTransactionReceipt: sandbox.stub().resolves(null)
      }
    };

    try {
      await addReceiptsToTxs(web3 as any, txs, { concurrency: 1, retries: 1, retryDelayMs: 0 });
      expect.fail('expected addReceiptsToTxs to throw');
    } catch (err: any) {
      expect(err.message).to.include('Unable to fetch receipt for confirmed tx 0xmissing after 2 attempts');
    }
  });
});
