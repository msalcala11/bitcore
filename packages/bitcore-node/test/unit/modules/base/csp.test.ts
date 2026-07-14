import { expect } from 'chai';
import { ObjectId } from 'bson';
import * as sinon from 'sinon';
import { CryptoRpc } from '@bitpay-labs/crypto-rpc';
import { EthDater } from '../../../../src/utils/ethDater';
import { MultiProviderEVMStateProvider } from '../../../../src/modules/multiProvider/api/csp';
import { MoralisStateProvider } from '../../../../src/modules/moralis/api/csp';
import { CacheStorage } from '../../../../src/models/cache';
import { BaseEVMStateProvider } from '../../../../src/providers/chain-state/evm/api/csp';
import { PopulateReceiptTransform } from '../../../../src/providers/chain-state/evm/api/populateReceiptTransform';
import { TxidDedupeTransform } from '../../../../src/providers/chain-state/evm/api/transform';
import { EVMBlockStorage } from '../../../../src/providers/chain-state/evm/models/block';
import { EVMTransactionStorage } from '../../../../src/providers/chain-state/evm/models/transaction';
import { Config } from '../../../../src/services/config';
import { Storage } from '../../../../src/services/storage';
import { TransformWithEventPipe } from '../../../../src/utils/streamWithEventPipe';


describe('BASE Chain State Provider', function() {
  const sandbox = sinon.createSandbox();

  beforeEach(() => {
    sandbox.stub(Config, 'get').returns({
      chains: {
        BASE: {
          mainnet: {
            chainSource: 'external',
            module: './moralis',
            needsL1Fee: true,
            providers: [{
              dataType: 'combined',
              host: 'sample.example',
              port: '1234',
              protocol: 'http',
            }, {
              dataType: 'realtime',
              host: 'sample.example',
              port: '1234',
              protocol: 'http',
            }]
          },
          sepolia: {
            chainSource: 'external',
            module: './moralis',
            needsL1Fee: true,
            providers: [{
              dataType: 'combined',
              host: 'sample.example',
              port: '1234',
              protocol: 'ws',
            }]
          }
        }
      }
    });
  });

  afterEach(() => {
    BaseEVMStateProvider.teardownRpcs();
    sandbox.restore();
  });

  describe('constructor', () => {
    it('should call initializeRpcs', function() {
      sandbox.stub(BaseEVMStateProvider, 'initializeRpcs');
      new BaseEVMStateProvider('BASE');
      expect((BaseEVMStateProvider.initializeRpcs as any).callCount).to.eq(1);
    });
  });

  describe('initializeRpcs', () => {
    beforeEach(function() {
      // Clear any existing RPCs before each test
      BaseEVMStateProvider.rpcs = {};
      BaseEVMStateProvider.rpcInitialized = {};
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.not.exist;
    });

    it('should initialize RPCs for BASE', function() {
      BaseEVMStateProvider.initializeRpcs('BASE');
      expect(BaseEVMStateProvider.rpcs['BASE:mainnet']).to.exist;
      expect(BaseEVMStateProvider.rpcs['BASE:mainnet'].realtime.length).to.equal(2); // realtime + combined
      expect(BaseEVMStateProvider.rpcs['BASE:mainnet'].historical.length).to.equal(1); // only combined
      expect(BaseEVMStateProvider.rpcIndicies['BASE:mainnet']).to.deep.equal({ realtime: 0, historical: 0 });
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia']).to.exist;
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].realtime.length).to.equal(1); // combined
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].historical.length).to.equal(1); // combined
      expect(BaseEVMStateProvider.rpcIndicies['BASE:sepolia']).to.deep.equal({ realtime: 0, historical: 0 });
      // 'combined' dataType will put the same object in both
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].realtime[0]).to.equal(BaseEVMStateProvider.rpcs['BASE:sepolia'].historical[0]);
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.be.true;
    });

    it('should not re-initialize RPCs for BASE if already initialized', function() {
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.not.exist;
      sandbox.spy(CryptoRpc.prototype, 'get');
      BaseEVMStateProvider.initializeRpcs('BASE');
      const existingRpcsMainnet = BaseEVMStateProvider.rpcs['BASE:mainnet'];
      const existingRpcsSepolia = BaseEVMStateProvider.rpcs['BASE:sepolia'];
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.be.true;
      expect((CryptoRpc.prototype.get as sinon.SinonSpy).callCount).to.equal(3);
      
      // Check for re-initialization
      (CryptoRpc.prototype.get as sinon.SinonSpy).resetHistory();
      BaseEVMStateProvider.initializeRpcs('BASE');
      expect(BaseEVMStateProvider.rpcs['BASE:mainnet']).to.equal(existingRpcsMainnet);
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia']).to.equal(existingRpcsSepolia);
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.be.true; // still true
      expect((CryptoRpc.prototype.get as sinon.SinonSpy).callCount).to.equal(0); // no new calls
    });

    it('should only initialize RPCs for provided data types', function() {
      (Config.get as sinon.SinonStub).restore();
      sandbox.stub(Config, 'get').returns({
        chains: {
          BASE: {
            sepolia: {
              chainSource: 'external',
              module: './moralis',
              needsL1Fee: true,
              providers: [{
                dataType: 'realtime', // no historical/combined
                host: 'sample.example',
                port: '1234',
                protocol: 'ws',
              }]
            }
          }
        }
      });
      BaseEVMStateProvider.initializeRpcs('BASE');
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia']).to.exist;
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].realtime.length).to.equal(1);
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].historical.length).to.equal(0);
      expect(BaseEVMStateProvider.rpcIndicies['BASE:sepolia']).to.deep.equal({ realtime: 0, historical: 0 });
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.be.true;
    });
  });

  describe('teardownRpcs', () => {
    it('should teardown RPCs for BASE', function() {
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.not.exist;
      BaseEVMStateProvider.initializeRpcs('BASE');
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.be.true;
      expect(BaseEVMStateProvider.rpcs['BASE:mainnet']).to.exist;
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia']).to.exist;
      expect(BaseEVMStateProvider.rpcIndicies).to.deep.equal({ 'BASE:mainnet': { realtime: 0, historical: 0 }, 'BASE:sepolia': { realtime: 0, historical: 0 } });
      BaseEVMStateProvider.teardownRpcs();
      expect(BaseEVMStateProvider.rpcs).to.deep.equal({});
      expect(BaseEVMStateProvider.rpcIndicies).to.deep.equal({});
      expect(BaseEVMStateProvider.rpcInitialized['BASE']).to.not.exist;
    });

    it('should work idempotently', function() {
      expect(BaseEVMStateProvider.rpcs).to.deep.equal({});
      expect(BaseEVMStateProvider.rpcIndicies).to.deep.equal({});
      BaseEVMStateProvider.teardownRpcs();
      expect(BaseEVMStateProvider.rpcs).to.deep.equal({});
      expect(BaseEVMStateProvider.rpcIndicies).to.deep.equal({});
    });

    it('should not error if historical array is missing', function() {
      // If no historical or combined providers are configured, the historical array will be missing
      (Config.get as sinon.SinonStub).restore();
      sandbox.stub(Config, 'get').returns({
        chains: {
          BASE: {
            sepolia: {
              chainSource: 'external',
              module: './moralis',
              needsL1Fee: true,
              providers: [{
                dataType: 'realtime', // no historical/combined
                host: 'sample.example',
                port: '1234',
                protocol: 'ws',
              }]
            }
          }
        }
      });
      BaseEVMStateProvider.initializeRpcs('BASE');
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia']).to.exist;
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].realtime.length).to.equal(1);
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].historical.length).to.equal(0);
      expect(BaseEVMStateProvider.rpcIndicies['BASE:sepolia']).to.deep.equal({ realtime: 0, historical: 0 });
      BaseEVMStateProvider.teardownRpcs();
      expect(BaseEVMStateProvider.rpcs).to.deep.equal({});
      expect(BaseEVMStateProvider.rpcIndicies).to.deep.equal({});
    });

    it('should not error if realtime array is missing', function() {
      // If no realtime or combined providers are configured, the realtime array will be missing
      (Config.get as sinon.SinonStub).restore();
      sandbox.stub(Config, 'get').returns({
        chains: {
          BASE: {
            sepolia: {
              chainSource: 'external',
              module: './moralis',
              needsL1Fee: true,
              providers: [{
                dataType: 'historical', // no realtime/combined
                host: 'sample.example',
                port: '1234',
                protocol: 'ws',
              }]
            }
          }
        }
      });
      BaseEVMStateProvider.initializeRpcs('BASE');
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia']).to.exist;
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].realtime.length).to.equal(0);
      expect(BaseEVMStateProvider.rpcs['BASE:sepolia'].historical.length).to.equal(1);
      expect(BaseEVMStateProvider.rpcIndicies['BASE:sepolia']).to.deep.equal({ realtime: 0, historical: 0 });
      BaseEVMStateProvider.teardownRpcs();
      expect(BaseEVMStateProvider.rpcs).to.deep.equal({});
      expect(BaseEVMStateProvider.rpcIndicies).to.deep.equal({});
    });
  });

  describe('getWeb3', () => {
    const network = 'sepolia';
    let BASE;

    before(() => {
      BASE = new MoralisStateProvider('BASE');
    });

    beforeEach(function() {
      BaseEVMStateProvider.initializeRpcs('BASE');
    });

    it('should be able to get web3 with only 1 realtime provider', async () => {
      const web3Stub = { eth: { getBlockNumber: sandbox.stub().resolves(1) } };
      sandbox.stub(BaseEVMStateProvider, 'rpcs').value({ [`BASE:${network}`]: {
        realtime: [{ web3: web3Stub, rpc: sandbox.stub(), dataType: 'combined' }]
      } });
      const { web3 } = await BASE.getWeb3(network);
      const block = await web3.eth.getBlockNumber();
      const stub = web3.eth.getBlockNumber as sinon.SinonStub;
      expect(stub.callCount).to.eq(1); // doesn't do a test call with only 1 provider
      expect(block).to.eq(1);
    });

    it('should be able to get web3 with multiple realtime provider', async () => {
      const web3Stub = { eth: { getBlockNumber: sandbox.stub().resolves(1) } };
      sandbox.stub(BaseEVMStateProvider, 'rpcs').value({ [`BASE:${network}`]: {
        realtime: [
          { web3: web3Stub, rpc: sandbox.stub(), dataType: 'combined' },
          { web3: web3Stub, rpc: sandbox.stub(), dataType: 'combined' }
        ]
      } });
      const { web3 } = await BASE.getWeb3(network);
      const block = await web3.eth.getBlockNumber();
      const stub = web3.eth.getBlockNumber as sinon.SinonStub;
      expect(stub.callCount).to.eq(2); // does a test call to select responsive provider
      expect(block).to.eq(1);
    });

    it('should handle when last used index is last in array', async () => {
      const web3Stub = { eth: { getBlockNumber: sandbox.stub().resolves(1) } };
      sandbox.stub(BaseEVMStateProvider, 'rpcs').value({ [`BASE:${network}`]: {
        realtime: [
          { web3: web3Stub, rpc: sandbox.stub(), dataType: 'combined', index: 0 },
          { web3: web3Stub, rpc: sandbox.stub(), dataType: 'combined', index: 1 },
        ]
      } });
      BaseEVMStateProvider.rpcIndicies[`BASE:${network}`].realtime = 1; // set to last index
      const response = await BASE.getWeb3(network);
      expect(response.index).to.eq(0); // should wrap around to index 0
      const block = await response.web3.eth.getBlockNumber();
      const stub = response.web3.eth.getBlockNumber as sinon.SinonStub;
      expect(stub.callCount).to.eq(2); // does a test call to select responsive provider
      expect(block).to.eq(1);
    });

    it('should round-robin multiple web3 providers', async () => {
      const web3Stub1 = { eth: { getBlockNumber: sandbox.stub().resolves(1) } };
      const web3Stub2 = { eth: { getBlockNumber: sandbox.stub().resolves(2) } };
      sandbox.stub(BaseEVMStateProvider, 'rpcs').value({ [`BASE:${network}`]: {
        realtime: [
          { web3: web3Stub1, rpc: sandbox.stub(), dataType: 'combined' },
          { web3: web3Stub2, rpc: sandbox.stub(), dataType: 'combined' }
        ]
      } });
      let { web3 } = await BASE.getWeb3(network);
      expect(web3).to.equal(web3Stub2); // index starts at index 1
      ({ web3 } = await BASE.getWeb3(network));
      expect(web3).to.equal(web3Stub1);
      ({ web3 } = await BASE.getWeb3(network));
      expect(web3).to.equal(web3Stub2);
    });

    it('should return web3 for provider dataType', async () => {
      const web3Stub1 = { eth: { getBlockNumber: sandbox.stub().resolves(1) } };
      const web3Stub2 = { eth: { getBlockNumber: sandbox.stub().resolves(2) } };
      sandbox.stub(BaseEVMStateProvider, 'rpcs').value({ [`BASE:${network}`]: {
        realtime: [{ web3: web3Stub1, rpc: sandbox.stub(), dataType: 'combined' }],
        historical: [{ web3: web3Stub2, rpc: sandbox.stub(), dataType: 'combined' }]
      } });
      let { web3 } = await BASE.getWeb3(network, { type: 'realtime' });
      expect(web3).to.equal(web3Stub1);
      ({ web3 } = await BASE.getWeb3(network, { type: 'historical' }));
      expect(web3).to.equal(web3Stub2);
    });

    it('should return web3 for provider dataType with round-robin for each', async () => {
      const web3StubRealtime1 = { eth: { getBlockNumber: sandbox.stub().resolves(11) } };
      const web3StubRealtime2 = { eth: { getBlockNumber: sandbox.stub().resolves(12) } };
      const web3StubHistorical1 = { eth: { getBlockNumber: sandbox.stub().resolves(21) } };
      const web3StubHistorical2 = { eth: { getBlockNumber: sandbox.stub().resolves(22) } };
      const web3StubCombined = { eth: { getBlockNumber: sandbox.stub().resolves(31) } };
      sandbox.stub(BaseEVMStateProvider, 'rpcs').value({ [`BASE:${network}`]: {
        realtime: [{ web3: web3StubRealtime1, rpc: sandbox.stub(), dataType: 'realtime' }, { web3: web3StubRealtime2, rpc: sandbox.stub(), dataType: 'realtime' }, { web3: web3StubCombined, rpc: sandbox.stub(), dataType: 'combined' }],
        historical: [{ web3: web3StubHistorical1, rpc: sandbox.stub(), dataType: 'historical' }, { web3: web3StubHistorical2, rpc: sandbox.stub(), dataType: 'historical' }, { web3: web3StubCombined, rpc: sandbox.stub(), dataType: 'combined' }]
      } });
      let { web3 } = await BASE.getWeb3(network, { type: 'realtime' });
      expect(web3).to.equal(web3StubRealtime2); // index starts at index 1
      ({ web3 } = await BASE.getWeb3(network, { type: 'historical' }));
      expect(web3).to.equal(web3StubHistorical2); // index starts at index 1
      ({ web3 } = await BASE.getWeb3(network, { type: 'historical' }));
      expect(web3).to.equal(web3StubCombined); // index 2
      ({ web3 } = await BASE.getWeb3(network, { type: 'historical' }));
      expect(web3).to.equal(web3StubHistorical1); // index 0
      ({ web3 } = await BASE.getWeb3(network, { type: 'realtime' }));
      expect(web3).to.equal(web3StubCombined); // index 2
      ({ web3 } = await BASE.getWeb3(network, { type: 'realtime' }));
      expect(web3).to.equal(web3StubRealtime1); // index 0
    });
  });
});

describe('MultiProviderEVMStateProvider: getLocalTip', function() {
  let cfgStub: sinon.SinonStub;
  let convertStub: sinon.SinonStub;

  before(function() {
    cfgStub = sinon.stub(Config, 'get').returns({ chains: { ETH: {} } } as any);
    (BaseEVMStateProvider as any).rpcInitialized = { ETH: true };
    // convertRawBlock writes Binary buffers; stub to return a height-only IBlock.
    convertStub = sinon.stub(EVMBlockStorage, 'convertRawBlock').callsFake((chain: string, network: string, raw: any) => ({
      chain, network, height: Number(raw.number), hash: raw.hash
    }) as any);
  });
  after(function() {
    cfgStub.restore();
    convertStub.restore();
  });

  function buildProvider(latestBlocks: any[]) {
    const provider = new MultiProviderEVMStateProvider('ETH');
    let i = 0;
    const getBlock = sinon.stub().callsFake(async (_tag: any) => latestBlocks[Math.min(i++, latestBlocks.length - 1)]);
    (provider as any).getWeb3 = async () => ({ web3: { eth: { getBlock } } });
    return { provider, getBlock };
  }

  it('returns tip from realtime RPC, not Mongo storage', async function() {
    const raw = { number: 12345, hash: '0xabc', timestamp: 1700000000 };
    const { provider, getBlock } = buildProvider([raw]);
    const tip = await provider.getLocalTip({ chain: 'ETH', network: 'mainnet' });
    expect(tip.height).to.equal(12345);
    expect(getBlock.calledWith('latest')).to.equal(true);
  });

  it('caches tip across calls within TTL window', async function() {
    const raw = { number: 100, hash: '0xa', timestamp: 1 };
    const { provider, getBlock } = buildProvider([raw, raw]);
    await provider.getLocalTip({ chain: 'ETH', network: 'mainnet' });
    await provider.getLocalTip({ chain: 'ETH', network: 'mainnet' });
    await provider.getLocalTip({ chain: 'ETH', network: 'mainnet' });
    expect(getBlock.callCount).to.equal(1);
  });

  it('caches per chain:network independently', async function() {
    const raw1 = { number: 100, hash: '0xa', timestamp: 1 };
    const raw2 = { number: 200, hash: '0xb', timestamp: 2 };
    const { provider, getBlock } = buildProvider([raw1, raw2]);
    const tip1 = await provider.getLocalTip({ chain: 'ETH', network: 'mainnet' });
    const tip2 = await provider.getLocalTip({ chain: 'ETH', network: 'sepolia' });
    expect(tip1.height).to.equal(100);
    expect(tip2.height).to.equal(200);
    expect(getBlock.callCount).to.equal(2);
  });

  it('throws when realtime RPC returns no block', async function() {
    const { provider } = buildProvider([null]);
    try {
      await provider.getLocalTip({ chain: 'ETH', network: 'mainnet' });
      throw new Error('should have thrown');
    } catch (e: any) {
      expect(e.message).to.match(/no latest block/i);
    }
  });
});

describe('MultiProviderEVMStateProvider: getFee', function() {
  let cfgStub: sinon.SinonStub;
  let cacheStub: sinon.SinonStub;
  before(function() {
    cfgStub = sinon.stub(Config, 'get').returns({ chains: { ETH: {} } } as any);
    (BaseEVMStateProvider as any).rpcInitialized = { ETH: true };
    // Bypass Mongo-backed CacheStorage; just call through to the refresh fn.
    cacheStub = sinon.stub(CacheStorage, 'getGlobalOrRefresh').callsFake(async (_key: string, refresh: any) => refresh());
  });
  after(function() { cfgStub.restore(); cacheStub.restore(); });

  it('uses RPC estimateFee, not Mongo tx history', async function() {
    const provider = new MultiProviderEVMStateProvider('ETH');
    const estimateFee = sinon.stub().resolves(2_000_000_000n);
    (provider as any).getWeb3 = async () => ({ rpc: { estimateFee } });
    const result = await provider.getFee({ network: 'mainnet-getfee-uniq1', target: 4, txType: 2 } as any);
    expect(result.feerate).to.equal(2_000_000_000);
    expect(result.blocks).to.equal(4);
    expect(estimateFee.calledOnce).to.equal(true);
    expect(estimateFee.firstCall.args[0]).to.deep.equal({ nBlocks: 4, txType: 2 });
  });

  it('accepts "livenet" alias without throwing', async function() {
    const provider = new MultiProviderEVMStateProvider('ETH');
    const estimateFee = sinon.stub().resolves(1_000_000_000n);
    (provider as any).getWeb3 = async () => ({ rpc: { estimateFee } });
    const result = await provider.getFee({ network: 'livenet', target: 7 } as any);
    expect(result.feerate).to.equal(1_000_000_000);
    expect(result.blocks).to.equal(7);
  });
});

describe('MultiProviderEVMStateProvider: streamBlocks and _getBlocks', function() {
  let cfgStub: sinon.SinonStub;
  let convertStub: sinon.SinonStub;
  before(function() {
    cfgStub = sinon.stub(Config, 'get').returns({ chains: { ETH: {} } } as any);
    (BaseEVMStateProvider as any).rpcInitialized = { ETH: true };
    convertStub = sinon.stub(EVMBlockStorage, 'convertRawBlock').callsFake((chain: string, network: string, raw: any) => ({
      chain, network, height: Number(raw.number), hash: raw.hash
    }) as any);
  });
  after(function() {
    cfgStub.restore();
    convertStub.restore();
  });

  function setupProvider(blockMap: Record<number, any>, tipHeight = 100) {
    const provider = new MultiProviderEVMStateProvider('ETH');
    const getBlock = sinon.stub().callsFake(async (n: any) => blockMap[Number(n)] ?? null);
    const getBlockNumber = sinon.stub().resolves(BigInt(tipHeight));
    (provider as any).getWeb3 = async () => ({ web3: { eth: { getBlock, getBlockNumber } } });
    (provider as any).getChainId = async () => 1n;
    (provider as any).getBlocksRange = async () => [10, 11, 12];
    return { provider, getBlock };
  }

  it('_getBlocks fetches blocks via RPC and computes tipHeight from getBlockNumber', async function() {
    const blockMap: Record<number, any> = {
      10: { number: 10n, hash: '0xa' },
      11: { number: 11n, hash: '0xb' },
      12: { number: 12n, hash: '0xc' },
      13: { number: 13n, hash: '0xd' }
    };
    const { provider } = setupProvider(blockMap, 200);
    const result = await (provider as any)._getBlocks({ chain: 'ETH', network: 'mainnet' });
    expect(result.tipHeight).to.equal(200);
    expect(result.blocks).to.have.length(3);
    expect(result.blocks[0].height).to.equal(10);
    expect(result.blocks[2].height).to.equal(12);
  });

  it('streamBlocks emits blocks from RPC range with confirmations and nextBlockHash', async function() {
    const blockMap: Record<number, any> = {
      10: { number: 10n, hash: '0xa' },
      11: { number: 11n, hash: '0xb' },
      12: { number: 12n, hash: '0xc' },
      13: { number: 13n, hash: '0xd' }
    };
    const { provider } = setupProvider(blockMap, 100);
    const stream: any = await (provider as any).streamBlocks({ chain: 'ETH', network: 'mainnet' });
    const out: any[] = [];
    await new Promise<void>((resolve, reject) => {
      stream.on('data', (b: any) => out.push(b));
      stream.on('end', () => resolve());
      stream.on('error', reject);
    });
    expect(out).to.have.length(3);
    expect(out[0].height).to.equal(10);
    expect(out[0].confirmations).to.equal(100 - 10 + 1);
    expect(out[0].nextBlockHash).to.equal('0xb');
    expect(out[2].nextBlockHash).to.equal('0xd');
  });
});

describe('MultiProviderEVMStateProvider: _buildWalletTransactionsStream tokenAddress routing', function() {
  let cfgStub: sinon.SinonStub;
  before(function() {
    cfgStub = sinon.stub(Config, 'get').returns({ chains: { ETH: {} } } as any);
    (BaseEVMStateProvider as any).rpcInitialized = { ETH: true };
  });
  after(function() { cfgStub.restore(); });

  function buildProviderWithFakeAdapter() {
    const provider = new MultiProviderEVMStateProvider('ETH');
    const fakeStream = { eventPipe: sinon.stub().callsFake((s: any) => s) };
    const adapter = {
      name: 'fake',
      streamAddressTransactions: sinon.stub().returns(fakeStream),
      streamERC20Transfers: sinon.stub().returns(fakeStream)
    };
    const fakeProvider = { adapter, health: { isAvailable: () => true, recordFailure: sinon.stub() }, priority: 1 };
    (provider as any).providersByNetwork = new Map([['mainnet', [fakeProvider]]]);
    (provider as any).getChainId = async () => 1n;
    // Minimal stub for WalletAddressStorage.updateLastQueryTime
    (provider as any).updateLastQueryTime = async () => {};
    return { provider, adapter, fakeStream };
  }

  function buildStreamParams(walletAddresses: string[]) {
    const transactionStream = new TransformWithEventPipe({ objectMode: true, passThrough: true });
    const populateReceipt = new TransformWithEventPipe({ objectMode: true, passThrough: true });
    const populateEffects = new TransformWithEventPipe({ objectMode: true, passThrough: true });
    sinon.spy(transactionStream, 'eventPipe');
    sinon.spy(populateReceipt, 'eventPipe');
    sinon.spy(populateEffects, 'eventPipe');
    return {
      transactionStream,
      populateReceipt,
      populateEffects,
      walletAddresses
    };
  }

  it('routes to streamERC20Transfers when args.tokenAddress is set', async function() {
    const { provider, adapter, fakeStream } = buildProviderWithFakeAdapter();
    const streamParams = buildStreamParams(['0xaddr1', '0xaddr2']);
    const result = await (provider as any)._buildWalletTransactionsStream(
      { network: 'mainnet', args: { tokenAddress: '0xtoken' } },
      streamParams
    );
    expect(adapter.streamERC20Transfers.callCount).to.equal(2);
    expect(adapter.streamAddressTransactions.callCount).to.equal(0);
    expect(adapter.streamERC20Transfers.firstCall.args[0].tokenAddress).to.equal('0xtoken');
    expect(fakeStream.eventPipe.alwaysCalledWith(streamParams.transactionStream)).to.equal(true);
    expect((streamParams.transactionStream.eventPipe as sinon.SinonSpy).calledOnceWith(streamParams.populateReceipt)).to.equal(true);
    expect((streamParams.populateReceipt.eventPipe as sinon.SinonSpy).calledOnceWith(streamParams.populateEffects)).to.equal(true);
    expect((streamParams.populateEffects.eventPipe as sinon.SinonSpy).calledOnce).to.equal(true);
    expect((streamParams.populateEffects.eventPipe as sinon.SinonSpy).firstCall.args[0]).to.be.instanceOf(TxidDedupeTransform);
    expect(result).to.be.instanceOf(TxidDedupeTransform);
  });

  it('routes to streamAddressTransactions when no tokenAddress is set', async function() {
    const { provider, adapter } = buildProviderWithFakeAdapter();
    const streamParams = buildStreamParams(['0xaddr1']);
    const result = await (provider as any)._buildWalletTransactionsStream(
      { network: 'mainnet', args: {} },
      streamParams
    );
    expect(adapter.streamAddressTransactions.callCount).to.equal(1);
    expect(adapter.streamERC20Transfers.callCount).to.equal(0);
    expect((streamParams.transactionStream.eventPipe as sinon.SinonSpy).calledOnceWith(streamParams.populateReceipt)).to.equal(true);
    expect((streamParams.populateReceipt.eventPipe as sinon.SinonSpy).calledOnceWith(streamParams.populateEffects)).to.equal(true);
    expect(result).to.equal(streamParams.populateEffects);
  });
});

describe('BaseEVMStateProvider: populateReceipt', function() {
  let cfgStub: sinon.SinonStub;
  let sandbox: sinon.SinonSandbox;

  const busdToken = '0x4Fabb145d64652a948d72533023f6E7A623C7C53';
  const sourceAddress = '0xa81011Ae274eF6deBd3BDaB634102c7b6c2C452D';
  const walletAddress = '0xa91cFe0DcAd33F36f3c9428D48eCCBD8A71951b4';
  const txid = '0xbaf62c1c4de9761a421608634a4ad0f7dfbfa3546227c0f4044322bdda095f43';
  const erc20TransferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
  const amount = '114519572370000000000';

  const topicForAddress = (address: string) => `0x${address.toLowerCase().replace('0x', '').padStart(64, '0')}`;
  const uint256 = (value: string) => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
  const receiptWithTransferLog = () => ({
    status: true,
    transactionHash: txid,
    transactionIndex: 0,
    blockHash: '0x0ce917ca8e25cccd7228a92895cc11c54fd61479dcec63c3234f16957e1970d9',
    blockNumber: 15777684,
    cumulativeGasUsed: 0,
    gasUsed: 100,
    logs: [{
      address: busdToken,
      topics: [erc20TransferTopic, topicForAddress(sourceAddress), topicForAddress(walletAddress)],
      data: uint256(amount),
      logIndex: 7
    }]
  });
  const expectedTransferEffect = () => ({
    type: 'ERC20:transfer',
    to: walletAddress,
    from: sourceAddress,
    amount,
    contractAddress: busdToken,
    callStack: 'log:7'
  });

  before(function() {
    cfgStub = sinon.stub(Config, 'get').returns({ chains: { ETH: {} } } as any);
    (BaseEVMStateProvider as any).rpcInitialized = { ETH: true };
  });

  after(function() { cfgStub.restore(); });
  beforeEach(function() { sandbox = sinon.createSandbox(); });
  afterEach(function() { sandbox.restore(); });

  it('normalizes fetched receipts on the read path', async function() {
    const provider = new BaseEVMStateProvider('ETH');
    const getTransactionReceipt = sandbox.stub().resolves({
      status: '0x1',
      transactionHash: txid,
      transactionIndex: '0x0',
      blockHash: '0x0ce917ca8e25cccd7228a92895cc11c54fd61479dcec63c3234f16957e1970d9',
      blockNumber: '0xf0b294',
      contractAddress: null,
      cumulativeGasUsed: '0x1',
      gasUsed: '0x64',
      effectiveGasPrice: '0x14',
      logsBloom: '0x'.padEnd(514, '0'),
      type: '0x2',
      logs: []
    });
    sandbox.stub(provider, 'getWeb3').resolves({ web3: { eth: { getTransactionReceipt } } } as any);

    const receipt = await provider.getReceipt('mainnet', txid);

    expect(receipt.status).to.equal(true);
    expect(receipt.blockNumber).to.equal(15774356);
    expect(receipt.gasUsed).to.equal(100);
    expect((receipt as any).effectiveGasPrice).to.equal(20);
    expect((receipt as any).contractAddress).to.equal(undefined);
    expect((receipt as any).logsBloom).to.equal(undefined);
    expect((receipt as any).type).to.equal(undefined);
  });

  it('derives ERC20 effects from fetched receipt logs before stripping the logs', async function() {
    const updateOne = sandbox.stub().resolves();
    sandbox.stub(EVMTransactionStorage, 'collection').get(() => ({ updateOne }));
    const provider = new BaseEVMStateProvider('ETH');
    sandbox.stub(provider, 'getReceipt').resolves(receiptWithTransferLog() as any);
    const tx = {
      _id: new ObjectId(),
      txid,
      chain: 'ETH',
      network: 'mainnet',
      from: '0x963737C550E70FFe4D59464542a28604eDb2eF9a',
      to: sourceAddress,
      value: 0,
      gasPrice: 20,
      gasLimit: 1500000,
      nonce: 79903,
      transactionIndex: 0,
      effects: []
    } as any;

    await provider.populateReceipt(tx);

    const expectedEffect = expectedTransferEffect();
    expect(tx.fee).to.equal(2000);
    expect(tx.effects).to.deep.equal([expectedEffect]);
    expect(tx.receipt.logs).to.equal(undefined);
    expect(updateOne.firstCall.args[1].$set).to.deep.equal({
      receipt: tx.receipt,
      fee: 2000,
      effects: [expectedEffect],
      receiptLogEffectsProcessed: true
    });
  });

  it('does not persist populated receipts for external rows without an id', async function() {
    const updateOne = sandbox.stub().resolves();
    sandbox.stub(EVMTransactionStorage, 'collection').get(() => ({ updateOne }));
    const provider = new BaseEVMStateProvider('ETH');
    sandbox.stub(provider, 'getReceipt').resolves(receiptWithTransferLog() as any);
    const tx = {
      txid,
      chain: 'ETH',
      network: 'mainnet',
      from: '0x963737C550E70FFe4D59464542a28604eDb2eF9a',
      to: sourceAddress,
      value: 0,
      gasPrice: 20,
      gasLimit: 1500000,
      nonce: 79903,
      transactionIndex: 0,
      effects: []
    } as any;

    await provider.populateReceipt(tx);

    expect(tx.effects).to.deep.equal([expectedTransferEffect()]);
    expect(tx.receipt.logs).to.equal(undefined);
    expect(updateOne.called).to.equal(false);
  });

  it('does not mark receipt-log processed when the fetched receipt has no logs array', async function() {
    const updateOne = sandbox.stub().resolves();
    sandbox.stub(EVMTransactionStorage, 'collection').get(() => ({ updateOne }));
    const provider = new BaseEVMStateProvider('ETH');
    const { logs, ...receiptWithoutLogs } = receiptWithTransferLog();
    sandbox.stub(provider, 'getReceipt').resolves(receiptWithoutLogs as any);
    const partialEffect = {
      to: walletAddress,
      from: sourceAddress,
      amount: '1',
      callStack: '0'
    };
    sandbox.stub(EVMTransactionStorage, 'getEffects').returns([partialEffect]);
    const tx = {
      _id: new ObjectId(),
      txid,
      chain: 'ETH',
      network: 'mainnet',
      from: sourceAddress,
      to: busdToken,
      value: 0,
      gasPrice: 20,
      gasLimit: 1500000,
      nonce: 79903,
      transactionIndex: 0,
      effects: []
    } as any;

    await provider.populateReceipt(tx);

    expect(tx.effects).to.deep.equal([partialEffect]);
    expect(tx.receiptLogEffectsProcessed).to.equal(undefined);
    expect(updateOne.firstCall.args[1].$set).to.deep.equal({
      receipt: tx.receipt,
      fee: 2000,
      effects: [partialEffect]
    });
  });

  it('serves stored receipts without refetching for log effects', async function() {
    const updateOne = sandbox.stub().resolves();
    sandbox.stub(EVMTransactionStorage, 'collection').get(() => ({ updateOne }));
    const provider = new BaseEVMStateProvider('ETH');
    const getReceipt = sandbox.stub(provider, 'getReceipt').rejects(new Error('should not refetch'));
    const storedReceipt = {
      status: true,
      transactionHash: txid,
      transactionIndex: 0,
      blockHash: '0x0ce917ca8e25cccd7228a92895cc11c54fd61479dcec63c3234f16957e1970d9',
      blockNumber: 15777684,
      cumulativeGasUsed: 0,
      gasUsed: 100
    };
    const nativeEffect = {
      to: walletAddress,
      from: '0x963737C550E70FFe4D59464542a28604eDb2eF9a',
      amount: '1',
      callStack: '0'
    };
    const tx = {
      _id: new ObjectId(),
      txid,
      chain: 'ETH',
      network: 'mainnet',
      from: nativeEffect.from,
      to: sourceAddress,
      value: 0,
      gasPrice: 20,
      gasLimit: 1500000,
      nonce: 79903,
      transactionIndex: 0,
      receipt: storedReceipt,
      effects: [nativeEffect]
    } as any;

    await provider.populateReceipt(tx);

    expect(getReceipt.called).to.equal(false);
    expect(tx.receipt).to.deep.equal(storedReceipt);
    expect(tx.effects).to.deep.equal([nativeEffect]);
    expect(updateOne.called).to.equal(false);
  });

  it('does not refetch receipts with known-empty logs', async function() {
    const updateOne = sandbox.stub().resolves();
    sandbox.stub(EVMTransactionStorage, 'collection').get(() => ({ updateOne }));
    const provider = new BaseEVMStateProvider('ETH');
    const getReceipt = sandbox.stub(provider, 'getReceipt').rejects(new Error('should not refetch'));
    const tx = {
      _id: new ObjectId(),
      txid,
      chain: 'ETH',
      network: 'mainnet',
      from: '0x963737C550E70FFe4D59464542a28604eDb2eF9a',
      to: sourceAddress,
      value: 0,
      gasPrice: 20,
      gasLimit: 1500000,
      nonce: 79903,
      transactionIndex: 0,
      receipt: {
        status: true,
        transactionHash: txid,
        transactionIndex: 0,
        blockHash: '0x0ce917ca8e25cccd7228a92895cc11c54fd61479dcec63c3234f16957e1970d9',
        blockNumber: 15777684,
        cumulativeGasUsed: 0,
        gasUsed: 100,
        logs: []
      },
      effects: []
    } as any;

    await provider.populateReceipt(tx);

    expect(getReceipt.called).to.equal(false);
    expect(tx.receipt.logs).to.equal(undefined);
    expect(updateOne.called).to.equal(false);
  });

  it('does not refetch or recompute effects for already-processed receipts on re-read', async function() {
    const updateOne = sandbox.stub().resolves();
    sandbox.stub(EVMTransactionStorage, 'collection').get(() => ({ updateOne }));
    const provider = new BaseEVMStateProvider('ETH');
    const getReceipt = sandbox.stub(provider, 'getReceipt').resolves(receiptWithTransferLog() as any);
    const tx = {
      _id: new ObjectId(),
      txid,
      chain: 'ETH',
      network: 'mainnet',
      from: '0x963737C550E70FFe4D59464542a28604eDb2eF9a',
      to: sourceAddress,
      value: 0,
      gasPrice: 20,
      gasLimit: 1500000,
      nonce: 79903,
      transactionIndex: 0,
      receipt: {
        status: true,
        transactionHash: txid,
        transactionIndex: 0,
        blockHash: '0x0ce917ca8e25cccd7228a92895cc11c54fd61479dcec63c3234f16957e1970d9',
        blockNumber: 15777684,
        cumulativeGasUsed: 0,
        gasUsed: 100
      },
      // Trace data that, recomputed without logs, would wrongly re-derive an ERC20 transfer effect
      calls: [{
        from: sourceAddress,
        to: busdToken,
        value: '0',
        depth: '0',
        type: 'CALL',
        abiType: {
          type: 'ERC20',
          name: 'transfer',
          params: [
            { name: '_to', type: 'address', value: walletAddress },
            { name: '_value', type: 'uint256', value: amount }
          ]
        }
      }],
      // The receipt logs previously found no matching Transfer, so the stored effects are empty
      effects: [],
      receiptLogEffectsProcessed: true
    } as any;

    await provider.populateReceipt(tx);
    provider.populateEffects(tx);
    expect(tx.effects).to.deep.equal([]);

    provider.populateEffectsForAddresses(tx, [walletAddress]);

    expect(getReceipt.callCount).to.equal(0);
    expect(tx.effects).to.deep.equal([]);
    expect(updateOne.called).to.equal(false);
  });

  it('does not recompute processed empty effects when streaming block transactions', async function() {
    const provider = new BaseEVMStateProvider('ETH');
    sandbox.stub(provider, 'getLocalTip').resolves({ height: 15777684 } as any);
    const getEffects = sandbox.spy(EVMTransactionStorage, 'getEffects');
    const tx = {
      _id: new ObjectId(),
      txid,
      chain: 'ETH',
      network: 'mainnet',
      blockHeight: 15777684,
      blockHash: '0x0ce917ca8e25cccd7228a92895cc11c54fd61479dcec63c3234f16957e1970d9',
      blockTime: new Date('2022-10-18T21:28:59.000Z'),
      blockTimeNormalized: new Date('2022-10-18T21:28:59.000Z'),
      from: '0x963737C550E70FFe4D59464542a28604eDb2eF9a',
      to: sourceAddress,
      value: 0,
      gasPrice: 20,
      gasLimit: 1500000,
      nonce: 79903,
      transactionIndex: 0,
      receipt: {
        status: true,
        transactionHash: txid,
        transactionIndex: 0,
        blockHash: '0x0ce917ca8e25cccd7228a92895cc11c54fd61479dcec63c3234f16957e1970d9',
        blockNumber: 15777684,
        cumulativeGasUsed: 0,
        gasUsed: 100
      },
      calls: [{
        from: sourceAddress,
        to: busdToken,
        value: '0',
        depth: '0',
        type: 'CALL',
        abiType: {
          type: 'ERC20',
          name: 'transfer',
          params: [
            { name: '_to', type: 'address', value: walletAddress },
            { name: '_value', type: 'uint256', value: amount }
          ]
        }
      }],
      effects: [],
      receiptLogEffectsProcessed: true
    } as any;
    let streamedTx = '';
    sandbox.stub(Storage, 'apiStreamingFind').callsFake((...args: any[]) => {
      streamedTx = args[5](tx);
      return 'streamed' as any;
    });

    const result = await provider.streamTransactions({
      chain: 'ETH',
      network: 'mainnet',
      req: {},
      res: {},
      args: { blockHeight: 15777684 }
    } as any);

    expect(result).to.equal('streamed');
    expect(getEffects.callCount).to.equal(0);
    expect(tx.effects).to.deep.equal([]);
    expect(JSON.parse(streamedTx).effects).to.deep.equal([]);
  });

  it('clears effects when a fetched receipt reports a failed tx', async function() {
    const updateOne = sandbox.stub().resolves();
    sandbox.stub(EVMTransactionStorage, 'collection').get(() => ({ updateOne }));
    const provider = new BaseEVMStateProvider('ETH');
    const failedReceipt = { ...receiptWithTransferLog(), status: false };
    sandbox.stub(provider, 'getReceipt').resolves(failedReceipt as any);
    const tx = {
      _id: new ObjectId(),
      txid,
      chain: 'ETH',
      network: 'mainnet',
      from: '0x963737C550E70FFe4D59464542a28604eDb2eF9a',
      to: sourceAddress,
      value: 0,
      gasPrice: 20,
      gasLimit: 1500000,
      nonce: 79903,
      transactionIndex: 0,
      effects: [expectedTransferEffect()]
    } as any;

    await provider.populateReceipt(tx);

    expect(tx.effects).to.deep.equal([]);
    expect(updateOne.firstCall.args[1].$set).to.deep.equal({
      receipt: tx.receipt,
      fee: 2000,
      effects: [],
      receiptLogEffectsProcessed: true
    });
  });
});

describe('PopulateReceiptTransform', function() {
  let sandbox: sinon.SinonSandbox;
  const duplicateTxid = '0xbaf62c1c4de9761a421608634a4ad0f7dfbfa3546227c0f4044322bdda095f43';
  const transferEffect = {
    type: 'ERC20:transfer',
    to: '0xa91cFe0DcAd33F36f3c9428D48eCCBD8A71951b4',
    from: '0xa81011Ae274eF6deBd3BDaB634102c7b6c2C452D',
    amount: '114519572370000000000',
    contractAddress: '0x4Fabb145d64652a948d72533023f6E7A623C7C53',
    callStack: 'log:7'
  };

  beforeEach(function() { sandbox = sinon.createSandbox(); });
  afterEach(function() { sandbox.restore(); });

  it('pushes rows unenriched when populateReceipt fails', async function() {
    const populateReceipt = sandbox.stub();
    populateReceipt.onFirstCall().rejects(new Error('rate limited'));
    populateReceipt.onSecondCall().callsFake(async tx => ({ ...tx, effects: [transferEffect], receiptLogEffectsProcessed: true }));
    const stream = new PopulateReceiptTransform({ populateReceipt } as any);
    const rows = new Array<any>();
    const done = new Promise<void>((resolve, reject) => {
      stream
        .on('data', tx => rows.push(tx))
        .on('error', reject)
        .on('end', resolve);
    });

    stream.write({ txid: duplicateTxid, value: '100', effects: [] } as any);
    stream.write({ txid: duplicateTxid, value: '200', effects: [] } as any);
    stream.end();
    await done;

    expect(populateReceipt.callCount).to.equal(2);
    expect(rows.map(row => row.value)).to.deep.equal(['100', '200']);
    expect(rows.map(row => row.receiptLogEffectsProcessed)).to.deep.equal([undefined, true]);
    expect(rows[1].effects).to.deep.equal([transferEffect]);
  });

  it('enriches each row through populateReceipt', async function() {
    const populateReceipt = sandbox.stub().callsFake(async tx => ({
      ...tx,
      fee: 2000,
      receipt: { status: true },
      effects: [transferEffect],
      receiptLogEffectsProcessed: true
    }));
    const stream = new PopulateReceiptTransform({ populateReceipt } as any);
    const rows = new Array<any>();
    const done = new Promise<void>((resolve, reject) => {
      stream
        .on('data', tx => rows.push(tx))
        .on('error', reject)
        .on('end', resolve);
    });

    stream.write({ txid: duplicateTxid, value: '100', effects: [] } as any);
    stream.write({ txid: duplicateTxid, value: '200', effects: [] } as any);
    stream.end();
    await done;

    expect(populateReceipt.callCount).to.equal(2);
    expect(rows.map(row => row.value)).to.deep.equal(['100', '200']);
    expect(rows.map(row => row.effects)).to.deep.equal([[transferEffect], [transferEffect]]);
    expect(rows.map(row => row.receiptLogEffectsProcessed)).to.deep.equal([true, true]);
  });
});

describe('MultiProviderEVMStateProvider: _verifyBlockBeforeDate EthDater fallback', function() {
  let cfgStub: sinon.SinonStub;
  let sandbox: sinon.SinonSandbox;

  before(function() {
    cfgStub = sinon.stub(Config, 'get').returns({ chains: { ETH: {} } } as any);
    (BaseEVMStateProvider as any).rpcInitialized = { ETH: true };
  });
  after(function() { cfgStub.restore(); });
  beforeEach(function() { sandbox = sinon.createSandbox(); });
  afterEach(function() { sandbox.restore(); });

  const ALWAYS_AHEAD_TS = '0xffffffff';
  const targetDate = new Date(1700000000 * 1000);

  it('falls back to EthDater when the bounded walk exceeds MAX_ADJUSTMENTS', async function() {
    const provider = new MultiProviderEVMStateProvider('ETH');
    const fakeWeb3 = { eth: { getBlock: sandbox.stub().resolves({ timestamp: ALWAYS_AHEAD_TS }) } };
    (provider as any).getWeb3 = async () => ({ web3: fakeWeb3 });
    const getDateStub = sandbox.stub(EthDater.prototype, 'getDate')
      .resolves({ block: 12345, timestamp: 1700000000, date: '2023-11-14T22:13:20Z' });

    const result = await (provider as any)._verifyBlockBeforeDate('mainnet', 100, targetDate);

    expect(result).to.equal(12345);
    expect(getDateStub.calledOnce).to.be.true;
    expect(getDateStub.firstCall.args[1]).to.equal(false);
  });

  it('caches the dater per network across calls', async function() {
    const provider = new MultiProviderEVMStateProvider('ETH');
    const fakeWeb3 = { eth: { getBlock: sandbox.stub().resolves({ timestamp: ALWAYS_AHEAD_TS }) } };
    (provider as any).getWeb3 = async () => ({ web3: fakeWeb3 });
    sandbox.stub(EthDater.prototype, 'getDate')
      .resolves({ block: 1, timestamp: 1, date: '1970-01-01T00:00:01Z' });

    await (provider as any)._verifyBlockBeforeDate('mainnet', 100, targetDate);
    await (provider as any)._verifyBlockBeforeDate('mainnet', 100, targetDate);

    expect((provider as any).daters.size).to.equal(1);
  });
});
