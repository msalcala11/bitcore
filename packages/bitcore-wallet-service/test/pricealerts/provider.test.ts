import { expect } from 'chai';
import sinon from 'sinon';
import config from '../../src/config';
import { CoinGeckoService, canonicalCoinGeckoAsset } from '../../src/externalservices/coingecko';
import logger from '../../src/lib/logger';
import { priceAlertOptions } from '../../src/lib/pricealerts/config';
import { PriceAlertDelivery, priceAlertMessage } from '../../src/lib/pricealerts/delivery';
import { PriceAlertService } from '../../src/lib/pricealerts/service';
import { readPriceObservation } from '../../src/lib/pricealerts/worker';
import { PushNotificationsService } from '../../src/lib/pushnotificationsservice';

const now = 1800000000000;
const address = '0x' + 'ab'.repeat(20);
const token = { chain: 'eth', tokenAddress: address };
const sol = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

describe('Price alert asset resolution and current prices', () => {
  let previous;
  let cg: CoinGeckoService;
  let cache;
  let get;
  beforeEach(() => {
    previous = config.coinGecko;
    config.coinGecko = { api: 'https://coingecko.invalid/api/', apiKey: 'test-pro-key' };
    cache = {
      checkAndUseGlobalCache: sinon.stub().callsFake((_key, _duration, cb) => cb(null, undefined, undefined)),
      storeGlobalCache: sinon.stub().callsFake((_key, _value, cb) => cb())
    };
    cg = new CoinGeckoService(cache as any);
    get = sinon.stub(); cg.request = { get };
    sinon.stub(logger, 'error'); sinon.stub(logger, 'warn');
  });
  afterEach(() => { config.coinGecko = previous; sinon.restore(); });
  it('reuses native selectors, aliases and address validation', () => {
    expect(canonicalCoinGeckoAsset({ coin: 'BTC' })).to.deep.equal({ assetKey: 'native:btc', coin: 'btc' });
    expect(canonicalCoinGeckoAsset({ coin: 'arc' }).assetKey).to.equal('native:arc');
    const polygon = canonicalCoinGeckoAsset({ chain: 'pol', tokenAddress: address.toUpperCase().replace('0X', '0x') });
    expect(polygon).to.deep.equal({ assetKey: `token:matic:${address}`, chain: 'matic', tokenAddress: address });
    expect(canonicalCoinGeckoAsset({ chain: 'matic', tokenAddress: address })).to.deep.equal(polygon);
    expect(canonicalCoinGeckoAsset(token).assetKey).not.to.equal(polygon.assetKey);
    expect(canonicalCoinGeckoAsset({ chain: 'sol', tokenAddress: sol }).tokenAddress).to.equal(sol);
    for (const query of [{}, { coin: 'unknown' }, { coin: 'btc', chain: 'eth' }, { tokenAddress: address },
      { chain: 'bad', tokenAddress: address }, { chain: 'eth', tokenAddress: 'bad' }, { chain: 'sol', tokenAddress: address }]) {
      expect(() => canonicalCoinGeckoAsset(query)).to.throw();
    }
  });
  it('takes token names/symbols from the single existing contract lookup', async () => {
    get.callsFake((_url, _opts, cb) => cb(null, { statusCode: 200, body: { id: 'usd-coin', name: 'USDC', symbol: 'usdc', asset_platform_id: 'ethereum' } }));
    const resolved = await cg.resolvePriceAlertAsset({ ...token, coin: 'USDC' });
    expect(resolved).to.deep.equal({ assetKey: `token:eth:${address}`, ...token, providerId: 'usd-coin', name: 'USDC', symbol: 'USDC' });
    expect(get.callCount).to.equal(1);
    expect(get.firstCall.args[0]).to.include('/v3/coins/ethereum/contract/');
    try { await cg.resolvePriceAlertAsset({ ...token, coin: 'DAI' }); throw new Error('Expected mismatch'); }
    catch (err) { expect(err.message).to.equal('tokenAddress does not match coin'); }
  });
  it('rejects unsupported tokens, inconsistent platforms and missing names', async () => {
    for (const body of [{}, { id: 'token', symbol: 'T', name: 'Token', asset_platform_id: 'solana' }, { id: 'token', symbol: 'T' }]) {
      get.callsFake((_url, _opts, cb) => cb(null, { statusCode: 200, body }));
      let failed = false;
      try { await cg.resolvePriceAlertAsset(token); } catch { failed = true; }
      expect(failed).to.equal(true);
    }
  });
  it('creates a COP rule but fetches the native name using cached USD market stats', async () => {
    get.callsFake((url, _opts, cb) => {
      const parsed = new URL(url);
      let body;
      if (parsed.pathname.endsWith('/markets')) {
        expect(parsed.searchParams.get('vs_currency')).to.equal('usd');
        body = [{ id: 'bitcoin', name: 'Bitcoin from CoinGecko', symbol: 'btc', current_price: 100 }];
      } else if (parsed.pathname.endsWith('/market_chart')) {
        expect(parsed.searchParams.get('vs_currency')).to.equal('usd'); body = { prices: [[now, 100]] };
      } else body = { description: { en: '' } };
      cb(null, { statusCode: 200, body });
    });
    let saved;
    const storage: any = {
      getRegistration: async () => ({ priceAlertsEnabled: true }), getRule: async () => saved,
      countEnabledRules: async () => 0,
      saveRule: async (_owner, asset, thresholdPct, code) => { saved = { ...asset, thresholdPct, code }; }
    };
    const result = await new PriceAlertService(storage, cg, priceAlertOptions()).save('owner', { coin: 'btc' }, { thresholdPct: 5, code: 'COP' });
    expect(result).to.include({ code: 'COP', name: 'Bitcoin from CoinGecko' });
    expect(cache.checkAndUseGlobalCache.firstCall.args[0]).to.equal('cgMarketStats:usd:bitcoin');
  });
  it('requests full precision per-currency changes and seconds with Pro credentials, without cache', async () => {
    const fixture = { 'usd-coin': { cop: 4000, cop_24h_change: -6, last_updated_at: now / 1000 } };
    get.callsFake((_url, _opts, cb) => cb(null, { statusCode: 200, body: fixture }));
    expect(await cg.priceAlertPrices(['bitcoin', 'usd-coin'], ['USD', 'COP'])).to.equal(fixture);
    const [url, opts] = get.firstCall.args;
    const parsed = new URL(url);
    expect(parsed.pathname).to.equal('/api/v3/simple/price');
    expect(Object.fromEntries(parsed.searchParams.entries())).to.deep.equal({
      ids: 'bitcoin,usd-coin', vs_currencies: 'usd,cop', include_24hr_change: 'true', include_last_updated_at: 'true', precision: 'full'
    });
    expect(opts.headers['x-cg-pro-api-key']).to.equal('test-pro-key');
    expect(opts.timeout).to.equal(15000);
    expect(cache.checkAndUseGlobalCache.called).to.equal(false);
    expect(readPriceObservation('usd-coin', 'COP', fixture['usd-coin'], now, 300000).observation.change24hPct).to.equal(-6);
  });
  it('rejects 429 and timeout once without a stale-cache fallback or retry', async () => {
    for (const failure of ['429', 'timeout']) {
      get.resetHistory();
      get.callsFake((_url, _opts, cb) => failure === '429' ? cb(null, { statusCode: 429, body: {} }) : cb({ code: 'ETIMEDOUT' }));
      let failed = false;
      try { await cg.priceAlertPrices(['bitcoin'], ['USD']); } catch { failed = true; }
      expect(failed).to.equal(true); expect(get.callCount).to.equal(1);
      expect(cache.checkAndUseGlobalCache.called).to.equal(false);
    }
  });
});

describe('Price alert observation validation', () => {
  const valid = { usd: 100, usd_24h_change: 0, last_updated_at: now / 1000 };
  it('accepts zero change and converts provider seconds to milliseconds', () => {
    expect(readPriceObservation('bitcoin', 'USD', valid, now, 300000).observation).to.include({ observedAt: now, change24hPct: 0 });
  });
  for (const [field, values] of Object.entries({ usd: [undefined, null, '100', NaN, Infinity, 0, -1],
    usd_24h_change: [undefined, null, '0', NaN, Infinity], last_updated_at: [undefined, null, '1800000000', NaN, Infinity, 0, now] })) {
    for (const value of values) {
      it(`rejects ${field}=${String(value)}`, () => {
        expect(readPriceObservation('bitcoin', 'USD', { ...valid, [field]: value }, now, 300000).observation).to.equal(undefined);
      });
    }
  }
  it('isolates missing currencies and stale or future observations', () => {
    expect(readPriceObservation('bitcoin', 'EUR', valid, now, 300000).reason).to.equal('invalid_price');
    expect(readPriceObservation('bitcoin', 'USD', valid, now + 300001, 300000).reason).to.equal('stale');
    expect(readPriceObservation('bitcoin', 'USD', valid, now - 30001, 300000).reason).to.equal('future');
    expect(readPriceObservation('bitcoin', 'USD', valid, now + 300000, 300000).observation).not.to.equal(undefined);
  });
});

describe('Price alert Braze delivery', () => {
  const rule: any = { assetKey: `token:eth:${address}`, ...token, name: 'A & B', symbol: 'A+B', code: 'COP', thresholdPct: 5 };
  const observation = { id: 'observation', providerId: 'token', code: 'COP', price: 4000, change24hPct: -6.12345, observedAt: now };
  let log;
  beforeEach(() => { log = sinon.stub(logger, 'info'); });
  afterEach(() => sinon.restore());
  it('uses required copy, encoded routing and identical metadata on both platforms', () => {
    const message = priceAlertMessage(rule, observation, now + 10);
    expect(message.apple_push.alert).to.deep.equal({ title: 'Price Alert: A & B', body: 'A & B has moved 5%. View the latest price.' });
    expect(message.android_push.alert).to.equal(message.apple_push.alert.body);
    expect(message.android_push.extra).to.deep.equal(message.apple_push.extra);
    expect(message.apple_push.extra).to.include({ thresholdPct: 5, change24hPct: -6.12345, direction: 'down', code: 'COP',
      observedAt: now, sentAt: now + 10, observationId: 'observation', notification_type: 'price_alert' });
    const link = new URL(message.apple_push.custom_uri);
    expect(link.hostname).to.equal('exchange-rate');
    expect(link.searchParams.get('currencyAbbreviation')).to.equal('a+b');
    expect(link.searchParams.get('tokenAddress')).to.equal(address);
    expect(link.searchParams.get('chain')).to.equal('eth');
    expect(message.apple_push.custom_uri).to.include('a%2Bb');
  });
  it('groups identical messages into <=50 recipients with bounded concurrency and reporting IDs', async () => {
    const sender = new PriceAlertDelivery(priceAlertOptions({ campaignId: 'campaign', appleMessageVariationId: 'apple', androidMessageVariationId: 'android' }),
      { pushServerUrlBraze: 'https://braze.invalid/', authorizationKeyBraze: 'secret' });
    let inflight = 0; let max = 0;
    const http = sinon.stub().callsFake((opts, cb) => {
      inflight++; max = Math.max(max, inflight);
      expect(opts.url).to.equal('https://braze.invalid/messages/send');
      expect(opts.timeout).to.equal(10000); expect(opts.body).not.to.have.property('recipient_subscription_state');
      expect(opts.body.campaign_id).to.equal('campaign');
      expect(opts.body.messages.apple_push.message_variation_id).to.equal('apple');
      expect(opts.body.messages.android_push.message_variation_id).to.equal('android');
      setImmediate(() => { inflight--; cb(null, { statusCode: 201 }, { message: 'success', dispatch_id: 'dispatch' }); });
    });
    sender.request = http;
    await sender.send(Array.from({ length: 121 }, (_, i) => ({ rule, observation, externalUserId: 'recipient' + i })));
    expect(http.getCalls().map(call => call.args[0].body.external_user_ids.length)).to.deep.equal([50, 50, 21]);
    expect(max).to.equal(2);
    expect(log.firstCall.args[1]).to.include({ outcome: 'accepted', dispatchId: 'dispatch' });
  });
  it('logs accepted, rejected and unknown outcomes and never retries', async () => {
    for (const [err, response, body, outcome] of [[null, { statusCode: 200 }, { message: 'success' }, 'accepted'],
      [null, { statusCode: 400 }, { message: 'bad request' }, 'rejected'], [null, { statusCode: 200 }, { message: 'success', errors: ['invalid'] }, 'rejected'],
      [{ code: 'ETIMEDOUT' }, undefined, undefined, 'unknown'], [{ code: 'ECONNRESET' }, undefined, undefined, 'unknown']]) {
      const sender = new PriceAlertDelivery(priceAlertOptions(), {});
      const http = sinon.stub().callsFake((_opts, cb) => cb(err, response, body)); sender.request = http;
      await sender.send([{ rule, observation, externalUserId: 'recipient' }]);
      expect(http.callCount).to.equal(1); expect(log.lastCall.args[1].outcome).to.equal(outcome);
    }
  });
  it('leaves the wallet sender request and callback semantics unchanged', () => {
    const sender = new PushNotificationsService();
    sender.pushServerUrlBraze = 'https://braze.invalid'; sender.authorizationKeyBraze = 'key';
    sender.request = sinon.stub().callsFake((_opts, cb) => cb(null, { statusCode: 500 }));
    const callback = sinon.spy(); sender._makeBrazeRequest({ messages: {} }, callback);
    const opts = (sender.request as sinon.SinonStub).firstCall.args[0];
    expect(opts).not.to.have.property('timeout');
    expect(opts).not.to.have.property('followRedirect');
    expect(callback.firstCall.args).to.deep.equal([null, { statusCode: 500 }]);
  });
});
