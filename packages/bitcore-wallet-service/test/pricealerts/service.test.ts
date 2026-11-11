import { createHash } from 'crypto';
import { setDefaultResultOrder } from 'dns';
import { expect } from 'chai';
import express from 'express';
import { MongoClient } from 'mongodb';
import * as secp256k1 from 'secp256k1';
import sinon from 'sinon';
import supertest from 'supertest';
import config from '../../src/config';
import { CoinGeckoService, canonicalCoinGeckoAsset } from '../../src/externalservices/coingecko';
import { Defaults } from '../../src/lib/common/defaults';
import { Utils } from '../../src/lib/common/utils';
import logger from '../../src/lib/logger';
import { PriceAlertDelivery, priceAlertMessage } from '../../src/lib/pricealerts/delivery';
import { priceAlertOptions } from '../../src/lib/pricealerts/config';
import { PriceAlertService } from '../../src/lib/pricealerts/service';
import { PRICE_ALERT_COLLECTIONS, PRICE_ALERT_COOLDOWN_MS, PriceAlertStorage } from '../../src/lib/pricealerts/storage';
import { PriceAlertWorker, readPriceObservation } from '../../src/lib/pricealerts/worker';
import { authAppRequest, verifyAppIdentity } from '../../src/lib/routes/middleware/authAppRequest';
import { authRequest } from '../../src/lib/routes/middleware/authRequest';
import { registerPriceAlertRoutes } from '../../src/lib/routes/pricealerts';
import { WalletService } from '../../src/lib/server';
import { Storage } from '../../src/lib/storage';
import { PushNotificationsService } from '../../src/lib/pushnotificationsservice';
import fixture from '../fixtures/price-alert-signatures.json';
import testConfig from '../test-config';

setDefaultResultOrder('ipv4first');
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();
const key = hash('bws-price-alerts-test-vector-1 (throwaway)');
const secondKey = hash('independent app identity');
const publicKey = (privateKey = key) => Buffer.from(secp256k1.publicKeyCreate(privateKey)).toString('hex');
const sign = (message: string, privateKey = key) => Buffer.from(secp256k1.signatureExport(secp256k1.ecdsaSign(hash(message), privateKey).signature)).toString('hex');
const owner = (privateKey = key) => hash(Buffer.from(publicKey(privateKey), 'hex')).toString('hex');
const options = () => priceAlertOptions({ enabled: true, workerEnabled: true });
const asset = { assetKey: 'native:btc', coin: 'btc', providerId: 'bitcoin', name: 'Bitcoin', symbol: 'BTC' };
const registerBody = { externalUserId: 'braze-profile', priceAlertsEnabled: true, pushEnabled: true };
const now = 1800000000000;
const market = (change = 10.2) => ({ bitcoin: { usd: 100, usd_24h_change: change, last_updated_at: Date.now() / 1000 } });
const originalTimers = { setTimeout: global.setTimeout, clearTimeout: global.clearTimeout };

describe('Price alert app signing', () => {
  for (const vector of fixture.vectors) {
    for (const form of ['signatureLowS', 'signatureHighS']) {
      it(`verifies BitAuth ${form}: ${vector.message}`, () => {
        expect(verifyAppIdentity(vector.message, fixture.publicKeyCompressed, vector[form])).to.equal(owner());
        expect(verifyAppIdentity(vector.message, fixture.publicKeyUncompressed, vector[form])).to.equal(owner());
        expect(Utils.verifyMessage(vector.message, vector[form], fixture.publicKeyCompressed)).to.equal(false);
        const imported = secp256k1.signatureImport(Buffer.from(vector[form], 'hex'));
        expect(secp256k1.ecdsaVerify(imported, hash(vector.message), Buffer.from(fixture.publicKeyCompressed, 'hex')))
          .to.equal(form === 'signatureLowS');
        expect(secp256k1.ecdsaVerify(secp256k1.signatureNormalize(imported), hash(hash(vector.message)),
          Buffer.from(fixture.publicKeyCompressed, 'hex'))).to.equal(false);
      });
    }
  }
  it('rejects both authoritative DELETE signatures with a tampered coin', () => {
    for (const signature of [fixture.vectors[1].signatureLowS, fixture.vectors[1].signatureHighS]) {
      let error;
      try { verifyAppIdentity('delete|/v1/pricealerts/?coin=eth|{}', fixture.publicKeyCompressed, signature); }
      catch (err) { error = err; }
      expect(error?.code).to.equal('NOT_AUTHORIZED');
    }
  });
});

describe('Price alert API, persistence and worker (Mongo)', function() {
  this.timeout(15000);
  let client: MongoClient;
  let storage: Storage;
  let db: PriceAlertStorage;
  let provider: CoinGeckoService;
  let service: PriceAlertService;
  let clock;
  let previousOptions;
  let resolve;
  let prices;
  let sent;
  let delivery;

  before(async () => {
    expect(testConfig.mongoDb.dbname).to.equal('bws_test');
    client = await MongoClient.connect(testConfig.mongoDb.uri, { useUnifiedTopology: true, serverSelectionTimeoutMS: 5000 });
    storage = new Storage({ db: client.db('bws_test') });
    db = storage.priceAlerts;
    // These tests use the real secondary indexes, and wait for their builds.
    await PriceAlertStorage.createIndexes(storage.db);
  });
  beforeEach(async () => {
    for (const collection of Object.values(PRICE_ALERT_COLLECTIONS)) await storage.db.collection(collection).deleteMany({});
    previousOptions = config.priceAlertsOpts;
    config.priceAlertsOpts = options();
    clock = sinon.useFakeTimers({ now, toFake: ['Date'] });
    sinon.stub(logger, 'info');
    sinon.stub(logger, 'error');
    sinon.stub(WalletService, 'getStorage').returns(storage);
    resolve = sinon.stub(CoinGeckoService.prototype, 'resolvePriceAlertAsset').callsFake(async query => {
      const selector = canonicalCoinGeckoAsset(query);
      return { ...selector, providerId: selector.coin === 'eth' ? 'ethereum' : 'bitcoin', name: selector.coin === 'eth' ? 'Ethereum' : 'Bitcoin', symbol: (selector.coin || 'TOKEN').toUpperCase() };
    });
    provider = new CoinGeckoService(storage);
    prices = sinon.stub(provider, 'priceAlertPrices').callsFake(async () => market());
    service = new PriceAlertService(db, provider, options());
    sent = [];
    delivery = { send: sinon.stub().callsFake(async items => { sent.push(...items); }) };
  });
  afterEach(() => {
    config.priceAlertsOpts = previousOptions;
    // Restore timer spies before the clock; otherwise a spy can reinstall the
    // fake setTimeout after the clock has already restored the real timer.
    sinon.restore();
    clock.restore();
    expect(global.setTimeout).to.equal(originalTimers.setTimeout);
    expect(global.clearTimeout).to.equal(originalTimers.clearTimeout);
  });
  after(async () => { if (client) await client.close(); });

  const api = (ignoreRateLimiter = true) => {
    const app = express();
    app.use(express.json());
    const router = express.Router();
    registerPriceAlertRoutes(router, { ignoreRateLimiter });
    app.use('/bws/api', router);
    return app;
  };
  const call = (app, method, path, body?, privateKey = key, signedPath = path) => {
    let req = supertest(app)[method]('/bws/api' + path)
      .set('x-identity', publicKey(privateKey))
      .set('x-signature', sign(`${method}|${signedPath}|${JSON.stringify(body ?? {})}`, privateKey));
    if (body !== undefined) req = req.set('Content-Type', 'application/json').send(body);
    return req;
  };
  const register = (id = owner(), fields = {}) => db.saveRegistration(id, { ...registerBody, ...fields });
  const rule = async (id = owner(), code = 'USD', threshold = 5, chosenAsset = asset) => {
    await db.saveRule(id, chosenAsset, threshold, code);
    return db.getRule(id, chosenAsset.assetKey);
  };
  const worker = () => new PriceAlertWorker(db, provider, delivery, options());
  const observation = (change = 10.2, code = 'USD') => ({ id: 'test-observation', providerId: 'bitcoin', code, price: 100, change24hPct: change, observedAt: Date.now() });

  it('lists an unregistered identity without writing records', async () => {
    const response = await call(api(), 'get', '/v1/pricealerts/').expect(200);
    expect(response.body).to.deep.equal({ registration: { registered: false }, alerts: [] });
    expect(await db.getRegistration(owner())).to.equal(null);
  });
  it('authenticates the exact mount-relative path, encoding, order and trailing slash', async () => {
    const app = api();
    const path = '/v1/pricealerts/?x=a%20b&y=%2f';
    await call(app, 'get', path).expect(200);
    await call(app, 'get', path, undefined, key, '/bws/api' + path).expect(401);
    await call(app, 'get', path, undefined, key, '/v1/pricealerts/?y=%2f&x=a%20b').expect(401);
    await call(app, 'get', path, undefined, key, '/v1/pricealerts/?x=a+b&y=%2F').expect(401);
    await call(app, 'get', '/v1/pricealerts', undefined, key, '/v1/pricealerts/').expect(401);
    await call(app, 'get', '/v1/pricealerts').expect(200);
  });
  it('rejects missing, malformed and invalid credentials and array mutation bodies', async () => {
    const app = api();
    await supertest(app).get('/bws/api/v1/pricealerts/').expect(401);
    for (const identity of ['', 'copayer-id', '02' + 'ff'.repeat(32), '00']) {
      await supertest(app).get('/bws/api/v1/pricealerts/').set('x-identity', identity).set('x-signature', '00').expect(401);
    }
    for (const signature of ['zz', '123', '30'.repeat(80), '00']) {
      await supertest(app).get('/bws/api/v1/pricealerts/').set('x-identity', publicKey()).set('x-signature', signature).expect(401);
    }
    await call(app, 'put', '/v1/pricealerts/registration/', []).expect(400);
    await call(app, 'put', '/v1/pricealerts/registration/', registerBody, secondKey)
      .set('x-identity', publicKey()).expect(401);
  });
  it('rejects query tampering before any rule is changed', async () => {
    await register();
    await rule();
    await rule(owner(), 'USD', 5, { ...asset, assetKey: 'native:eth', coin: 'eth' });
    const app = api();
    await call(app, 'delete', '/v1/pricealerts/?coin=eth', undefined, key, '/v1/pricealerts/?coin=btc').expect(401);
    expect((await db.listRules(owner())).length).to.equal(2);
    await supertest(app).delete('/bws/api/v1/pricealerts/?coin=btc').set('x-identity', fixture.publicKeyCompressed)
      .set('x-signature', fixture.vectors[1].signatureHighS).expect(200);
    expect((await db.listRules(owner())).map(r => r.coin)).to.deep.equal(['eth']);
  });
  it('keeps wallet authentication on its copayer and double-SHA convention', async () => {
    const lookup = sinon.stub(storage, 'fetchCopayerLookup').resolves(null);
    const app = express();
    app.use(express.json());
    app.get('/v1/pricealerts/', authRequest(), (_req, res) => res.sendStatus(200));
    await supertest(app).get('/v1/pricealerts/').set('x-identity', publicKey())
      .set('x-signature', fixture.vectors[0].signatureLowS).expect(401);
    expect(lookup.firstCall.args[0]).to.equal(publicKey());
  });
  it('isolates owners sharing a destination and rejects ownership overrides', async () => {
    const app = api();
    for (const privateKey of [key, secondKey]) await call(app, 'put', '/v1/pricealerts/registration/', registerBody, privateKey).expect(200);
    await call(app, 'put', '/v1/pricealerts/?coin=btc', { thresholdPct: 10, code: 'USD' }).expect(200);
    const other = await call(app, 'get', '/v1/pricealerts/', undefined, secondKey).expect(200);
    expect(other.body.alerts).to.deep.equal([]);
    await call(app, 'delete', '/v1/pricealerts/?coin=btc', undefined, secondKey).expect(200);
    expect((await db.listRules(owner())).length).to.equal(1);
    await call(app, 'put', '/v1/pricealerts/?coin=btc', { thresholdPct: 10, code: 'USD', ownerId: owner() }, secondKey).expect(400);
  });
  it('validates initial registration and preserves supplied-field update semantics', async () => {
    const app = api();
    for (const body of [{}, { externalUserId: 'x' }, { ...registerBody, pushEnabled: 1 }, { ...registerBody, externalUserId: 'x'.repeat(257) }]) {
      await call(app, 'put', '/v1/pricealerts/registration/', body).expect(400);
    }
    await call(app, 'put', '/v1/pricealerts/registration/', { ...registerBody, priceAlertsEnabled: false }).expect(200);
    await call(app, 'put', '/v1/pricealerts/registration/', { externalUserId: 'new-profile' }).expect(200);
    let registration = await db.getRegistration(owner());
    expect(registration.priceAlertsEnabled).to.equal(false);
    await call(app, 'put', '/v1/pricealerts/registration/', { pushEnabled: false }).expect(200);
    registration = await db.getRegistration(owner());
    expect(registration.externalUserId).to.equal('new-profile');
    expect(registration.pushEnabled).to.equal(false);
  });
  it('requires registration, validates every threshold and fiat, and lists while paused', async () => {
    const app = api();
    await call(app, 'put', '/v1/pricealerts/?coin=btc', { thresholdPct: 5, code: 'USD' }).expect(400);
    await register(owner(), { priceAlertsEnabled: false, pushEnabled: false });
    for (const thresholdPct of [5, 10, 15, 20]) {
      await call(app, 'put', '/v1/pricealerts/?coin=btc', { thresholdPct, code: 'COP' }).expect(200);
    }
    for (const body of [{ thresholdPct: 6, code: 'USD' }, { thresholdPct: '5', code: 'USD' }, { thresholdPct: 5, code: 'FAKE' }]) {
      await call(app, 'put', '/v1/pricealerts/?coin=btc', body).expect(400);
    }
    const response = await call(app, 'get', '/v1/pricealerts/').expect(200);
    expect(response.body.alerts[0]).to.include({ thresholdPct: 20, code: 'COP', name: 'Bitcoin' });
    expect(response.body.alerts[0]).not.to.have.property('nextEligibleAt');
    expect(response.body.registration.priceAlertsEnabled).to.equal(false);
  });
  it('preserves updatedAt on identical retries and cooldown across every configuration change', async () => {
    await register();
    await service.save(owner(), { coin: 'btc' }, { thresholdPct: 10, code: 'USD' });
    const first = await db.getRule(owner(), asset.assetKey);
    await db.reserve(first, observation(), Date.now());
    clock.tick(1000);
    await service.save(owner(), { coin: 'btc' }, { thresholdPct: 10, code: 'USD' });
    expect((await db.getRule(owner(), asset.assetKey)).updatedAt).to.equal(first.updatedAt);
    await service.disable(owner(), { coin: 'btc' });
    const disabled = await db.getRule(owner(), asset.assetKey);
    clock.tick(1000);
    await service.disable(owner(), { coin: 'btc' });
    expect((await db.getRule(owner(), asset.assetKey)).updatedAt).to.equal(disabled.updatedAt);
    await service.save(owner(), { coin: 'btc' }, { thresholdPct: 5, code: 'EUR' });
    await service.register(owner(), { priceAlertsEnabled: false });
    await service.register(owner(), { externalUserId: 'new-destination' });
    await service.register(owner(), { priceAlertsEnabled: true });
    const final = await db.getRule(owner(), asset.assetKey);
    expect(final.nextEligibleAt).to.equal(now + PRICE_ALERT_COOLDOWN_MS);
    expect(final.code).to.equal('EUR');
    expect(await db.reserve(final, observation(10, 'EUR'), Date.now())).to.equal(false);
  });
  for (const chosen of [asset, {
    assetKey: 'token:eth:0x' + 'ab'.repeat(20), chain: 'eth', tokenAddress: '0x' + 'ab'.repeat(20),
    providerId: 'stored-token', name: 'Stored Token', symbol: 'TOKEN'
  }]) {
    it(`edits, retries and re-enables ${chosen.assetKey} without an available resolver`, async () => {
      await register();
      const first = await rule(owner(), 'USD', 5, chosen as any);
      await db.reserve(first, observation(), now);
      resolve.resetHistory(); resolve.rejects(new Error('resolver unavailable'));
      const query = 'tokenAddress' in chosen
        ? { chain: chosen.chain, tokenAddress: chosen.tokenAddress, coin: 'locally-valid-symbol' }
        : { coin: chosen.coin };
      clock.tick(1000);
      await service.save(owner(), query, { thresholdPct: 10, code: 'EUR' });
      const edited = await db.getRule(owner(), chosen.assetKey);
      expect(edited.updatedAt).to.equal(now + 1000);
      expect(edited).to.include({ thresholdPct: 10, code: 'EUR', providerId: chosen.providerId, name: chosen.name, symbol: chosen.symbol });
      clock.tick(1000);
      await service.save(owner(), query, { thresholdPct: 10, code: 'EUR' });
      expect(await db.getRule(owner(), chosen.assetKey)).to.deep.equal(edited);
      await service.disable(owner(), query);
      await service.save(owner(), query, { thresholdPct: 15, code: 'COP' });
      const enabled = await db.getRule(owner(), chosen.assetKey);
      expect(enabled).to.include({ enabled: true, thresholdPct: 15, code: 'COP', nextEligibleAt: now + PRICE_ALERT_COOLDOWN_MS });
      if ('tokenAddress' in chosen) expect(enabled).not.to.have.property('coin');
      expect(resolve.called).to.equal(false);
    });
  }
  it('still requires successful provider resolution for a new rule', async () => {
    await register();
    resolve.rejects(new Error('resolver unavailable'));
    try {
      await service.save(owner(), { coin: 'btc' }, { thresholdPct: 10, code: 'USD' });
      throw new Error('Expected provider failure');
    } catch (err) {
      expect(err.message).to.equal('resolver unavailable');
    }
    expect(resolve.callCount).to.equal(1);
    expect(await db.getRule(owner(), asset.assetKey)).to.equal(null);
  });
  it('disables locally with aliases, equivalent EVM case and ignored token coin', async () => {
    await register();
    const token = { assetKey: 'token:matic:0x' + 'ab'.repeat(20), chain: 'matic', tokenAddress: '0x' + 'ab'.repeat(20), providerId: 'token', name: 'Token', symbol: 'T' };
    await rule(owner(), 'USD', 5, token as any);
    resolve.resetHistory();
    await call(api(), 'delete', '/v1/pricealerts/?chain=pol&tokenAddress=0x' + 'AB'.repeat(20) + '&coin=WRONG').expect(200);
    expect(resolve.called).to.equal(false);
    expect((await db.getRule(owner(), token.assetKey)).enabled).to.equal(false);
  });
  it('caps newly enabled rules but permits editing and idempotent saving', async () => {
    await register();
    service = new PriceAlertService(db, provider, priceAlertOptions({ maxEnabledRules: 1 }));
    await service.save(owner(), { coin: 'btc' }, { thresholdPct: 5, code: 'USD' });
    await service.save(owner(), { coin: 'btc' }, { thresholdPct: 10, code: 'USD' });
    try { await service.save(owner(), { coin: 'eth' }, { thresholdPct: 5, code: 'USD' }); throw new Error('Expected limit'); }
    catch (err) { expect(err.code).to.equal('PRICE_ALERTS_LIMIT'); }
    await service.disable(owner(), { coin: 'btc' });
    await service.save(owner(), { coin: 'eth' }, { thresholdPct: 5, code: 'USD' });
    try { await service.save(owner(), { coin: 'btc' }, { thresholdPct: 5, code: 'USD' }); throw new Error('Expected limit'); }
    catch (err) { expect(err.code).to.equal('PRICE_ALERTS_LIMIT'); }
  });
  it('enforces uniqueness under concurrent upserts before secondary indexes exist', async () => {
    await storage.db.collection(PRICE_ALERT_COLLECTIONS.PRICE_ALERT_RULES).dropIndexes();
    await Promise.all(Array.from({ length: 12 }, () => register()));
    await Promise.all(Array.from({ length: 12 }, () => rule()));
    expect(await storage.db.collection(PRICE_ALERT_COLLECTIONS.PRICE_ALERT_REGISTRATIONS).countDocuments({})).to.equal(1);
    expect(await storage.db.collection(PRICE_ALERT_COLLECTIONS.PRICE_ALERT_RULES).countDocuments({})).to.equal(1);
    await PriceAlertStorage.createIndexes(storage.db);
  });
  it('returns the same disabled error on all routes without accessing storage', async () => {
    config.priceAlertsOpts = { enabled: false };
    const app = api();
    const getStorage = WalletService.getStorage as sinon.SinonStub;
    getStorage.resetHistory();
    for (const [method, path, body] of [['put', '/v1/pricealerts/registration/', registerBody], ['get', '/v1/pricealerts/', undefined],
      ['put', '/v1/pricealerts/?coin=btc', {}], ['delete', '/v1/pricealerts/?coin=btc', undefined]]) {
      const response = await call(app, method, path, body).expect(400);
      expect(response.body.code).to.equal('PRICE_ALERTS_DISABLED');
    }
    expect(getStorage.called).to.equal(false);
  });
  it('shares the actual 300 request budget across all mutations without delays', async () => {
    expect(Defaults.RateLimit.priceAlerts).to.include({ max: 300, windowMs: 600000, delayMs: 0 });
    const app = api(false);
    await register();
    for (let i = 0; i < 300; i++) {
      if (i % 3 === 0) await call(app, 'put', '/v1/pricealerts/registration/', {}).expect(200);
      else if (i % 3 === 1) await call(app, 'put', '/v1/pricealerts/?coin=btc', { thresholdPct: 5, code: 'USD' }).expect(200);
      else await call(app, 'delete', '/v1/pricealerts/?coin=btc').expect(200);
    }
    await call(app, 'delete', '/v1/pricealerts/?coin=btc').expect(429);
    await call(app, 'put', '/v1/pricealerts/registration/', {}).expect(429);
    await call(app, 'get', '/v1/pricealerts/').expect(200);
  });

  for (const change of [5, -5, -6, 10.2]) {
    it(`reserves on the first observation at ${change}%`, async () => {
      await register(); await rule(); prices.callsFake(async () => market(change));
      await worker().poll();
      expect(sent.length).to.equal(1);
      expect(sent[0].observation.change24hPct).to.equal(change);
    });
  }
  it('uses full precision and the selected fiat including COP', async () => {
    await register(); await rule(owner(), 'USD');
    await register('eur'); await rule('eur', 'EUR');
    await register('cop'); await rule('cop', 'COP');
    prices.resolves({ bitcoin: { usd: 100, usd_24h_change: 4.9, eur: 90, eur_24h_change: 5.1, cop: 400000, cop_24h_change: 5, last_updated_at: now / 1000 } });
    await worker().poll();
    expect(sent.map(item => item.rule.code).sort()).to.deep.equal(['COP', 'EUR']);
    prices.callsFake(async () => market(4.999)); await worker().poll();
    expect(sent.length).to.equal(2);
  });
  it('enforces a shared direction cooldown and fires again on a sustained condition', async () => {
    await register(); await rule(owner(), 'USD', 10);
    const w = worker();
    for (const change of [9.8, 10.2, 10.8, -10.5]) { prices.callsFake(async () => market(change)); await w.poll(); }
    expect(sent.length).to.equal(1);
    clock.tick(PRICE_ALERT_COOLDOWN_MS);
    await w.poll();
    expect(sent.length).to.equal(2);
  });
  it('competing workers and repeated passes over one observation send once', async () => {
    await register(); await rule();
    await Promise.all([worker().poll(), worker().poll(), worker().poll()]);
    await worker().poll();
    expect(sent.length).to.equal(1);
    expect((await db.getRule(owner(), asset.assetKey)).nextEligibleAt).to.equal(now + PRICE_ALERT_COOLDOWN_MS);
  });
  it('does not overlap polls within one worker', async () => {
    await register(); await rule();
    let release;
    prices.callsFake(() => new Promise(resolvePrice => { release = resolvePrice; }));
    const w = worker();
    const first = w.poll();
    while (!release) await new Promise(resolveWait => setImmediate(resolveWait));
    await w.poll();
    expect(prices.callCount).to.equal(1);
    release(market()); await first;
  });
  it('shares one provider request across subscribers and preserves separate canonical assets', async () => {
    for (let i = 0; i < 12; i++) { await register('sub' + i); await rule('sub' + i); }
    await register('arc'); await rule('arc', 'USD', 5, { ...asset, assetKey: 'native:arc', coin: 'arc' });
    await worker().poll();
    expect(prices.callCount).to.equal(1);
    expect(prices.firstCall.args).to.deep.equal([['bitcoin'], ['USD']]);
    expect(sent.length).to.equal(13);
  });
  it('skips paused, push-ineligible and missing registrations without cooldowns', async () => {
    await register('paused', { priceAlertsEnabled: false }); await rule('paused');
    await register('ineligible', { pushEnabled: false }); await rule('ineligible'); await rule('missing');
    await worker().poll(); expect(sent.length).to.equal(0);
    for (const id of ['paused', 'ineligible', 'missing']) expect((await db.getRule(id, asset.assetKey)).nextEligibleAt).to.equal(undefined);
    await register('paused'); await worker().poll(); expect(sent.length).to.equal(1);
  });
  it('honors an edit observed before the conditional reservation', async () => {
    await register(); await rule();
    const original = db.registrationsForRules.bind(db);
    sinon.stub(db, 'registrationsForRules').callsFake(async rules => {
      await db.saveRule(owner(), asset, 20, 'EUR');
      return original(rules);
    });
    await worker().poll(); expect(sent.length).to.equal(0);
    expect((await db.getRule(owner(), asset.assetKey)).nextEligibleAt).to.equal(undefined);
  });
  it('stops all further reservations in a poll after a database error', async () => {
    for (let i = 0; i < 4; i++) { await register('owner' + i); await rule('owner' + i); }
    const original = db.reserve.bind(db);
    const reserve = sinon.stub(db, 'reserve');
    reserve.onCall(0).callsFake(original); reserve.onCall(1).rejects(new Error('write concern timeout'));
    await worker().poll();
    expect(reserve.callCount).to.equal(2);
    expect(sent.length).to.equal(1);
  });
  it('fails closed on an unacknowledged or uncertain Mongo reservation result', async () => {
    const stored = await rule();
    for (const result of [{ result: { ok: 1 } }, { result: { ok: 0 }, matchedCount: 1, modifiedCount: 1 },
      { result: { ok: 1, writeConcernError: {} }, matchedCount: 1, modifiedCount: 1 }, { result: { ok: 1 }, matchedCount: 1, modifiedCount: 0 }]) {
      const collection = { updateOne: sinon.stub().resolves(result) };
      const uncertain = new PriceAlertStorage({ collection: () => collection } as any);
      let failed = false;
      try { await uncertain.reserve(stored, observation(), now); } catch { failed = true; }
      expect(failed).to.equal(true);
      expect(collection.updateOne.firstCall.args.length).to.equal(2); // no w override
    }
  });
  it('continues past paused prefixes and reaches rules beyond a reservation bound in one poll', async () => {
    for (let i = 0; i < 9; i++) { await register('owner' + i); await rule('owner' + i); }
    const sorted = await db.candidates(observation(), now, undefined, undefined, 20);
    for (const item of sorted.slice(0, 6)) await db.saveRegistration(item.alertSetId, { priceAlertsEnabled: false });
    const w = worker(); w.pageSize = 2; w.maxReservationsPerMarket = 1;
    await w.poll();
    expect(sent.map(item => item.rule._id)).to.deep.equal(sorted.slice(6).map(item => item._id));
    expect(prices.callCount).to.equal(1);
  });
  it('retains the unprocessed next candidate when data goes stale between pages', async () => {
    for (let i = 0; i < 5; i++) { await register('owner' + i); await rule('owner' + i); }
    const sorted = await db.candidates(observation(), now, undefined, undefined, 20);
    for (const item of sorted.slice(0, 4)) await db.saveRegistration(item.alertSetId, { priceAlertsEnabled: false });
    const original = db.registrationsForRules.bind(db);
    let pages = 0;
    sinon.stub(db, 'registrationsForRules').callsFake(async rules => {
      if (++pages === 3) clock.tick(300001);
      return original(rules);
    });
    const w = worker(); w.pageSize = 2; w.maxReservationsPerMarket = 1;
    await w.poll(); expect(sent.length).to.equal(0);
    expect((await db.getRule(sorted[4].alertSetId, asset.assetKey)).nextEligibleAt).to.equal(undefined);
    await w.poll(); expect(sent.length).to.equal(1);
    expect(sent[0].rule._id).to.equal(sorted[4]._id);
  });
  it('a send failure or timeout consumes cooldown without retry', async () => {
    await register(); await rule();
    const realDelivery = new PriceAlertDelivery(options(), { pushServerUrlBraze: 'https://braze.invalid', authorizationKeyBraze: 'test' });
    const http = sinon.stub().callsFake((_opts, cb) => cb(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    realDelivery.request = http;
    const w = new PriceAlertWorker(db, provider, realDelivery, options());
    await w.poll(); await w.poll();
    expect(http.callCount).to.equal(1);
    expect((await db.getRule(owner(), asset.assetKey)).nextEligibleAt).to.equal(now + PRICE_ALERT_COOLDOWN_MS);
  });
  it('skips timeout and 429 batches, continues healthy batches with two in flight', async () => {
    for (let i = 0; i < 4; i++) {
      await register('owner' + i); await rule('owner' + i, 'USD', 5, { ...asset, assetKey: 'asset' + i, providerId: 'market' + i });
    }
    let inflight = 0; let maximum = 0;
    prices.callsFake(async ids => {
      inflight++; maximum = Math.max(inflight, maximum);
      await new Promise(resolveWait => setImmediate(resolveWait)); inflight--;
      if (ids[0] === 'market0') throw { statusCode: 429 };
      if (ids[0] === 'market1') throw { code: 'ETIMEDOUT' };
      return { [ids[0]]: market().bitcoin };
    });
    await new PriceAlertWorker(db, provider, delivery, priceAlertOptions({ ...options(), coinGeckoBatchSize: 1 })).poll();
    expect(maximum).to.equal(2); expect(prices.callCount).to.equal(4); expect(sent.length).to.equal(2);
  });
  it('does no work with either switch off and keeps a disabled daemon idle', async () => {
    const markets = sinon.spy(db, 'markets');
    for (const opts of [{ enabled: false, workerEnabled: true }, { enabled: true, workerEnabled: false }]) {
      const w = new PriceAlertWorker(db, provider, delivery, priceAlertOptions(opts));
      w.start(); await w.poll(); w.stop();
    }
    expect(markets.called).to.equal(false); expect(prices.called).to.equal(false); expect(sent.length).to.equal(0);
  });

  it('keeps independently owned rules and cooldowns separate at the same Braze destination', async () => {
    await register(); await register(owner(secondKey));
    await rule(); await rule(owner(secondKey));
    await worker().poll();
    expect(sent.length).to.equal(2);
    expect(sent[0].externalUserId).to.equal(sent[1].externalUserId);
    await service.register(owner(), { externalUserId: 'new-profile', priceAlertsEnabled: false });
    expect((await db.getRegistration(owner(secondKey))).externalUserId).to.equal('braze-profile');
    expect((await db.getRule(owner(secondKey), asset.assetKey)).nextEligibleAt).to.equal(now + PRICE_ALERT_COOLDOWN_MS);
  });

  it('uses the destination read in the current pass and honors a pause already present at that read', async () => {
    await register(); await rule();
    const original = db.registrationsForRules.bind(db);
    const read = sinon.stub(db, 'registrationsForRules').callsFake(async rules => {
      await db.saveRegistration(owner(), { externalUserId: 'refreshed', priceAlertsEnabled: false });
      return original(rules);
    });
    const w = worker();
    await w.poll(); expect(sent.length).to.equal(0);
    expect((await db.getRule(owner(), asset.assetKey)).nextEligibleAt).to.equal(undefined);
    read.restore(); await db.saveRegistration(owner(), { priceAlertsEnabled: true });
    await w.poll(); expect(sent[0].externalUserId).to.equal('refreshed');
  });

  it('rejects stale/invalid parts while reserving healthy observations from a partial response', async () => {
    for (const code of ['USD', 'EUR', 'COP']) { await register(code); await rule(code, code); }
    prices.resolves({ bitcoin: { usd: 100, usd_24h_change: null, eur: 90, eur_24h_change: -6, last_updated_at: now / 1000 } });
    await worker().poll();
    expect(sent.map(item => item.rule.code)).to.deep.equal(['EUR']);
    expect((await db.getRule('USD', asset.assetKey)).nextEligibleAt).to.equal(undefined);
    expect((await db.getRule('COP', asset.assetKey)).nextEligibleAt).to.equal(undefined);
    prices.resolves(market()); clock.tick(300001);
    await worker().poll(); expect(sent.length).to.equal(1);
  });

  it('retains and sends prior reservations when the next page goes stale', async () => {
    for (let i = 0; i < 3; i++) { await register('owner' + i); await rule('owner' + i); }
    const original = db.registrationsForRules.bind(db);
    let pages = 0;
    sinon.stub(db, 'registrationsForRules').callsFake(async rules => {
      if (++pages === 2) clock.tick(300001);
      return original(rules);
    });
    const w = worker(); w.pageSize = 1;
    await w.poll(); expect(sent.length).to.equal(1);
    expect(await storage.db.collection(PRICE_ALERT_COLLECTIONS.PRICE_ALERT_RULES).countDocuments({ nextEligibleAt: { $exists: true } })).to.equal(1);
    await w.poll(); expect(sent.length).to.equal(3);
  });

  it('a reservation made before an abrupt process exit is never recovered or released', async () => {
    await register(); const stored = await rule();
    expect(await db.reserve(stored, observation(), now)).to.equal(true);
    // No send occurs, as if the process died immediately after Mongo acknowledged.
    await worker().poll(); expect(sent.length).to.equal(0);
    clock.tick(PRICE_ALERT_COOLDOWN_MS); await worker().poll(); expect(sent.length).to.equal(1);
  });

  it('an explicit Braze rejection leaves the reservation consumed', async () => {
    await register(); await rule();
    const sender = new PriceAlertDelivery(options(), {});
    const http = sinon.stub().callsFake((_opts, cb) => cb(null, { statusCode: 400 }, { message: 'invalid destination' }));
    sender.request = http;
    const w = new PriceAlertWorker(db, provider, sender, options());
    await w.poll(); await w.poll();
    expect(http.callCount).to.equal(1);
    expect((await db.getRule(owner(), asset.assetKey)).nextEligibleAt).to.equal(now + PRICE_ALERT_COOLDOWN_MS);
  });

  it('uses one qualifying observation for more than two caps worth of rules', async () => {
    for (let i = 0; i < 7; i++) { await register('owner' + i); await rule('owner' + i); }
    prices.onFirstCall().resolves(market(10.2)); prices.onSecondCall().resolves(market(0));
    const w = worker(); w.pageSize = 3; w.maxReservationsPerMarket = 2;
    expect(await w.poll()).to.equal('complete');
    expect(sent.length).to.equal(7);
    expect(new Set(sent.map(item => item.rule._id)).size).to.equal(7);
    expect(new Set(sent.map(item => item.observation.id)).size).to.equal(1);
    expect(sent.every(item => item.observation.observedAt === now && item.observation.change24hPct === 10.2)).to.equal(true);
    expect(prices.callCount).to.equal(1);
    await w.poll(); expect(sent.length).to.equal(7);
  });

  it('competing workers taking continuation turns still send each reserved rule only once', async () => {
    for (let i = 0; i < 7; i++) { await register('owner' + i); await rule('owner' + i); }
    const workers = [worker(), worker(), worker()];
    for (const w of workers) { w.pageSize = 3; w.maxReservationsPerMarket = 2; }
    await Promise.all(workers.map(w => w.poll()));
    expect(sent.length).to.equal(7);
    expect(new Set(sent.map(item => item.rule._id)).size).to.equal(7);
    await workers[0].poll();
    expect(sent.length).to.equal(7);
    for (let i = 0; i < 7; i++) {
      expect((await db.getRule('owner' + i, asset.assetKey)).nextEligibleAt).to.equal(now + PRICE_ALERT_COOLDOWN_MS);
    }
  });

  it('gives all provider batches their first round before any continuation', async () => {
    for (const id of ['a', 'b', 'c', 'd', 'e']) {
      for (let i = 0; i < (id === 'a' ? 3 : 1); i++) {
        await register(id + i); await rule(id + i, 'USD', 5, { ...asset, providerId: id });
      }
    }
    prices.callsFake(async ids => Object.fromEntries(ids.map(id => [id, market().bitcoin])));
    const w = new PriceAlertWorker(db, provider, delivery, priceAlertOptions({ ...options(), coinGeckoBatchSize: 1 }));
    w.pageSize = 2; w.maxReservationsPerMarket = 1;
    await w.poll();
    expect(sent.map(item => item.observation.providerId)).to.deep.equal(['a', 'b', 'c', 'd', 'e', 'a', 'a']);
    expect(prices.getCalls().map(call => call.args[0])).to.deep.equal([['a'], ['b'], ['c'], ['d'], ['e']]);
  });

  it('keeps separate observations for currencies sharing a provider market', async () => {
    for (const code of ['USD', 'EUR']) for (let i = 0; i < 3; i++) {
      await register(code + i); await rule(code + i, code);
    }
    prices.resolves({ bitcoin: { usd: 100, usd_24h_change: 6, eur: 90, eur_24h_change: -7, last_updated_at: now / 1000 } });
    const w = worker(); w.maxReservationsPerMarket = 1;
    await w.poll();
    expect(sent.map(item => item.rule.code)).to.deep.equal(['EUR', 'USD', 'EUR', 'USD', 'EUR', 'USD']);
    for (const code of ['USD', 'EUR']) {
      const items = sent.filter(item => item.rule.code === code);
      expect(new Set(items.map(item => item.observation.id)).size).to.equal(1);
      expect(items.every(item => item.observation.change24hPct === (code === 'USD' ? 6 : -7))).to.equal(true);
    }
    expect(new Set(sent.map(item => item.observation.id)).size).to.equal(2);
    expect(prices.callCount).to.equal(1);
  });

  it('rotates acquisition and first turns past a paused cohort that consumes freshness', async () => {
    for (let i = 0; i < 6; i++) { await register('paused' + i, { priceAlertsEnabled: false }); await rule('paused' + i); }
    const eth = { ...asset, assetKey: 'native:eth', coin: 'eth', providerId: 'ethereum' };
    await register('eth'); await rule('eth', 'USD', 5, eth);
    prices.callsFake(async () => ({ ...market(), ethereum: market().bitcoin }));
    const original = db.registrationsForRules.bind(db);
    sinon.stub(db, 'registrationsForRules').callsFake(async rules => {
      if (rules[0].providerId === 'bitcoin') clock.tick(100001);
      return original(rules);
    });
    const candidates = sinon.spy(db, 'candidates');
    const w = worker(); w.pageSize = 2; w.maxReservationsPerMarket = 1;
    await w.poll();
    expect(sent.length).to.equal(0);
    expect((await db.getRule('eth', eth.assetKey)).nextEligibleAt).to.equal(undefined);
    expect(candidates.getCalls().every(call => call.args[0].providerId === 'bitcoin')).to.equal(true);
    await w.poll();
    expect(sent.map(item => item.rule.alertSetId)).to.deep.equal(['eth']);
    expect(prices.firstCall.args[0]).to.deep.equal(['bitcoin', 'ethereum']);
    expect(prices.secondCall.args[0]).to.deep.equal(['ethereum', 'bitcoin']);
  });

  it('stops stale continuations and resumes at the saved position on a fresh poll', async () => {
    for (let i = 0; i < 5; i++) { await register('owner' + i); await rule('owner' + i); }
    const sorted = await db.candidates(observation(), now, undefined, undefined, 20);
    await register('eth'); await rule('eth', 'USD', 5, { ...asset, providerId: 'ethereum' });
    prices.callsFake(async () => ({ ...market(), ethereum: market().bitcoin }));
    delivery.send.callsFake(async items => {
      sent.push(...items);
      if (items.some(item => item.observation.providerId === 'ethereum')) clock.tick(300001);
    });
    const candidates = sinon.spy(db, 'candidates');
    const w = worker(); w.pageSize = 3; w.maxReservationsPerMarket = 2;
    await w.poll();
    expect(sent.map(item => item.rule._id).slice(0, 2)).to.deep.equal(sorted.slice(0, 2).map(item => item._id));
    expect(sent.length).to.equal(3);
    for (const item of sorted.slice(2)) expect((await db.getRule(item.alertSetId, asset.assetKey)).nextEligibleAt).to.equal(undefined);
    candidates.resetHistory();
    await w.poll();
    expect(sent.length).to.equal(6);
    expect(new Set(sent.map(item => item.rule._id)).size).to.equal(6);
    const resumed = candidates.getCalls().find(call => call.args[0].providerId === 'bitcoin');
    expect(resumed.args[2]).to.equal(sorted[1]._id);
    expect(resumed.args[0].observedAt).to.equal(now + 300001);
    expect(sent[3].observation.id).not.to.equal(sent[0].observation.id);
    expect(prices.callCount).to.equal(2);
  });

  it('handles a cap within a page, paused boundaries and wraparound without skipping or duplicating', async () => {
    for (let i = 0; i < 8; i++) { await register('owner' + i); await rule('owner' + i); }
    const sorted = await db.candidates(observation(), now, undefined, undefined, 20);
    for (const index of [1, 3, 6]) await db.saveRegistration(sorted[index].alertSetId, { priceAlertsEnabled: false });
    const w = worker(); w.pageSize = 4; w.maxReservationsPerMarket = 2;
    (w as any).positions.set('bitcoin:USD', sorted[6]._id);
    expect(await w.poll()).to.equal('complete');
    expect(sent.map(item => item.rule._id)).to.deep.equal([7, 0, 2, 4, 5].map(index => sorted[index]._id));
    for (const index of [1, 3, 6]) expect((await db.getRule(sorted[index].alertSetId, asset.assetKey)).nextEligibleAt).to.equal(undefined);
    expect(prices.callCount).to.equal(1);
  });

  describe('poll scheduling', () => {
    const useTimerClock = () => {
      clock.restore();
      clock = sinon.useFakeTimers({ now, toFake: ['Date', 'setTimeout', 'clearTimeout'] });
      return sinon.spy(global, 'setTimeout');
    };

    for (const duration of [250, 1200]) {
      it(`waits only the remaining interval after a ${duration}ms poll and never overlaps`, async () => {
        await register(); await rule();
        const timer = useTimerClock();
        prices.callsFake(async () => { clock.tick(duration); return market(); });
        const w = new PriceAlertWorker(db, provider, delivery, priceAlertOptions({ ...options(), pollIntervalMs: 1000 }));
        const poll = sinon.spy(w, 'poll');
        try {
          w.start();
          expect(await poll.firstCall.returnValue).to.equal('complete');
          const delay = Math.max(0, 1000 - duration);
          expect(timer.lastCall.args[1]).to.equal(delay);
          expect(poll.callCount).to.equal(1);
          if (delay) { clock.tick(delay - 1); expect(poll.callCount).to.equal(1); clock.tick(1); }
          else clock.tick(0);
          expect(poll.callCount).to.equal(2);
          await poll.secondCall.returnValue;
          expect(sent.length).to.equal(1);
        } finally { w.stop(); }
      });
    }

    for (const failure of ['429', 'timeout', 'stale']) {
      it(`does not apply database backoff to ${failure} provider data`, async () => {
        await register(); await rule();
        const timer = useTimerClock();
        prices.callsFake(async () => {
          const original = market(); clock.tick(2000);
          if (failure === '429') throw { statusCode: 429 };
          if (failure === 'timeout') throw { code: 'ETIMEDOUT' };
          return original;
        });
        const w = new PriceAlertWorker(db, provider, delivery, priceAlertOptions({ ...options(), pollIntervalMs: 1000, maxSourceAgeMs: 100 }));
        const poll = sinon.spy(w, 'poll');
        try {
          w.start(); expect(await poll.firstCall.returnValue).to.equal('complete');
          expect(timer.lastCall.args[1]).to.equal(0);
          expect(sent.length).to.equal(0);
        } finally { w.stop(); }
      });
    }

    for (const switches of [{ enabled: true, workerEnabled: true }, { enabled: false, workerEnabled: true }, { enabled: true, workerEnabled: false }]) {
      it(`waits a full interval when idle with switches ${JSON.stringify(switches)}`, async () => {
        const timer = useTimerClock();
        const markets = sinon.stub(db, 'markets').callsFake(async () => { clock.tick(2000); return []; });
        const w = new PriceAlertWorker(db, provider, delivery, priceAlertOptions({ ...switches, pollIntervalMs: 1000 }));
        const poll = sinon.spy(w, 'poll');
        try {
          w.start(); expect(await poll.firstCall.returnValue).to.equal('idle');
          expect(timer.lastCall.args[1]).to.equal(1000);
          clock.tick(999); expect(poll.callCount).to.equal(1);
          clock.tick(1); expect(poll.callCount).to.equal(2);
          await poll.secondCall.returnValue;
          expect(markets.callCount).to.equal(switches.enabled && switches.workerEnabled ? 2 : 0);
          expect(prices.called).to.equal(false);
        } finally { w.stop(); }
      });
    }

    it('waits a full interval after a market-discovery failure without reserving anything', async () => {
      await register(); await rule();
      const timer = useTimerClock();
      const markets = sinon.stub(db, 'markets');
      markets.onFirstCall().callsFake(async () => { clock.tick(1200); throw new Error('discovery failed'); });
      markets.onSecondCall().resolves([]);
      const reserve = sinon.spy(db, 'reserve');
      const w = new PriceAlertWorker(db, provider, delivery, priceAlertOptions({ ...options(), pollIntervalMs: 1000 }));
      const poll = sinon.spy(w, 'poll');
      try {
        w.start(); expect(await poll.firstCall.returnValue).to.equal('error');
        expect(timer.lastCall.args[1]).to.equal(1000);
        clock.tick(999); expect(poll.callCount).to.equal(1);
        clock.tick(1); await poll.secondCall.returnValue;
        expect(markets.callCount).to.equal(2);
        expect(reserve.called).to.equal(false); expect(sent.length).to.equal(0);
      } finally { w.stop(); }
    });

    it('stops all markets on a continuation error, sends acknowledged reservations and backs off', async () => {
      for (const id of ['bitcoin', 'zeta']) for (let i = 0; i < 4; i++) {
        await register(id + i); await rule(id + i, 'USD', 5, { ...asset, providerId: id });
      }
      const timer = useTimerClock();
      prices.callsFake(async () => ({ ...market(), zeta: market().bitcoin }));
      const original = db.reserve.bind(db);
      let count = 0;
      const reserve = sinon.stub(db, 'reserve').callsFake(async (...args) => {
        if (++count === 6) { clock.tick(1200); throw new Error('continuation write failed'); }
        return original(...args);
      });
      const w = new PriceAlertWorker(db, provider, delivery, priceAlertOptions({ ...options(), pollIntervalMs: 1000 }));
      w.pageSize = 3; w.maxReservationsPerMarket = 2;
      const poll = sinon.spy(w, 'poll');
      try {
        w.start(); expect(await poll.firstCall.returnValue).to.equal('error');
        expect(reserve.callCount).to.equal(6);
        expect(sent.map(item => item.observation.providerId)).to.deep.equal(['bitcoin', 'bitcoin', 'zeta', 'zeta', 'bitcoin']);
        expect(timer.lastCall.args[1]).to.equal(1000);
        clock.tick(999); expect(poll.callCount).to.equal(1);
        clock.tick(1); await poll.secondCall.returnValue;
        expect(sent.length).to.equal(8);
        expect(new Set(sent.map(item => item.rule._id)).size).to.equal(8);
      } finally { w.stop(); }
    });
  });
});

describe('Price alert primary reads and configuration', () => {
  it('explicitly requests primary reads for every registration/rule query', async () => {
    const cursor = { sort: sinon.stub().returnsThis(), limit: sinon.stub().returnsThis(), toArray: async () => [] };
    const collection = { findOne: sinon.stub().resolves(null), find: sinon.stub().returns(cursor),
      countDocuments: sinon.stub().resolves(0), aggregate: sinon.stub().returns(cursor) };
    const storage = new PriceAlertStorage({ collection: () => collection } as any);
    await storage.getRegistration('owner'); await storage.getRule('owner', 'native:btc');
    await storage.listRules('owner'); await storage.countEnabledRules('owner');
    await storage.markets(); await storage.registrationsForRules([]);
    await storage.candidates({ providerId: 'bitcoin', code: 'USD', change24hPct: 10 } as any, now, undefined, undefined, 100);
    for (const method of Object.values(collection)) for (const call of method.getCalls()) {
      expect(call.args[1].readPreference).to.equal('primary');
    }
  });
  it('defaults both switches off and rejects unbounded/invalid numeric settings', () => {
    expect(priceAlertOptions()).to.include({ enabled: false, workerEnabled: false, coinGeckoBatchSize: 100, maxEnabledRules: 50 });
    for (const options of [{ coinGeckoBatchSize: 516 }, { maxEnabledRules: 0 }, { brazeConcurrency: NaN }, { pollIntervalMs: -1 }, { enabled: 'true' }]) {
      expect(() => priceAlertOptions(options as any)).to.throw();
    }
    expect(priceAlertOptions({ coinGeckoBatchSize: 515 }).coinGeckoBatchSize).to.equal(515);
  });
});
