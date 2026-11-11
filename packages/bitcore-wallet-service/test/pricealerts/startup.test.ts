import { spawnSync } from 'child_process';
import { expect } from 'chai';
import { validatePriceAlertBrazeSettings } from '../../src/lib/pricealerts/config';

describe('Price alert Braze startup settings', function() {
  this.timeout(10000);
  const valid = { pushServerUrlBraze: 'https://braze.invalid', authorizationKeyBraze: 'test-key-not-a-credential' };
  const invalid = [
    { label: 'missing URL', settings: { ...valid, pushServerUrlBraze: undefined }, field: 'pushServerUrlBraze' },
    { label: 'malformed URL', settings: { ...valid, pushServerUrlBraze: 'https://[bad' }, field: 'pushServerUrlBraze' },
    { label: 'relative URL', settings: { ...valid, pushServerUrlBraze: '/messages/send' }, field: 'pushServerUrlBraze' },
    { label: 'URL without authority', settings: { ...valid, pushServerUrlBraze: 'https:braze.invalid' }, field: 'pushServerUrlBraze' },
    { label: 'non-HTTP URL', settings: { ...valid, pushServerUrlBraze: 'file:///tmp/braze' }, field: 'pushServerUrlBraze' },
    { label: 'missing key', settings: { ...valid, authorizationKeyBraze: undefined }, field: 'authorizationKeyBraze' },
    { label: 'non-string key', settings: { ...valid, authorizationKeyBraze: 12345 }, field: 'authorizationKeyBraze' },
    { label: 'empty key', settings: { ...valid, authorizationKeyBraze: '' }, field: 'authorizationKeyBraze' },
    { label: 'blank key', settings: { ...valid, authorizationKeyBraze: ' \t\n ' }, field: 'authorizationKeyBraze' },
    { label: 'placeholder key', settings: { ...valid, authorizationKeyBraze: 'You_have_to_put_something_here' }, field: 'authorizationKeyBraze' },
    { label: 'padded placeholder key', settings: { ...valid, authorizationKeyBraze: '  You_have_to_put_something_here  ' }, field: 'authorizationKeyBraze' }
  ];

  for (const { label, settings, field } of invalid) {
    it(`rejects ${label} without exposing the key`, () => {
      let failure: Error;
      try { validatePriceAlertBrazeSettings(settings); } catch (err) { failure = err; }
      expect(failure).to.be.instanceOf(Error);
      expect(failure.message).to.include('pushNotificationsOpts.' + field);
      const key = String(settings.authorizationKeyBraze ?? '').trim();
      if (key) expect(failure.message).not.to.include(key);
      expect(failure.message).not.to.include('You_have_to_put_something_here');
    });
  }

  it('accepts plausible HTTP and HTTPS settings without a network check', () => {
    expect(() => validatePriceAlertBrazeSettings(valid)).not.to.throw();
    expect(() => validatePriceAlertBrazeSettings({ ...valid, pushServerUrlBraze: 'http://localhost:7358' })).not.to.throw();
    expect(() => validatePriceAlertBrazeSettings()).to.throw('pushServerUrlBraze');
  });

  // A fresh process runs the real entry point. Guards fail the test if it connects
  // or polls, so even a broken startup check cannot touch a DB or send a push.
  const daemon = (settings, switches, disabled = false) => spawnSync(process.execPath, ['-e', `
    const config = require(${JSON.stringify(require.resolve('../../src/config'))}).default;
    config.priceAlertsOpts = ${JSON.stringify(switches)};
    config.pushNotificationsOpts = ${JSON.stringify(settings)};
    const { Storage } = require(${JSON.stringify(require.resolve('../../src/lib/storage'))});
    Storage.prototype.connect = () => { throw new Error('Unexpected storage connection'); };
    const { PriceAlertWorker } = require(${JSON.stringify(require.resolve('../../src/lib/pricealerts/worker'))});
    ${disabled ? `
      const checks = require(${JSON.stringify(require.resolve('../../src/lib/pricealerts/config'))});
      checks.validatePriceAlertBrazeSettings = () => { throw new Error('Unexpected validation'); };
      const start = PriceAlertWorker.prototype.start;
      PriceAlertWorker.prototype.start = function() { start.call(this); setImmediate(() => this.stop()); };
    ` : 'PriceAlertWorker.prototype.poll = () => { throw new Error("Unexpected poll"); };'}
    require(${JSON.stringify(require.resolve('../../src/pricealertsservice/pricealertsservice'))});
  `], { encoding: 'utf8', timeout: 5000, env: { ...process.env, BITCORE_CONFIG_PATH: '/dev/null', BWS_CONFIG_PATH: '/dev/null' } });

  for (const field of ['pushServerUrlBraze', 'authorizationKeyBraze']) {
    it(`exits before connecting or polling with an invalid ${field}`, () => {
      const settings = { ...valid, [field]: field === 'pushServerUrlBraze' ? '/relative' : 'You_have_to_put_something_here' };
      const result = daemon(settings, { enabled: true, workerEnabled: true });
      expect(result.error).to.equal(undefined);
      expect(result.status).to.equal(1);
      const output = result.stdout + result.stderr;
      expect(output).to.include('Price alert service cannot start');
      expect(output).to.include('pushNotificationsOpts.' + field);
      expect(output).not.to.include(settings.authorizationKeyBraze);
      expect(output).not.to.include('Unexpected');
    });
  }
  for (const switches of [{ enabled: false, workerEnabled: true }, { enabled: true, workerEnabled: false }]) {
    it(`stays idle without validating Braze when switches are ${JSON.stringify(switches)}`, () => {
      const result = daemon({}, switches, true);
      expect(result.error).to.equal(undefined);
      expect(result.status).to.equal(0);
      expect(result.stdout + result.stderr).to.include('Price alert worker disabled; staying idle');
      expect(result.stdout + result.stderr).not.to.include('Unexpected');
    });
  }
});
