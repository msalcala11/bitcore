import { expect } from 'chai';
import { spawnSync } from 'child_process';
import path from 'path';
import { computeBackfillExitCode } from '../../src/providers/chain-state/evm/backfillExitCode';

describe('backfillEvmReceiptLogEffects exit codes', function() {
  this.timeout(30000);
  const script = path.resolve(__dirname, '../../../scripts/backfillEvmReceiptLogEffects.js');
  const missingConfig = path.resolve(__dirname, 'missing-bitcore.config.json');

  function runScript(args: string[]) {
    return spawnSync('node', [script, ...args], {
      env: { ...process.env, BITCORE_CONFIG_PATH: missingConfig },
      encoding: 'utf8'
    });
  }

  it('maps clean completion to 0', function() {
    expect(computeBackfillExitCode({})).to.equal(0);
  });

  it('maps skipped or unwritten transactions to 2', function() {
    expect(computeBackfillExitCode({ skippedTransactions: 1 })).to.equal(2);
    expect(computeBackfillExitCode({ unwrittenTransactions: 1 })).to.equal(2);
  });

  it('maps interruption to 2', function() {
    expect(computeBackfillExitCode({ interrupted: true })).to.equal(2);
  });

  it('maps fatal failure to 1', function() {
    expect(computeBackfillExitCode({ fatal: true })).to.equal(1);
  });

  it('gives fatal failure precedence over incomplete state', function() {
    expect(computeBackfillExitCode({
      fatal: true,
      skippedTransactions: 1,
      unwrittenTransactions: 1,
      interrupted: true
    })).to.equal(1);
  });

  // Keep the real process boundary covered for usage validation. The deliberately
  // missing config proves these paths do not load configured runtime dependencies.
  it('exits 0 for --help', function() {
    const result = runScript(['--help']);
    expect(result.status).to.equal(0);
    expect(result.stdout).to.contain('EXIT CODES');
    expect(result.stderr).not.to.contain('No bitcore config');
  });

  it('exits 1 when required options are missing', function() {
    const result = runScript(['--network', 'mainnet']);
    expect(result.status).to.equal(1);
    expect(result.stdout).to.contain('Missing required options');
  });

  it('exits 1 for invalid option values', function() {
    const result = runScript(['--chain', 'ETH', '--network', 'mainnet', '--startHeight', 'abc']);
    expect(result.status).to.equal(1);
    expect(result.stdout).to.contain('Invalid option value');
  });

  it('exits 1 for an invalid height range', function() {
    const result = runScript(['--chain', 'ETH', '--network', 'mainnet', '--startHeight', '100', '--endHeight', '5']);
    expect(result.status).to.equal(1);
    expect(result.stdout).to.contain('Invalid height range');
  });
});
