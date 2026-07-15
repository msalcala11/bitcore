import { expect } from 'chai';
import { spawnSync } from 'child_process';
import path from 'path';

// Exercises the script's argument-validation exit codes for real: scheduled
// automation keys off them (0 complete, 1 usage/fatal, 2 incomplete). The
// incomplete/fatal runtime paths need a database and are covered by review +
// the runbook; validation runs before Storage.start so these spawn cleanly.
describe('backfillEvmReceiptLogEffects exit codes', function() {
  this.timeout(30000);
  const script = path.resolve(__dirname, '../../../scripts/backfillEvmReceiptLogEffects.js');

  function runScript(args: string[]) {
    return spawnSync('node', [script, ...args], { env: process.env, encoding: 'utf8' });
  }

  it('exits 0 for --help', function() {
    const result = runScript(['--help']);
    expect(result.status).to.equal(0);
    expect(result.stdout).to.contain('EXIT CODES');
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
