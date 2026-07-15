import { expect } from 'chai';
import sinon from 'sinon';
import { WalletService } from '../src/lib/server';

describe('_normalizeTxHistory move aggregation', function() {
  const walletAddress = '0xa91cFe0DcAd33F36f3c9428D48eCCBD8A71951b4';
  const tokenAddress = '0x4Fabb145d64652a948d72533023f6E7A623C7C53';
  const txid = '0xbaf62c1c4de9761a421608634a4ad0f7dfbfa3546227c0f4044322bdda095f43';

  const moveEffect = (amount: number, callStack: string) => ({
    type: 'ERC20:transfer',
    to: walletAddress,
    from: walletAddress,
    amount: String(amount),
    contractAddress: tokenAddress,
    callStack
  });

  const moveRow = (id: string, amount: number, callStack?: string) => ({
    id,
    txid,
    blockTime: '2022-10-18T21:28:59.000Z',
    category: 'move',
    height: 10,
    satoshis: amount,
    address: walletAddress,
    chain: 'ETH',
    network: 'mainnet',
    ...(callStack ? { callStack, effects: [moveEffect(amount, callStack)] } : { effects: [] })
  });

  async function normalize(rows: any[], changeAddresses: string[] = []) {
    const fetchAddressesByWalletId = sinon.stub().callsFake((_walletId, _addresses, cb) => {
      cb(null, changeAddresses.map(address => ({ address, isChange: true })));
    });
    const context = { storage: { fetchAddressesByWalletId } };
    const txs = await new Promise<any[]>((resolve, reject) => {
      WalletService.prototype._normalizeTxHistory.call(context as any, 'wallet', rows, 0, 10, (err, result) => {
        if (err) {
          return reject(err);
        }
        resolve(result);
      });
    });
    return { txs, fetchAddressesByWalletId };
  }

  it('suppresses repeated known outputs while summing distinct identities', async function() {
    const { txs } = await normalize([
      moveRow('known-1', 5, 'log:7'),
      moveRow('known-1-conflicting-duplicate', 999, 'log:7'),
      moveRow('known-2', 7, 'log:8'),
      moveRow('known-3', 5, 'log:9')
    ]);

    expect(txs[0].amount).to.equal(17);
    expect(txs[0].outputs.map(output => output.amount)).to.deep.equal([5, 7, 5]);
    expect(txs[0].effects.map(effect => effect.callStack)).to.deep.equal(['log:7', 'log:8', 'log:9']);
  });

  it('retains identity-less outputs while using only the first fallback amount', async function() {
    const { txs } = await normalize([
      moveRow('raw-1', 5),
      moveRow('raw-2', 5)
    ]);

    expect(txs[0].amount).to.equal(5);
    expect(txs[0].outputs.map(output => output.amount)).to.deep.equal([5, 5]);
  });

  it('uses known identities regardless of mixed-row ordering', async function() {
    const identitylessFirst = await normalize([
      moveRow('raw', 11),
      moveRow('known-1', 5, 'log:7'),
      moveRow('known-2', 7, 'log:8')
    ]);
    const identitylessLast = await normalize([
      moveRow('known-1', 5, 'log:7'),
      moveRow('known-2', 7, 'log:8'),
      moveRow('raw', 11)
    ]);

    expect(identitylessFirst.txs[0].amount).to.equal(12);
    expect(identitylessLast.txs[0].amount).to.equal(12);
  });

  it('treats zero as a valid known amount and identity-less fallback', async function() {
    const knownZero = await normalize([
      moveRow('raw', 11),
      moveRow('known-zero', 0, 'log:7')
    ]);
    const identitylessZero = await normalize([
      moveRow('raw-zero-1', 0),
      moveRow('raw-zero-2', 0)
    ]);

    expect(knownZero.txs[0].amount).to.equal(0);
    expect(identitylessZero.txs[0].amount).to.equal(0);
  });

  it('uses raw row count to run and apply change-address cleanup', async function() {
    const { txs, fetchAddressesByWalletId } = await normalize([
      moveRow('known-1', 5, 'log:7'),
      moveRow('known-1-duplicate', 5, 'log:7')
    ], [walletAddress]);

    expect(fetchAddressesByWalletId.calledOnce).to.equal(true);
    expect(fetchAddressesByWalletId.firstCall.args[1]).to.deep.equal([walletAddress]);
    expect(txs[0].outputs).to.deep.equal([]);
    expect(txs[0].addressTo).to.equal(null);
  });
});
