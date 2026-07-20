import { expect } from 'chai';
import sinon from 'sinon';
import { WalletService } from '../src/lib/server';

describe('_normalizeTxHistory move aggregation', function() {
  const walletAddress = '0xa91cFe0DcAd33F36f3c9428D48eCCBD8A71951b4';
  const tokenAddress = '0x4Fabb145d64652a948d72533023f6E7A623C7C53';
  const txid = '0xbaf62c1c4de9761a421608634a4ad0f7dfbfa3546227c0f4044322bdda095f43';

  const moveEffect = (amount: number | string, callStack: string) => ({
    type: 'ERC20:transfer',
    to: walletAddress,
    from: walletAddress,
    amount: String(amount),
    contractAddress: tokenAddress,
    callStack
  });

  const moveRow = (
    id: string,
    amount: number | string,
    callStack?: string,
    extra: Record<string, any> = {}
  ) => ({
    id,
    txid,
    blockTime: '2022-10-18T21:28:59.000Z',
    category: 'move',
    height: 10,
    satoshis: amount,
    address: walletAddress,
    chain: 'ETH',
    network: 'mainnet',
    ...(callStack ? { callStack, effects: [moveEffect(amount, callStack)] } : { effects: [] }),
    ...extra
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

  it('uses provider event ids for exact distinct-leg totals and duplicate suppression', async function() {
    const large = '9007199254740993';
    const { txs } = await normalize([
      moveRow('provider-1', large, undefined, {
        eventId: 'log:7',
        tokenHistorySource: 'provider',
        effects: [moveEffect('999', 'log:99')]
      }),
      moveRow('provider-1-duplicate', large, undefined, {
        eventId: 'log:7',
        tokenHistorySource: 'provider',
        effects: [moveEffect('999', 'log:99')],
        tokenHistoryIncomplete: true
      }),
      moveRow('provider-2', '1', undefined, {
        eventId: 'alchemy:opaque-2',
        tokenHistorySource: 'provider',
        effects: [moveEffect('999', 'log:99')]
      })
    ]);

    expect(txs[0].amount).to.equal('9007199254740994');
    expect(txs[0].outputs.map(output => output.amount)).to.deep.equal([large, '1']);
    expect(txs[0].effects).to.equal(undefined);
    expect(txs[0].tokenHistoryIncomplete).to.equal(true);
  });

  it('does not expose partial cloned effects as authoritative provider history', async function() {
    const { txs } = await normalize([
      moveRow('provider-1', 5, undefined, {
        eventId: 'log:7',
        tokenHistorySource: 'provider',
        effects: [moveEffect(5, '')],
        tokenHistoryIncomplete: true
      }),
      moveRow('provider-2', 7, undefined, {
        eventId: 'alchemy:opaque-2',
        tokenHistorySource: 'provider',
        effects: [moveEffect(5, '')]
      })
    ]);

    expect(txs[0].amount).to.equal(12);
    expect(txs[0].outputs.map(output => output.amount)).to.deep.equal([5, 7]);
    expect(txs[0].effects).to.equal(undefined);
    expect(txs[0].abiType).to.deep.equal({ name: 'transfer' });
    expect(txs[0].tokenHistoryIncomplete).to.equal(true);
  });

  it('keeps cloned effects inert for identity-less provider rows', async function() {
    const clonedEffects = [moveEffect('999', 'log:99')];
    const { txs } = await normalize([
      moveRow('provider-raw-1', '9007199254740993', undefined, {
        tokenHistorySource: 'provider',
        effects: clonedEffects
      }),
      moveRow('provider-raw-2', '7', undefined, {
        tokenHistorySource: 'provider',
        effects: clonedEffects
      })
    ]);

    // Without a trustworthy event identity both outputs remain visible, while the
    // conservative legacy fallback counts only the first provider amount.
    expect(txs[0].amount).to.equal('9007199254740993');
    expect(txs[0].outputs.map(output => output.amount)).to.deep.equal(['9007199254740993', '7']);
  });

  it('is order-independent when identified provider rows mix with identity-less rows', async function() {
    const identified = moveRow('known', '9007199254740993', undefined, {
      eventId: 'log:7',
      tokenHistorySource: 'provider'
    });
    const identityless = moveRow('raw', '11', undefined, { tokenHistorySource: 'provider' });

    const first = await normalize([{ ...identityless }, { ...identified }]);
    const last = await normalize([{ ...identified }, { ...identityless }]);

    expect(first.txs[0].amount).to.equal('9007199254740993');
    expect(last.txs[0].amount).to.equal('9007199254740993');
    expect(first.txs[0].outputs).to.have.length(2);
    expect(last.txs[0].outputs).to.have.length(2);
  });

  it('preserves exact decimal strings for send and receive totals', async function() {
    const send = await normalize([
      moveRow('send-1', '-9007199254740993', undefined, { category: 'send', eventId: 'log:7' }),
      moveRow('send-1-duplicate', '-9007199254740993', undefined, { category: 'send', eventId: 'log:7' }),
      moveRow('send-2', '-1', undefined, { category: 'send', eventId: 'log:8' })
    ]);
    const receive = await normalize([
      moveRow('receive-1', '9007199254740993', undefined, { category: 'receive', eventId: 'log:7' }),
      moveRow('receive-1-duplicate', '9007199254740993', undefined, { category: 'receive', eventId: 'log:7' }),
      moveRow('receive-2', '1', undefined, { category: 'receive', eventId: 'log:8' })
    ]);

    expect(send.txs[0].amount).to.equal('9007199254740994');
    expect(send.txs[0].outputs.map(output => output.amount)).to.deep.equal(['9007199254740993', '1']);
    expect(receive.txs[0].amount).to.equal('9007199254740994');
    expect(receive.txs[0].outputs.map(output => output.amount)).to.deep.equal(['9007199254740993', '1']);
  });
});
