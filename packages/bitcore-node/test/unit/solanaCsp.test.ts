import { expect } from 'chai';
import { Request, Response } from 'express';
import sinon from 'sinon';
import { Transform, Writable } from 'stream';
import { SOL } from '../../src/modules/solana/api/csp';

describe('Solana CSP', function() {
  const chain = 'SOL';
  const network = 'devnet';
  const address = 'DGqGrPJu5QgQ5pFHimGKX6wqPmUVnk5L1NAmpHdP6n8F';
  const ataAddress = 'ATAqGrPJu5QgQ5pFHimGKX6wqPmUVnk5L1NAmpHdP6n8F';
  const tokenAddress = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  const wallet = {
    chain,
    network,
    pubKey: '',
    name: 'solana-wallet',
    singleAddress: false,
    path: 'm/44\'/501\'/0\'/0/0'
  };

  let sandbox: sinon.SinonSandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

  function makeReqRes() {
    const chunks: string[] = [];
    const req = (new Writable({
      write(_data, _encoding, cb) {
        cb();
      }
    }) as unknown) as Request;

    const res = (new Transform({
      transform(data, _encoding, cb) {
        chunks.push(data.toString());
        cb(null, data);
      }
    }) as unknown) as Response;

    res.type = () => res;

    return { req, res, chunks };
  }

  it('should stream SPL token transactions for a wallet when tokenAddress is provided', async function() {
    const txStatus = {
      signature: 'tx1',
      confirmationStatus: 'confirmed',
      slot: 123,
      err: null
    };
    const tx = {
      txid: 'tx1',
      feePayerAddress: address,
      slot: 123,
      meta: { fee: 5000, err: null },
      version: '0',
      status: 'confirmed',
      lifetimeConstraint: { blockhash: 'hash123' },
      blockTime: 1710000000,
      instructions: {
        transferCheckedToken: [
          {
            source: ataAddress,
            destination: 'otherAtaAddress',
            amount: '42',
            mint: tokenAddress
          }
        ]
      }
    };
    const getConfirmedAta = sandbox.stub().resolves(ataAddress);
    const getSignaturesForAddress = sandbox.stub().returns({
      send: sandbox.stub().onFirstCall().resolves([txStatus]).onSecondCall().resolves([])
    });
    const getTransaction = sandbox.stub().resolves(tx);

    sandbox.stub(SOL, 'getRpc').resolves({
      rpc: { getConfirmedAta, getTransaction },
      connection: { getSignaturesForAddress }
    } as any);
    sandbox.stub(SOL, 'getWalletAddresses').resolves([{ address }] as any);

    const { req, res, chunks } = makeReqRes();

    const err = await new Promise(resolve => {
      res.on('error', resolve).on('finish', resolve);
      SOL.streamWalletTransactions({
        chain,
        network,
        wallet: wallet as any,
        req,
        res,
        args: { tokenAddress }
      }).catch(resolve);
    });

    expect(err).to.not.exist;
    expect(getConfirmedAta.calledOnceWith({ solAddress: address, mintAddress: tokenAddress })).to.equal(true);
    expect(getSignaturesForAddress.firstCall.args[0]).to.equal(ataAddress);

    const docs = chunks.map(chunk => JSON.parse(chunk));
    expect(docs).to.have.length(2);
    expect(docs[0]).to.include({
      txid: 'tx1',
      address: 'otherAtaAddress',
      category: 'send',
      satoshis: -42
    });
    expect(docs[1]).to.include({
      txid: 'tx1',
      category: 'fee',
      satoshis: -5000
    });
  });

  it('should return empty wallet token history when the ATA is not initialized', async function() {
    const getConfirmedAta = sandbox.stub().rejects(new Error('ATA not initialized on mint for provided account. Initialize ATA first.'));
    const getSignaturesForAddress = sandbox.stub();

    sandbox.stub(SOL, 'getRpc').resolves({
      rpc: { getConfirmedAta },
      connection: { getSignaturesForAddress }
    } as any);
    sandbox.stub(SOL, 'getWalletAddresses').resolves([{ address }] as any);

    const { req, res, chunks } = makeReqRes();

    const err = await new Promise<any>(resolve => {
      res.on('error', resolve).on('finish', resolve);
      SOL.streamWalletTransactions({
        chain,
        network,
        wallet: wallet as any,
        req,
        res,
        args: { tokenAddress }
      }).catch(resolve);
    });

    expect(err).to.not.exist;
    expect(getSignaturesForAddress.called).to.equal(false);
    expect(chunks).to.deep.equal([]);
  });

  it('should still reject wallet token streaming on unexpected ATA lookup errors', async function() {
    const getConfirmedAta = sandbox.stub().rejects(new Error('boom'));
    const getSignaturesForAddress = sandbox.stub();

    sandbox.stub(SOL, 'getRpc').resolves({
      rpc: { getConfirmedAta },
      connection: { getSignaturesForAddress }
    } as any);
    sandbox.stub(SOL, 'getWalletAddresses').resolves([{ address }] as any);

    const { req, res } = makeReqRes();

    const err = await new Promise<any>(resolve => {
      res.on('error', resolve).on('finish', resolve);
      SOL.streamWalletTransactions({
        chain,
        network,
        wallet: wallet as any,
        req,
        res,
        args: { tokenAddress }
      }).catch(resolve);
    });

    expect(err).to.exist;
    expect(err.message).to.equal('Error getting ATA address');
    expect(getSignaturesForAddress.called).to.equal(false);
  });
});
