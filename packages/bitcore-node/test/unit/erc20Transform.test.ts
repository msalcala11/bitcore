import { expect } from 'chai';
import { Web3 } from '@bitpay-labs/crypto-wallet-core';
import { splitTxByTokenEffects } from '../../src/providers/chain-state/evm/api/erc20Transform';

describe('splitTxByTokenEffects', function() {
  const walletAddress = Web3.utils.toChecksumAddress('0xa91cfe0dcad33f36f3c9428d48eccbd8a71951b4');
  const eventSender = Web3.utils.toChecksumAddress('0x8489935991b0eac9ce9e9330d35b9734ecdf2cad');
  const rootSender = Web3.utils.toChecksumAddress('0x963737c550e70ffe4d59464542a28604edb2ef9a');
  const tokenAddress = Web3.utils.toChecksumAddress('0x4fabb145d64652a948d72533023f6e7a623c7c53');

  const receiveEffect = () => ({
    to: walletAddress,
    from: eventSender,
    amount: '50',
    type: 'ERC20:transfer' as const,
    contractAddress: tokenAddress,
    callStack: 'log:7'
  });

  const providerReceiveRow = (extra: any = {}) => ({
    txid: '0xrelayed',
    chain: 'ETH',
    network: 'mainnet',
    from: eventSender,
    to: walletAddress,
    value: '50',
    effects: [receiveEffect()],
    ...extra
  });

  it('uses the receipt sender when the surviving provider row is a receive leg', function() {
    const [row] = splitTxByTokenEffects(
      providerReceiveRow({ receipt: { status: true, from: rootSender.toLowerCase() } }) as any,
      [receiveEffect()]
    );

    expect(row.from).to.equal(eventSender);
    expect(row.initialFrom).to.equal(rootSender);
  });

  it('safely falls back to tx.from and compares addresses case-insensitively', function() {
    const effect = { ...receiveEffect(), from: eventSender.toLowerCase() };
    const [row] = splitTxByTokenEffects(
      providerReceiveRow({ receipt: { status: true, from: 'not-an-address' } }) as any,
      [effect]
    );

    expect(row.initialFrom).to.equal(undefined);
  });

  it('does not overwrite an existing authoritative initialFrom', function() {
    const [row] = splitTxByTokenEffects(
      providerReceiveRow({ initialFrom: walletAddress, receipt: { status: true, from: rootSender } }) as any,
      [receiveEffect()]
    );

    expect(row.initialFrom).to.equal(walletAddress);
  });
});
