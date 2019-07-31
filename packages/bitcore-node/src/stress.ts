import { Storage } from './services/storage';
import { P2pWorker } from './services/p2p';
import { Api } from './services/api';

const chain = 'BCH';
const network = 'testnet';

const p2p = new P2pWorker({
  chain,
  network,
  chainConfig: {
    trustedPeers: [
      {
        host: '127.0.0.1',
        port: 30002
      }
    ]
  }
});

async function syncBigBlock() {
  await Storage.start();
  await Api.start();
  await p2p.connect();
  await p2p.resync(1307543, 1307544);
}

syncBigBlock();
