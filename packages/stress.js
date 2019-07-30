const { Storage } = require('./packages/bitcore-node/build/src/services/storage');
const { P2pWorker } = require('./packages/bitcore-node/build/src/services/p2p');


const p2p = new P2pWorker({chain, network, chainConfig: {trustedPeers: [{host: "127.0.0.1", port: 30002}]}});
p2p.resync(1307540, 1307540 + 3);