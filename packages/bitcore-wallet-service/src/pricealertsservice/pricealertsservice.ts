#!/usr/bin/env node
import config from '../config';
import { CoinGeckoService } from '../externalservices/coingecko';
import logger from '../lib/logger';
import { priceAlertOptions } from '../lib/pricealerts/config';
import { PriceAlertDelivery } from '../lib/pricealerts/delivery';
import { PriceAlertWorker } from '../lib/pricealerts/worker';
import { Storage } from '../lib/storage';

const options = priceAlertOptions(config.priceAlertsOpts);
const storage = new Storage();
const worker = new PriceAlertWorker(storage.priceAlerts, new CoinGeckoService(storage),
  new PriceAlertDelivery(options, config.pushNotificationsOpts), options);

if (!options.enabled || !options.workerEnabled) {
  // The timer keeps this disabled daemon alive, matching start.sh's pid file.
  worker.start();
} else {
  // Do not inherit bcmonitor's secondaryPreferred option.
  storage.connect({ mongoDb: { ...config.storageOpts.mongoDb } }, err => {
    if (err) throw err;
    const connectedWorker = new PriceAlertWorker(storage.priceAlerts, new CoinGeckoService(storage),
      new PriceAlertDelivery(options, config.pushNotificationsOpts), options);
    connectedWorker.start();
    logger.info('Price alert service started');
  });
}
