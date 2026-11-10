import express from 'express';
import config from '../../config';
import { CoinGeckoService } from '../../externalservices/coingecko';
import { ClientError } from '../errors/clienterror';
import { priceAlertOptions } from '../pricealerts/config';
import { PriceAlertService } from '../pricealerts/service';
import { WalletService } from '../server';
import { error } from './helpers';
import { authAppRequest } from './middleware/authAppRequest';
import { createPriceAlertLimiter } from './setup';

export function registerPriceAlertRoutes(router: express.Router, opts) {
  const options = priceAlertOptions(config.priceAlertsOpts);
  const enabled: express.RequestHandler = (req, res, next) => {
    if (!options.enabled) return error.returnError(
      new ClientError('PRICE_ALERTS_DISABLED', 'Price alerts are disabled'), res, req);
    next();
  };
  // ONE instance shared by every mutation in this API process.
  const limiter = createPriceAlertLimiter(opts);
  const auth = authAppRequest();
  const handler = (method: 'register' | 'list' | 'save' | 'disable'): express.RequestHandler => async (req, res) => {
    try {
      const storage = WalletService.getStorage();
      const service = new PriceAlertService(storage.priceAlerts, new CoinGeckoService(storage), options);
      const owner = res.locals.priceAlertOwner;
      const result = method === 'register' ? await service.register(owner, req.body) :
        method === 'list' ? await service.list(owner) :
          method === 'save' ? await service.save(owner, req.query, req.body) : await service.disable(owner, req.query);
      res.json(result);
    } catch (err) {
      error.returnError(err, res, req);
    }
  };
  router.put('/v1/pricealerts/registration/', enabled, limiter, auth, handler('register'));
  router.get('/v1/pricealerts/', enabled, auth, handler('list'));
  router.put('/v1/pricealerts/', enabled, limiter, auth, handler('save'));
  router.delete('/v1/pricealerts/', enabled, limiter, auth, handler('disable'));
}
