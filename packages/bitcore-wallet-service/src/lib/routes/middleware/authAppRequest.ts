import { createHash } from 'crypto';
import express from 'express';
import * as secp256k1 from 'secp256k1';
import { ClientError } from '../../errors/clienterror';
import { error } from '../helpers';

export function verifyAppIdentity(message: string, publicKey: string, signature: string): string {
  try {
    if (!/^(?:[0-9a-f]{66}|[0-9a-f]{130})$/i.test(publicKey || '') ||
        !/^[0-9a-f]{16,144}$/i.test(signature || '') || signature.length % 2) throw new Error();
    const key = secp256k1.publicKeyConvert(Buffer.from(publicKey, 'hex'), true);
    const imported = secp256k1.signatureImport(Buffer.from(signature, 'hex'));
    const normalized = secp256k1.signatureNormalize(imported);
    const digest = createHash('sha256').update(message, 'utf8').digest();
    if (!secp256k1.ecdsaVerify(normalized, digest, key)) throw new Error();
    return createHash('sha256').update(key).digest('hex');
  } catch {
    throw new ClientError('NOT_AUTHORIZED', 'Invalid app signing credentials');
  }
}

export function authAppRequest(): express.RequestHandler {
  return (req, res, next) => {
    try {
      if (req.body !== undefined && (req.body === null || typeof req.body !== 'object' || Array.isArray(req.body))) {
        throw new ClientError('BADREQUEST', 'Request body must be a JSON object');
      }
      if (req.method === 'PUT' && !req.is('application/json')) {
        throw new ClientError('BADREQUEST', 'Content-Type must be application/json');
      }
      // Installed directly on the API router: req.url excludes only the BWS mount.
      // Do not parse/rebuild the query or install beneath a /pricealerts router.
      const message = req.method.toLowerCase() + '|' + req.url + '|' + JSON.stringify(req.body || {});
      res.locals.priceAlertOwner = verifyAppIdentity(message, req.header('x-identity'), req.header('x-signature'));
      next();
    } catch (err) {
      error.returnError(err, res, req);
    }
  };
}
