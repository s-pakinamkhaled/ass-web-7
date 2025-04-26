// jwt-utils.js
const crypto = require('crypto');

function base64url(input) {
  return Buffer.from(JSON.stringify(input)).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function signJWT(payload, secret, expiresInSeconds = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const fullPayload = { ...payload, exp };

  const encodedHeader = base64url(header);
  const encodedPayload = base64url(fullPayload);
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJWT(token, secret) {
  const [encodedHeader, encodedPayload, receivedSignature] = token.split('.');

  const validSignature = crypto
    .createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  if (validSignature !== receivedSignature) {
    throw new Error('Invalid signature');
  }

  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
  const now = Math.floor(Date.now() / 1000);

  if (payload.exp < now) {
    throw new Error('Token expired');
  }

  return payload;
}

module.exports = { signJWT, verifyJWT };
