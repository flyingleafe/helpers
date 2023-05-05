import * as jose from "jose";
import {jwt} from './types';

export const ed25519PrivateToPublic = async (privateKey: jose.KeyLike) => {
  const jwk = await jose.exportJWK(privateKey);
  delete jwk.d;
  return jose.importJWK(jwk, "EdDSA");
};

export const generate = async ({
  payload,
  secret,
  expiresIn = null,
}: jwt.generate) => {
  const publicKey = await ed25519PrivateToPublic(secret);
  const pubkeyJWK = await jose.exportJWK(publicKey);
  const header = {
    alg: "EdDSA",
    jwk: pubkeyJWK,
  };

  let token = new jose.SignJWT(payload).setProtectedHeader(header);

  if (expiresIn) {
    token = token.setExpirationTime(expiresIn);
  }

  return token.sign(secret);
};

export const verify = async ({token, secret}: jwt.verify) => {
  try {
    token = token.replace('Bearer ', '');
    const data = jose.jwtVerify(token, secret);

    if (!Object.keys(data).length) return false;

    return data;
  } catch (error) {
    return false;
  }
};
