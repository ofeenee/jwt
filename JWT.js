import dotenv from 'dotenv';
dotenv.config();

import crypto from 'crypto';
const { webcrypto, KeyObject } = crypto;
const { subtle } = webcrypto;

// const APL = crypto.createPrivateKey(process.env.ACCESS_TOKEN_PRIVATE);
// const APK = crypto.createPublicKey(process.env.ACCESS_TOKEN_PUBLIC);
// const RPL = crypto.createPrivateKey(process.env.REFRESH_TOKEN_PRIVATE);
// const RPK = crypto.createPublicKey(process.env.REFRESH_TOKEN_PUBLIC);

import validator from 'validator';
const { isJWT } = validator;

import { SignJWT } from 'jose/jwt/sign';
import { jwtVerify } from 'jose/jwt/verify';
import { EncryptJWT } from 'jose/jwt/encrypt';
import { jwtDecrypt } from 'jose/jwt/decrypt';
import { generateSecret } from 'jose/util/generate_secret';
import { generateKeyPair } from 'jose/util/generate_key_pair';
import { toASCII } from 'punycode';


function JWT({
  accessIssuer = 'admin.example.com/access',
  refreshIssuer = 'admin.example.com/refresh',
  audience = 'audience.example.com',
  exp = '1h'} = {}) {
  try {
    if (new.target === undefined) return new JWT();

    // load environment variables
    const {
      ACCESS_PRIVATE_TOKEN,
      ACCESS_PUBLIC_TOKEN,
      ACCESS_SECRET_KEY,
      REFRESH_PRIVATE_TOKEN,
      REFRESH_PUBLIC_TOKEN,
      REFRESH_SECRET_KEY
    } = process.env;

    const secret = Object.create({}, {
      access: {
        value: setTokens({
          privateKey: ACCESS_PRIVATE_TOKEN,
          publicKey: ACCESS_PUBLIC_TOKEN,
          secretKey: ACCESS_SECRET_KEY
        }),
        enumerable: true
      },
      refresh: {
        value: setTokens({
          privateKey: REFRESH_PRIVATE_TOKEN,
          publicKey: REFRESH_PUBLIC_TOKEN,
          secretKey: REFRESH_SECRET_KEY
        }),
        enumerable: true
      }
    });



    Object.defineProperties(this, {

      validateJWT: {
        value: validateJWT,
        enumerable: true
      },
      signAccessJWT: {
        value: async function generateAccessToken(payload) {
          try {

            const jwt = await new SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256', enc: 'A256GCM'})
            .setIssuedAt()
            .setIssuer(accessIssuer)
            .setAudience(audience)
            .setExpirationTime(exp)
              .sign(secret.access.privateKey);

            return jwt;
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      signRefreshJWT: {
        value: async function generateRefreshToken(payload) {
          try {
            const jwt = await new SignJWT(payload)
              .setProtectedHeader({ alg: 'ES256', enc: 'A256GCM' })
              .setIssuedAt()
              .setIssuer(refreshIssuer)
              .setAudience(audience)
              .setExpirationTime(exp)
              .sign(secret.refresh.privateKey);

            return jwt;
          }
          catch (error) {
            error;
          }
        },
        enumerable: true
      },
      verifyAccessJWT: {
        value: async function verifyAccessToken(accessToken) {
          try {
            const { payload, protectedHeader } = await jwtVerify(accessToken, secret.access.publicKey, {
              issuer: accessIssuer,
              audience: audience
            });

            return {protectedHeader, payload};
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      verifyRefreshJWT: {
        value: async function verifyRefreshToken(refreshToken) {
          try {
            const { payload, protectedHeader } = await jwtVerify(refreshToken, secret.refresh.publicKey, {
              issuer: refreshIssuer,
              audience: audience
            });

            return { protectedHeader, payload };
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      encryptAccessJWT: {
        value: async function encryptAccessToken(payload) {
          try {
            const jwt = await new EncryptJWT(payload)
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM'})
            .setIssuedAt()
            .setIssuer(accessIssuer + '/encrypted')
            .setAudience(audience)
            .setExpirationTime(exp)
            .encrypt(secret.access.secretKey);

            return jwt;
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      encryptRefreshJWT: {
        value: async function encryptAccessToken(payload) {
          try {
            const jwt = await new EncryptJWT(payload)
              .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
              .setIssuedAt()
              .setIssuer(refreshIssuer + '/encrypted')
              .setAudience(audience)
              .setExpirationTime(exp)
              .encrypt(secret.refresh.secretKey);

            return jwt;
          }
          catch (error) {
            error;
          }
        },
        enumerable: true
      },
      decryptAccessJWT: {
        value: async function decryptAccessToken(accessToken) {
          try {
            const { payload, protectedHeader } = await jwtDecrypt(accessToken, secret.access.secretKey, {
              issuer: accessIssuer + '/encrypted',
              audience: audience
            });

            return {protectedHeader, payload};
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      decryptRefreshJWT: {
        value: async function decryptRefreshToken(refreshToken) {
          try {
            const { payload, protectedHeader } = await jwtDecrypt(refreshToken, secret.refresh.secretKey, {
              issuer: refreshIssuer + '/encrypted',
              audience: audience
            });

            return { protectedHeader, payload };
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
    });

    return Object.create(this, {
      set: {
        value: async (string) => {
          try {
            // if string value is invalid (not strong password)
            if (!validateJWT(string)) throw new Error('jwt value is invalid.');

          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      get: {
        value: () => {
          try {
            if (this.jwt) return this.jwt;
            else return null;
          } catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
    });
  }
  catch (error) {
    throw error;
  }
}

export default JWT;

// testing and debugging
try {
  const test = new JWT();
  // await test.initSecretKeys();
  // const theKeys = await test.setSecretKeys({
  //   accessPrivateKey: process.env.ACCESS_TOKEN_PRIVATE,
  //   accessPublicKey: process.env.ACCESS_TOKEN_PUBLIC,
  //   refreshPrivateKey: process.env.REFRESH_TOKEN_PRIVATE,
  //   refreshPublicKey: process.env.REFRESH_TOKEN_PUBLIC,
  //   aSecretKey: process.env.ACCESS_SECRET_KEY,
  //   rSecretKey: process.env.REFRESH_SECRET_KEY
  // });

  const accessToken = await test.signAccessJWT({name: 'yousif', age: 37});
  console.log(accessToken);

  const verifyAccessToken = await test.verifyAccessJWT(accessToken);
  console.log(verifyAccessToken);

  const refreshToken = await test.signRefreshJWT({name: 'yousif', age: 37});
  console.log(refreshToken);

  const verifyRefreshToken = await test.verifyRefreshJWT(refreshToken);
  console.log(verifyRefreshToken);

  const encryptAccessToken = await test.encryptAccessJWT({name: 'yousif', age: 37});
  console.log(encryptAccessToken);

  const decryptAccessToken = await test.decryptAccessJWT(encryptAccessToken);
  console.log(decryptAccessToken);

  const encryptRefreshToken = await test.encryptRefreshJWT({name: 'yousif', age: 37});
  console.log(encryptRefreshToken);

  const decryptRefreshToken = await test.decryptRefreshJWT(encryptRefreshToken);
  console.log(decryptRefreshToken);


} catch (error) {
  console.log(error.message);
}

// HELPER FUNCTIONS
function validateJWT(string) {
  try {
    if (typeof string !== 'string' || !string) throw new Error('value is invalid.');
    return isJWT(string);
  }
  catch (error) {
    throw error;
  }
}

function setTokens({ privateKey, publicKey, secretKey } = {}) {
  try {
    // const newAsymmetricPair = await generateKeyPair('ES256');
    // const newSymmetricKey = await generateSecret('HS256')
    const hash = crypto.createHash('sha256');


    // const key = crypto.createSecretKey(hash.digest(secretKey));
    // console.log(hash.digest(secretKey));
    // const hmac = crypto.createHmac('sha256', secretKey);
    // const sign = crypto.createSign(hmac);
    // console.log(key.export().toString());

    const secrets =  Object.create({}, {
      privateKey:{
        value: crypto.createPrivateKey(privateKey),
        enumerable: true,
        configurable: true
      },
      publicKey: {
        value: crypto.createPublicKey(publicKey),
        enumerable: true,
        configurable: true
      },
      secretKey: {
        value: crypto.createSecretKey(hash.digest(secretKey)),
        enumerable: true,
        configurable: true
      }
    });

    return secrets;
  }
  catch (error) {
    console.log(error.message);
  }
}

function genTokens() {
  try {

  }
  catch (error) {

  }
}

function expTokens() {
  try {

  }
  catch (error) {

  }
}

try {


  // const ACCESS = await setTokens({
  //   privateKey: ACCESS_PRIVATE_TOKEN,
  //   publicKey: ACCESS_PUBLIC_TOKEN,
  //   secretKey: ACCESS_SECRET_KEY
  // });

  // const REFRESH = await setTokens({
  //   privateKey: REFRESH_PRIVATE_TOKEN,
  //   publicKey: REFRESH_PUBLIC_TOKEN,
  //   secretKey: REFRESH_SECRET_KEY
  // });

  // console.log(ACCESS.secretKey.export().toString());
}
catch (error) {
  console.log(error.message);
}