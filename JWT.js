import dotenv from 'dotenv';
dotenv.config();

import crypto from 'crypto';

import validator from 'validator';
const { isJWT } = validator;

import { SignJWT } from 'jose/jwt/sign';
import { jwtVerify } from 'jose/jwt/verify';
import { EncryptJWT } from 'jose/jwt/encrypt';
import { jwtDecrypt } from 'jose/jwt/decrypt';


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
    const hash = crypto.createHash('sha256');

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