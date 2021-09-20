import dotenv from 'dotenv';
dotenv.config();

import crypto from 'crypto';

import validator from 'validator';
const { isJWT } = validator;

import { SignJWT } from 'jose/jwt/sign';
import { jwtVerify } from 'jose/jwt/verify';
import { EncryptJWT } from 'jose/jwt/encrypt';
import { jwtDecrypt } from 'jose/jwt/decrypt';

import { generateKeyPair } from 'jose/util/generate_key_pair';
import { generateSecret } from 'jose/util/generate_secret';

function JWT({
  issuer = null,
  audience = null,
  expiration = null,
  encrypted = false,
  subject = null,
  PRIVATE_TOKEN = process.env.JWT_PRIVATE_TOKEN,
  PUBLIC_TOKEN = process.env.JWT_PUBLIC_TOKEN,
  SECRET_KEY = process.env.JWT_SECRET_KEY
} = {}) {
  try {
    if (new.target === undefined)
      return new JWT({
        issuer,
        audience,
        expiration,
        encrypted,
        subject,
        PRIVATE_TOKEN,
        PUBLIC_TOKEN,
        SECRET_KEY
      });

    const secret = Object.create({}, {
        keys: {
          value: setTokens({
            privateKey: PRIVATE_TOKEN,
            publicKey: PUBLIC_TOKEN,
            secretKey: SECRET_KEY
          }),
          enumerable: true
        },
      });


    Object.defineProperties(this, {

      validateJWT: {
        value: validateJWT,
        enumerable: true
      },
      signJWT: {
        value: async function signToken(payload) {
          try {

            const jwt = new SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256', enc: 'A256GCM'})
            .setIssuedAt();

            if (issuer) jwt.setIssuer(issuer);
            if (audience) jwt.setAudience(audience);
            if (subject) jwt.setSubject(subject);
            if (expiration) jwt.setExpirationTime(expiration);

            return await jwt.sign(secret.keys.privateKey);
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      verifyJWT: {
        value: async function verifyToken(token) {
          try {
            let claims = {};
            if (issuer) claims.issuer = issuer;
            if (audience) claims.audience = audience;
            if (Object.keys(claims)) claims = undefined;

            const {
              payload,
              protectedHeader
            } = await jwtVerify(token, secret.keys.publicKey, claims);

            return {protectedHeader, payload};
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      encryptJWT: {
        value: async function encryptToken(payload) {
          try {
            const jwt = new EncryptJWT(payload)
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM'})
            .setIssuedAt();

            if (issuer) jwt.setIssuer(issuer);
            if (audience) jwt.setAudience(audience);
            if (subject) jwt.setSubject(subject);
            if (expiration) jwt.setExpirationTime(expiration);

            return await jwt.encrypt(secret.keys.secretKey);
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      decryptJWT: {
        value: async function decryptToken(token) {
          try {

            let claims = {};
            if (issuer) claims.issuer = issuer;
            if (audience) claims.audience = audience;
            if (Object.keys(claims)) claims = undefined;

            const {
              payload,
              protectedHeader
            } = await jwtDecrypt(token, secret.keys.secretKey, claims);

            return {protectedHeader, payload};
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
    });

    return Object.create(this, {
      sign: {
        value: async (payload) => {
          try {
            if (encrypted) return await this.encryptJWT(payload);
            else return await this.signJWT(payload);
          }
          catch (error) {
            throw error;
          }
        },
        enumerable: true
      },
      verify: {
        value: async (token) => {
          try {
            if (encrypted) return await this.decryptJWT(token);
            else return await this.verifyJWT(token);

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
    console.log(error);
  }
}

async function generateTokens() {
  try {
    const {
      privateKey,
      publicKey
    } = await generateKeyPair('HS256');
    const secretKey = await generateSecret('ES256')

    return {
      privateKey,
      publicKey,
      secretKey
    };
  }
  catch (error) {
    throw error;
  }
}




// try {
//   const jwt = new JWT({
//     PRIVATE_TOKEN: process.env.ACCESS_PRIVATE_TOKEN,
//     PUBLIC_TOKEN: process.env.ACCESS_PUBLIC_TOKEN,
//     SECRET_KEY: process.env.ACCESS_SECRET_KEY,
//     encrypted: false,
//     expiration: '1h',
//     subject: crypto.randomUUID()
//   });
//   console.log(jwt);

//   const token = await jwt.sign({name: 'yousif', age: '37'});
//   console.log(token);
//   const payload = await jwt.verify(token);
//   console.log(payload);
// } catch (error) {
//   console.log(error.message);
// }