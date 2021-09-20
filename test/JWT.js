import {assert} from 'chai';
import validator from 'validator';
const {isJWT} = validator;

import JWT from '../JWT.js';

const {
ACCESS_PRIVATE_TOKEN,
ACCESS_PUBLIC_TOKEN,
ACCESS_SECRET_KEY,
REFRESH_PRIVATE_TOKEN,
REFRESH_PUBLIC_TOKEN,
REFRESH_SECRET_KEY
} = process.env

const user = {
  name: 'yousif',
  age: 37,
  sex: 'male'
}

describe(`new JWT({encrypted: false})`, function() {
  let token;
  let payload;

  const jwt = JWT({
    encrypted: false,
    expiration: '2h',
    PRIVATE_TOKEN: ACCESS_PRIVATE_TOKEN,
    PUBLIC_TOKEN: ACCESS_PUBLIC_TOKEN,
    SECRET_KEY: ACCESS_SECRET_KEY,
    issuer: 'Ofeenee the developer',
    audience: 'test file',
    subject: '123kdd'
  });

  it(`create new instance of JWT()`, function() {
    try {
      assert.instanceOf(jwt, JWT);
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

  it(`jwt.sign() JWT token with payload`, async function() {
    try {
      token = await jwt.sign(user);
      assert.isTrue(isJWT(token));
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

  it(`jwt.verify() JWT token and payload`, async function() {
    try {
      const response = await jwt.verify(token);
      assert.hasAllKeys(response.payload, ['name', 'age', 'sex', 'iat', 'iss', 'aud', 'sub', 'exp']);

      assert.strictEqual(response.payload.name, user.name);
      assert.strictEqual(response.payload.age, user.age);
      assert.strictEqual(response.payload.sex, user.sex);
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

});

describe(`new JWT({encrypted: true})`, function() {
  let token;
  let payload;

  const jwt = JWT({
    encrypted: true,
    expiration: '2h',
    PRIVATE_TOKEN: REFRESH_PRIVATE_TOKEN,
    PUBLIC_TOKEN: REFRESH_PUBLIC_TOKEN,
    SECRET_KEY: REFRESH_SECRET_KEY,
    issuer: 'Ofeenee the developer',
    audience: 'test file',
    subject: '123kdd'
  });

  it(`create new instance of JWT()`, function() {
    try {
      assert.instanceOf(jwt, JWT);
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

  it(`jwt.sign() JWT token with payload`, async function() {
    try {
      token = await jwt.sign(user);
      assert.isDefined(token);
      assert.isString(token)
      // assert.isTrue(isJWT(token));
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

  it(`jwt.verify() JWT token and payload`, async function() {
    try {
      const response = await jwt.verify(token);
      assert.hasAllKeys(response.payload, ['name', 'age', 'sex', 'iat', 'iss', 'aud', 'sub', 'exp']);

      assert.strictEqual(response.payload.name, user.name);
      assert.strictEqual(response.payload.age, user.age);
      assert.strictEqual(response.payload.sex, user.sex);
    }
    catch (error) {
      assert.fail(error.message);
    }
  });
  beforeEach(function (done) {
    setTimeout(done, 250);
  });

});
