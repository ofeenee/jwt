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



describe(`new JWT({encrypted: false})`, function() {
  let token;
  let payload;
  const issuer = 'Ofeenee';
  const audience = 'Debuggers';
  const subject = '123';
  const expiration = '2h';

  const user = {
    name: 'yousif',
    age: 37,
    sex: 'male'
  }

  const jwt = JWT({
    PRIVATE_TOKEN: ACCESS_PRIVATE_TOKEN,
    PUBLIC_TOKEN: ACCESS_PUBLIC_TOKEN,
    SECRET_KEY: ACCESS_SECRET_KEY,
    encrypted: false,
    expiration,
    issuer,
    audience,
    subject
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
      assert.strictEqual(response.payload.iss, issuer);
      assert.strictEqual(response.payload.aud, audience);
      assert.strictEqual(response.payload.exp, response.payload.iat + (60 * (60 * 2)));
      assert.strictEqual(response.payload.sub, subject);
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

  it(`jwt.sign() override sub, aud, iss, exp JWT token with payload`, async function () {
    try {
      user.iss = 'Not Ofeenee';
      user.exp = '10m';
      user.aud = 'Not Debuggers';
      user.sub = 'kdd';

      token = await jwt.sign(user);
      assert.isTrue(isJWT(token));
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

  it(`jwt.verify() JWT token and payload`, async function () {
    try {
      const response = await jwt.verify(token);
      // console.log(response.payload);
      assert.hasAllKeys(response.payload, ['name', 'age', 'sex', 'iat', 'iss', 'aud', 'sub', 'exp']);

      assert.strictEqual(response.payload.name, user.name);
      assert.strictEqual(response.payload.age, user.age);
      assert.strictEqual(response.payload.sex, user.sex);
      assert.strictEqual(response.payload.iss, 'Not Ofeenee');
      assert.strictEqual(response.payload.aud, 'Not Debuggers');
      assert.strictEqual(response.payload.exp, response.payload.iat + (60 * 10));
      assert.strictEqual(response.payload.sub, 'kdd');
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

});

describe(`new JWT({encrypted: true})`, function() {
  let token;
  let payload;
  const expiration = '2h';
  const issuer = 'Ofeenee';
  const audience = 'Debuggers';
  const subject = '123';

  const user = {
    name: 'yousif',
    age: 37,
    sex: 'male'
  }

  const jwt = JWT({
    PRIVATE_TOKEN: REFRESH_PRIVATE_TOKEN,
    PUBLIC_TOKEN: REFRESH_PUBLIC_TOKEN,
    SECRET_KEY: REFRESH_SECRET_KEY,
    encrypted: true,
    expiration,
    issuer,
    audience,
    subject
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
      assert.strictEqual(response.payload.iss, issuer);
      assert.strictEqual(response.payload.aud, audience);
      assert.strictEqual(response.payload.exp, response.payload.iat + (60 * (60 * 2)));
      assert.strictEqual(response.payload.sub, subject);

    }
    catch (error) {
      assert.fail(error.message);
    }
  });

  it(`jwt.sign() override sub, aud, iss, exp JWT token with payload`, async function () {
    try {
      user.iss = 'Not Ofeenee';
      user.exp = '10m';
      user.aud = 'Not Debuggers';
      user.sub = 'kdd';

      token = await jwt.sign(user);
      assert.isDefined(token);
      assert.isString(token);
      // assert.isTrue(isJWT(token));
    }
    catch (error) {
      assert.fail(error.message);
    }
  });

  it(`jwt.verify() JWT token and payload`, async function () {
    try {
      const response = await jwt.verify(token);
      // console.log(response.payload);
      assert.hasAllKeys(response.payload, ['name', 'age', 'sex', 'iat', 'iss', 'aud', 'sub', 'exp']);

      assert.strictEqual(response.payload.name, user.name);
      assert.strictEqual(response.payload.age, user.age);
      assert.strictEqual(response.payload.sex, user.sex);
      assert.strictEqual(response.payload.iss, 'Not Ofeenee');
      assert.strictEqual(response.payload.aud, 'Not Debuggers');
      assert.strictEqual(response.payload.exp, response.payload.iat + (60 * 10));
      assert.strictEqual(response.payload.sub, 'kdd');
    }
    catch (error) {
      assert.fail(error.message);
    }
  });
  beforeEach(function (done) {
    setTimeout(done, 250);
  });

});
