const request = require('supertest');

const app = require('../src/app');
const User = require('../src/models/user');
const {
  testUser,
  setupTestUserInDatabase,
} = require('./fixtures/db');

beforeEach(setupTestUserInDatabase);

test('a POST request to /user will respond with a 201 status code (created) after a resource is successfully created.', async () => {
  const response = await request(app)
    .post('/user')
    .send({
      email: 'tester1@email.com',
      password: 'p@ssWURD',
    });

  const expectedStatusCode = 201;
  const actualStatusCode = response.status;

  expect(actualStatusCode).toEqual(expectedStatusCode);
});

test('a POST request to /user will respond with the expected user data', async () => {
  const sampleUser = {
    email: 'tester2@email.com',
    password: 'p@ssWURD',
  };

  const response = await request(app)
    .post('/user')
    .send(sampleUser);

  const expectedUserEmail = sampleUser.email;
  const { user } = response.body;
  const actualUserId = user._id;
  const actualUserEmail = user.email;

  expect(actualUserId).toBeTruthy();
  expect(actualUserEmail).toEqual(expectedUserEmail);
});

test('a POST request to /user will insert the expected data into the database', async () => {
  const sampleUser = {
    email: 'tester3@email.com',
    password: 'p@ssWURD',
  };

  const response = await request(app)
    .post('/user')
    .send(sampleUser);

  const expectedUserEmail = sampleUser.email;
  const expectedUserAdminStatus = false; // this is the default
  const expectedUserTokenCount = 0; // this is the default
  const insertedUser = await User.findById(response.body.user._id);

  const actualUserEmail = insertedUser.email;
  const actualUserPassword = insertedUser.password;
  const actualUserAdminStatus = insertedUser.isAdmin;
  const actualUserTokenCount = insertedUser.tokens.length;

  expect(actualUserEmail).toEqual(expectedUserEmail);
  expect(actualUserPassword).toBeTruthy(); // Note: pass is hashed so we just expect a value
  expect(actualUserAdminStatus).toEqual(expectedUserAdminStatus);
  expect(actualUserTokenCount).toEqual(expectedUserTokenCount);
});

test('a POST request to /user/login will respond with a 200 status (Ok) after a successful login', async () => {
  const response = await request(app)
    .post('/user/login')
    .send({
      email: testUser.email, // note, testUser is created in test database before each test run
      password: testUser.password,
    });

  const expectedStatusCode = 200;
  const actualStatusCode = response.status;
  expect(actualStatusCode).toEqual(expectedStatusCode);
});

test('POST /user/login request will respond with the expected data', async () => {
  const response = await request(app)
    .post('/user/login')
    .send({
      email: testUser.email,
      password: testUser.password,
    });

  const expectedUserEmail = testUser.email;
  const { user } = response.body;
  const actualUserId = user._id;
  const actualUserEmail = user.email;
  const actualToken = response.body;

  expect(actualUserEmail).toEqual(expectedUserEmail);
  expect(actualUserId).toBeTruthy(); // generated by MongodDB, we just expect there is a value
  expect(actualToken).toBeTruthy(); // generated by api middleware, we just expect there is a value
});

test('a POST /user/login request will insert the generated token into the database (i.e. user.tokens)', async () => {
  const response = await request(app)
    .post('/user/login')
    .send({
      email: testUser.email,
      password: testUser.password,
    });

  const insertedUser = await User.findById(response.body.user._id);
  const actualTokens = insertedUser.tokens;

  expect(actualTokens.length).toBeGreaterThan(0);
});

test('a POST request to /user/login will respond with a 401 status (unauthorized) when invalid credentials are provided', async () => {
  // provide valid user but invalid password
  await request(app)
    .post('/user/login')
    .send({
      email: testUser.email,
      password: 'NotUserOnesEmail',
    })
    .expect(401);

  // Provide invalid user but valid password
  await request(app)
    .post('/user/login')
    .send({
      email: 'NotUserOnesEmail@email.com',
      password: testUser.password,
    })
    .expect(401);
});

test('a GET request to /user/me should respond with a 200 (ok) status code', async () => {
  const response = await request(app)
    .get('/user/me')
    .set('Authorization', `Bearer ${testUser.tokens[0].token}`)
    .send();

  const expectedStatusCode = 200;
  const actualStatusCode = response.status;

  expect(actualStatusCode).toEqual(expectedStatusCode);
});

test('a GET request to /user/me should respond with the expected user data', async () => {
  const response = await request(app)
    .get('/user/me')
    .set('Authorization', `Bearer ${testUser.tokens[0].token}`)
    .send();

  const expectedUserEmail = testUser.email;
  const { user } = response.body;
  const actualUserId = user._id;
  const actualUserEmail = user.email;

  expect(actualUserEmail).toEqual(expectedUserEmail);
  expect(actualUserId).toBeTruthy(); // generated by MongodDB, we just expect there is a value
});

test('an PACTH requet to /user/me', async () => {

});

test('a DELETE request to /user/me should resturn a 200 (ok) status code', async () => {
  const response = await request(app)
    .delete('/user/me')
    .set('Authorization', `Bearer ${testUser.tokens[0].token}`)
    .send();

  const expectedStatusCode = 200;
  const actualStatusCode = response.status;

  expect(actualStatusCode).toEqual(expectedStatusCode);
});

test('a DELETE request to /user/me should delete the user from the database', async () => {
  await request(app)
    .delete('/user/me')
    .set('Authorization', `Bearer ${testUser.tokens[0].token}`)
    .send();

  // Assert that after successful delete, the user is no longer in the DB
  const actualUser = await User.findById(testUser);
  expect(actualUser).toBeNull();
});

test('a DELETE requet to /user/me should responds with a 401 status (not authorized) when request does not provide authorization header', async () => {
  const response = await request(app)
    .delete('/user/me')
    .send();

  const expectedStatusCode = 401;
  const actualStatusCode = response.status;

  expect(actualStatusCode).toEqual(expectedStatusCode);
});
