# Developer Notes

Below are notes when implementing this template.

## Directory Structure

* Start a project.
* Create package.json in root project folder.

````
npm init -y
````

Implement the following directory structure:

* /config
    * dev.env
    * prod.env
    * test.env 
* /src
    * /db
        * mongoose.js - connects to MongoDB db server
    * /middleware
        * authentication.js  
    * /models - defines Mongoose models, validation rules, etc.
        * product.js
        * user.js 
    * /routers - defines Routers for each resource.
        * product.js
        * user.js
    * app.js - the Express app
    * index.js - runs the Express app.
* /tests - automated test cases
	* product.test.js
    * user.test.js

## JavaScript style

* Use Airbnb style guide
* Enformce compliance with ESLint plugin in VS Code.

````
eslint --init
````

* This repo uses the following config:

````
{
    "env": {
        "commonjs": true,
        "es6": true,
        "node": true
    },
    "extends": [
        "airbnb-base"
    ],
    "globals": {
        "Atomics": "readonly",
        "SharedArrayBuffer": "readonly"
    },
    "parserOptions": {
        "ecmaVersion": 2018
    },
    "rules": {
      "no-underscore-dangle": ["error", { "allow": ["_id"] }]
    }
}
````

## MongoDB (local)

Install MongoDB with the following:

* Install MongoDB by going to [MongoDB Download Center](https://www.mongodb.com/download-center/community)
* Download the latest as a TGZ package for Mac.
* Extract contents from .tgz file.
* Rename folder to simply mongodb
* Move yo Users folder
* Create the associated mongodb-data folder
* In Terminal, run the mongodb database with ...

````
/Users/clintcabanero/mongodb/bin/mongod --dbpath=/Users/clintcabanero/mongodb-data
````

Run MongoDB via Terminal:

````
/Users/clintcabanero/mongodb/bin/mongod --dbpath=/Users/clintcabanero/mongodb-data
````

Stop MongoDB via TerminaL:

````
CMD + C
````

Install a MongoDB database client:

* Download [Robo 3T](https://robomongo.org/download)
* Double-click the .dmg
* Drag to the Applications folder
* MongoDB Connections dialog
    * Create
    * Rename to Local MongoDB Database

## MongoDB (AWS)

Below are notes on how to stand up and configure a 'Development' MongoDB on EC2.

__Create EC2 Instance__

* AMI - Amazon Linux 2 AMI
* Instance Type - t2.micro
* Configure Instance - defaults
* Add Storage
* Tags
  * Name: <enter>
  * Project: <enter>
  * Client: <enter>
  * Administrator: Clint Cabanero
  * Environment: Dev
* Security group
  * Name: tmobile
  * Type: SSH -  Port 22 - Source=My IP
* Keypair
  Name: <enter>
* Login with Terminal:

````
cd ~/location/of/pem file/aws

ssh -i tmobile.pem ec2-user@x.y.z.a

yes 
````

* If you view WARNING: UNPROTECTED PRIVATE KEY FILE then do:

````
sudo chmod 600 nameofyour.pem
````

* Update packages

````
sudo yum -y update
````

__Installing MongoDB__

* Create a file to download MongoDB directly using yum:

````
sudo nano /etc/yum.repos.d/mongodb-org-4.2.repo
````

* Copy paste the following in the repo file

````
[mongodb-org-4.2]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/amazon/2/mongodb-org/4.2/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-4.2.asc
````
* Install mongoDB packages:

````
sudo yum -y install mongodb-org
````

* Check MongoDB is installed properly

````
which mongo  # should print /usr/bin/mongo
````

* Ensure MongoDB will start following a system reboot with:

````
sudo chkconfig mongod on
````

* Check status

````
service MongoDB status
````

__Connecting to EC2 MongoDB with Robo 3T__

* On EC2 instance (SSH connection)

````
sudo nano /etc/mongod.conf
````

* Update the following:

````
# bindIp: 127.0.0.1      # comment this out
bindIpAll: true          # add this line

````

* Restart MongoDB:

````
sudo service mongod restart
sudo service mongod status
````

* In AWS Management Console
  * Go to Ec2 instace
  * Go to Security group
  * Add inbound rule
  * Custome TCP Rule, protocol TCP, Port: 27017, Source: MyIP
* In Robot3T
  * Create direct connection
  * Name <enter>
  * Address use EC2 public ip e.g. 54.189.202.111
  * Save
  * Test

  

## Data Models with Mongoose

Add the MongoDB Node.js Driver

````
npm install mongodb
````

Mongoose is a ODM for MongoDB. Install mongoose via Terminal:

````
npm install mongoose
````

[Validator](https://www.npmjs.com/package/validator) will give us validation goodies to use in our Mongoose models.  Install via Terminal:

````
npm install validator
````

[bcrypt.js](https://www.npmjs.com/package/bcryptjs) is used for password hashing.

````
npm install bcryptjs
````

[jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) library is used to work with JWTs in Express routes.

````
npm install jsonwebtoken
````

Create __/src/db/mongoose.js__

````
const mongoose = require('mongoose');

mongoose.connect(process.env.MONGODB_URL, {
  useNewUrlParser: true,
  useCreateIndex: true,
  useUnifiedTopology: true,
});

````

Create __/src/models/user.js__. 

Define a User model.  Special patterns to call out for the User resource are the following:

* Can define a variety of static or instance properties on the User schema.
* Middleware is used to customize what happens before Mongoose saves a User into MongoDB.
* Before saving, we use bcrypt to hash the password before saving to the database.


````
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

/**
 * Define the schema for User.
 */
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    unique: true,
    validate(value) {
      if (!validator.isEmail(value)) {
        throw new Error('Email is invalid');
      }
    },
  },
  password: {
    type: String,
    required: true,
    trim: true,
    minlength: 7,
    validate(value) {
      if (value.toLowerCase().includes('password')) {
        throw new Error('Password cannot contain the word password');
      }
    },
  },
  tokens: [{
    token: {
      type: String,
      required: true,
    },
  }],
  isAdmin: {
    type: Boolean,
    required: true,
    default: false,
  },
});

/**
 * Instance method for creating JWT and saving to the db.
 */
userSchema.methods.generateAuthToken = async () => {
  const user = this;
  const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET);
  user.tokens = user.tokens.concat({ token });
  await user.save();
  return token;
};

/**
 * Instance method for getting a User instance's public profile properties (provided by .toJSON)
 */
userSchema.methods.toJSON = () => {
  const user = this;
  const userObject = user.toObject();
  delete userObject.password;
  delete userObject.tokens;
  delete userObject.isAdmin;
  return userObject;
};

/**
 * Middle-ware method to hash the plain text password before calling the Mongoose .save() method.
 */
userSchema.pre('save', async (next) => {
  const user = this;
  if (user.isModified('password')) {
    user.password = await bcrypt.hash(user.password, 8);
  }
  next();
});

/**
 * Static method that finds the user in MongoDB.
 */
userSchema.statics.findByCredentials = async (email, password) => {
  // eslint-disable-next-line no-use-before-define
  const user = await User.findOne({ email });
  if (!user) {
    throw new Error('Unable to login');
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new Error('Unable to login');
  }
  return user;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
````

## Modeling Relationsihps

Here is an example whereby a reports are owned by a user.

The Report model - note the __owner__ property which is a reference to the Uesr model ...

````
const mongoose = require('mongoose');

const SchemaTypes = mongoose.Schema.Types;
const Report = mongoose.model('Report', {
    name: {
        type: SchemaTypes.String,
        required: true,
        trim: true,
    },
    date: {
        type: SchemaTypes.Date,
        required: true,
        default: Date.now
    },
    description: {
        type: SchemaTypes.String,
        trim: true,
    },
    owner: {
        type: SchemaTypes.ObjectId,
        required: true,
        ref: 'User'
    }
});

module.exports = Report;
````

The User model - note the virtual property ...

````
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        unique: true,
        validate(value) {
            if (!validator.isEmail(value)) {
                throw new Error('Email is invalid');
            }
        }
    },
    password: {
        type: String,
        required: true,
        trim: true,
        minlength: 7,
        validate(value) {
            if (value.toLowerCase().includes('password')) {
                throw new Error('Password cannot contain the word password');
            }
        }
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }]
    ...
});

/**
 * Add virtual property that for Reports owned by user. 
 */
userSchema.virtual('reports', {
    ref: 'Report',
    localField: '_id',
    foreignField: 'owner'
})

````

## Environment Variables

Use env-cmd for declaring environment variables that will be git ignored.  Install with:

````
npm install env-cmd --save-dev
````

Nodemon allows for watching changes and re-running our node app.

````
npm install nodemon --save-dev
````

Edit package.json with:

````
  "scripts": {
    "start": "node src/index.js",
    "dev": "env-cmd -f ./config/dev.env nodemon src/index.js",
    "test": "env-cmd -f ./config/test.env jest --watch --runInBand"
  },
````

Just a note: we tell Jest to runInBand so that tests are run serially.

An example of a ./config/dev.env file would be:

````
PORT=3000
MONGODB_URL=mongodb://127.0.0.1:27017/your-name-here
JWT_SECRET=yoursecrethere
````

An example of a ./config/test.env file would be:

````
PORT=3000
MONGODB_URL=mongodb://127.0.0.1:27017/your-name-here-TEST
JWT_SECRET=yoursecrethere
````

## Setup Express App

Express for creating RESTful resources.

````
npm install express
npm install cors
````
    
In src/app.js create an Express app.  Note, the routes are defined below in another section.  

````
const express = require('express');
const cors = require('cors');
require('./db/mongoose'); // simply run so mongoose can connect to db
const moduleRouter = require('./routers/user');

const app = express();

const webAppOrigin = process.env.WEB_APP_ORIGIN;
app.use(cors({
  origin: webAppOrigin,
}));

app.use(express.json());
app.use(moduleRouter);

module.exports = app;

````

In src/index.js add the following:

````
const app = require('./app');

const port = process.env.PORT;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Server is running on port ${port}`);
});

````

## Create Routers for each Resource

Create __/src/routers/user.js__


````
/* eslint-disable arrow-body-style */
const express = require('express');
const User = require('../models/user');
const auth = require('../middleware/authentication');

const router = new express.Router();

/**
 * Creates a User (i.e. sign up)
 */
router.post('/user', async (req, res) => {
  // Create the User.
  const user = new User(req.body);
  try {
    await user.save();
    res.status(201).send({
      user,
    });
  } catch (e) {
    res.status(400).send(e);
  }
});

/**
 * Logs in a registered User - returning a JWT.
 */
router.post('/user/login', async (req, res) => {
  try {
    const user = await User.findByCredentials(req.body.email, req.body.password);
    const token = await user.generateAuthToken();
    res.send({
      user,
      token,
    });
  } catch (e) {
    res.status(400).send();
  }
});

/**
 * Logs out a User - removing the request JWT associated with registered User.
 * Note: uses auth middleware for handling request authentication.
 */
router.post('/user/logout', auth, async (req, res) => {
  try {
    const logoutToken = req.header('Authorization').replace('Bearer ', '');
    req.user.tokens = req.user.tokens.filter((userToken) => {
      return userToken.token !== logoutToken;
    });
    await req.user.save();
    res.send();
  } catch (e) {
    res.status(500).send();
  }
});

/**
 * Logs out a User - removing ALL JWTs associated with registered User.
 */
router.post('/user/logoutAll', auth, async (req, res) => {
  try {
    req.user.tokens = [];
    await req.user.save();
    res.send();
  } catch (e) {
    res.status(500).send();
  }
});

/**
 * Fetches the authenticated users to get their own user info.
 */
router.get('/user/me', auth, async (req, res) => {
  res.send(req.user);
});

/**
 * Updates an authenticated User's info.
 */
router.patch('/user/me', auth, async (req, res) => {
  // Validate fields to be updated are allowed.
  const requestUpdates = Object.keys(req.body);
  const allowedUpdates = ['email', 'password'];
  const isValidOperation = requestUpdates.every((requestUpdate) => {
    return allowedUpdates.includes(requestUpdate);
  });
  if (!isValidOperation) {
    res.status(400).send({
      error: 'Invalid update fields',
    });
  }

  // Update the User.
  try {
    requestUpdates.forEach((updateField) => {
      req.user[updateField] = req.body[updateField];
    });
    await req.user.save();
    res.status(200).send(req.user);
  } catch (e) {
    res.status(500).send(e);
  }
});

/**
 * Deletes an authenticated User.
 */
router.delete('/user/me', auth, async (req, res) => {
  // Delete the User.
  try {
    // Use the authenticated User (provided by auth) middelware.
    await req.user.remove();
    res.send(req.user);
  } catch (e) {
    res.status(500).send();
  }
});

module.exports = router;
````

## Auth Middleware

Add the auth middleware to src/middleware/auth.js

````
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const auth = async (req, res, next) => {
  try {
    // Get token from request header.
    const token = req.header('Authorization').replace('Bearer ', '');

    // Check that the token in the request is associated with a User in the database.
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });

    // Handle authentication failure (no User found associated with the token)
    if (!user) {
      throw new Error(); // sends to catch
    }

    // Pass route handler the authenticated user and token (reduce look-up)
    req.user = user;

    // Allow route handlers to proceed.
    next();
  } catch (e) {
    res.status(401).send({
      error: 'Please authenticate.',
    });
  }
};

module.exports = auth;

````

## Run the API

Run the API with:

````
npm run dev
````

Use Postman (or other) to manually hit the API and confirm.

````
POST localhost:3001/user

Header: Content-Type application/json

Body (raw JSON):
{
	"email": "clintcabanero@email.com",
	"password": "p@ssWURD"
}

````

## Add Unit and Integration Tests

Install Jest test framework as a development dependency with:

````
npm install jest --save-dev
````

Configure Jest in the package.json with:

````
 "jest": {
    "testEnvironment": "node"
  },
  
````

Install Supertest for testing Express APIs.

````
npm install supertest --save-dev
````

If using ESLint then add the following in .eslintrc.json

````
{
    "env": {
        "commonjs": true,
        "es6": true,
        "node": true,
        "jest": true <--- ADD THIS
    },
    ...
}
````

__Testing Patterns:__

In general, we test the APIs by evaluting:

* the API returns the expected response codes, data structure and data values.
* the API, makes the expected changes to the database when updating, inserting, or deleting.

Create __/tests/fixtures/db.js__

````

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const User = require('../../src/models/user');

// Creates test user to add to test database.
const testUserId = new mongoose.Types.ObjectId();
const testUser = {
  _id: testUserId,
  email: 'userone@email.com',
  password: 'p@ssWURD!',
  tokens: [{
    token: jwt.sign({ _id: testUserId }, process.env.JWT_SECRET),
  }],
};

// Create a second test user for authenticating sale requests
const testUser2Id = new mongoose.Types.ObjectId();
const testUser2 = {
  _id: testUserId,
  email: 'usertwo@email.com',
  password: 'p@ssWURD!',
  tokens: [{
    token: jwt.sign({ _id: testUser2Id }, process.env.JWT_SECRET),
  }],
};

/**
 * Set up test database with test user and test sale.  Remove any previous users.
 */
const setupTestUserInDatabase = async () => {
  await User.deleteMany();
  await new User(testUser).save();
};

module.exports = {
  testUser,
  testUser2,
  setupTestUserInDatabase,
};

````

Create __/tests/user.test.js__

````
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
````

## Run the API

Run the tests with:

````
npm run dev
````

## Deploy API to EC2

Below are notes on a manual procedure.  Consider Docker > AWS EC2 Fargate.

__Overview__

For a single-server solution, we will implement the following on the EC2 server

* NGINX
	* request through security group PORT 80
	* configure /etc/nginx/nginx.conf
* Git
* Node, run API app with PM2
* Express
* Mongoose
* MongoDB

__EC2 - Install Node.js__

In sections above, we have installed MongoDB on the EC2 server.  We will continue adding more.

Install NVM with: 

````
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.2/install.sh | bash
````

Confirm NVM installation with:

````
nvm --version
````

Install Node with: 

````
nvm install <node_version>
````

Confirm Node install with:

````
node --version
````

__EC2 - Install Git and Clone API repo__

To install Gith do:

````
sudo yum install git
````

Clone the API library

````
cd /hom/ec2-user

git clone https://github.com/<the-api-repo>.git
````

After cloning, go into root of API project directory and do:

````
npm install
````

__EC2 - Configure Security Group__

Note, your *.env file will declare what port the API will be avialable at. 

In AWS Console, go to the security group - and open the API app port needed (e.g. 3000 or 3001).

* Type: Custom TCP
* Protocol: TCP
* Port Range: 3001

Then run the API node app with:

````
npm run dev (or prod)
````

Confirm by hitting the api at: http://elastic-ip:3001/api

__EC2 - PM2__

Kill all running node processes

````
killall -9 node
````

Install PM2 globally with the following:

````
npm install pm2 -g
````

CD into the directory with the Node App:

````
pm2 run dev (or prod)
````
