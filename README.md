# RESTful API Template

## Summary

This is a template repository for starting a new RESTful API using GitHub's ['Create a repository from a template'](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/creating-a-repository-from-a-template) workflow. This API uses the following technology stack:

![architecture](docs/technology-stack.png)

*  The authentication strategy uses [JSON Web Token](https://www.npmjs.com/package/jsonwebtoken) (JWT).
* The API is implemented using [Express](https://expressjs.com).
* [Mongoose](https://mongoosejs.com) is used as the Object document model (ODM) when interfacing with the database.
* [MongoDB](https://www.mongodb.com) is the NoSQL database.
* Unit and Integration Testing
  * [Jest](https://jestjs.io) - JavaScrip testing library.
  * [Supertest](https://github.com/visionmedia/supertest) - provides testing utilites for RESTful APIs.
  
## Features

* After clonging this repo, environments can be configured to connect to either a local or remote MongoDB instance.
* Auth middleware is implemented to support authenticating REST endpoints.
* A user resource is implemented and supports the following general requirements:

|  HTTP Verb | Resource  | General Description  |     
|---|---|---|
|  POST | /user  | Registers a new user.  |   
|  POST | /user/login  |  Logs in a user, returns a JWT on success.  A user can create a collection of tokens for multi-device support. |      
|  POST | /user/logout |  Logs out the user. | 
|  POST | /user/logoutAll | Logs out user from all devices. |
|  GET  | /user/me | Returns information about the authenticated user. |
|  PATCH| /user/me | Updates information for the authenticated user. |
|  DELETE | /user/me | Deletes the authenticated user. |    

* Testing libraries/utilities are configured to support unit and integration tests. Test coverage is implemented for the /user endpoints.
* Ability to add project-specific REST enspoints for your project.


## Using this Template

1. Stand up a MongoDB database.  
2. If you are running a local/dev MongoDB then run it via Terminal with:

````
/Users/clintcabanero/mongodb/bin/mongod --dbpath=/Users/clintcabanero/mongodb-data
````

3. Add .env files to the node app.  At the root of the Node app, add the following:

config.dev.env

````
PORT=3001
MONGODB_URL=mongodb://<enter.your.dev.url.here>:27017/api
WEB_APP_ORIGIN=http://localhost:3000
JWT_SECRET=enteryourrecrethere
````

config.test.env

````
PORT=3001
MONGODB_URL=mongodb://<enter.your.test.url.here>:27017/api-test
WEB_APP_ORIGIN=http://localhost:3000
JWT_SECRET=enteryourrecrethere
````

Run Dev

````
npm run dev
````

Run Tests

````
npm run test
````


## Directory Structure

TBD

## Developer Notes

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
estlint --init
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
  useUnifiedTopology: true,,
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
    }],
    isAdmin: {
        type: Boolean,
        required: true,
        default: false
    }
});

/**
 * Static method that finds the user in MongoDB. 
 */
userSchema.statics.findByCredentials = async (email, password) => {
    const user = await User.findOne({ email: email });
    if (!user) {
        throw new Error('Unable to login');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        throw new Error('Unable to login');
    }
    return user;
};

/**
 * Instance method for creating JWT and saving to the db.
 */
userSchema.methods.generateAuthToken = async function() {
    const user = this;
    const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET);
    user.tokens = user.tokens.concat({ token: token });
    await user.save();
    return token;
}

/**
 * Instance method for getting a User instance's public profile properties (provided by .toJSON)
 */
userSchema.methods.toJSON = function() {
    const user = this;
    const userObject = user.toObject();
    delete userObject.password;
    delete userObject.tokens;
    delete userObject.isAdmin;
    return userObject;
}

/**
 * Middle-ware method to hash the plain text password before calling the Mongoose .save() method.
 */
userSchema.pre('save', async function(next) {
    const user = this;
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8);
    }
    next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;
````
Create __/src/models/product.js__.

````
const mongoose = require('mongoose');

const Product = mongoose.model('Product', {
    name: {
        type: String,
        required: true,
        trim: true,
    },
    price: {
        type: Number,
        required: true
    },
    description: {
        type: String,
        trim: true,
    },
    category: {
        type: [String]
    },
    tags: {
        type: [String]
    },
    images: {
        type: [String]
    }
});

module.exports = Product;
````

Before we create our Express routes, and while we are developing our models, we can just use node to run logic that will create models into the MongoDB database.

For example, in the mongoose file test manually with:

````
const me = new User({
    name: 'Clint',
    email: 'clint@email.com',
    password: 'p@ssword'
});

me.save().then((user) => {
    console.log(user);
}).catch((error) => {
    console.log('Error:', error);
});

// then run node mongoose.js
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
MONGODB_URL=mongodb://127.0.0.1:27017/your-api-name-here
JWT_SECRET=yoursecrethere
````

An example of a ./config/test.env file would be:

````
PORT=3000
MONGODB_URL=mongodb://127.0.0.1:27017/your-api-name-here-TEST
JWT_SECRET=yoursecrethere
````

## Setup Express App

Express for creating RESTful resources.

````
npm install express
````
    
In index.js initialize Express with the below.  Note, the routes are defined below in another section.  

````
const express = require('express');
require('./db/mongoose'); // simply run so mongoose can connect to db
const userRouter = require('./routers/user');
const productRouter = require('./routers/product');

const app = express();

app.use(express.json());
app.use(userRouter);
app.use(productRouter);

const port = process.env.PORT;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
````

Now use npm to run our app with nodemon:

````
npm run dev
````

## Create Routers for each Resource

Create __/src/routers/user.js__


````
const express = require('express');
const User = require('../models/user');
const auth = require('../middleware/auth');

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
            user: user
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
            user: user,
            token: token
        });
    } catch (e) {
        res.status(400).send();
    }
});

/**
 * Logs out a User - removing the request JWT associated with registered User.
 * Note: uses auth middleware for handling request authentication.
 */
router.post('/user/logout', auth, async(req, res) => {
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
router.post('/user/logoutAll', auth, async(req, res) => {
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
        return res.status(400).send({
            error: 'Invalid update fields'
        });
    }

    // Update the User.
    try {
        requestUpdates.forEach((updateField) => {
            req.user[updateField] = req.body[updateField]
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
router.delete('/user/me', auth, async(req, res) => {

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

Create __/src/routers/product.js__

````
const express = require('express');
const mongoose = require('mongoose');
const Product = require('../models/product');
const auth = require('../middleware/auth');

const router = new express.Router();

/**
 * Creates a Product (must be in admin role).
 */
router.post('/product', auth, async (req, res) => {

    // Handle admin authorization.
    if (req.user.isAdmin) {
        const product = Product(req.body);
        try {
            await product.save();
            res.status(201).send(product);
        } catch (e) {
            res.status(400).send(e);
        }
    } else {
        res.status(401).send();
    }
});

/**
 * Fetches all Products (public endpoint).
 */
router.get('/products', async (req, res) => {
    try {
        const products = await Product.find({});
        res.status(200).send(products);
    } catch (e) {
        res.status(500).send();
    }
});

/**
 * Fetches an existing Product by Id (public endpoint).
 */
router.get('/product/:id', async (req, res) => {

    // Validate ObjectId.
    const id = req.params.id;
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).send({
            error: 'Provided id is not a valid MongoDB ObjectId'
        });
    }

    // Fetch the Product.
    try {
        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).send();
        }
        res.send(product);
    } catch (e) {
        res.status(500).send();
    }
});

/**
 * Updates an existing Product by Id (must be in admin role).
 */
router.patch('/product/:id', auth, async (req, res) => {

    // Handle admin authorization.
    if (req.user.isAdmin) {

        // Validate fields to be updated are allowed.
        const requestUpdates = Object.keys(req.body);
        const allowedUpdates = ['name', 'price', 'description', 'category', 'tags', 'images'];
        const isValidOperation = requestUpdates.every((requestUpdate) => {
            return allowedUpdates.includes(requestUpdate);
        });
        if (!isValidOperation) {
            return res.status(400).send({
                error: 'Invalid update fields'
            });
        }

        // Validate ObjectId.
        const id = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).send({
                error: 'Provided id is not a valid MongoDB ObjectId'
            });
        }

        // Update the Product.
        try {
            const product = await Product.findById(id);
            if (!product) {
                return res.status(404).send();
            }
            requestUpdates.forEach((updateField) => {
                product[updateField] = req.body[updateField]
            });
            await product.save();
            res.status(200).send();
        } catch (e) {
            res.status(500).send();
        }
    } else {
        res.status(401).send();
    }
});

/**
 * Deletes an existing Product by Id.
 */
router.delete('/product/:id', auth, async(req, res) => {

    // Handle admin authorization.
    if (req.user.isAdmin) {

        // Validate ObjectId.
        const id = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).send({
                error: 'Provided id is not a valid MongoDB ObjectId'
            });
        }

        // Delete the Product.
        try {
            const product = await Product.findByIdAndDelete(id);
            if (!product) {
                return res.status(404).send();
            }
            res.send(product);
        } catch (e) {
            res.status(500).send();
        }
    } else {
        res.status(401).send();
    }
});

module.exports = router;
````

## API Testing

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

* Use supertest to call Express app and assert against response status codes. 
* Use mongoose to check the state of the DB.
    * Use env-cmd to target a test database
    * Use Jest lifecycle to clear User collection before running each test.
    * Use Jest lifecycle to insert User before running each test.

Create __/tests/user.test.js__

````
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/user');

// Creates a mongoose ObjectId - to be used to create a JWT
const userOneId = new mongoose.Types.ObjectId();

// A user to be used for testing endpoints that require an existing user (e.g. Login)
const userOne = {
    _id: userOneId,
    email: 'userone@email.com',
    password: 'p@ssWURD!',
    tokens: [{
        token: jwt.sign({ _id: userOneId }, process.env.JWT_SECRET)
    }]
}

beforeEach(async () => {
    await User.deleteMany();
    await new User(userOne).save();
});

test('Should sign up a new user', async () => {

    // Assert that the endpoint responds with the correct status code.
    const response = await request(app).post('/user').send({
        email: 'tester@email.com',
	    password: 'p@ssWURD'
    }).expect(201);

    // Assert that the response body structure is what we expect.
    expect(response.body).toMatchObject({
        user: {
            email: 'tester@email.com'
        }
    });

    // Assert that the database was changed correctly.
    const user = await User.findById(response.body.user._id);
    expect(user).not.toBeNull();

    // Assert that the password is not saved in the DB as plain text.
    expect(user.password).not.toBe('p@ssWURD');
});

test('Should login existing user', async () => {

    // Assert that the endpoint responds with the correct status code.
    const response = await request(app).post('/user/login').send({
        email: userOne.email,
        password: userOne.password
    }).expect(200);

    // Assert that after successful login, token is stored for user in the DB.
    const user = await User.findById(userOneId);
    expect(response.body.token).toBe(user.tokens[0].token);
});

test('Should handle login for existing user with wrong password', async () => {

    // Assert that the endpoint responds with the correct status code.
    await request(app).post('/user/login').send({
        email: userOne.email,
        password: 'badpassword'
    }).expect(400);
});

test('Should handle login for nonexistent user', async () => {

    // Assert that the endpoint responds with the correct status code.
    await request(app).post('/user/login').send({
        email: 'not-a-user',
        password: userOne.password
    }).expect(400);
});

test('Should get profile for user', async () => {

    // Assert that the endpoint responds with the correct status code.
    await request(app)
        .get('/user/me')
        .set('Authorization', `Bearer ${userOne.tokens[0].token}`)
        .send()
        .expect(200)
});

test('Should not get profile for un-authenticated user', async () => {

    // Assert that the endpoint responds with the correct status code.
    await request(app)
        .get('/user/me')
        .send()
        .expect(401)
});

test('Should delete registered user when authenticated', async () => {

    // Assert that the endpoint responds with the correct status code.
    await request(app)
        .delete('/user/me')
        .set('Authorization', `Bearer ${userOne.tokens[0].token}`)
        .send()
        .expect(200)

    // Assert that after successful delete, the user is no longer in the DB
    const user = await User.findById(userOneId);
    expect(user).toBeNull();
});

test('Should not delete registered user when un-authenticated', async () => {

    // Assert that the endpoint responds with the correct status code.
    await request(app)
        .delete('/user/me')
        .send()
        .expect(401)
});
````

Create __/tests/report.test.js__

````
const request = require('supertest');
const app = require('../src/app');
const Report = require('../src/models/report');
const {
  userOne,
  userTwo,
  reportOne,
  reportOneId,
  setupTestDatabase,
} = require('./fixtures/db');

beforeEach(setupTestDatabase);

test('Should create a new report', async () => {
  const testReport = {
    name: 'This is a test Report',
    description: 'This is a test report description',
    date: '2019-10-16T12:45:01.171Z',
    siteExtent: {
      swCoords: [-73.9876, 40.7661],
      neCoords: [-73.9397, 40.8002],
    },
  };

  // Assert that the POST /api/report endpoint responds with the correct status code (201).
  const response = await request(app)
    .post('/api/report')
    .set('Authorization', `Bearer ${userOne.tokens[0].token}`)
    .set('Content-Type', 'application/json')
    .send(testReport)
    .expect(201);

  // Assert that after POST /api/report is called, the database was changed correctly
  // by adding the new report to the Report collection.
  const report = await Report.findById(response.body._id);
  expect(report._id).not.toBeNull();
  expect(report.name).toBe(testReport.name);
  expect(report.description).toBe(testReport.description);
});

test('Should get report for id', async () => {
  // Assert that the GET /api/report/{id} endpoints responds with the correct status code.
  const response = await request(app)
    .get(`/api/report/${reportOneId}`)
    .set('Authorization', `Bearer ${userOne.tokens[0].token}`)
    .send()
    .expect(200);

  // Assert that the GET /api/report/{id} returns a Report with the expected attributes.
  const report = await Report.findById(response.body._id);
  expect(report.name).toBe(reportOne.name);
  expect(report.description).toBe(reportOne.description);
});

test('Should handle when a report is requested with a non-existent id', async () => {
  /**
   * Assert that the GET /api/report/{id} endpoints responds with the correct status code (400)
   * when an invalid id is provided.
  */
  await request(app)
    .get('/api/report/123NONSENSEID')
    .set('Authorization', `Bearer ${userOne.tokens[0].token}`)
    .send()
    .expect(400);
});

test('Should get all reports for authenticated user', async () => {
  // Assert that the GET api/reports endpoint responds with the correct status code (200).
  const response = await request(app)
    .get('/api/reports')
    .set('Authorization', `Bearer ${userOne.tokens[0].token}`)
    .send()
    .expect(200);

  /**
   * Assert that the GET api/reports endpoint returns the correct number of reports owned
   * by the authenticated user.
   */
  expect(response.body.length).toEqual(1);

  /**
   * Assert that the GET api/reports endpoint returns a report owned by the authenticated
   * user with the proper fields.
   */
  const report = response.body[0];
  expect(report.name).toBe(reportOne.name);

  /*
   * Assert that the GET api/reports endpoint return the correct status (404) - NotFound -
   * when authenticated user does NOT own any reports.
   */
  await request(app)
    .get('/api/report')
    .set('Authorization', `Bearer ${userTwo.tokens[0].token}`) // User2 does not own any reports
    .send()
    .expect(404);
});

test('Should update a report owned by the authenticated user', async () => {
  // Represents the update to a report.
  const reportUpdate = {
    name: 'This is a an updated Report',
  };

  // Assert that the PATCH api/report endpoints responds with the correct status code (200).
  const response = await request(app)
    .patch(`/api/report/${reportOneId}`)
    .set('Authorization', `Bearer ${userOne.tokens[0].token}`)
    .send(reportUpdate)
    .expect(200);

  // Assert that the PATCH /api/report endpoint returns a report with the expected fields.
  const reportResponse = response.body;
  expect(reportResponse.name).toBe(reportUpdate.name);

  // Assert that after the PATCH /api/report is called, the Report is updated in the test database.
  const reportInDB = await Report.findById(reportOneId);
  expect(reportInDB.name).toBe(reportUpdate.name);
});

test('Should delete a report owned by the authenticated user', async () => {
  // Assert that that prior to DELETE api/report, the Report exists in the test database.
  const report = await Report.findById(reportOneId);
  expect(report).not.toBeNull();

  /**
   * Assert that the DELETE api/report responds with the correct status code (200) when deleted
   * by the report owner.
   */
  await request(app)
    .delete(`/api/report/${reportOneId}`)
    .set('Authorization', `Bearer ${userOne.tokens[0].token}`)
    .send()
    .expect(200);

  // Assert that after DELETE api/report, the Report does not exist in the test database.
  const reportAfterDelete = await Report.findById(reportOneId);
  expect(reportAfterDelete).toBeNull();
});

test('Should not delete a report when not owned by the authenticated user', async () => {
  /**
   * Assert that the DELETE api/report responds with the correct status code (404) - NotFound
   * when the authenticated user attempts to delete a report they do not own.
   */
  await request(app)
    .delete(`/api/report/${reportOneId}`)
    .set('Authorization', `Bearer ${userTwo.tokens[0].token}`)
    .send()
    .expect(404);

  /**
   * Assert that that after DELETE api/report is requested by a user that does not own the
   * report, it remains in the test database
   */
  const report = await Report.findById(reportOneId);
  expect(report).not.toBeNull();
});

````

__PostMan__

* I use Postman to manually integration test.
* I have also used Postman to automate integration testing (see BMM).

## API Documentation

Because Postman is used to manually integration test ... just export as documentation!

## Deploy API to EC2

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



__

Deployment workflow is:

* SSH connect to the EC2 via Terminal
* Clonse the api repo 
* Start the API app
* Keep the API app running