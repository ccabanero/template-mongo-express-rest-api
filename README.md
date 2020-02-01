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
* Auth middleware is implemented to support requiring authentication when making API requests.
* A user resource is implemented and supports the following general requirements below.  

|  HTTP Verb | Resource  | General Description  |     
|---|---|---|
|  POST | /user  | Registers a new user.  |   
|  POST | /user/login  |  Logs in a user, returns a JWT on success.  A user can create a collection of tokens for multi-device support. |      
|  POST | /user/logout |  Logs out the user. The token is cleared. Requires authorization header (i.e. Bearer token).| 
|  POST | /user/logoutAll | Logs out user from all devices. All tokens are cleared. Requires authorization header (i.e. Bearer token).|
|  GET  | /user/me | Returns information about the authenticated user. Requires authorization header (i.e. Bearer token).|
|  PATCH| /user/me | Updates information for the authenticated user. Requires authorization header (i.e. Bearer token).|
|  DELETE | /user/me | Deletes the authenticated user. Requires authorization header (i.e. Bearer token).|    

* Testing libraries/utilities are configured to support unit and integration tests. Test coverage is implemented for the /user endpoints.
* Ability to add project-specific REST enspoints for your project.


## Using this Template
  
__Step 1__. On this repo page, choose __Use this template__.

  * Enter new repository name.
  * Enter description.
  * Declare Public or Private
  * Choose __Create repository from template__.
  * Clone the new repository created using the template.
  * Install dependencies with:

````
npm install
````

__Step 2__. Stand up a MongoDB database.

* If you are running a local/dev MongoDB then run it via Terminal. For example, based on how I installed MongoDB for local development, I run it with:

````
/Users/clintcabanero/mongodb/bin/mongod --dbpath=/Users/clintcabanero/mongodb-data
````

__Step 3__. Open the project in VS Code. Add .env files to the root of the Node app in a 'config' directory for connecting to your MongoDB.

/config/dev.env

````
PORT=3001
MONGODB_URL=mongodb://<enter.your.dev.url.here>:27017/api
WEB_APP_ORIGIN=http://localhost:3000
JWT_SECRET=enteryoursecrethere
````

/config/test.env

````
PORT=3001
MONGODB_URL=mongodb://<enter.your.test.url.here>:27017/api-test
WEB_APP_ORIGIN=http://localhost:3000
JWT_SECRET=enteryoursecrethere
````

__Step 4__. Run the app.

````
npm run dev
````
__Step 5__. Run the unit and integration tests.

````
npm run test
````

## Directory Structure

Below is a brief discussion of the Node app's directory structure.

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
        * user.js 
        * {add more models here}
    * /routers - defines Routers for each resource.
        * user.js
        * {add more routers here}
    * app.js - the Express app
    * index.js - runs the Express app.
* /tests - automated test cases
	* product.test.js
    * user.test.js

