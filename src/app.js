const express = require('express');
const cors = require('cors');
require('./db/mongoose'); // simply run so mongoose can connect to db
const userRouter = require('./routers/user');

const app = express();

const webAppOrigin = process.env.WEB_APP_ORIGIN;
app.use(cors({
  origin: webAppOrigin,
}));

app.use(express.json());
app.use(userRouter);

module.exports = app;
