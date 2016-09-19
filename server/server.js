#!/usr/bin/env node

'use strict';

/**
 * module dependencies.
 */

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const http = require('http');
const https = require('https');
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const router = require('./router');
var app = express();

/**
 * tls options
 */

const options = {
  key: fs.readFileSync(path.join(__dirname, 'certs', 'privkey.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'fullchain.pem')),
  dhparam: fs.readFileSync(path.join(__dirname, 'certs', 'dh.pem')),
  SNICallback: function(domainname, cb) {

    // normally check the domainname choose the correct certificate,
    // but for testing/dev always use this one (the default) instead
    cb(null, tls.createSecureContext(options));
  },
  NPNProtcols: ['http/1.1']
};

/**
 * normalize a port into a number, string, or false.
 */

function normalizePort(val) {
  var port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}

var port = normalizePort(process.env.PORT || 3761);

/**
 * 'error' event listener
 */

function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }

  var bind = typeof port === 'string' ? 'Pipe ' + port : 'Port ' + port;

  // handle specific listen errors with friendly messages
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * get port from environment and store in Express.
 */

app.set('port', port);

/**
 * redirect http requests to https
 */

http.createServer((req, res) => {
  res.writeHead(301, {"Location": "https://" + req.headers.host + req.url});
  res.end();
}).listen(3571);

/**
 * create HTTPS server.
 */

var server = https.createServer(options, app);
//var server = http.createServer(app);

/**
 * listen on provided port, on all network interfaces.
 */

server.listen(port, () => {
  console.log(`elfpm-server listening on port ${port}..`);
});

server.on('error', onError);

/**
 * app view engine and middlewares
 */

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
// use helmet which consists of 9 different security
// middlewares for setting http headers appropriately
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use('/', router);

