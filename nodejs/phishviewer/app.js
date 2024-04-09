var createError = require('http-errors');
var passport = require('passport');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');
var authRouter = require('./routes/auth');

var app = express();

/* Load database and auth modules for authentication */
require('./boot/auth')();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/* Code specific for authentication functionality */
var session = require('express-session');
var SQLiteStore = require('connect-sqlite3')(session);

app.use(session({
        store: new SQLiteStore,
        secret: process.env.AUTHENTICATION_SESSION_SECRET_KEY,
        cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }, // 1 week
        resave: false,
        saveUninitialized: false
}));

app.use(function(req, res, next) {
  var msgs = req.session.messages || [];
  res.locals.messages = msgs;
  res.locals.hasMessages = !! msgs.length;
  req.session.messages = [];
  next();
});

/* Passport and session initialization for authentication */
app.use(passport.initialize());
app.use(passport.authenticate('session'));

app.use('/', indexRouter);
app.use('/', authRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
