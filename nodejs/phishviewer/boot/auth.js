var passport = require('passport');
var Strategy = require('passport-local');

const FRONT_END_USERNAME = process.env.FRONT_END_USERNAME;
const FRONT_END_PASSWORD = process.env.FRONT_END_PASSWORD;

// Configure the local strategy for use by Passport.
module.exports = function() {
  /* The local strategy requires a `verify` function which receives the credentials
    (`username` and `password`) submitted by the user.  The function must verify
    that the password is correct and then invoke `cb` with a user object, which
    will be set at `req.user` in route handlers after authentication. */
    passport.use(new Strategy(function(username, password, cb) {
      if (username === FRONT_END_USERNAME && password === FRONT_END_PASSWORD) {
        var user = {
          id: 1,
          username: username,
          displayName: username
        };
        return cb(null, user);
      }
      else {
        return cb(null, false, { message: 'Incorrect username or password.' });
      }
    }));

  /* Configure Passport authenticated session persistence.

    In order to restore authentication state across HTTP requests, Passport needs
    to serialize users into and deserialize users out of the session.  The
    typical implementation of this is as simple as supplying the user ID when
    serializing, and querying the user record by ID from the database when
    deserializing. */
  passport.serializeUser(function(user, done) {
    done(null,user);
  });

  passport.deserializeUser(function(user, done) {
    done(null,user);
  });
};
