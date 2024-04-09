var express = require('express');
var passport = require('passport');

var router = express.Router();

/* Login endpoint */
router.get('/login', function(req, res, next) {
    if (req.user) {
        res.redirect('/');
    } else {
        res.render('login');
    }
});

/* Basic login endpoint */
router.post('/login/password', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureMessage: true
}));

/* Logout endpoint */
router.get('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

module.exports = router;
