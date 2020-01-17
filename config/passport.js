// config/passport.js

// load all the things we need
var Repoman = require("../models/company.js");
var users = require("../models/users.js");
var Sequelize = require("sequelize")
const passport = require("passport"),
LocalStrategy = require('passport-local').Strategy;

// load up the user model
//var mysql = require('mysql');
var bcrypt = require('bcrypt-nodejs');
var dbconfig = require('./connection.js');

module.exports = function(passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(email, done) {
        done(null, email.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        users.connect();
        users.query("SELECT * FROM users WHERE id = ? ",[id], function(err, rows){
            done(err, rows[0]);
        });
        users.end();
    });

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use(new LocalStrategy(
        // Our user will sign in using an email, rather than a "username"
        {
          usernameField: "email"
        },
        function(email, password, done) {
          // When a user tries to sign in this code runs
          users.User.findOne({
            where: {
              email: email
            }
          }).then(function(dbUser) {
            // If there's no user with the given email
            if (!dbUser) {
              return done(null, false, {
                message: "Incorrect email."
              });
            }
            // If there is a user with the given email, but the password the user gives us is incorrect
            else if (!dbUser.validPassword(password)) {
              return done(null, false, {
                message: "Incorrect password."
              });
            }
            // If none of the above, return the user
            return done(null, dbUser);
          });
        }
      ));
      //
      // In order to help keep authentication state across HTTP requests,
      // Sequelize needs to serialize and deserialize the user
      // Just consider this part boilerplate needed to make it all work
      passport.serializeUser(function(user, cb) {
        cb(null, user);
      });
      //
      passport.deserializeUser(function(obj, cb) {
        cb(null, obj);
      });
      //
      // Exporting our configured passport
      module.exports = passport;
};
