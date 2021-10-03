//jshint esversion:6
require('dotenv').config(); //add this line at top
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

//place this part of code above mongoose.connect
app.use(session({
    secret:'Our secret key',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//add this below line before creating the model
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password']});

const User = mongoose.model("User", userSchema);

//add these 3 parts below mongoose model
passport.use(User.createStrategy());

//this below 2 lines of code are used for local authentication
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//Use this for all types of authentication
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//put google oauth code here after serializeUser and deserializeUser
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_OAUTH_CLIENT_ID,
    clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
    res.render('home');
});

//open google signin page
app.get('/auth/google', 
    passport.authenticate('google', { scope: ['profile'] })
);

//redirect page after user signin from google
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login", function (req, res) {
    res.render('login');
})

app.get("/register", function (req, res) {
    res.render('register');
})

app.get("/secrets", function(req, res) {
    User.find({"secret":{$ne: null}}, function(err, foundUsers) {
        if(err) {
            console.log(err);
        } else {
            if(foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    })
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser) {
        if(err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function() {
                    res.redirect("/secrets");
                })
            }
        }
    })
});

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
})

app.post('/register', function (req, res) {
    registerUsingPassport(req, res);
});

app.post('/login', function (req, res) {
    loginUsingPassport(req, res);
});

const loginUsingPassport = (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    //to login user we will use the function of passport
    req.login(user, function(err) {
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    });
}

const registerUsingPassport = (req, res) => {
    User.register({username:req.body.username}, req.body.password, function(err, user) {
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                //if the session is successfully saved of user
                res.redirect("/secrets");
            })
        }
    });
}

app.listen(3000, function () {
    console.log("Server running on port 3000");
})

//App post requests using bcrypt hashing method

// app.post('/register', function (req, res) {

//     bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });

//         newUser.save(function (err) {
//             if (err) {
//                 console.log(err);
//             } else {
//                 res.render("secrets");
//             }
//         });

//     });
// })

// app.post('/login', function (req, res) {
//     const username = req.body.username;
//     const password = req.body.password;

//     User.findOne({ email: username }, function (err, foundUser) {
//         if (err) {
//             console.log(err);
//         } else {
//             if (foundUser) {
//                 bcrypt.compare(password, foundUser.password, function (err, result) {
//                     if (result === true) {
//                         res.render("secrets");
//                     } 
//                 });
//             }
//         }
//     });
// });