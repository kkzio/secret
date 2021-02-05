require("dotenv").config();
const exprees = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const passport = require("passport");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = exprees();

app.set("view engine", "ejs");

app.use(exprees.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({
    secret: `${process.env.SECRET}`,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Databse
mongoose.connect(
    `mongodb+srv://admin-aji:${process.env.PASSWORD_MONGO}@cluster0.tyks3.mongodb.net/${process.env.DBNAME}?retryWrites=true&w=majority`, 
    {
        useNewUrlParser: true, 
        useUnifiedTopology: true, 
        useCreateIndex: true,
    }
);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error"));
db.once("open", () => {
    console.log("Successfully connect database");
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    twitterId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
});
  
passport.deserializeUser(function(user, done) {
    done(null, user);
});

// Google oauth
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Twitter oauth
passport.use(new TwitterStrategy({
        consumerKey: process.env.APIKEY_TWITTER,
        consumerSecret: process.env.APISECRET_TWITTER,
        callbackURL: "http://www.localhost:3000/auth/twitter/secrets"
    },
    function(token, tokenSecret, profile, cb) {
        User.findOrCreate({ twitterId: profile.id }, function (err, user) {
          return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get('/auth/twitter',
  passport.authenticate('twitter')
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get('/auth/twitter/secrets', 
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/secrets", (req, res) => {
    if(req.isAuthenticated()){
        User.find({"secret": {$ne: null}}, (err, foundUsers) => {
            if(err) {
                console.log(err);
            } else {
                if(foundUsers){
                    res.render("secrets", {userWithSecrets: foundUsers});
                }
            }
        });
    } else {
        res.redirect("/login");
    }
});

app.route("/register")
.get( (req, res) => {
    res.render("register");
})
.post( (req, res) => {
    User.register({username:req.body.username}, req.body.password, (err, user) => {
        if(err){
            console.log(err);
            res.redirect("/register")
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.route("/login")
.get( (req, res) => {
    res.render("login");
})
.post( (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if(err){
            console.log(err);
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.route("/submit")
.get( (req, res) => {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login")
    }
})
.post( (req, res) => {
    const submittedSecret = req.body.secret;
    
    User.findById(req.user._id, (err, foundUser) => {
        if(err){
            console.log(err);
            res.redirect("/submit");
        } else {
            if(foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save( () => {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.listen(3000, () => {
    console.log("Server jalan di localhost:3000");
});