// Import required packages and modules
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// Create an instance of the Express application
const app = express();

// Middleware setup
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useUnifiedTopology: true,
    useNewUrlParser: true,
    family: 4,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Error connecting to MongoDB: ' + err));

// Define the User Schema and Model
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    googleName: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model('User', userSchema);

// Passport Configuration
passport.use(User.createStrategy());

passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser((id, cb) => {
    User.findById(id, (err, user) => {
        cb(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    userProfileURL: process.env.GOOGLE_PROFILE_URL
}, (accessToken, refreshToken, profile, cb) => {
    User.findOrCreate({ googleId: profile.id, googleName: profile.displayName }, (err, user) => {
        return cb(err, user);
    });
});

// Define the routes

// Home page route
app.get('/', (req, res) => {
    res.render('home');
});

// Login page route
app.get('/login', (req, res) => {
    res.render('login');
});

// Register page route
app.get('/register', (req, res) => {
    res.render('register');
});

// Secrets page route
app.get('/secrets', (req, res) => {
    User.find({ secret: { $ne: null } })
        .then(users => {
            res.render('secrets', { usersWithSecret: users });
        })
        .catch(err => console.error(err));
});

// Submit page route
app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('submit');
    } else {
        res.redirect('/login');
    }
});

// Logout route
app.get('/logout', (req, res) => {
    req.logout(err => {
        if (err) {
            console.error(err);
        } else {
            res.redirect('/');
        }
    });
});

// Google OAuth route
app.get('/auth/google', passport.authenticate('google', {
    scope: ['email', 'profile']
}));

// Google OAuth callback route
app.get('/auth/google/secrets', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    res.redirect('/secrets');
});

// Registration route
app.post('/register', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    User.register(new User({ username: username }), password, (err, user) => {
        if (err) {
            console.error(err);
            res.redirect('/register');
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });
});

// Login route
app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, err => {
        if (err) {
            console.error(err);
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });
});

// Submit a secret route
app.post('/submit', (req, res) => {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id)
        .then(user => {
            user.secret = submittedSecret;
            user.save();
            res.redirect('/secrets');
        })
        .catch(err => console.error(err));
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
