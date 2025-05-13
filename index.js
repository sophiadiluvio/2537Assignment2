require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require('bcrypt');
const Joi = require("joi");
const { database } = require("./databaseConnections");
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

const expireTime = 60 * 60 * 1000;

// Middleware to parse form data
app.use(express.urlencoded({ extended: true }));

app.use(express.static('public'));

// set up view engine and views directory
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); 

// session stuff with MongoDB store
app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`,
      crypto: {
        secret: process.env.MONGODB_SESSION_SECRET
      }
    }),
    cookie: { 
      maxAge: expireTime,
      httpOnly: true
    }
  })
);

// admin check and authorization middleware
function isAdmin(req) {
    if (req.session.user_type === 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("404", { 
            message: "Not Authorized - Admin access required", 
            user: req.session.authenticated ? {
                name: req.session.name,
                email: req.session.email,
                user_type: req.session.user_type
            } : null 
        });
        return;
    }
    else {
        next();
    }
}

// database connection
let userCollection;
database.connect()
  .then(() => {
    const db = database.db(process.env.MONGODB_DATABASE);
    userCollection = db.collection("users");
  })
  .catch(err => {
    console.error("Failed to connect to database:", err);
  });

// home page route
app.get("/", (req, res) => {
  // if user is logged in, pass user object to template, otherwise pass null
  const user = req.session.authenticated ? 
    {
      name: req.session.name,
      email: req.session.email,
      user_type: req.session.user_type
    } : null;
  
  res.render("index", { user: user });
});

// signup page
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

// signup form submission
app.post('/signup', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
  
    try {
      // joi validation
      const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
      });
      
      const validationResult = schema.validate({ name, email, password });
      
      // checks if field is missing with null
      if (validationResult.error != null) {
        const errorMessage = validationResult.error.details[0].message;
        
        // error message depending on which field is missing
        let message = "Please provide all required fields.";
        if (errorMessage.includes("name")) {
          message = "Please provide a name.";
        } else if (errorMessage.includes("email")) {
          message = "Please provide an email address.";
        } else if (errorMessage.includes("password")) {
          message = "Please provide a password.";
        }
        
        res.render("signup", { error: message });
        return;
      }
    
      // bcrypted password
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      // inserts a new user
      await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        user_type: "user" // Default user type
      });
    
      // this creates a sessions then redirects to home page
      req.session.authenticated = true;
      req.session.name = name;
      req.session.email = email;
      req.session.user_type = "user";
      res.redirect("/"); 
    } catch (error) {
      console.error("Error during signup:", error);
      res.render("signup", { error: "An error occurred during signup. Please try again." });
    }
  });

// login page
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// login form submission
app.post('/login', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
  
    try {
      // joi validation
      const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
      });
    
      const validationResult = schema.validate({ email, password });
      if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("login", { error: "Invalid email or password format." });
        return;
      }
    
      // find user in user collection by their email
      const user = await userCollection.findOne({ email: email });
      
      if (!user) {
        res.render("login", { error: "User and password not found." });
        return;
      }
      
      // compare passwords and checks if they match
      const passwordMatch = await bcrypt.compare(password, user.password);
      
      if (passwordMatch) {
        // creates a session with user info
        req.session.authenticated = true;
        req.session.name = user.name;
        req.session.email = user.email;
        req.session.user_type = user.user_type || "user";
        res.redirect("/");
      } else {
        res.render("login", { error: "User and password not found." });
      }
    } catch (error) {
      console.error("Error during login:", error);
      res.render("login", { error: "An error occurred during login. Please try again." });
    }
  });

// logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Admin page
app.get("/admin", adminAuthorization, async (req, res) => {
  try {
    const users = await userCollection.find().project({name: 1, email: 1, user_type: 1, _id: 1}).toArray();
    
    const user = {
      name: req.session.name,
      email: req.session.email,
      user_type: req.session.user_type
    };
    
    res.render("admin", { users: users, user: user });
  } catch (error) {
    console.error("Error in admin page:", error);
    res.render("404", { 
      message: "An error occurred loading the admin page.",
      user: req.session.authenticated ? {
        name: req.session.name,
        email: req.session.email,
        user_type: req.session.user_type
      } : null 
    });
  }
});

// promote to admin
app.post("/promote", adminAuthorization, async (req, res) => {
  try {
    const { email } = req.body;
    await userCollection.updateOne(
      { email: email }, 
      { $set: { user_type: "admin" } }
    );
    res.redirect("/admin");
  } catch (error) {
    console.error("Error promoting user:", error);
    res.render("404", { 
      message: "An error occurred while promoting the user.",
      user: req.session.authenticated ? {
        name: req.session.name,
        email: req.session.email,
        user_type: req.session.user_type
      } : null 
    });
  }
});

// demote to normal
app.post("/demote", adminAuthorization, async (req, res) => {
  try {
    const { email } = req.body;

    if (req.session.email === email) {
      return res.render("404", { 
        message: "You cannot demote yourself.",
        user: req.session.authenticated ? {
          name: req.session.name,
          email: req.session.email,
          user_type: req.session.user_type
        } : null 
      });
    }

    await userCollection.updateOne(
      { email: email }, 
      { $set: { user_type: "user" } }
    );
    res.redirect("/admin");
  } catch (error) {
    console.error("Error demoting user:", error);
    res.render("404", { 
      message: "An error occurred while demoting the user.",
      user: req.session.authenticated ? {
        name: req.session.name,
        email: req.session.email,
        user_type: req.session.user_type
      } : null 
    });
  }
});

// Members page
app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
      res.redirect("/");
      return;
    }
    
    // array for images
    const images = [
      "banana.gif", 
      "spin.gif", 
      "huh.gif"
    ];
    
    const user = {
      name: req.session.name,
      email: req.session.email,
      user_type: req.session.user_type
    };
    
    res.render("members", { user: user, images: images });
  });

// 404 error handler
app.use((req, res) => {
  res.status(404).render("404", { user: req.session.authenticated ? {
    name: req.session.name,
    email: req.session.email,
    user_type: req.session.user_type
  } : null });
});

// port listen
app.listen(PORT, () => {
  console.log("Node application listening on port " + PORT);
});