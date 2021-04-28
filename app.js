
//cookies get stored on browsers
require('dotenv').config(); //,config() lets it access our variables that were created in .env
const express=require("express"); //hashing is one step safer than .env vars. Hashing, gets rid of encryption keeys. This is the history of Internet Security. 
const bodyParser=require("body-parser");//thee reason why hash is more secure is because of its irreversible mathematical function equations. 
const ejs=require("ejs"); // Registered-hash-password is compared to Login-hash-password to seek a match,
const mongoose = require("mongoose");
const session = require('express-session'); //keyword her to be used for code is 'session'
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate'); //fixing googles madeup function of findOrCreate
const app = express();

console.log(process.env.API_KEY);//we will TAP INTO the .env variables by referring to them 
app.use(express.static("public"));// we need a key to crypt and another key to decrypyt
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({//package is called session. package from npm
    secret: "Our little secret.",          //js object with properties: secret, which is a string that we will keep secret in our env file
    resave: false, // config steps
    saveUninitialized: false //u can read more on this on docs since it has to do with cookies and regulation
    }));  
app.use(passport.initialize());//initiliaze passport package
app.use(passport.session());// telling app to use passport to set up session. telling passport to deal with the session login
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});//connecting mongoose to mondoDB. name our database will be userDB
mongoose.set("useCreateIndex", true);//solving deprecating warning. 
const userSchema = new mongoose.Schema({ //we are always updating the schema depedngin on what data we want to be fetching
    email: String, 
    password: String, 
    googleId: String,
    secret: String   //secret submmited at submit 
});//settin up our new user databsase. this is an object created from the mongose schema class. adding the googleID so it makes a match with googles own ID in our db. 

//this is the KEY to encrypt the db. you moved it to your .env file (envuronmental variables for encrytption) ppl also take advatage of API keys. keep all your keys off the internet


//REMOVED.  using secret right above to encypt our schema, and we don that by defining our schema that we defined just a few lines above. passing over our secret as a js object. addin mongoose plug in to schema. its important to add plug in before mongoose model. we are only enctypting password and not email, so we dont ahve to encrypt the whole db, theres a crypting and decypting process process. mongoose encypts ur password once you create it at login, but decrypts it at end when it needs to find a match at db. 

userSchema.plugin(passportLocalMongoose);//tapping into mangoose schema. using this to salt and hash our passwords and save users via mongo db
userSchema.plugin(findOrCreate); //having to add plugin for fixing gogoles pseudo method findOrCreate ()
const User = new mongoose.model("User", userSchema);//using userSchema to set up model. name of our collection is "User"

passport.serializeUser(function(user, done) {; //REPLACED from passport docs so it can work w google authentication. so I just copy and pasted this.  authenticating users and passwords. serializing is only necessary when using sessions. serializing creates the cookies and stores the user info/identification inside (like  fortune cookie) so we can authenticate them in our server. 
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


passport.use(new GoogleStrategy({ //configuration setup
    clientID: process.env.CLIENT_ID, //being collected from .env file
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //adding this from github to fix google plus issues bug. so it wont pull data gfrom google plus but from userinfo
  },
  function(accessToken, refreshToken, profile, cb) {// google sending back an access token which allows us to get data on that user. ther refreshtoken lets us use users data for a long period of time. 
    console.log(profile);// so theres 2 IDs at play here. one for our db and the other createc by googel
    User.findOrCreate({ googleId: profile.id }, function (err, user) { //profile contains email and google id. find user with that googleID or create one. after authentication by google, it will attempt to create user in db after authentication so it can pair up(not create new ID) with our id our db
      return cb(err, user);
    });
  }
)); 

app.get("/",(req,res)=>{
    res.render("home");
});


app.get("/auth/google", //get route for google button. you will see this same path on the register.ejs and login.ejs
   passport.authenticate("google", {scope: ["profile"]})//'google' is googles servers where the auth initiation happens, asking google for users profile once logged in. this creates the google pop up for them to sign in . profile is the users. googled id and email is all inside this profile. inside our callbackl is where we are going to inititate our authentication w google. identifying type of strategy(google strategy we declared above) we want to authenticate our user with. passport library is very flexible as b4 we used local auth. scope object was copied from the passprot docs
);

app.get("/auth/google/secrets", // this is what we provided when we created the URI on google cloud console. this get method code was grabbed form passport docs
  passport.authenticate('google', { failureRedirect: "/login" }), //authenticating locally and checking for err. redirect them to login if auth fails. authenticating locally and saving session
  function(req, res) {
   
    res.redirect("/secrets"); // if auth is good then send here
  });


app.get("/login",(req,res)=>{
    res.render("login");
});
app.get("/register",(req,res)=>{
    res.render("register");
});
 
app.get("/secrets", (req, res)=>{//UPDATED/REMOVEDcreating secrets route. checking to see if user is authenticated. alos so no one can just directly land on this page without being authenticated. but if they not logged in, we gonna redirect them to login page. 
    User.find({"secret": {$ne: null}}, (err, foundUsers) => { // looks like 'foundUsers' was first defined here. callback for any error OR foundusers/ this will look through all the users. we are not checking to see if ppl are authenticated, anyone can post. Instead we gonna troll through db and c all secrets posted-so gonna load all users that have a secret field with a value. mongoose docs: 'ne'= not equal, making sure secrets field is not null.  conditions are inside the curly braces.
            if(err) {
                console.log(err);
            } else { 
                 if (foundUsers) {       //  ANGELA HAS A FINSIHED VERSION OF THIS RIGHT BEFORE THE INTRO TO REACT MODULES
                res.render("secrets",{usersWithSecrets: foundUsers}) ;//'ussersWithSecrets' will be picked up/used at our secrets.ejs.  at we are passing in a variable we initially defined here 'usersWithSecrets'. the value for this var is 'foundUsers'-which was intitially defined a few lines above. 
            }
        }
    });
});

app.get("/submit", (req, res)=>{//sidenote: local users are the people saved to our local db. 
    if (req.isAuthenticated()){
        res.render("secrets");
    }else {
        res.redirect("/login");
    }
});

app.post("/submit", (req, res)=>{ // the reason this is a post is beacause the submit page is submiting a button, so the form makes a post to the submit route
      const submittedSecret = req.body.secret ; //this 'secret' is the field that was created in the schema. this is where we are going to save the secret submitted. 'secret' comes from 
      console.log (req.user.id);//this id refers to the id we have in our mongoose db. this is user making post request. finding user and attching that secret to their profile. passport will save users details/session in the 'req' variable. 

User.findById(req.user.id, (err, foundUser)=>{  //assumung foundUser was first defined here. tapping into user model. once we find user, we might get an error or we may get a found user-thats whats happening inside the call back-IMPORTANT
    if(err){
        console.log(err);
        } else {
        if (foundUser)  { //if founduser did indeed exist
        foundUser.secret = submittedSecret;//setting the foundUsers secret field = to the submittedSecret/  we declared 'submittesSecret inside this route
    foundUser.save(function(){ // saving new updated secret to this founduser. Once the save has completed (this is the callback)
res.redirect("/secrets")//user will be rdirected to all users secrets. 
    });
}
    }
});
});

app.get("/logout", (req,res) =>  { // deauthenticating user to end their session
        req.logout();
        res.redirect("/");
});


 app.post("/register", (req, res) => { //catching post requests made by client when hitting the submit button on w user. 'username' and 'password' are from the input form in register.ejs
    User.register({username: req.body.username}, req.body.password, function(err, user){     //registering users. the callback with either return an error or a user.register() comes from the mongoose-local package. 
        if(err) {
            console.log(err);
            res.redirect("/register"); 
        
        }else { // if auth is successful then a cookie with their login is saved
        passport.authenticate("local")(req,res, function(){  //this callback will only be triggered if authentication was succesful. //if there were no errors then we are going to authenticate our users. the type of authentication we are performing is local
            res.redirect("/secrets");
});
        }
    });


});

app.post("/login", (req, res) => {
     const user = new User({ //new user created from our mongoose model User.
              username: req.body.username, //this user will have 2 properties.  username is coming from req.body.username
            password: req.body.password// this all comes from the login form 
     
        });


        req.login(user, (err)=> {//this call back is in case for error when we cannot finder user in db
     if (err) {     //we are passing in three new users credentials that was just created. using passport to login user we just created. login() comes from passport docs. 
 console.log(err);
     }           else {
         passport.authenticate("local")(req,res,function(){   // if no errors, then auth the user
   res.redirect("/secrets");
     
        });
    }
    });
});

app.listen(3000,function(){
    console.log("Server Started on port 3000");
}); // in hacking, step one is gaining access to a companies database. 
// hashing is a level up from encryption. encryption is just adding a key to the password using certain methods such as cipher, etc. 