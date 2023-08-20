 - [Level 1](#level-1---register-users-with-username-and-password)
 - [Level 2](#level-2---database-encryption)
   - [Env Variables](#using-environment-variables-to-keep-secrets-safe)
 - [Level 3](#level-3---hashing-passwords)
 - [Level 4](#level-4---salting-and-hashing-passwords-with-bcrypt)
 - [Level 5](#level-5---cookies-and-sessions)
 - [Level 6](#level-6---oauth-20--how-to-implement-sign-in-with-google)
   - [OAuth Granular Access Level](#oauth---granular-access-levels)
   - [Read/Read+Write Access](#readread-write-access)
   - [Revoke Access](#revoke-access)
   - [Adding OAuth to Our Code](#adding-oauth-into-our-code)
 - [Letting Users Submit Secrets](#adding-functionality---letting-users-submit-secrets)
 - [Screenshots](#screenshots)

# Authentication
If we deploy our web application then users might start using it, they may create posts and like other's posts. To make sure we encapsulate their actions to only themselves we need to give them an account which they can sign in to with a username and password. This also helps if the user has the ability to send private messages they may not want others to see.  
Or if we want to restrict users from certain actions/areas of the website

While explaining what the different levels of Authentication are we will be coding a simple registration page where users can Register, Login, Logout and post their secrets anonymously!  

## Level 1 - Register Users with Username and Password
On level 1 we must create an account for the user, storing their email and password in our database so they may login whenever they want if their login credentials match.  
To begin, as usual, we declare a schema for our new table in the database: 
```js
const userSchema = {
    email: String,
    password: String
};
const User = mongoose.model("User", userSchema);
```
The user by default will find themselves in the "/" root route which is rendering the "Home.ejs" page :  
```js
app.get("/", function (req, res) {
    res.render("Home");
});
```
The Home page has two links, one leads to the Registration page and the other to the Login page. We will focus on the Registration for now.  
When the user clicks on "Register" he will be sent here : 
```js
app.get("/register", function (req, res) {
    res.render("Register");
});
```
Which renders the "Register.ejs" page. In this page exists a form that targets the /register with a POST request and the data that this form can send over is "username" and "password" (the username is an email input type). We can create a new Document with that data :  
```js
app.post("/register", function (req, res) {
    const registerUser = new User({
        email: req.body.username,
        password: req.body.password
    });
    registerUser.save(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.render("secrets");
        }
    });
});
```
If the new username and password got saved successfully then the page "secrets.ejs" will be rendered. Note that we do not have an app.get that leads to this page, this is done purposefully so the user cannot write websitename.com/secrets and view the page by sending a GET request to it.  
So the "secrets.ejs" page can only be rendered if the user creates an account.  

Now when the user clicks on Login and enters those credentials again we need to check if there is a user with that username (email) and if yes then we check if the password entered is the same as the one existing in the found Document :   
```js
app.post("/login", function (req, res) {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({ email: username }, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                if (foundUser.password === password) {
                    res.render("secrets");
                }
            }
        }
    });
});
```
If everything was entered correctly then the "secrets.ejs" page will get rendered.  


## Level 2 - Database Encryption
*Now, what if an employee/hacker just looks into the database and sees all of the passwords and usernames? They can do so because they are being shown as plain readable text.*  
This is where the level 2 security comes in, the Database Encryption.  
What encryption does generally is scramble your original message using a specific Cipher Method and require a key to unscramble it back to the original message.  
Since we are using the mongoose package we will be using the [mongoose-encryption package](https://www.npmjs.com/package/mongoose-encryption) to encrypt our text.  
For this to work we need to change our Schema a little bit as per shown in the documentation of the package :
```js
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});
```
We will need to define a secret string that is unguessable which we will use to encrypt our database, the syntax is this :  
```js
var secret = process.env.SOME_LONG_UNGUESSABLE_STRING;
userSchema.plugin(encrypt, { secret: secret });
```
implemented into our code :
```js
const secret ="Thisisourlittlesecret.";
userSchema.plugin(encrypt, { secret: secret });
```
Note: for this to work it must be put before our Model declaration since it uses the userSchema.  
Now we will only be encrypting the password, to encrypt only specific items in a document we can use this syntax from the documentation : 
```js
// encrypt age regardless of any other options. name and _id will be left unencrypted
userSchema.plugin(encrypt, { encryptionKey: encKey, signingKey: sigKey, encryptedFields: ['age'] });
```
Implemented into our code:
```js
userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password'] });
```
mongoose-encrypt will encrypt our data when we call .save() function and it will decrypt when we use the find() function.  
If we register a new user and try to view their password in our database this is what we will see : 
![](https://media.discordapp.net/attachments/1141016274160328756/1141761502794231918/Screenshot_17.png)

### Using Environment Variables to Keep Secrets Safe
Our next security problem is that our secret word is within our app.js and anyone can access the page's source code and find it. A hacker could find our app.js with our secret word and use the same package as us to decrypt all of the password.  
To store these secret Variables while also be able to share them with our coworkers working on the same project we will need to use Environment Variables, a popular package for Env Variables is ["dotenv"](https://www.npmjs.com/package/dotenv).    
After installing the dotenv package we must require it on top of all of our code as the documentation asks :
```js
require('dotenv').config();
```
We are not assigning it to a variable because we just need to require it and will never use it in our code.   
The next step is to create a .env file in our root directory. So from our terminal we type the command `touch .env` just like .bash_profile this is a hidden file. As for the variables to put inside of this .env file they must follow this syntax `NAME=VALUE`. Following this syntax our Js Variable will go from 
```js
const secret ="Thisisourlittlesecret.";
``` 
to 
```env
SECRET=Thisisourlittlesecret.
``` 
within the .env file.  
We can now console log this env variable following the syntax shown in the documentation :
```js
console.log(process.env.SECRET);
```
With this in mind we also need to modify our code wherever we used the old Js secret variable to the new env SECRET variable: 
```js
userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });
```

## Level 3 - Hashing Passwords
Having an encryption key can make the decryption process possible for anyone who spends enough time trying to figure it out. This is where Hashing Passwords comes in. With Hashing Passwords we do not require a key to encrypt our text anymore. Once the text is encrypted is almost impossible to go back and decrypt it because there is no key to help us achieve that. To Hash a Password takes a few milliseconds but to decrypt it could take up to 2 years, which makes it less likely for a hacker to want to do so.  
The user obviously won't enter their encrypted version of their password so if we want to compare whether the password entered by the user is the same as his registration password we must hash the password they entered and compare it to the hashed password in our Database.  

A popular package that we can use to implement the Hash Passwords is ["md5"](https://www.npmjs.com/package/md5)  
If we're going to Hash our Data then we do not need the previous Encryption method anymore and can go ahead and delete the lines of code associated with the "mongoose-encryption" package:
```js
const encrypt = require("mongoose-encryption");
userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });
```
Now we can very cleverly immediately convert the password the user registers with into a Hash code 
```js
const registerUser = new User({
        email: req.body.username,
        password: md5(req.body.password)
    });
```
Now, because a certain word's hash is always the same, for example if we hash the word "123123" the output will always be the same even if we hash 123123 again.  
With this in mind we can compare the hashed version of the password with the hashed version of the entered password to check if the user entered the correct password in the Login:  
```js
app.post("/login", function (req, res) {
    const username = req.body.username;
    const password = md5(req.body.password);

    User.findOne({ email: username }, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                if (foundUser.password === password) {
                    res.render("secrets");
                }
            }
        }
    });
});
```

## Level 4 - Salting and Hashing Passwords with bcrypt
*On this fun website [Plain Text Offenders](https://plaintextoffenders.com/) we can see the websites that do not Hash or Encrypt their user's passwords in any way. 
You can also check on this website ["Have I been pwned?"](https://haveibeenpwned.com/) to check if passwords associated with your email have been hacked.* 

The security problem with Hash is that when a hacker gets the data in our Database they can start doing a "Hash Table" where they Hash many different common passwords/dictionay words until they find a match with the passwords in the Database
![](https://media.discordapp.net/attachments/1141016274160328756/1142157243798790255/Screenshot_1.png)

*To fix this Hash security issue we could suggest to the user to use numbers, upper case, lower case, a long password, letters and symbols in their password creation.  
You can check how strong your password is on [this website](http://password-checker.online-domain-tools.com/) and it also tells you how long a computer would take to crack it down.*

To actually fix this Security vulnerability is to use **Salting**.  
What Salting does is add a few random characters at the end of the user created password to add more complexety before the password gets Hashed.  
But we're still not quite there yet because if a hacker tries the most common password combinations + Salting combinations and Hashes it, with the newest GPUs out there it will still take not a very long time for them to crack down the password.  
We can use another Hashing algorithm together with the md5, this Hashing algorithm is called "**bcrypt**".  
Because meanwhile a good GPU can decrypt 20,000,000,000 MD5 Hashes/second it can only decrypt 17,000 bcrypt Hashes/second.  
We can also do more than one **Salt Round**, in one salt round we add a random set of characters at the end of the user's password (salting) and then Hash it with bcrypt, we can then add another set of Salt characters at the end of the Hashed password and repeat this process (Rounds) to make it more secure.  
As CPUs become faster our Salt Rounds should also increase. 


We will be using the bcrypt package ["bcrypt"](https://www.npmjs.com/package/bcrypt)   
Because this package is very picky on which node version we are running, we can use something called [nvm](https://github.com/nvm-sh/nvm), we install it by running the command given in the github repo
```
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.4/install.sh | bash
```
If you have issues installing bcrypt then try downgrading your node version with nvm, you just need to specify which version you need :
```
nvm install 12.3.1
```
After installing all the dependencies for bcrypt 😭😭😭 you can finally run
```
npm i bcrypt@3.0.6
```
This is the syntax from the documentation they suggest we use
```js
const bcrypt = require('bcrypt');
const saltRounds = 10;
const myPlaintextPassword = 's0/\/\P4$$w0rD';

bcrypt.hash(myPlaintextPassword, saltRounds, function(err, hash) {
    // Store hash in your password DB.
});
```
Let's put this into our code:
```js
app.post("/register", function (req, res) {

    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {

        const registerUser = new User({
            email: req.body.username,
            password: hash
        });
        registerUser.save(function (err) {
            if (err) {
                console.log(err);
            } else {
                res.render("secrets");
            }
        });

    });

});
```
In the code above what changed is :
 - We are Hashing through bcrypt the password our user has entered to register with and we are passing in how many salt rounds he should do, then that new Hashed and Round Salted password gets stored in `hash`.  
 - We are now saving the Hashed Salted version of the user's password in our database.   

*Since we're going to use **bcrypt** as our Hash we have to *remove* **md5** which was our older Hash package.*    

Now that the user has registered and their password is safely stored how can we access that password so we can check that it is the same as the one the user is trying to Login with? The syntax from the `bcrypt`'s docs is:
```js
// Load hash from your password DB.
bcrypt.compare(myPlaintextPassword, hash, function(err, result) {
    // result == true
});
```
Applied to our code :
```js
app.post("/login", function (req, res) {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({ email: username }, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                bcrypt.compare(password, foundUser.password, function (err, result) {
                    if (result == true) {
                        res.render("secrets");
                    }
                });
            }
        }
    });
});
```
We are checking to see :
 - If there is a user with that email in our Database
 - If yes and no errors then we use bcrypt's compare method to compare the `password` our user has entered against the hashed one from our Database `foundUser.password`
 - If the result returns a boolean of True then it's a match and the user should be allowed to see the "secrets.ejs" page


## Level 5 - Cookies and Sessions
How can we remember what an user was up to so they dont lose all of their progress on our website?  
*For example, if an user hasn't logged in on their amazon account but decides to add a Nintendo Switch to their cart because they want to buy it but then get distracted and click on a different website, amazon needs to remember that the user added a Nintendo Switch to their cart so the next time they come back they can resume and buy it.*  
To fix this amazon, like many other websites, will create a **cookie** and store it on your browser.  
*When we make a GET request to the amazon servers then they send us back their html/css/js etc... if while interacting with their page we make a POST request containing information on something we want to buy then our data can be saved in a cookie and the next time we make a GET request to their servers we will also be sending them our cookie which will be opened and read so the amazon page can be rendered specifically for us depending on our past interactions with their website*.   

*The cookie that we will be looking at is called a **Session Cookie**, they are responsible for estabishing and maintaining a session. A session is a period of time when a browser interacts with a server. This Session Cookie gets created when we Log In successfully and maintains our session until we log out.*  
We will be using [passport](https://www.passportjs.org/) which is a simple package made for Express.js.  
To make the passport package work we will need to install all of the following packages : 
```
npm i passport passport-local passport-local-mongoose express-session
```
We can go ahead and delete any code associated with the bcrypt package for Hashing. We will be using passport for Hashing/Salting/Authentication.  
If we go on each of those package's documentation then we will know how to require them 
```js
const session = require("express-session");
const passport= require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
```

On the [express-session](https://www.npmjs.com/package/express-session)'s documentation, for opening a session they give this syntax to follow:
```js
app.use(session({
  secret: 'This is our little secret.',
  resave: false,
  saveUninitialized: false
}))
```
Which is basically the package's name and a Javacsript object to which pass the secret word for the Hashing which we will later on convert into an env variable and some other configurations.  
We now need to tell our app to use passport and to use passport to deal with our session.   
```js
app.use(passport.initialize());
app.use(passport.session());
```
Note: both of these two pieces of code, the one which sets our secret word and the one above must be put between our mongoose.connect and the app.use and app.set declared previously.  

Now it's time to set up our last package: [Passport-Local Mongoose](https://www.npmjs.com/package/passport-local-mongoose).  
You have to of declared a Schema with this following syntax:
```js
const userSchema = new mongoose.Schema({});
```
and right below our Schema we have to declare the plugin:
```js
userSchema.plugin(passportLocalMongoose);
```
`passportLocalMongoose` is what we'll use to Hash and Salt our passwords
Now we just need to configure the passport-local configurations. This is the syntax: 
```js
const User = require('./models/user');

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
```
`serialize` and `deserialize` are only necessary when we use sessions. They are what start the Session Cookie and store the user's identification inside. When we run `deserialize` we destroy the cookie.   
So right below our already declared model we only need to paste these two lines of code 
```js
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
```

Now that we've done all of the configurations, we can finally use the Hashing and Salting for the password in the registration section
```js
app.post("/register", function (req, res) {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })

});
```
In the code above: 
 - We are tapping into the user model and using the register method (from passport-local mongoose) thanks to it we do not need to create a new user/save them, it will do it for us.
 - The register method accepts an user username (in our case an email) and a password and it has a callback function which may return an error or a user if everything worked
 - If there were errors then we will redirect the user back to the Register page
 - If no errors found then we go ahead and authenticate the user with a local authentication type and a callback function which only gets triggered if the authentication was successful. Knowing this we can safely res.redirect to the secrets's page route.

Before this piece of code we never had a res.redirect to a secrets route because we relied on rendering it in the login and register post's. We will need to create a route to the secrets page so the user can keep viewing it as long as their session cookie is valid :
```js
app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});
```
in the code above :
 - We check to see if the request is authenticated through the `isAuthenticated()` function, if yes then we will res.render the secrets.ejs page
 - If user is not authenticated to view this route then we will redirect them to the /login route

 Now if the user Registers he will be automatically logged in and even if they go back into the home page and try to access the "secrets" route manually they will still be logged in because they are already authenticated thanks to the Session Cookie which stores that data. As long as we dont restart our server or our browser the session will remain alive.  

If that happens and the user wants to be able to **Login** back into their account then we can use a passport function called "`login()`" to do so.  
It has to be called on the **request** object and this function takes as it's first parameter the user that we are trying to log in and a callback function which gives an error if there were any errors.  
If no errors found then we go ahead and authenticate the user with a local authentication type and a callback function which only gets triggered if the authentication was successful. Knowing this we can safely res.redirect to the secrets's page route.
 ```js
 app.post("/login", function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.log(user, function(err){
        if(err){
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });

});
```

Now we just need to add a Log out option too : 
```js
app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});
```
In the code above we :
 - Deauthenticate our user through passport's `req.logout()` when they are making a GET request to the /logout route
 - If no errors then user is redirected to the Home page


Now the user is able to successfully :
- Register
- Login
- Stay logged in after Registration/Login
- Logout

## Level 6 - OAuth 2.0 & How to Implement Sign In with Google
Third Party OAuth, Open Authorization allows a user to access our website with their eg. Facebook account and give us the data we need, maybe the friends they have and compare to see if any of them are already users of our website. This way if a new user signs up to our website they will already have friends. Depending on what data Facebook wishes to provide when a user decides to OAuth on an external website with their website, we can tap into that information and use it in any way we please. For example we could compare the given data to our Database and see if there were any matching friend names or emails that already exist.  
This is also helpful because we leave the password Hashing and Salting to those big giant companies that also Pepper their entire database in encryption among other mathematical solutions to keep their user passwords safe. 
We can also leave the Authentication to the big tech companies if we use a 3rd party OAuth.  
We can achieve this Authentication by other popular websites like Facebook, Twitter, google etc... by using OAuth.  
### OAuth - Granular Access Levels
We can specify what type of information we are requiring from their previous user's account. The Developer can determine what user data they need from the user's Facebook account for eg.
### Read/Read+ Write Access
As a Developer you can ask to Read only access, so only retrieve pieces of information or you could ask for Write access as well
### Revoke Access
If for eg. you are Authenticating with Facebook then the user should be able to go into their Facebook account and deauthorize the access that they granted to your website

To setup the OAuth for our website we have to tell the 3rd party app of Facebook or Google (for eg.) about our application. So we have to set up our App in their developer console.  
When the user tries to Login or Register using their Facebook account they will be taken to the Facebook login page, after logging in they will be reviewing the permissions that we are asking for.  
When they log in successfully and accept the read/read+write requests then Facebook will generate an "Auth Code" which helps us to check that the user has actually successfully signed on Facebook.  
If you wish to request from information from the user accessing your App through an OAuth then you can ask back for something called an "Access Token".  

## Adding OAuth Into Our Code
To start implemeting OAuth like Google's we can go into the passport's ["Strategies" documentation](https://www.passportjs.org/packages/) and we'll be selecting the [passport-google-oauth20](https://www.passportjs.org/packages/passport-google-oauth20/) and we can go ahead and install it 
```
npm install passport-google-oauth20
```
While it's installing we can go ahead and use the [Google Developers Console](https://console.cloud.google.com/projectselector2/apis/dashboard?supportedpurview=project) as per suggested in the Documentation and create a "new project"   
![](https://media.discordapp.net/attachments/1141016274160328756/1142489075975196682/Screenshot_2.png)
I called it "Secret". We then go ahead and navigate our way into the "OAuth Consent Screen" tab. We can add a name for our App, a logo and most importantly in the Scopes is where we get to choose which information to access from our user. To enable some specific scopes you might need to implement specific Google API libraries. We won't need to since we will only be requiring basic user information such as "Email, profile and id". For now we won't be touching the domain link because our website is not live yet.  
![](https://media.discordapp.net/attachments/1141016274160328756/1142501716907012127/Screenshot_3.png)
Then we need to add OAuth client ID which is what will allow the users to be Authenticated, we are a Web Application with name "Secrets" and the Authorized JavaScript origin is `http://localhost:3000` which is ment for testing, when our website is live we can come back to update this line. Authorized Redirect URIs is where Google redirects the user to after a successful authentication, for us it's `http://localhost:3000/auth/google/secrets`  
![](https://media.discordapp.net/attachments/1141016274160328756/1142501716596637777/Screenshot_4.png?width=397&height=676)  
At the end of this Google will give us a very important Client ID and Client secret, we have to copy both of them and put them inside of our env file :
```env
CLIENT_ID=youclientidgoeshere
CLIENT_SECRET=yourclientsecretgoeshere
```
Now we can go ahead and follow the "Configure Strategy" part of the passport's Documentation

```js
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
```
note: code must be below the sessions (serialization)
What the code above does is:
 - We use passport to Authenticate our user using Google OAuth *(Requests an authentication at Google)*;
 - Give the `clientID` the value of `CLIENT_ID` from the env file and the `clientSecret` the `CLIENT_SECRET`;
 - We add in the same callback URL as the one from the *Authorized Redirect URIs*;
 - Retrieves the user information not from the Google+ account anymore (depricated) but from the user info which is another endpoint of Google's;
 - After adding all the strategies to log in our user and once that is gone through we have a callback function which is where Google sends back an "access token" and "refreshToken" (allows us to get data related to the user), "profile" (which contains emails/google id) and we use the `googleId` to either `findOrCreate` a user in our Database of Users.  
 `findOrCreate` is pseudocode, which means it doesnt really exist, passport added it to tell us to implement some sort of functionality that can find or create a user. 
 You can do really complex things with it thanks to a person who has kindly made a library by that name for this very use. Documentation [here](https://www.npmjs.com/package/mongoose-findorcreate). 😥

```
npm i mongoose-findorcreate
```
We just need to requre it and add it as a plugin to our Schema:
```js
const findOrCreate = require('mongoose-findorcreate');
userSchema.plugin(findOrCreate);
```
Our issue now is that there is no way for us to click a button that has this functionality and can Register/Login with Google OAuth : 
```html
 <div class="col-sm-4">
      <div class="card social-block">
        <div class="card-body">
          <a class="btn btn-block" href="/auth/google" role="button">
            <i class="fab fa-google"></i>
            Sign Up with Google
          </a>
        </div>
      </div>
    </div>
```
Both these buttons are located in the Register and Login .ejs pages and both of them have an anchor tag which targets the /auth/google route with a GET request.

Now to make sure our user has been authenticated successfully we will use the passport's Google OAuth (view Authentication Requests in the documentation)
```js
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);
```
The code above: 
- We initiate Authentication with Google
- We use passport.authenticate with the "google" strategy(which we have set up in the previous code) unlike previously where we used the "local" strategy (passport is so flexible)
- When we hit up Google we are saying that the information that we want is the "profile" (which contains email/userid from Google) so we can identify them in the future

That piece of code should be enough to pop up a sign in google auth page

Once the user has been Authenticated successfully by Google OAuth then it will redirect the user automatically to "`http://localhost:3000/auth/google/secrets`" which means that after the user has been authenticated remotely by google we also have to authenticate them locally and save their login session cookie once they make a GET request to that route.  
In "Authentication Requests" from the documentation if we scroll we can see the syntax that allows us to do so.
```js
app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect('/secrets');
    });
```
- If there were any problems they will be sent to the Login page
- If everything worked okay then user is redirected to the "/secrets" route (GET Request to /secrets)

Help
![](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fimages-wixmp-ed30a86b8c4ca887773594c2.wixmp.com%2Ff%2Fcf971ad2-c812-4cc1-aa2e-5aef61ad7cf5%2Fdfcq06s-46dfb01b-95af-4f08-af85-0e190ea3937f.jpg%2Fv1%2Ffill%2Fw_1070%2Ch_747%2Cq_70%2Cstrp%2Frubber_by_goosewyre_dfcq06s-pre.jpg%3Ftoken%3DeyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1cm46YXBwOjdlMGQxODg5ODIyNjQzNzNhNWYwZDQxNWVhMGQyNmUwIiwiaXNzIjoidXJuOmFwcDo3ZTBkMTg4OTgyMjY0MzczYTVmMGQ0MTVlYTBkMjZlMCIsIm9iaiI6W1t7ImhlaWdodCI6Ijw9MTY2OCIsInBhdGgiOiJcL2ZcL2NmOTcxYWQyLWM4MTItNGNjMS1hYTJlLTVhZWY2MWFkN2NmNVwvZGZjcTA2cy00NmRmYjAxYi05NWFmLTRmMDgtYWY4NS0wZTE5MGVhMzkzN2YuanBnIiwid2lkdGgiOiI8PTIzODgifV1dLCJhdWQiOlsidXJuOnNlcnZpY2U6aW1hZ2Uub3BlcmF0aW9ucyJdfQ.cWfmK35kowantN2wLKE1vm2632wRaMcl6HQiD61gyiA&f=1&nofb=1&ipt=ffa6aa50bcfddf9c56395affecd879dcd1e65aa770a341735d854a6355723bbe&ipo=images)

Ahem...

So this code will still not work, because we are using the package passport-local mongoose's serialization/deserialization. We need to use passport's so it can word with any kind of Authentication :
We replace this
```js
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
```
with this
```js
passport.serializeUser(function(user, done){
    done(null, user.id);
});
passport.deserializeUser(function (id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});
```

Because google is giving us back a "profile" with an id of googleId we need to integrate that into our Schema in order to store it in our database and later on check if a user trying to login has that same googleId : 
```js
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});
```
thanks to that even if a user tries to accidentaly Register again with the same google account they will only be redirected instead


### Adding Functionality - Letting Users Submit Secrets
It's time to let the users submit their secrets on the submit.ejs page. First off just to see the page when there is a GET request to the /submit route :
```js
app.get("/submit", function(req, res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});
```
The same code as the app.get route for /secrets, we check if the user is authenticated in order to show/render the submit.ejs page otherwise they will be redirected to the /login route.  

When we tap into the `req.user` we can see that an _id and a username (email) gets printed identifying them, so with this in mind we are now sure that whenever a secret gets submitted only the logged in user will be the one submitting it. We can add it to their table in our Database, to do so we need to add a `secret: String` to our Schema.  
```js
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});
```
In the code below: 
- If user makes a post request to the /submit (from the submit.ejs form)
- We tap into an input with the name of secret
- We try to find a user with the id corrisponding to the one of the user in the session
- If there is a foundUser then we tap into their secret property and update it's value to the submitted secret
- foundUser's Document gets saved
- They get redirected to the /secrets route where they should be able to view all of the secrets
```js
app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets");
                })
            }
        }
    });
});
```

When the user gets redirected to the /secrets route and the secret.ejs page gets rendered, their secret is still not there. We need to render it.  
We can do that by using mongoose's property `db.mycollection.find({"IMAGE URL":{$ne:null}});`. I also want everybody to be able to see the /secrets route so I will remove the auth part : 
```js
app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", { usersWithSecrets: foundUsers });
            }
        }
    });
});
```
In the code above:  
- Upon GET request on /secrets 
- Find user that has property `secret` not null (using native mongo $ne)
- If foundUsers is true then render secret.ejs page and pass in the EJS usersWithSecrets which equals to foundUsers

We are passing the whole user Document that we find to the EJS scriptlet so we tap into it's user.secret property in the secrets.ejs page like this (with a foreach loop) :
```html
<% usersWithSecrets.forEach(function(user){ %>
        <p class="secret-text">
          <%=user.secret%>
        </p>
        <% }) %>
```



















# Screenshots
**Home Page**
![](https://media.discordapp.net/attachments/1141016274160328756/1142799203450503240/Home.png?width=1360&height=676)
**Register Page**
![](https://media.discordapp.net/attachments/1141016274160328756/1142799203177857045/Screenshot_2023-08-20_at_07-29-53_Secrets.png?width=1360&height=676)
**Login Page**
![](https://media.discordapp.net/attachments/1141016274160328756/1142799202871681206/Screenshot_2023-08-20_at_07-30-08_Secrets.png?width=1360&height=676)
**Secrets Page**
![](https://media.discordapp.net/attachments/1141016274160328756/1142799203693764718/Screenshot_2023-08-20_at_07-34-53_Secrets.png?width=1360&height=676)
**Submit Page**
![](https://media.discordapp.net/attachments/1141016274160328756/1142799204004135003/Screenshot_2023-08-20_at_07-35-02_Secrets.png?width=1360&height=676)
