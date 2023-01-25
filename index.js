const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const { User, Kitten } = require('./db');
const { reset } = require('nodemon');
require('dotenv').config();

const SALT_ROUNDS = 10;

app.use(express.json());
app.use(express.urlencoded({extended:true}));

// Verifies token with jwt.verify and sets req.user
// TODO - Create authentication middleware
const setUser = async (req, res, next) => {
  
    //get the authorization header, so we can compare to our token
    const auth = req.header('Authorization');

    //no auth header, no token!!
    if(!auth){
      next();
    }else{
      //the second part of the string is our token, we can decode this with our JWT_SECRET
      //and store it as use info for the next function to use
      //if it is invalide user data, verify will throw an error!!
      const [, token] = auth.split(' ');
      const user = jwt.verify(token, process.env.JWT_SECRET);
      req.user = user;
      next();
    }
};


app.get('/', async (req, res, next) => {
  try {
    res.send(`
      <h1>Welcome to Cyber Kittens!</h1>
      <p>Cats are available at <a href="/kittens/1">/kittens/:id</a></p>
      <p>Create a new cat at <b><code>POST /kittens</code></b> and delete one at <b><code>DELETE /kittens/:id</code></b></p>
      <p>Log in via POST /login or register via POST /register</p>
    `);
  } catch (error) {
    console.error(error);
    next(error)
  }
});



// POST /register
// OPTIONAL - takes req.body of {username, password} and creates a new user with the hashed password
app.post('/register', async (req, res, next) => {
  
  try {
    
    const {username, password} = req.body;

    hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    let {id, username:createdUsername} = await User.create({username:username, password:hashedPassword});
    let token = jwt.sign({id, createdUsername}, process.env.JWT_SECRET);
    res.send({message: "success", token: token});

  } catch (error) {
    res.send(error);
  }
  
})


// POST /login
// OPTIONAL - takes req.body of {username, password}, finds user by username, and compares the password with the hashed version from the DB
app.post('/login', async (req, res, next) => {
  try {

    const {id, username, password} = await User.findOne({where: {username: req.body.username}});

    if(id){
      const isMatch = await bcrypt.compare(req.body.password, password);
      if(isMatch){
        let token = jwt.sign({id, username}, process.env.JWT_SECRET);
        res.send({message: "success", token: token});

      }else{
        res.status(401).send("Unauthorized");
      }
    }else{
      res.status(401).send("Unauthorized");
    }
  } catch (error) {
    res.send(error);
  }
})


// GET /kittens/:id
// TODO - takes an id and returns the cat with that id
//We need to use our middleware here to determine the user owns the kitten
app.get('/kittens/:id', setUser, async (req, res, next) => {
  if(!req.user){
    res.sendStatus(401);
  }else{
    try {
      const foundKitten = await Kitten.findByPk(req.params.id);
        if(foundKitten.ownerId === req.user.id){
          res.send({age:foundKitten.age, color:foundKitten.color, name:foundKitten.name});
        }else{
          res.send(401);
        }
      
    } catch (error) {
      console.log(error);
    }
  }
  
})

// POST /kittens
// TODO - takes req.body of {name, age, color} and creates a new cat with the given name, age, and color
app.post('/kittens', setUser,async (req, res, next) => {
  if(!req.user){
    res.sendStatus(401);
  }else{
    try {
      const newKitten = await Kitten.create({name:req.body.name, age:req.body.age, color:req.body.color, ownerId: req.user.id});
      res.status(201).send({age:newKitten.age, color:newKitten.color, name:newKitten.name});
    } catch (error) {
      res.send(error);
    }
  }
})


// DELETE /kittens/:id
// TODO - takes an id and deletes the cat with that id
app.delete('/kittens/:id', setUser, async (req, res, next) => {
  if(!req.user){
    res.sendStatus(401);
  }else{
    try {
      const foundKitten = await Kitten.findByPk(req.params.id);
        if(foundKitten.ownerId === req.user.id){
          await foundKitten.destroy();
          res.status(204).send({message:"success"});
        }else{
          res.send(401);
        }
      
    } catch (error) {
      console.log(error);
    }
  }
})


// error handling middleware, so failed tests receive them
app.use((error, req, res, next) => {
  console.error('SERVER ERROR: ', error);
  if(res.statusCode < 400) res.status(500);
  res.send({error: error.message, name: error.name, message: error.message});
});

// we export the app, not listening in here, so that we can run tests
module.exports = app;
