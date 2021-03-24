const router = require("express").Router();
const { checkUsernameExists, validateRoleName, buildToken } = require('./auth-middleware');
const User = require('../users/users-model')
const bcryptjs = require("bcryptjs");

router.post("/register", validateRoleName, (req, res, next) => {
  const {username, password} = req.body
    const hash = bcryptjs.hashSync(password, 10)
  const hashedUser = {username, role_name: req.role_name, password: hash}
  User.add(hashedUser)
  .then((user) => {
    res.status(201).json(user)
  })
  .catch(next)
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const {username, password} = req.body
  User.findBy({username:username}).first()
  .then((user) => {
    if(user && bcryptjs.compareSync(password, user.password))
    {
      const token = buildToken(user)
      res.json({message:`${username} is back!`, token})
    }
    else
    {
      res.status(401).json({ message: "Invalid credentials" });
    }
  })
  .catch(next)
});

module.exports = router;
