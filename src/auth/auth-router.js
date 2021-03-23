const express = require('express');
const AuthService = require('./auth-service');
const { requireAuth } = require('../middleware/jwt-auth');

const authRouter = express.Router();
const jsonBodyParser = express.json();

authRouter
  .route('/token')
  .post(jsonBodyParser, (req, res, next) => {
    console.log(req.body);
    const { username, password } = req.body;
    const loginUser = { username, password };

    for (const [key, value] of Object.entries(loginUser))
      if (value == null)
        return res.status(400).json({
          error: `Missing '${key}' in request body`,
        });

    try {
      AuthService.getUserWithUserName(
        req.app.get('db'),
        loginUser.username
      ).then((dbUser) => {
        if (!dbUser)
          return res.status(400).json({
            error: 'Incorrect username or password',
          });

        AuthService.comparePasswords(loginUser.password, dbUser.password).then(
          (compareMatch) => {
            if (!compareMatch)
              return res.status(400).json({
                error: 'Incorrect username or password',
              });

            const sub = dbUser.username;
            const payload = {
              user_id: dbUser.id,
              name: dbUser.name,
            };
            res.send({
              authToken: AuthService.createJwt(sub, payload),
            });
          }
        );
      });
    } catch (error) {
      console.log(error);
      next(error);
    }
  })

  .put(requireAuth, (req, res, next) => {
    const sub = req.user.username;
    const payload = {
      user_id: req.user.id,
      name: req.user.name,
    };
    res
      .send({
        authToken: AuthService.createJwt(sub, payload),
      })
      .catch((error) => {
        console.log(error);
        next(error);
      });
  });

module.exports = authRouter;
