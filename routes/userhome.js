var express = require('express');
var router = express.Router(); 
const bcrypt = require('bcrypt');
const Joi = require('joi'); 
const validator = require('validator');

const {PrismaClient} = require("@prisma/client");
const { clearScreenDown } = require('readline');
const prisma = new PrismaClient() 


/* GET admin profile page. */ 
router.get('/user/user', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'User') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    res.render('user/user', { title: 'User Profile', user: user });
  } catch (err) {
    console.error(err)
    next(err)
  }
});


/* POST update password page. */
router.post('/user/updatepassword', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    const { oldPassword, newPassword, confirmNewPassword } = req.body;
 
    // Check if the old password matches the registered password
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      // If the old password does not match, show an error message
      res.render('user/user', { error: 'Incorrect old password.' });
      return;
    }

    // Check if the new password and confirm password match
    if (newPassword !== confirmNewPassword) {
      // If the new password and confirm password do not match, show an error message
      res.render('user/user', { error: 'New password and confirm password do not match.' });
      return;
    }

      // Hash the new password using bcrypt
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    await prisma.user.update({
      where: { id: String(user.id) },
      data: { password: hashedPassword }
    });


    // Redirect to dashboard page with success message
    res.render('user/user', { success: 'Password updated successfully.' });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

// Password policy setting
const passwordPolicy = Joi.object({
  password: Joi.string()
    .pattern(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character',
      'any.required': 'Password is required'
    })
});


module.exports = router;
