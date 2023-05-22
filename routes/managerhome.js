var express = require('express');
var router = express.Router(); 
const bcrypt = require('bcrypt');
const Joi = require('joi'); 
const validator = require('validator');

const {PrismaClient} = require("@prisma/client");
const { clearScreenDown } = require('readline');
const prisma = new PrismaClient() 


/* GET manager page. */ 
router.get('/manager/manager', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Manager') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }
    const query = req.query.q // Get the value of the 'q' parameter from the query string
    const users = await prisma.user.findMany()
    let filteredUsers = users.filter(user => user.usertype === 'User')

    if (query) { // If a search query is provided, filter the results
      filteredUsers = filteredUsers.filter(user => {
        const fullName = `${user.firstname} ${user.middlename ? user.middlename + ' ' : ''}${user.lastname}`
        return fullName.toLowerCase().includes(query.toLowerCase()) || user.email.toLowerCase().includes(query.toLowerCase())
      })
    }

    res.render('manager/manager', { title: 'Manager', users: filteredUsers, isEmpty: filteredUsers.length === 0, query: query });
  } catch (err) {
    console.error(err)
    next(err)
  }
});


/* GET admin profile page. */ 
router.get('/manager/managerprofile', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Manager') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    res.render('manager/managerprofile', { title: 'Manager Profile', user: user });
  } catch (err) {
    console.error(err)
    next(err)
  }
});



// GET admin edit user page
router.post('/manager/manageredituser', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Manager') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId } = req.body; // Retrieve the user ID from the request body

    // Fetch the user record from the database
    const selectedUser = await prisma.user.findUnique({
      where: { id: String(userId) } // Convert id to string
    });

    res.render('manager/manageredituser', {
      title: 'Edit User Data',
      user: selectedUser,
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

// POST admin edit user record
router.post('/manager/manageredituserrecord', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Manager') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId, email, usertype } = req.body; // Retrieve the form data

    // Validate email
    if (!validator.isEmail(email)) {
      return res.render('manager/manageredituser', {
        title: 'Edit User Data',
        user: { id: userId },
        error: 'Invalid email address.'
      });
    }

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser && existingUser.id !== userId) {
      return res.render('manager/manageredituser', {
        title: 'Edit User Data',
        user: { id: userId },
        error: 'Email already exists.'
      });
    }

    // Update the user record in the database
    const updatedUser = await prisma.user.update({
      where: { id: String(userId) }, // Convert id to string
      data: { email, usertype }
    });
    
    // Render the edit user page with the updated user data and success message
    res.render('manager/manageredituser', {
      title: 'Edit User Data',
      user: updatedUser,
      success: 'User data updated successfully.'
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

// POST admin update user password
router.post('/manager/managerupdateuserpassword', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Manager') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId, newPassword, confirmPassword } = req.body; // Retrieve the form data

    if (newPassword !== confirmPassword) {
      // Passwords don't match, handle the error
      res.render('manager/manageredituser', {
        title: 'Update User Password',
        user: { id: userId },
        error: 'Passwords do not match.'
      });
      return;
    }

    // Validate password against password policy
    const { error } = passwordPolicy.validate({ password: newPassword });
    if (error) {
      return res.render('manager/manageredituser', {
        title: 'Update User Password',
        user: { id: userId },
        error: error.details[0].message
      });
    }

    // Encrypt the entered password using bcrypt
    const saltRounds = 10; // Number of salt rounds for bcrypt
    const encryptedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user password in the database
    const updatedUser = await prisma.user.update({
      where: { id: String(userId) }, // Convert id to string
      data: { password: encryptedPassword }
    });

    // Render the edit user page with the updated user data and success message
    res.render('manager/manageredituser', {
      title: 'Edit User Data',
      user: updatedUser,
      success: 'User password updated successfully.'
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

/* POST update password page. */
router.post('/manager/updatepassword', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    const { oldPassword, newPassword, confirmNewPassword } = req.body;
 
    // Check if the old password matches the registered password
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      // If the old password does not match, show an error message
      res.render('manager/managerprofile', { error: 'Incorrect old password.' });
      return;
    }

    // Check if the new password and confirm password match
    if (newPassword !== confirmNewPassword) {
      // If the new password and confirm password do not match, show an error message
      res.render('manager/managerprofile', { error: 'New password and confirm password do not match.' });
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
    res.render('manager/managerprofile', { success: 'Password updated successfully.' });
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
