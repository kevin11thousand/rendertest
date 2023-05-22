const express = require('express');
const router = express.Router();
const session = require('express-session');
const { PrismaClient } = require("@prisma/client"); 
const bcrypt = require('bcrypt');
const Joi = require('joi'); 

const prisma = new PrismaClient();

// Initialize the session middleware
router.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

router.get('/login', function(req, res, next) {
  // If user is already logged in, redirect to appropriate page
  if (req.session.user) { 
    switch (req.session.user.usertype) {
      case 'Admin':
        res.redirect("/admin/admincharts");
        break; 
      case "Manager":
        res.redirect("/manager/manager");
        break;
      case "User":
        res.redirect("/user/user");
        break;
      default:
        res.render('error', { message: 'Invalid userType: ' + user.usertype });
        break;
    }
    return;
  }

  // Otherwise, render the login page
  res.render('login', { title: 'Login', error: undefined, success: undefined });
});

// POST login
router.post('/login', async function(req, res, next) {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({
      where: { email: email }
    });

    if (!user) {
      res.render('login', { title: 'Login', error: 'Email not registered', success: undefined });
      return;
    }

    // Compare the entered password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      // Save user data in session
      req.session.user = user;

      // Redirect user based on their userType
      switch (user.usertype) {
        case "Admin":
          res.redirect("/admin/admincharts");
          break;
        case "Manager":
          res.redirect("/manager/manager");
          break;
        case "User":
          res.redirect("/user/user");
          break;
        default:
          res.render('error', { message: 'Invalid userType: ' + user.usertype });
          break;
      }
    } else {
      res.render('login', { title: 'Login', error: 'Password incorrect!', success: undefined });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Something went wrong");
  }
});

router.get('/forgot-password', (req, res, next) => {
  // If user is already logged in, redirect to appropriate page
  if (req.session.user) { 
    switch (req.session.user.usertype) {
      case 'Admin':
        res.redirect("/admin/admincharts");
        break; 
      case "Manager":
        res.redirect("/manager/manager");
        break;
      case "User":
        res.redirect("/user/user");
        break;
      default:
        res.render('error', { message: 'Invalid userType: ' + user.usertype });
        break;
    }
    return;
  }
  res.render('forgot-password', { title: 'Forgot Password' });
});

router.post('/forgot-password', async (req, res, next) => {
  const email = req.body.email;

  try {
   // Check if the email is valid and belongs to an admin
    const user = await prisma.user.findUnique({
      where: { email: email },
      select: { usertype: true }
    });

    if (!user || user.usertype !== 'Admin') {
      res.render('forgot-password', { title: 'Forgot Password', error: 'Invalid email address', success: undefined });
      return;
    }


    // Generate a new password based on the password policy
    const newPassword = generatePassword();

    // Hash the new password using bcrypt
    const hashedPassword = await bcrypt.hash(newPassword, 10);

  // Update the user's password in the database
    await prisma.user.update({
      where: { email: email }, // Provide the user's email or other unique identifier
      data: { password: hashedPassword }
    });


    // Render the success page with the new password
    res.render('success', { message: 'Password reset successful. Your new password is: ' + newPassword });
  } catch (error) {
    console.error(error);
    res.status(500).send('Something went wrong');
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

// Generate a random password based on the password policy
function generatePassword() {
  // Generate a random password based on the password policy
  // This is just a simple example, you should use a more secure password generation approach
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};\'\\|,.<>/?';
  let password = '';
  const passwordLength = 10;
  for (let i = 0; i < passwordLength; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    password += charset[randomIndex];
  }
  return password;
}

router.get('/success', function(req, res, next) {
  // If user is already logged in, redirect to appropriate page
  if (req.session.user) { 
    switch (req.session.user.usertype) {
      case 'Admin':
        res.redirect("/admin/admincharts");
        break; 
      case "Manager":
        res.redirect("/manager/manager");
        break;
      case "User":
        res.redirect("/user/user");
        break;
      default:
        res.render('error', { message: 'Invalid userType: ' + req.session.user.usertype });
        break;
    }
    return;
  }
  if (!req.query.message) {
    res.redirect('/forgot-password');
    return;
  }

  res.render('success', { title: 'Success', message: '' });
});


router.post('/success', function(req, res, next) {
  res.redirect('/login');
});


module.exports = router;
