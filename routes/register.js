const express = require('express');
const router = express.Router(); 
const session = require('express-session');
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const Joi = require('joi');
const bcrypt = require('bcrypt');
const validator = require('validator');

// Initialize the session middleware
router.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

/* GET register page. */
router.get('/register', async function(req, res, next) {
      const students = await prisma.user.findMany();
      res.render('register', { title: 'Register', students: students }); 
});

// POST register page
router.post('/register', async function(req, res, next) {
  try {
    // Sanitize user input
    const { email, firstname, lastname, password, usertype } = req.body;
    const sanitizedEmail = validator.normalizeEmail(email);
    const sanitizedFirstname = validator.escape(firstname);
    const sanitizedLastname = validator.escape(lastname);

    // Validate email
    if (!validator.isEmail(sanitizedEmail)) {
      return res.render('register', { title: 'Register', error: 'Invalid email address.' });
    }

    // Validate password against password policy
    const { error } = passwordPolicy.validate({ password });
    if (error) {
      return res.render('register', { title: 'Register', error: error.details[0].message });
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({ where: { email: sanitizedEmail } });
    if (existingUser) {
      return res.render('register', { title: 'Register', error: 'Email already exists.' });
    }

    // Create new user
    await prisma.user.create({
      data: {
        email: sanitizedEmail,
        firstname: sanitizedFirstname,
        lastname: sanitizedLastname,
        password: hashedPassword,
        usertype
      },
    });

    res.render('register', { title: 'Register', successMessage: 'Registration successful.' });
  } catch (error) {
    console.error(error);
    res.status(500).render('register', { title: 'Register', error: 'Something went wrong. Please try again later.' });
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
