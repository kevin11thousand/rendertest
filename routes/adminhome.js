var express = require('express');
var router = express.Router(); 
const bcrypt = require('bcrypt');
const Joi = require('joi'); 
const validator = require('validator');

const {PrismaClient} = require("@prisma/client");
const { clearScreenDown } = require('readline');
const prisma = new PrismaClient() 
 


/* GET admin page. */
router.get('/admin/admindashboard', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }
    
    const query = req.query.q // Get the value of the 'q' parameter from the query string
    const users = await prisma.user.findMany()
    let filteredUsers = users.filter(user => user.usertype === 'Admin')

    if (query) { // If a search query is provided, filter the results
      filteredUsers = filteredUsers.filter(user => {
        const fullName = `${user.firstname} ${user.middlename ? user.middlename + ' ' : ''}${user.lastname}`
        return fullName.toLowerCase().includes(query.toLowerCase()) || user.email.toLowerCase().includes(query.toLowerCase())
      })
    }

    res.render('admin/admindashboard', { title: 'Admin', users: filteredUsers, isEmpty: filteredUsers.length === 0, query: query });
  } catch (err) {
    console.error(err)
    next(err)
  }
});

/* GET manager page. */
router.get('/admin/managerdashboard', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }
    const query = req.query.q // Get the value of the 'q' parameter from the query string
    const users = await prisma.user.findMany()
    let filteredUsers = users.filter(user => user.usertype === 'Manager')

    if (query) { // If a search query is provided, filter the results
      filteredUsers = filteredUsers.filter(user => {
        const fullName = `${user.firstname} ${user.middlename ? user.middlename + ' ' : ''}${user.lastname}`
        return fullName.toLowerCase().includes(query.toLowerCase()) || user.email.toLowerCase().includes(query.toLowerCase())
      })
    }

    res.render('admin/managerdashboard', { title: 'Manager', users: filteredUsers, isEmpty: filteredUsers.length === 0, query: query });
  } catch (err) {
    console.error(err)
    next(err)
  }
});

/* GET user page. */
router.get('/admin/userdashboard', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
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

    res.render('admin/userdashboard', { title: 'User', users: filteredUsers, isEmpty: filteredUsers.length === 0, query: query });
  } catch (err) {
    console.error(err)
    next(err)
  }
});

/* GET admin profile page. */ 
router.get('/admin/adminprofile', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    res.render('admin/adminprofile', { title: 'Admin Profile', user: user });
  } catch (err) {
    console.error(err)
    next(err)
  }
});

/* GET admin profile delete confirmation page. */ 
router.get('/admin/adminprofiledelete', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }
    
    // Check if the user email matches the email to be protected
    if (user.email === 'mjjrrugas@tip.edu.ph') {
      // Redirect to admin profile page
      res.redirect('/admin/adminprofile');
      return;
    }


    res.render('admin/adminprofiledelete', { title: 'Delete Admin Profile', user: user });
  } catch (err) {
    console.error(err)
    next(err)
  }
});
   

/* POST admin profile delete confirmation page. */
router.post('/admin/adminprofiledeleteconfirm', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session

    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const password = req.body.password; // Get the password from the request body

    // Retrieve the hashed password from the database
    const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
    const storedPassword = dbUser.password;

   // Check if the entered password matches the stored password
    const passwordMatch = await bcrypt.compare(password, storedPassword);
    if (!passwordMatch) {
      // If passwords don't match, render the delete confirmation page with an error message
      return res.render('admin/adminprofiledelete', { title: 'Delete Admin Profile', user: user, error: 'Incorrect password. Deletion failed.' });
    }

    if (user.email === 'mjjrrugas@tip.edu.ph') {
      // If the user's email is mjjrrugas@tip.edu.ph, do not delete the account
      return res.render('admin/adminprofiledelete', { title: 'Delete Admin Profile', user: user, error: 'Deletion of this account is not allowed.' });
    }

    // Delete the user account from the database
    await prisma.user.delete({
      where: { id: user.id }
    });

    // Clear the user data from the session and redirect to login page
    req.session.user = null;
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    next(err);
  }
});




/* POST update password page. */
router.post('/admin/updatepassword', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    const { oldPassword, newPassword, confirmNewPassword } = req.body;
 
    // Check if the old password matches the registered password
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      // If the old password does not match, show an error message
      res.render('admin/adminprofile', { error: 'Incorrect old password.' });
      return;
    }

    // Check if the new password and confirm password match
    if (newPassword !== confirmNewPassword) {
      // If the new password and confirm password do not match, show an error message
      res.render('admin/adminprofile', { error: 'New password and confirm password do not match.' });
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
    res.render('admin/adminprofile', { success: 'Password updated successfully.' });
  } catch (err) {
    console.error(err);
    next(err);
  }
});
 
/* POST delete manager record */
router.post('/admin/admindeletemanager', async function(req, res, next) {
  try {
    const { userId, password } = req.body;
    const adminUser = req.session.user;
    if (!adminUser || adminUser.usertype !== 'Admin') {
      res.redirect('/login');
      return;
    }

    // Compare the entered password with the stored password
    const passwordMatch = await bcrypt.compare(password, adminUser.password);
    if (!passwordMatch) {
      res.redirect('/admin/managerdashboard');
      return;
    }

    // Delete the manager record from the database
    await prisma.user.delete({ where: { id: userId } });
    res.redirect('/admin/managerdashboard');
  } catch (err) {
    console.error(err);
    res.render('admin/managerdashboard', { title: 'Manager Dashboard', user: adminUser, error: 'Error occurred during deletion. Please try again.' });
  }
});





// GET admin edit manager page
router.post('/admin/admineditmanager', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId } = req.body; // Retrieve the user ID from the request body

    // Fetch the user record from the database
    const selectedUser = await prisma.user.findUnique({
      where: { id: String(userId) } // Convert id to string
    });

    res.render('admin/admineditmanager', {
      title: 'Edit Manager Data',
      user: selectedUser,
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});



// POST admin edit manager record
router.post('/admin/admineditmanagerrecord', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId, email, usertype } = req.body; // Retrieve the form data

    // Validate email
    if (!validator.isEmail(email)) {
      return res.render('admin/admineditmanager', {
        title: 'Edit Manager Data',
        user: { id: userId },
        error: 'Invalid email address.'
      });
    }

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser && existingUser.id !== userId) {
      return res.render('admin/admineditmanager', {
        title: 'Edit Manager Data',
        user: { id: userId },
        error: 'Email already exists.'
      });
    }

    // Update the user record in the database
    const updatedUser = await prisma.user.update({
      where: { id: String(userId) }, // Convert id to string
      data: { email, usertype }
    });
    
     // Render the edit manager page with the updated user data and success message
     res.render('admin/admineditmanager', {
      title: 'Edit Manager Data',
      user: updatedUser,
      success: 'Manager data updated successfully.'
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

// POST admin update manager password
router.post('/admin/adminupdatemanagerpassword', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId, newPassword, confirmPassword } = req.body; // Retrieve the form data

    if (newPassword !== confirmPassword) {
      // Passwords don't match, handle the error
      res.render('admin/admineditmanager', {
        title: 'Update Manager Password',
        user: { id: String(userId) },
        error: 'Passwords do not match.'
      });
      return;
    }

    // Validate password against password policy
    const { error } = passwordPolicy.validate({ password: newPassword });
    if (error) {
      return res.render('admin/admineditmanager', {
        title: 'Update Manager Password',
        user: { id: String(userId) },
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

    // Render the edit manager page with the updated user data and success message
    res.render('admin/admineditmanager', {
      title: 'Edit Manager Data',
      user: updatedUser,
      success: 'Manager password updated successfully.'
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});





// POST delete user record
router.post('/admin/admindeleteuser', async function(req, res, next) {
  try {
    const { userId, password } = req.body;
    const userUser = req.session.user;
    if (!userUser || userUser.usertype !== 'Admin') {
      res.redirect('/login');
      return;
    }

    // Compare the entered password with the stored encrypted password
    const passwordMatch = await bcrypt.compare(password, userUser.password);
    if (!passwordMatch) {
      res.redirect('/admin/userdashboard');
      return;
    }

    // Delete the User record from the database
    await prisma.user.delete({ where: { id: userId } });
    res.redirect('/admin/userdashboard');
  } catch (err) {
    console.error(err);
    res.render('admin/userdashboard', { title: 'User Dashboard', user: userUser, error: 'Error occurred during deletion. Please try again.' });
  }
});





// GET admin edit user page
router.post('/admin/adminedituser', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId } = req.body; // Retrieve the user ID from the request body

    // Fetch the user record from the database
    const selectedUser = await prisma.user.findUnique({
      where: { id: String(userId) } // Convert id to string
    });

    res.render('admin/adminedituser', {
      title: 'Edit User Data',
      user: selectedUser,
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});



// POST admin edit user record
router.post('/admin/adminedituserrecord', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId, email, usertype } = req.body; // Retrieve the form data

    // Validate email
    if (!validator.isEmail(email)) {
      return res.render('admin/adminedituser', {
        title: 'Edit User Data',
        user: { id: userId },
        error: 'Invalid email address.'
      });
    }

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser && existingUser.id !== userId) {
      return res.render('admin/adminedituser', {
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
    res.render('admin/adminedituser', {
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
router.post('/admin/adminupdateuserpassword', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const { userId, newPassword, confirmPassword } = req.body; // Retrieve the form data

    if (newPassword !== confirmPassword) {
      // Passwords don't match, handle the error
      res.render('admin/adminedituser', {
        title: 'Update User Password',
        user: { id: userId },
        error: 'Passwords do not match.'
      });
      return;
    }

    // Validate password against password policy
    const { error } = passwordPolicy.validate({ password: newPassword });
    if (error) {
      return res.render('admin/adminedituser', {
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
    res.render('admin/adminedituser', {
      title: 'Edit User Data',
      user: updatedUser,
      success: 'User password updated successfully.'
    });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

// admin/admincharts route 
router.get('/admin/admincharts', async function(req, res, next) {
  try {
    const user = req.session.user; // Fetch the user data from session
    if (!user || user.usertype !== 'Admin') {
      // If user is not logged in or not an admin, redirect to login page
      res.redirect('/login');
      return;
    }

    const adminCount = await prisma.user.count({ where: { usertype: 'Admin' } });
    const managerCount = await prisma.user.count({ where: { usertype: 'Manager' } });
    const userCount = await prisma.user.count({ where: { usertype: 'User' } });

    // Render the admincharts page with the counts
    res.render('admin/admincharts', {
      title: 'Admin Charts',
      adminCount,
      managerCount,
      userCount
    });
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


/* GET logout page. */
router.get('/admin/logout', function(req, res, next) {
  req.session.destroy(err => {
    if (err) {
      console.error(err)
    } else {
      res.redirect('/login')
    }
  })
});

// GET admin login page
router.get('/admin-login', function(req, res) {
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
    
  res.render('admin-login', { title: 'Admin Login', error: null });
});

// POST admin login
router.post('/admin-login', async function(req, res) {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({
    where: { email: email }
  });


  try {
    // Check if the email is mjjrrugas@tip.edu.ph
    if (email !== 'mjjrrugas@tip.edu.ph') {
      return res.render('admin-login', { title: 'Admin Login', error: 'Access denied' });
    }

    // Find the admin user by email
    const adminUser = await prisma.user.findUnique({ where: { email } });

    if (!adminUser) {
      return res.render('admin-login', { title: 'Admin Login', error: 'Email not registered' });
    }

    // Compare the entered password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, adminUser.password);

    if (passwordMatch) {
      // Store admin user information in session
      
      req.session.user = user; 
      res.redirect('/admin-backup'); // Redirect to the admin backup page
    } else {
      res.render('admin-login', { title: 'Admin Login', error: 'Password incorrect' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Something went wrong');
  }
});

// GET admin backup page
router.get('/admin-backup', function(req, res) {
  
 
  const user = req.session.user; // Fetch the user data from session
  if (!user || user.usertype !== 'Admin') {
    // If user is not logged in or not an admin, redirect to login page
    res.redirect('/admin-login');
    return;
  }

  res.render('admin-backup', { title: 'Admin Backup', successMessage: null, errorMessage: null });
});

// POST admin backup
router.post('/admin-backup', async function(req, res, next) {

  const user = req.session.user; // Fetch the user data from session
  if (!user || user.usertype !== 'Admin') {
    // If user is not logged in or not an admin, redirect to login page
    res.redirect('/admin-login');
    return;
  }

  try {
    // Retrieve all users from the User model
    const users = await prisma.user.findMany();

    // Create backup entries in the UserBackup model
    await prisma.userBackup.createMany({
      data: users.map(user => ({
        email: user.email,
        firstname: user.firstname,
        lastname: user.lastname,
        password: user.password,
        usertype: user.usertype
      }))
    });
    
    res.redirect('/admin-backup');
  } catch (error) {
    console.error(error);
    res.status(500).send('Something went wrong.');
  }
});

module.exports = router;
