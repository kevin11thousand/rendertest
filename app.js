var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var loginRouter = require('./routes/login');
var registerRouter = require('./routes/register'); 
var adminRouter = require('./routes/adminhome'); 
var managerRouter = require('./routes/managerhome'); 
var userRouter = require('./routes/userhome'); 

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


app.use('/', registerRouter);  
app.use('/', loginRouter); 
app.use('/', adminRouter);  
app.use('/', managerRouter);  
app.use('/', userRouter);  

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // check if the user is logged in
  if (req.session.user) {
    // render the appropriate page based on the user type 
    switch (req.session.user.usertype) {
    
      case 'Admin':
        res.redirect('/admin/admincharts');
        break;
      case 'Manager':
        res.redirect('/manager/manager');
        break;
      case 'User':
        res.redirect('/user/user');
        break;
      default:
        res.status(400).send('Invalid userType');
    }
  } else {
    // user is not logged in, render the landing page
    res.status(err.status || 500);
    res.render('index');
  }
});


module.exports = app;
