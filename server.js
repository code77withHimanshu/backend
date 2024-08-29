const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cron = require('node-cron'); // Import node-cron
const nodemailer = require('nodemailer'); // Import nodemailer for sending email notifications
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client("486880569229-te48aevb35vql663i8rn8dshhb5m9enn.apps.googleusercontent.com");

// Define User model
const userSchema = new mongoose.Schema({
  googleId: String,
  name: String,
  email: String,
  passwordHash: String
}, { collection: 'User' });

const User = mongoose.model('User', userSchema);

// Define Task model
const taskSchema = new mongoose.Schema({
  title: String,
  description: String,
  createdAt: { type: Date, default: Date.now },
  dueDate: Date,
  reminder: String,
  column: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { collection: 'Tasks' });

const Task = mongoose.model('Task', taskSchema);

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// JWT Secret
const JWT_SECRET = 'your_jwt_secret'; // Replace with your JWT secret

// Passport configuration
passport.use(new GoogleStrategy({
  clientID: "486880569229-te48aevb35vql663i8rn8dshhb5m9enn.apps.googleusercontent.com",
  clientSecret: "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",
  callbackURL: '/auth/google/callback',
  scope: ["profile", "email"]
}, async (accessToken, refreshToken, profile, done) => {
  const existingUser = await User.findOne({ googleId: profile.id });
  if (existingUser) {
    return done(null, existingUser);
  }
  const newUser = new User({ googleId: profile.id, name: profile.displayName });
  await newUser.save();
  done(null, newUser);
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// Authentication middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Reminder notification function
function getReminderTime(dueDate, reminder) {
  const due = new Date(dueDate);
  
  switch (reminder) {
    case '5 minutes before':
      return new Date(due.getTime() - 5 * 60000);
    case '10 minutes before':
      return new Date(due.getTime() - 10 * 60000);
    case '15 minutes before':
      return new Date(due.getTime() - 15 * 60000);
    case '1 hour before':
      return new Date(due.getTime() - 60 * 60000);
    case '2 hours before':
      return new Date(due.getTime() - 120 * 60000);
    case '1 day before':
      return new Date(due.getTime() - 24 * 60 * 60000);
    case '2 days before':
      return new Date(due.getTime() - 48 * 60 * 60000);
    default:
      return due;
  }
}

// Set up email transporter using Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail', // Use your email service
  auth: {
    user: 'hd259364@gmail.com', // Your email
    pass: 'badoxpkuafgfbysu' // Your email password
  }
});

// Function to send email notifications
async function sendReminderEmail(userEmail, taskTitle, taskId) {
  const mailOptions = {
    from: 'hd259364@gmail.com',
    to: userEmail,
    subject: 'Task Reminder',
    text: `Reminder for task: ${taskTitle}\nTask ID: ${taskId}`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Reminder email sent to:', userEmail);
  } catch (error) {
    console.error('Error sending reminder email:', error);
  }
}

// Cron job to check reminders every minute
cron.schedule('* * * * *', async () => {
  const now = new Date();
  const tasks = await Task.find({ reminder: { $ne: 'None' } });

  for (const task of tasks) {
    const reminderTime = getReminderTime(task.dueDate, task.reminder);
    if (now >= reminderTime && now <= new Date(reminderTime.getTime() + 60000)) {
      // Find the user for the task
      const user = await User.findById(task.userId);
      if (user) {
        await sendReminderEmail(user.email, task.title, task._id);
      }
    }
  }
});

// Routes

// Google OAuth routes
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

app.get('/auth/google/callback', passport.authenticate('google'), (req, res) => {
  const token = jwt.sign({ id: req.user.id, email: req.user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.redirect(`http://localhost:3000/dashboard`);
});

app.get('/auth/logout', (req, res) => {
  res.redirect('/');
});

app.get('/auth/current_user', authenticateJWT, (req, res) => {
  res.json(req.user);
});

app.post('/api/google-login', async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: "486880569229-te48aevb35vql663i8rn8dshhb5m9enn.apps.googleusercontent.com"
    });

    const { sub: googleId, email, name } = ticket.getPayload();
    let user = await User.findOne({ googleId });

    if (!user) {
      user = new User({ googleId, email, name });
      await user.save();
    }

    const jwtToken = jwt.sign({ id: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token: jwtToken });
  } catch (error) {
    console.error('Google login failed', error);
    res.status(500).json({ message: 'Google login failed' });
  }
});


// User Registration
app.post('/api/register', async (req, res) => {
  const { firstName, lastName, email, password, confirmPassword } = req.body;
  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name: `${firstName} ${lastName}`,
      email,
      passwordHash: hashedPassword
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error });
  }
});

app.post('/api/google-register', async (req, res) => {
  const { googleId, name, email } = req.body;

  try {
    // Check if a user with the same googleId already exists
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(201).json({ message: 'Email Id already exists' });
    }

    // If no existing user, proceed with registration
    const newUser = new User({
      googleId,
      name,
      email
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token, user });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error });
  }
});

app.post('/api/google-login', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token, user });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error });
  }
});

app.post('/id', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email' });
    }

    res.status(200).json({ id: user._id }); // Return the user ID wrapped in an object
  } catch (error) {
    res.status(500).json({ message: 'Error retrieving user ID', error });
  }
});

// User Logout
app.post('/api/logout', (req, res) => {
  res.status(200).json({ message: 'Logged out successfully' });
});

// Task management routes
app.get('/tasks', authenticateJWT, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.user.id });
    res.json(tasks);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching tasks', error });
  }
});

app.get('/tasks/:id', authenticateJWT, async (req, res) => {
  try {
    const taskId = req.params.id;
    const task = await Task.findOne({ _id: taskId });

    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }

    res.json(task);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching task details', error });
  }
});

app.post('/api/tasks', authenticateJWT, async (req, res) => {
  const { title, description, dueDate, column } = req.body;

  try {
    const newTask = new Task({
      title,
      description,
      dueDate,
      reminder: "None",
      column,
      userId: req.user.id
    });

    await newTask.save();
    res.status(201).json(newTask);
  } catch (error) {
    res.status(500).json({ message: 'Error creating task', error });
  }
});

app.put('/api/tasks/:id', authenticateJWT, async (req, res) => {
  const { title, description, dueDate, reminder, column } = req.body;

  try {
    const task = await Task.findByIdAndUpdate(req.params.id, { title, description, dueDate, reminder, column }, { new: true });
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    res.json(task);
  } catch (error) {
    res.status(500).json({ message: 'Error updating task', error });
  }
});

app.delete('/api/tasks/:id', authenticateJWT, async (req, res) => {
  try {
    await Task.findByIdAndDelete(req.params.id);
    res.status(204).end();
  } catch (error) {
    res.status(500).json({ message: 'Error deleting task', error });
  }
});

// Database connection
mongoose.connect('mongodb://localhost:27017/task_manager', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
