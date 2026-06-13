const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_cheese_token_key_123!';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:5173', // Vite development server
    credentials: true
}));

// MySQL connection pool configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    port: process.env.DB_PORT || 3306
};

let pool;

// Auto-initialize Database and Tables
async function initDB() {
    try {
        // First connect without database selected to create DB if not exists
        const tempConn = await mysql.createConnection(dbConfig);
        await tempConn.query(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME || 'cheeseboy_db'}\``);
        await tempConn.end();

        // Create the connection pool with the database selected
        pool = mysql.createPool({
            ...dbConfig,
            database: process.env.DB_NAME || 'cheeseboy_db',
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0
        });

        // Create Users Table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL UNIQUE,
                phone VARCHAR(20) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                otp_code VARCHAR(6) NULL,
                otp_expiry DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB;
        `);

        // Create Jobs Table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS jobs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(150) NOT NULL,
                requirements TEXT NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                auto_response VARCHAR(255) DEFAULT 'Thank you for the possible employment. Will be in-touch.',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB;
        `);

        console.log('✅ Database and tables initialized successfully.');
    } catch (err) {
        console.error('❌ Failed to initialize database:', err);
        process.exit(1);
    }
}

// Authentication Middleware
async function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Access denied. Please sign in.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie('token');
        return res.status(403).json({ error: 'Session expired. Please sign in again.' });
    }
}

// Nodemailer SMTP Transporter setup (if configured)
function getMailTransporter() {
    if (process.env.SMTP_HOST && process.env.SMTP_USER) {
        return nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT || 587,
            secure: process.env.SMTP_PORT == 465,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });
    }
    return null;
}

// Auth Routes

// 1. Sign Up
app.post('/api/auth/signup', async (req, res) => {
    const { name, email, phone, password } = req.body;

    // Validation
    if (!name || !email || !phone || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        // Check if user already exists (parameterized query)
        const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered.' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(12);
        const passwordHash = await bcrypt.hash(password, salt);

        // Save to Database (parameterized query)
        const [result] = await pool.query(
            'INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)',
            [name, email, phone, passwordHash]
        );

        // Generate JWT Token
        const token = jwt.sign({ id: result.insertId, email, name }, JWT_SECRET, { expiresIn: '1d' });

        // Set secure cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        res.status(201).json({ message: 'User registered successfully!', user: { id: result.insertId, name, email, phone } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error. Please try again.' });
    }
});

// 2. Sign In
app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // Fetch user from DB (parameterized query)
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        const user = users[0];

        // Compare password hashes
        const validPass = await bcrypt.compare(password, user.password_hash);
        if (!validPass) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        // Generate Token
        const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '1d' });

        // Set secure cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.json({ message: 'Welcome back!', user: { id: user.id, name: user.name, email: user.email, phone: user.phone } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error. Please try again.' });
    }
});

// 3. Log Out
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully.' });
});

// 4. Get Current User Status
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.query('SELECT id, name, email, phone FROM users WHERE id = ?', [req.user.id]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }
        res.json({ user: users[0] });
    } catch (err) {
        res.status(500).json({ error: 'Database error.' });
    }
});

// 5. Trigger OTP for Password Recovery
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email address is required.' });
    }

    try {
        const [users] = await pool.query('SELECT id, name, phone FROM users WHERE email = ?', [req.user.email || email]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'No account found with this email.' });
        }

        const user = users[0];

        // Generate 6-digit OTP code
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        // Set expiry to 5 minutes from now
        const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

        // Save OTP info to Database
        await pool.query('UPDATE users SET otp_code = ?, otp_expiry = ? WHERE id = ?', [otpCode, otpExpiry, user.id]);

        // Attempt real mail sending
        const transporter = getMailTransporter();
        if (transporter) {
            const mailOptions = {
                from: `"Cheese Boy Calvin Support" <${process.env.SMTP_USER}>`,
                to: email,
                subject: 'Cheese Boy Recovery - OTP Verification Code',
                text: `Hello ${user.name},\n\nYour OTP code to verify and recover your Cheese Boy account is: ${otpCode}.\nThis code is valid for 5 minutes.\n\nBest wishes,\nCheese Boy Calvin`
            };
            await transporter.sendMail(mailOptions);
            return res.json({ message: 'OTP verification code sent to your email.' });
        } else {
            // Log to terminal for Sandbox testing
            console.log('\n======================================================');
            console.log(`🔑 SANDBOX MODE OTP: Generated OTP for user: ${email}`);
            console.log(`CODE: ${otpCode}`);
            console.log('======================================================\n');
            
            return res.json({
                message: 'OTP verification code sent! (Sandbox mode: check the developer/terminal console to read the OTP code)',
                sandboxOtp: otpCode // Send it in response for simple sandbox verification popup
            });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error processing password recovery.' });
    }
});

// 6. Verify OTP Code
app.post('/api/auth/verify-otp', async (req, res) => {
    const { email, otpCode } = req.body;

    if (!email || !otpCode) {
        return res.status(400).json({ error: 'Email and OTP code are required.' });
    }

    try {
        const [users] = await pool.query('SELECT id, otp_code, otp_expiry FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid user or OTP.' });
        }

        const user = users[0];

        if (!user.otp_code || user.otp_code !== otpCode) {
            return res.status(400).json({ error: 'Incorrect OTP code.' });
        }

        if (new Date() > new Date(user.otp_expiry)) {
            return res.status(400).json({ error: 'OTP code has expired.' });
        }

        // OTP is correct! Clear it from database to prevent reuse
        await pool.query('UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE id = ?', [user.id]);

        // Generate a temporary reset token (valid for 10 minutes)
        const resetToken = jwt.sign({ resetUserId: user.id }, JWT_SECRET, { expiresIn: '10m' });
        res.json({ message: 'OTP verified successfully.', resetToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error. Please try again.' });
    }
});

// 7. Reset Password using reset token
app.post('/api/auth/reset-password', async (req, res) => {
    const { password, resetToken } = req.body;

    if (!password || !resetToken) {
        return res.status(400).json({ error: 'Password and reset token are required.' });
    }

    try {
        const decoded = jwt.verify(resetToken, JWT_SECRET);
        
        // Hash the new password
        const salt = await bcrypt.genSalt(12);
        const passwordHash = await bcrypt.hash(password, salt);

        // Update password in DB
        await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, decoded.resetUserId]);

        res.json({ message: 'Password updated successfully. You can now sign in.' });
    } catch (err) {
        res.status(400).json({ error: 'Invalid or expired recovery token.' });
    }
});


// Jobs Routes (Protected)

// 1. Submit a Job
app.post('/api/jobs', authenticateToken, async (req, res) => {
    const { title, requirements } = req.body;

    if (!title || !requirements) {
        return res.status(400).json({ error: 'Job title and requirements are required.' });
    }

    try {
        const [result] = await pool.query(
            'INSERT INTO jobs (user_id, title, requirements) VALUES (?, ?, ?)',
            [req.user.id, title, requirements]
        );

        // Return the added job along with Calvin's auto-response
        const [newJob] = await pool.query('SELECT * FROM jobs WHERE id = ?', [result.insertId]);

        res.status(201).json({
            message: 'Job submitted successfully!',
            job: newJob[0],
            alertResponse: 'Thank you for the possible employment. Will be in-touch.'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to submit job.' });
    }
});

// 2. Get User's Submitted Jobs
app.get('/api/jobs', authenticateToken, async (req, res) => {
    try {
        const [jobs] = await pool.query('SELECT * FROM jobs WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
        res.json({ jobs });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to retrieve jobs.' });
    }
});

// Start the server
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 API Server running on http://localhost:${PORT}`);
    });
});
